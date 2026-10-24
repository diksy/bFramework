<?php

declare(strict_types=1);

namespace bFramework;

defined('APP_BOOTED') || define('APP_BOOTED', true);

require_once __DIR__ . '/core/Autoloader.php';

Autoloader::register(__DIR__ . '/core');

/**
 * Perakitan runtime halaman (M9): dipanggil sekali per request oleh front controller setelah
 * koneksi DB dan SessionStore tersedia. Satu-satunya tempat PageController::configure() dipanggil.
 */
function configureRuntime(
    string $appDir,
    Runtime\Connection $conn,
    Contracts\SessionStore $session,
    ?Contracts\Logger $logger = null,
    ?Runtime\FileRefs $files = null,
): void {
    $defs = new Runtime\Definitions(new Runtime\CacheStore($appDir . '/storage/cache'));
    Runtime\PageController::configure(
        $defs,
        new Runtime\Query($conn, $conn->grammar(), $defs->allowlist(), $logger),
        new Runtime\Authorizer(),
        new Runtime\HookRunner($appDir . '/extensions'),
        new Core\Template($appDir . '/core/Runtime/views', $appDir . '/storage/cache/views'),
        new Core\Template($appDir . '/core/Core/views', $appDir . '/storage/cache/views'),
        $session,
        new Runtime\CurrentIdentity($session),
        new Core\Csrf($session),
        Core\Config::devMode(),
        $logger,
        $files,
    );
}

/**
 * Perakitan upload (M12b): UploadService (Query khusus tabel `files`) + FileController. Satu-satunya tempat
 * Runtime dan Upload bertemu (ARCH-03). Direktori default app/storage/uploads (di luar docroot); `docroot`
 * diisi bila public_html bersebelahan dengan app/ (mode cadangan: tanpa pengecekan ini, andalkan deny-all).
 * Opsi config `upload`: dir, maxFilesPerOwner, maxBytesPerOwner, rateMax, rateWindow.
 *
 * @return array{0:Upload\UploadService,1:Upload\FileController}
 */
function buildUploads(
    string $appDir,
    Runtime\Connection $conn,
    Runtime\Definitions $defs,
    Runtime\CurrentIdentity $identity,
    ?Contracts\Logger $logger = null,
): array {
    $cfg = Core\Config::get('upload', []);
    $cfg = is_array($cfg) ? $cfg : [];
    $dir = is_string($cfg['dir'] ?? null) && $cfg['dir'] !== '' ? $cfg['dir'] : $appDir . '/storage/uploads';
    $docroot = realpath($appDir . '/../public_html');
    $opts = [];
    foreach (['maxFilesPerOwner', 'maxBytesPerOwner', 'rateMax', 'rateWindow'] as $k) {
        if (isset($cfg[$k])) {
            $opts[$k] = $cfg[$k];
        }
    }
    $g = $conn->grammar();
    $service = new Upload\UploadService(
        new Runtime\Query($conn, $g, Upload\FilesTable::allowlist(), $logger),
        $dir,
        $opts,
        $docroot === false ? null : $docroot,
        new Core\RateLimiter($appDir . '/storage/ratelimit'),
        $logger,
    );
    $controller = new Upload\FileController(
        $service,
        $identity,
        new Runtime\Authorizer(),
        static fn(string $m): ?array => $defs->model($m),
        new Runtime\Query($conn, $g, $defs->allowlist(), $logger),
        ['admin'],
        $logger,
    );
    return [$service, $controller];
}

/**
 * Perakitan builder (M14, SEC-BLD-01). Rute hanya terdaftar bila BuilderGate::enabled() (dev, atau produksi dengan
 * `builder.unsafeBuilderInProduction` + `builder.allowedIps` + hash kata sandi builder). Konfigurasi `builder`:
 * unsafeBuilderInProduction (bool), allowedIps (list), passwordHash (password_hash; env BUILDER_PASSWORD_HASH
 * menimpa), loginTtl, rateMax, rateWindow. Dev/produksi ditentukan SATU sumber: Config::devMode().
 */
function buildBuilder(
    string $appDir,
    Runtime\Connection $conn,
    Runtime\Definitions $defs,
    Contracts\SessionStore $session,
    Core\Csrf $csrf,
    ?Contracts\Logger $logger = null,
): Builder\BuilderController {
    $cfg = Core\Config::get('builder', []);
    $cfg = is_array($cfg) ? $cfg : [];
    $envHash = getenv('BUILDER_PASSWORD_HASH');
    if ($envHash !== false && $envHash !== '') {
        $cfg['passwordHash'] = $envHash;
    }
    $clock = new Auth\SystemClock();
    $identity = new Runtime\CurrentIdentity($session);
    $gate = new Builder\BuilderGate(
        Core\Config::devMode(),
        $cfg,
        $session,
        static fn(): ?Contracts\Identity => $identity->get(),
        new Core\RateLimiter($appDir . '/storage/ratelimit', $clock),
        $clock,
        $logger,
    );
    $compiler = new Runtime\Compiler(new Runtime\CacheStore($appDir . '/storage/cache'), $appDir . '/extensions');
    $writer = new Builder\DefinitionWriter($appDir . '/definitions', $compiler, $conn->dialect(), $appDir . '/extensions', $logger);
    $roles = new Auth\RoleStore($conn);
    return new Builder\BuilderController(
        $gate,
        $writer,
        new Builder\HookScanner($appDir . '/extensions'),
        new Builder\AuditLog($conn, $clock, $logger),
        $conn,
        $csrf,
        new Core\Template($appDir . '/core/Builder/views', $appDir . '/storage/cache/views'),
        new Core\Template($appDir . '/core/Core/views', $appDir . '/storage/cache/views'),
        static function (string $n) use ($appDir): ?array {
            try {
                return (new Runtime\Definitions(new Runtime\CacheStore($appDir . '/storage/cache')))->model($n); // segar tiap panggilan
            } catch (\Throwable) {
                return null; // cache belum dibangun
            }
        },
        static fn(): array => $roles->names(),
        static function (Contracts\Identity $who) use ($defs): array {
            try {
                return Runtime\Navigation::build($defs->pages(), $who);
            } catch (\Throwable) {
                return [];
            }
        },
        $logger,
    );
}

/**
 * Koneksi database dari config (DB_DRIVER sqlite|mysql). Kata sandi dari config/env, tidak pernah dicatat.
 */
function connectDatabase(string $appDir): Runtime\Connection
{
    $driver = Core\Config::get('DB_DRIVER', 'sqlite');
    if ($driver === 'mysql') {
        $pass = getenv('DB_PASSWORD');
        return Runtime\Connection::mysql(
            (string) Core\Config::get('DB_HOST', 'localhost'),
            (string) Core\Config::get('DB_NAME', ''),
            (string) Core\Config::get('DB_USER', ''),
            $pass !== false ? $pass : (string) Core\Config::get('DB_PASSWORD', ''),
            (int) Core\Config::get('DB_PORT', 3306),
        );
    }
    return Runtime\Connection::sqlite($appDir . '/storage/' . basename((string) Core\Config::get('DB_FILE', 'app.sqlite')));
}

/**
 * Merakit autentikasi lokal (M10): sesi file + cookie, AuthManager, LocalDriver, ingat-saya, token,
 * Mailer, TOTP (hanya bila APP_KEY >= 32 karakter), dan antrean pekerjaan tunda.
 */
function buildAuth(string $appDir, Runtime\Connection $conn, bool $https, ?Contracts\Logger $logger = null): Auth\AuthKit
{
    $clock = new Auth\SystemClock();
    $jar = new Auth\CookieJar();
    $session = new Core\FileSessionStore($appDir . '/storage/sessions', $https, 1800, 28800, null, $jar->add(...), $clock);
    $csrf = new Core\Csrf($session);
    $accounts = new Auth\AccountStore($conn, $clock, $logger);
    $manager = new Auth\AuthManager($session, new Runtime\CurrentIdentity($session), $csrf, $accounts, $clock);

    $authCfg = Core\Config::get('auth', []);
    $authCfg = is_array($authCfg) ? $authCfg : [];
    $rememberDays = is_int($authCfg['remember_days'] ?? null) ? max(1, min(90, $authCfg['remember_days'])) : 30;
    $remember = new Auth\RememberMe($conn, $clock, $logger, $rememberDays * 86400);

    $key = getenv('APP_KEY');
    $key = $key !== false ? $key : Core\Config::get('APP_KEY');
    $twofa = null;
    if (is_string($key) && strlen($key) >= 32) {
        $twofa = new Auth\TwoFactor($accounts, new Auth\SecretVault($key), $clock);
    } else {
        $logger?->warning('APP_KEY tidak valid; 2FA dinonaktifkan');
    }

    $smtp = [];
    foreach (['SMTP_HOST', 'SMTP_PORT', 'SMTP_SECURE', 'SMTP_USER', 'APP_HOST'] as $k) {
        $smtp[$k] = Core\Config::get($k);
    }
    $pass = getenv('SMTP_PASSWORD');
    $smtp['SMTP_PASSWORD'] = $pass !== false ? $pass : Core\Config::get('SMTP_PASSWORD');

    $deferred = new Auth\Deferred($logger);
    $mailer = Auth\Mailer::fromConfig($smtp, $logger);
    $tokens = new Auth\OneTimeToken($conn, $clock);
    $driver = new Auth\LocalDriver(
        $manager,
        $accounts,
        new Auth\PasswordHasher(),
        new Auth\LoginThrottle(new Core\RateLimiter($appDir . '/storage/ratelimit', $clock)),
        $remember,
        $tokens,
        $twofa,
        $mailer,
        $deferred,
        $session,
        $csrf,
        new Core\Template($appDir . '/core/Auth/views', $appDir . '/storage/cache/views'),
        new Core\Template($appDir . '/core/Core/views', $appDir . '/storage/cache/views'),
        $clock,
        [
            'appUrl' => Core\Config::get('APP_URL', ''),
            'allowHttp' => Core\Config::devMode(),
            'registration' => ($authCfg['registration'] ?? false) === true, // AUTH-08: mati secara default
            'defaultRole' => $authCfg['default_role'] ?? 'staf',
            'from' => Core\Config::get('MAIL_FROM', 'noreply@example.invalid'),
        ],
        $logger,
    );

    // M11: administrasi pengguna/peran + pembersihan probabilistik akun pending kedaluwarsa (setelah respons dikirim).
    $users = new Auth\DbUserStore($conn, $clock, $accounts, $logger);
    if (random_int(1, 200) === 1) {
        $deferred->push(static function () use ($users): void {
            $users->purgeExpiredPending(7 * 86400);
        });
    }
    $defs = new Runtime\Definitions(new Runtime\CacheStore($appDir . '/storage/cache'));
    $admin = new Auth\AdminController(
        $manager,
        $users,
        new Auth\RoleStore($conn),
        $tokens,
        $mailer,
        $deferred,
        $session,
        $csrf,
        new Core\Template($appDir . '/core/Auth/views', $appDir . '/storage/cache/views'),
        new Core\Template($appDir . '/core/Core/views', $appDir . '/storage/cache/views'),
        new Runtime\Authorizer(),
        static fn(): array => $defs->pages(),
        [
            'appUrl' => Core\Config::get('APP_URL', ''),
            'from' => Core\Config::get('MAIL_FROM', 'noreply@example.invalid'),
        ],
        $logger,
    );
    return new Auth\AuthKit($session, $jar, $csrf, $manager, $remember, $driver, $deferred, $admin);
}
