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
    ?Runtime\PageCacheSink $pageCache = null,
    ?Runtime\Definitions $defs = null,
): void {
    $defs ??= new Runtime\Definitions(new Runtime\CacheStore($appDir . '/storage/cache'));
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
        $pageCache,
    );
}

/**
 * Cache halaman (F8). Berkas HTML di <docroot>/_pc, metadata (indeks tag, generasi, kunci) di app/storage/pagecache
 * (di luar docroot). Rute yang boleh di-cache = halaman `cache: true` + access `*` pada definisi ter-compile aktif.
 * Satu-satunya tempat Runtime dan Cache bertemu (ARCH-03).
 */
function buildPageCache(string $appDir, string $docroot, Runtime\Definitions $defs, ?Contracts\Logger $logger = null): Cache\PageCache
{
    $cfg = Core\Config::get('page_cache', []);
    $cfg = is_array($cfg) ? $cfg : [];
    $limits = [];
    foreach (['maxFiles', 'maxFileBytes', 'maxTotalBytes', 'ttl'] as $k) {
        if (isset($cfg[$k]) && is_int($cfg[$k])) {
            $limits[$k] = $cfg[$k];
        }
    }
    return new Cache\PageCache(
        rtrim($docroot, '/') . '/_pc',
        $appDir . '/storage/pagecache',
        static function () use ($defs): array {
            $out = [];
            foreach ($defs->pages() as $p) {
                if (is_array($p) && ($p['cache'] ?? false) === true && ($p['access'] ?? null) === '*' && is_string($p['route'] ?? null)) {
                    $out[] = $p['route'];
                }
            }
            return $out;
        },
        $logger,
        $limits,
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
    ?Cache\PageCache $pageCache = null,
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
    $compiler = new Runtime\Compiler(
        new Runtime\CacheStore($appDir . '/storage/cache'),
        $appDir . '/extensions',
        null,
        $pageCache === null ? null : $pageCache->purgeAll(...), // definisi/akses berubah: buang semua cache halaman (F8)
        $logger,
    );
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
        static function (string $issuer) use ($logger): array { // SSO-21: kode SSO dimuat hanya saat tombol ditekan
            $port = parse_url($issuer, PHP_URL_PORT);
            return Sso\OidcClient::probe(new Core\HttpClient($logger, null, 1048576, [], is_int($port) ? [443, $port] : [443]), $issuer);
        },
    );
}

/**
 * Build pertama otomatis + tabel model (create-if-not-exists; tabel yang ada tidak disentuh, tanpa allowLoss).
 * True = siap: versi aktif ada DAN tabel modelnya sudah dipastikan. Penanda siap `.schema_ok` (berisi versi) ditulis
 * paling akhir, sesudah tabel dibuat, sehingga request lain tidak pernah menganggap siap saat tabel belum ada.
 * Seluruh urutan compile + migrasi di bawah satu flock eksklusif `storage/first_build.lock` (urutan kunci:
 * kunci ini lalu build.lock milik Compiler; Compiler tidak pernah mengambil kunci ini -> tanpa deadlock).
 * Gagal compile/migrasi: dicatat, false (fail-closed: rute definisi tidak dimuat), versi aktif valid TIDAK dicabut,
 * percobaan ulang ditahan 60 detik (negative cache yang kedaluwarsa).
 * Versi baru hasil build terpisah (builder/updater, yang memigrasi sendiri) diberi jendela 30 detik sebelum tabel
 * yang hilang dibuat di sini, agar tidak bentrok dengan migrasi milik builder.
 */
function ensureCompiled(string $appDir, Runtime\Connection $conn, ?Contracts\Logger $logger = null): bool
{
    $cacheDir = $appDir . '/storage/cache';
    $store = new Runtime\CacheStore($cacheDir);
    $okFile = $cacheDir . '/.schema_ok';
    if (schemaReady($store, $okFile)) {
        return true; // jalur cepat: tanpa kunci, tanpa kueri DB
    }
    if ($store->current() === null && !is_dir($appDir . '/definitions')) {
        return false;
    }
    $lock = null;
    try {
        $store->ensureDir();
        $lock = @fopen($appDir . '/storage/first_build.lock', 'c');
        if ($lock === false) {
            throw new \RuntimeException('kunci build pertama tidak dapat dibuka');
        }
        $deadline = microtime(true) + 20; // > batas tunggu kunci Compiler (15 detik)
        while (!flock($lock, LOCK_EX | LOCK_NB)) {
            if (microtime(true) > $deadline) {
                $logger?->warning('build pertama: kunci sibuk');
                return false; // fail-closed untuk request ini saja
            }
            usleep(50000);
        }
        if (schemaReady($store, $okFile)) {
            return true; // diselesaikan request lain selagi menunggu kunci
        }
        $cur = $store->current();
        $prevOk = trim((string) @file_get_contents($okFile));
        if ($cur !== null && $prevOk !== '' && time() - (int) @filemtime($cacheDir . '/' . $cur) < 30) {
            return true; // versi baru dari builder/updater: migrasinya milik pemanggil itu (perilaku lama)
        }
        $mark = $cacheDir . '/.build_failed';
        if (is_file($mark) && time() - (int) @filemtime($mark) < 60) {
            return false;
        }
        if ($cur === null) {
            $r = (new Runtime\Compiler($store, $appDir . '/extensions', null, null, $logger))->build($appDir . '/definitions', $conn->dialect());
            if (!$r->ok()) {
                throw new \RuntimeException('compile gagal: ' . count($r->errors) . ' galat');
            }
        }
        $defs = new Runtime\Definitions($store);
        $cur = $defs->version(); // dipatok: penanda siap merujuk versi yang tabelnya diperiksa
        $sqlite = $conn->dialect() === Contracts\Dialect::Sqlite;
        $exists = $conn->pdo()->prepare(
            $sqlite ? "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?"
                : 'SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?',
        );
        $m = new Runtime\Migrator($conn, $conn->grammar(), $logger);
        foreach ($defs->tables() as $t) {
            if (tableExists($exists, $t->name)) {
                continue;
            }
            try {
                $m->apply($m->planCreate($t));
                $logger?->info('tabel model dibuat', ['table' => $t->name]);
            } catch (\Throwable $e) {
                if (!tableExists($exists, $t->name)) { // 'table already exists' (dibuat proses lain) = sukses
                    throw $e;
                }
            }
        }
        $tmp = $cacheDir . '/.tmp_' . bin2hex(random_bytes(8));
        if (@file_put_contents($tmp, $cur, LOCK_EX) === false || !@rename($tmp, $okFile)) {
            @unlink($tmp);
            throw new \RuntimeException('penanda siap tidak dapat ditulis');
        }
        @unlink($mark);
        return true; // penanda siap = langkah terakhir
    } catch (\Throwable $e) {
        $logger?->error('build pertama gagal', ['ex' => $e::class]);
        @file_put_contents($cacheDir . '/.build_failed', '1');
        return false;
    } finally {
        if (is_resource($lock)) {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
}

/** @phpstan-impure Siap = versi aktif ada dan penanda `.schema_ok` berisi versi itu. */
function schemaReady(Runtime\CacheStore $store, string $okFile): bool
{
    $cur = $store->current();
    return $cur !== null && trim((string) @file_get_contents($okFile)) === $cur;
}

/** @phpstan-impure */
function tableExists(\PDOStatement $exists, string $name): bool
{
    $exists->execute([$name]);
    $v = $exists->fetchColumn();
    $exists->closeCursor();
    return $v !== false;
}

/**
 * Koneksi database dari config (DB_DRIVER sqlite|mysql). Kata sandi dari config/env, tidak pernah dicatat.
 */
/**
 * Halaman status pembaruan (M17, baca-saja). Root instalasi = induk app/. Public key dari UpdateKey (placeholder = fail-closed).
 */
function buildUpdateStatus(string $appDir, Auth\AuthKit $auth, Runtime\Definitions $defs, ?Contracts\Logger $logger = null): Update\UpdateController
{
    $root = dirname($appDir);
    return new Update\UpdateController(
        $auth->manager,
        new Runtime\Authorizer(),
        $auth->csrf,
        $auth->session,
        new Core\Template($appDir . '/core/Update/views', $appDir . '/storage/cache/views'),
        new Core\Template($appDir . '/core/Core/views', $appDir . '/storage/cache/views'),
        new Core\RateLimiter($appDir . '/storage/ratelimit', new Auth\SystemClock()),
        new Update\CoreManifest($root),
        new Update\UpdatePackage($root, Update\UpdateKey::raw(), $logger),
        static fn(): array => $defs->pages(),
        $auth->stepUp ?? throw new \LogicException('StepUp belum dirakit'),
        $logger,
    );
}

function registerHome(Core\Router $router, Auth\AuthKit $auth, Runtime\Definitions $defs): void
{
    (new Runtime\HomeRedirect(static fn(): ?Contracts\Identity => $auth->manager->current(), static fn(): array => $defs->pages()))->registerRoutes($router);
}

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
function buildAuth(string $appDir, Runtime\Connection $conn, bool $https, ?Contracts\Logger $logger = null, ?Contracts\Logger $auditLogger = null): Auth\AuthKit
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
    $hasher = new Auth\PasswordHasher();
    $throttle = new Auth\LoginThrottle(new Core\RateLimiter($appDir . '/storage/ratelimit', $clock));
    [$mode, $ssoRaw] = ssoSettings($appDir, $authCfg);
    $views = new Core\Template($appDir . '/core/Auth/views', $appDir . '/storage/cache/views');
    $layout = new Core\Template($appDir . '/core/Core/views', $appDir . '/storage/cache/views');
    $local = new Auth\LocalDriver(
        $manager,
        $accounts,
        $hasher,
        $throttle,
        $remember,
        $tokens,
        $twofa,
        $mailer,
        $deferred,
        $session,
        $csrf,
        $views,
        $layout,
        $clock,
        [
            'appUrl' => Core\Config::get('APP_URL', ''),
            'allowHttp' => Core\Config::devMode(),
            'registration' => $mode === 'local' && ($authCfg['registration'] ?? false) === true, // AUTH-08: mati secara default
            'defaultRole' => $authCfg['default_role'] ?? 'staf',
            'from' => Core\Config::get('MAIL_FROM', 'noreply@example.invalid'),
            'breakGlass' => $mode === 'hybrid', // SSO-01
            'loginPath' => $authCfg['break_glass_path'] ?? '/auth/break-glass',
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
    $stepUp = new Auth\StepUp($manager, $accounts, new Runtime\Authorizer(), $session, $clock);
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
        $stepUp,
        [
            'appUrl' => Core\Config::get('APP_URL', ''),
            'from' => Core\Config::get('MAIL_FROM', 'noreply@example.invalid'),
        ],
        $logger,
        $auditLogger,
    );
    // M15 (SSO-19): kode SSO + library JWT hanya dimuat/dipasang bila driver bikinin_sso atau hybrid.
    $driver = $mode === 'local'
        ? $local
        : buildSso($appDir, $conn, $mode, $ssoRaw, $key, $manager, $users, $accounts, $hasher, $throttle, $session, $csrf, $views, $layout, $clock, $mode === 'hybrid' ? $local : null, $logger);
    return new Auth\AuthKit($session, $jar, $csrf, $manager, $remember, $driver, $deferred, $admin, $stepUp);
}

/**
 * Mode auth + blok sso gabungan: config.php (`auth.driver`, `auth.sso.*`, termasuk client_secret) menimpa
 * definisi ter-compile `auth.json` (tanpa rahasia). env SSO_CLIENT_SECRET menimpa client_secret. Nilai driver
 * tak dikenal dianggap `local`.
 *
 * @param array<mixed> $authCfg
 * @return array{0:string,1:array<string,mixed>}
 */
function ssoSettings(string $appDir, array $authCfg): array
{
    $compiled = [];
    try {
        $c = (new Runtime\Definitions(new Runtime\CacheStore($appDir . '/storage/cache')))->auth();
        $compiled = is_array($c) ? $c : [];
    } catch (\Throwable) {
        // cache belum dibangun
    }
    $driver = $authCfg['driver'] ?? $compiled['driver'] ?? 'local';
    $driver = is_string($driver) && in_array($driver, ['local', 'bikinin_sso', 'hybrid'], true) ? $driver : 'local';
    $sso = array_merge(
        is_array($compiled['sso'] ?? null) ? $compiled['sso'] : [],
        is_array($authCfg['sso'] ?? null) ? $authCfg['sso'] : [],
    );
    $env = getenv('SSO_CLIENT_SECRET');
    if ($env !== false && $env !== '') {
        $sso['client_secret'] = $env;
    }
    /** @var array<string,mixed> $sso */
    return [$driver, $sso];
}

/**
 * Perakitan driver SSO (M15). Konfigurasi tidak sah -> driver tetap dipasang dalam keadaan "tidak tersedia"
 * (fail-closed: tidak jatuh kembali ke login lokal). Refresh token hanya bila APP_KEY >= 32 karakter.
 *
 * @param 'bikinin_sso'|'hybrid'|string $mode
 * @param array<string,mixed> $ssoRaw
 */
function buildSso(
    string $appDir,
    Runtime\Connection $conn,
    string $mode,
    array $ssoRaw,
    mixed $appKey,
    Auth\AuthManager $manager,
    Auth\DbUserStore $users,
    Auth\AccountStore $accounts,
    Auth\PasswordHasher $hasher,
    Auth\LoginThrottle $throttle,
    Core\FileSessionStore $session,
    Core\Csrf $csrf,
    Core\Template $views,
    Core\Template $layout,
    Contracts\Clock $clock,
    ?Auth\AuthDriver $local,
    ?Contracts\Logger $logger,
): Sso\SsoDriver {
    $marker = $appDir . '/storage/cache/sso_schema';
    if (!is_file($marker)) {
        try {
            Sso\SsoTables::install($conn);
            @file_put_contents($marker, '1');
        } catch (\Throwable) {
            $logger?->error('Tabel SSO tidak dapat dibuat');
        }
    }
    $appUrl = Core\Config::get('APP_URL', '');
    $cfg = Sso\SsoConfig::from($ssoRaw, is_string($appUrl) ? $appUrl : '');
    $mode = $mode === 'hybrid' ? 'hybrid' : 'bikinin_sso';
    $sids = new Sso\SidMap($conn, $clock, $logger);
    $vault = is_string($appKey) && strlen($appKey) >= 32
        ? new Sso\RefreshVault($conn, new Auth\SecretVault($appKey), $clock, $appDir . '/storage/locks', $logger)
        : null;
    $oidc = null;
    $backchannel = null;
    // S20: sso.backchannel_rate = [maks, detik]; bentuk/rentang tak sah memakai bawaan 30/60.
    $bcRate = Sso\BackchannelHandler::rateFromConfig($ssoRaw['backchannel_rate'] ?? null, $logger);
    $claims = null;
    if ($cfg === null) {
        $logger?->error('Konfigurasi SSO tidak lengkap/tidak sah; SSO dinonaktifkan sementara');
    } else {
        $port = parse_url($cfg->issuer, PHP_URL_PORT);
        $http = new Core\HttpClient($logger, null, 1048576, [], is_int($port) ? [443, $port] : [443]);
        $cache = new Sso\FileCache($appDir . '/storage/sso', $clock);
        $oidc = new Sso\OidcClient($http, $cache, $clock, $cfg, new Sso\FirebaseJwtVerifier(), $logger);
        $claims = new Sso\ClaimsValidator($cfg->issuer, $cfg->clientId);
        $backchannel = new Sso\BackchannelHandler(
            $oidc,
            $claims,
            new Sso\JtiStore($appDir . '/storage/sso/jti', $clock),
            $sids,
            $vault,
            $clock,
            $logger,
            new Core\RateLimiter($appDir . '/storage/ratelimit', $clock),
            ...$bcRate,
        );
    }
    return new Sso\SsoDriver($mode, $cfg, $oidc, $backchannel, $claims, $manager, $users, $accounts, $sids, $vault, $hasher, $throttle, $session, $csrf, $views, $layout, $clock, $local, $logger);
}
