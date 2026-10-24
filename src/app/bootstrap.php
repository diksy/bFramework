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
    $driver = new Auth\LocalDriver(
        $manager,
        $accounts,
        new Auth\PasswordHasher(),
        new Auth\LoginThrottle(new Core\RateLimiter($appDir . '/storage/ratelimit', $clock)),
        $remember,
        new Auth\OneTimeToken($conn, $clock),
        $twofa,
        Auth\Mailer::fromConfig($smtp, $logger),
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
    return new Auth\AuthKit($session, $jar, $csrf, $manager, $remember, $driver, $deferred);
}
