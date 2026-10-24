<?php

declare(strict_types=1);

use bFramework\Core\Config;
use bFramework\Core\ErrorHandler;
use bFramework\Core\Kernel;
use bFramework\Core\RotatingFileLogger;
use bFramework\Core\Router;
use bFramework\Core\Template;

// Satu-satunya pintu masuk; app/ berada di luar docroot (ARCH-01).
ini_set('display_errors', '0'); // SEC-LOG-01: sebelum apa pun dimuat.
require dirname(__DIR__) . '/app/bootstrap.php';

$app = dirname(__DIR__) . '/app';
Config::load($app . '/config/config.php');

// Log di app/storage/logs (di luar docroot), rotasi 5 MB x 5 berkas (SEC-LOG-01).
$production = !Config::devMode();
$logger = new RotatingFileLogger($app . '/storage/logs', 5 * 1024 * 1024, 5);
$errors = ErrorHandler::register(
    $production,
    $logger,
    new Template($app . '/core/Core/views', $app . '/storage/cache/views'),
);

// Installer (M13). Belum terpasang (tanpa installed.lock dan tanpa APP_URL): HANYA /install yang dilayani
// (rute lain dialihkan/503) dan hanya dengan install_token pemilik. Sudah terpasang: /install = 404.
$httpsEnv = $_SERVER['HTTPS'] ?? '';
$https = is_string($httpsEnv) && $httpsEnv !== '' && strtolower($httpsEnv) !== 'off';
// Mode pemeliharaan singkat selama update diterapkan (M17); kedaluwarsa 10 menit agar kegagalan proses tidak mengunci selamanya.
$maint = $app . '/storage/maintenance';
if (is_file($maint) && time() - (int) @filemtime($maint) < 600) {
    http_response_code(503);
    header('Retry-After: 60');
    header('Cache-Control: no-store');
    echo 'Sedang dalam pemeliharaan. Coba lagi sebentar.';
    return;
}
$installer = new bFramework\Install\Installer($app, __DIR__, new bFramework\Auth\SystemClock(), $logger);
$appUrl = Config::get('APP_URL', '');
$configured = is_string($appUrl) && $appUrl !== '';
if (!$installer->isInstalled() && !$configured) {
    $clock = new bFramework\Auth\SystemClock();
    $jar = new bFramework\Auth\CookieJar();
    $session = new bFramework\Core\FileSessionStore($app . '/storage/sessions', $https, 1800, 28800, null, $jar->add(...), $clock);
    $csrf = new bFramework\Core\Csrf($session);
    $router = new Router();
    (new bFramework\Install\InstallController(
        $installer,
        $csrf,
        new Template($app . '/core/Install/views', $app . '/storage/cache/views'),
        new Template($app . '/core/Core/views', $app . '/storage/cache/views'),
        new bFramework\Core\RateLimiter($app . '/storage/ratelimit'),
        $logger,
    ))->registerRoutes($router);
    $middleware = [
        new bFramework\Core\SecurityHeaders(bFramework\Core\Nonce::current(...)),
        new bFramework\Install\InstallGate(),
        new bFramework\Auth\SessionMiddleware($session, $jar, $session->gc(...)),
        new bFramework\Core\CsrfMiddleware($router, $csrf, $session),
    ];
    $auth = null;
    $response = (new Kernel($router, $middleware, $logger, $errors->page(...)))->handleGlobals();
    $response->send();
    return;
}
if (!$configured) {
    // Terpasang tetapi APP_URL hilang: fail-closed (jangan layani tanpa HostGuard).
    http_response_code(503);
    echo 'Konfigurasi tidak lengkap.';
    return;
}

$conn = bFramework\connectDatabase($app);
// Build pertama + tabel model sebelum rute dibaca. Belum siap/gagal -> rute definisi tidak dimuat (fail-closed).
$compiledReady = bFramework\ensureCompiled($app, $conn, $logger);

// Rute dari hasil compile (lazy: hanya dibaca bila versi aktif ada dan tabelnya siap).
$router = new Router();
$current = $compiledReady ? @file_get_contents($app . '/storage/cache/current') : false;
if (is_string($current) && preg_match('/^v_[a-f0-9]{6,32}$/', trim($current)) === 1) {
    $routesFile = $app . '/storage/cache/' . trim($current) . '/routes.php';
    if (is_file($routesFile)) {
        $table = require $routesFile;
        if (is_array($table)) {
            $router = Router::fromCompiled(array_values($table));
        }
    }
}

// Perakitan autentikasi (M10) + runtime halaman (M9). HTTPS ditentukan dari SAPI saja (header proxy tidak dipercaya).
// ALLOWED_HOSTS kosong -> host dari APP_URL; HostGuard selalu dipasang (SEC-REQ-03, fail-closed).
$hosts = bFramework\Install\HostPolicy::allowed(Config::get('ALLOWED_HOSTS', []), $appUrl);
$auth = bFramework\buildAuth($app, $conn, $https, $logger);
$defs = new bFramework\Runtime\Definitions(new bFramework\Runtime\CacheStore($app . '/storage/cache'));
[$uploads, $fileCtl] = bFramework\buildUploads($app, $conn, $defs, new bFramework\Runtime\CurrentIdentity($auth->session), $logger);
$pageCache = bFramework\buildPageCache($app, __DIR__, $defs, $logger);
bFramework\configureRuntime($app, $conn, $auth->session, $logger, $uploads, $pageCache, $defs);
$fileCtl->registerRoutes($router);
bFramework\buildBuilder($app, $conn, $defs, $auth->session, $auth->csrf, $logger, $pageCache)->registerRoutes($router); // 404 di produksi kecuali dibuka eksplisit (SEC-BLD-01)
if (random_int(1, 200) === 1) {
    $auth->deferred->push(static function () use ($uploads): void {
        $uploads->purgeOrphans(86400); // upload yang tak pernah di-submit (setelah respons dikirim)
    });
}
if (random_int(1, 200) === 1) {
    $auth->deferred->push(static function () use ($pageCache): void {
        $pageCache->gc(); // kedaluwarsa/yatim; halaman statis tidak menjalankan PHP, jadi dipicu dari request lain
    });
}
bFramework\buildUpdateStatus($app, $auth, $defs, $logger)->registerRoutes($router);
bFramework\registerHome($router, $auth, $defs);
$auth->driver->registerRoutes($router);
$auth->admin?->registerRoutes($router);
// Halaman cache anonim (GET tanpa query/cookie sesi) tidak memulai sesi sama sekali, jadi tanpa Set-Cookie (F8).
$middleware = $auth->middleware($router, $hosts, false, $pageCache->eligible(...));

$response = (new Kernel($router, $middleware, $logger, $errors->page(...)))->handleGlobals();
// Respons dikirim dan koneksi ditutup sebelum pekerjaan tunda (email) dijalankan.
$auth->deferred->respondThenRun($response);
