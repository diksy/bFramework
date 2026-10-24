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

// Rute dari hasil compile (lazy: hanya dibaca bila versi aktif ada).
$router = new Router();
$current = @file_get_contents($app . '/storage/cache/current');
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
// Belum terpasang (APP_URL kosong; installer M13 yang mengisinya): hanya rute compile + header keamanan, tanpa login.
$hosts = Config::get('ALLOWED_HOSTS', []);
$hosts = is_array($hosts) ? array_values(array_filter($hosts, 'is_string')) : [];
$appUrl = Config::get('APP_URL', '');
if (is_string($appUrl) && $appUrl !== '') {
    $httpsEnv = $_SERVER['HTTPS'] ?? '';
    $https = is_string($httpsEnv) && $httpsEnv !== '' && strtolower($httpsEnv) !== 'off';
    $conn = bFramework\connectDatabase($app);
    $auth = bFramework\buildAuth($app, $conn, $https, $logger);
    bFramework\configureRuntime($app, $conn, $auth->session, $logger);
    $auth->driver->registerRoutes($router);
    $middleware = $auth->middleware($router, $hosts, Config::devMode());
} else {
    $auth = null;
    $middleware = [new bFramework\Core\SecurityHeaders(bFramework\Core\Nonce::current(...))];
}

$response = (new Kernel($router, $middleware, $logger, $errors->page(...)))->handleGlobals();
// Respons dikirim dan koneksi ditutup sebelum pekerjaan tunda (email) dijalankan.
if ($auth !== null) {
    $auth->deferred->respondThenRun($response);
} else {
    $response->send();
}
