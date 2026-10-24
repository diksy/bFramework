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
$production = Config::get('APP_ENV', 'production') !== 'development';
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

(new Kernel($router, [], $logger, $errors->page(...)))->handleGlobals()->send();
