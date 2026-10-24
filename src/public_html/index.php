<?php

declare(strict_types=1);

use bFramework\Core\Config;
use bFramework\Core\Kernel;
use bFramework\Core\Router;

// Satu-satunya pintu masuk; app/ berada di luar docroot (ARCH-01).
require dirname(__DIR__) . '/app/bootstrap.php';

$app = dirname(__DIR__) . '/app';
Config::load($app . '/config/config.php');

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

(new Kernel($router))->handleGlobals()->send();
