<?php

declare(strict_types=1);

require __DIR__ . '/../app/bootstrap.php';

// Fixture tes: bFramework\Tests\Fixtures\X -> tests/Fixtures/X.php
spl_autoload_register(static function (string $class): void {
    $p = 'bFramework\\Tests\\Fixtures\\';
    if (str_starts_with($class, $p) && preg_match('/^\w+$/', $n = substr($class, strlen($p))) === 1) {
        require __DIR__ . '/Fixtures/' . $n . '.php';
    }
});
