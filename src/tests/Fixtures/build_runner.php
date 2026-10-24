<?php

declare(strict_types=1);

// Dipakai tes konkurensi: php build_runner.php <defDir> <cacheDir> <extDir>
require __DIR__ . '/../bootstrap.php';

use bFramework\Contracts\Dialect;
use bFramework\Runtime\CacheStore;
use bFramework\Runtime\Compiler;

$r = (new Compiler(new CacheStore($argv[2]), $argv[3]))->build($argv[1], Dialect::Sqlite);
echo $r->version ?? 'ERR';
