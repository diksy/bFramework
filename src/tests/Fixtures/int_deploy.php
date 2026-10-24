<?php

declare(strict_types=1);

// Langkah deploy tes: php int_deploy.php <sandbox>  -> compile definisi + buat tabel model (pekerjaan builder/CLI di dunia nyata).
$root = (string) ($_SERVER['argv'][1] ?? '');
$app = $root . '/app';
require $app . '/bootstrap.php';

use bFramework\Core\Config;

Config::load($app . '/config/config.php');
$conn = bFramework\connectDatabase($app);
$store = new bFramework\Runtime\CacheStore($app . '/storage/cache');
$res = (new bFramework\Runtime\Compiler($store, $app . '/extensions'))->build($app . '/definitions', $conn->dialect());
if (!$res->ok()) {
    fwrite(STDERR, json_encode($res->errors) . "\n");
    exit(1);
}
$defs = new bFramework\Runtime\Definitions($store);
$m = new bFramework\Runtime\Migrator($conn, $conn->grammar());
foreach ($defs->tables() as $t) {
    try {
        $m->apply($m->planCreate($t));
    } catch (Throwable) {
        // tabel sudah ada
    }
}
echo 'ok';
