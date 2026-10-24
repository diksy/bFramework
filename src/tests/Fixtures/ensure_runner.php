<?php

declare(strict_types=1);

// Dipakai tes konkurensi ensureCompiled: php ensure_runner.php <appDir> <sqlitePath>
require __DIR__ . '/../bootstrap.php';

use bFramework\Runtime\Connection;
use bFramework\Tests\Fixtures\CaptureLogger;

$log = new CaptureLogger();
$ok = bFramework\ensureCompiled($argv[1], Connection::sqlite($argv[2]), $log);
echo json_encode(['ready' => $ok, 'log' => $log->lines]);
