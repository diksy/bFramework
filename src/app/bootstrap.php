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
