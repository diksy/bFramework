<?php

declare(strict_types=1);

namespace bFramework;

defined('APP_BOOTED') || exit;

/** Autoload PSR-4 sederhana: bFramework\<Folder>\X -> core/<Folder>/X.php (tanpa Composer). */
final class Autoloader
{
    public static function register(string $coreDir): void
    {
        $base = rtrim($coreDir, '/\\') . DIRECTORY_SEPARATOR;
        spl_autoload_register(static function (string $class) use ($base): void {
            $prefix = 'bFramework\\';
            if (!str_starts_with($class, $prefix)) {
                return;
            }
            $rel = substr($class, strlen($prefix));
            if (preg_match('/^[A-Za-z0-9_\\\\]+$/', $rel) !== 1) {
                return;
            }
            $file = $base . str_replace('\\', DIRECTORY_SEPARATOR, $rel) . '.php';
            if (is_file($file)) {
                require $file;
            }
        });
    }
}
