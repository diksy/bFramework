<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

/**
 * Memuat library JWT yang di-vendor (firebase/php-jwt, lihat docs/decisions.md untuk versi + hash) tanpa Composer.
 * Dipanggil lazy hanya saat verifikasi pertama sehingga driver `local` tidak pernah memuatnya (SSO-19).
 */
final class JwtLibrary
{
    private static bool $loaded = false;

    public static function dir(): string
    {
        return dirname(__DIR__) . '/vendor/firebase-php-jwt';
    }

    public static function load(): void
    {
        if (self::$loaded) {
            return;
        }
        $dir = self::dir();
        spl_autoload_register(static function (string $class) use ($dir): void {
            $p = 'Firebase\\JWT\\';
            if (!str_starts_with($class, $p)) {
                return;
            }
            $n = substr($class, strlen($p));
            if (preg_match('/^[A-Za-z]+$/D', $n) === 1 && is_file($dir . '/' . $n . '.php')) {
                require_once $dir . '/' . $n . '.php';
            }
        });
        self::$loaded = true;
    }
}
