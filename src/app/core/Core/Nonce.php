<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

/** SEC-OUT-02: nonce CSP 16 byte acak per request (heks, 32 karakter). Sambungkan: new SecurityHeaders([Nonce::class, 'current']). */
final class Nonce
{
    private static ?string $value = null;

    public static function current(): string
    {
        return self::$value ??= bin2hex(random_bytes(16));
    }

    /** Dipanggil di awal request (worker long-lived) dan di tes. */
    public static function reset(): void
    {
        self::$value = null;
    }
}
