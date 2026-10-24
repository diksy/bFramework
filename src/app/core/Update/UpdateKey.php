<?php

declare(strict_types=1);

namespace bFramework\Update;

defined('APP_BOOTED') || exit;

/**
 * Public key Ed25519 penandatangan update (SEC-UPD-01), ditanam di core, 32 byte dalam 64 heks.
 *
 * !!! PLACEHOLDER !!! Nilai di bawah BUKAN kunci. Selama belum diganti pemilik dengan 64 heks hasil
 * `php tools/gen-update-key.php`, updater menolak SEMUA paket (fail-closed) dan halaman /admin/pembaruan
 * memperingatkan. Kunci privat tidak pernah ada di repo.
 */
final class UpdateKey
{
    public const PUBLIC_KEY_HEX = '571b21c6c189a27b1ac1be5c451ee2ede76ce6f3a89232d7df121b28a45de16f';

    /** @return ?string 32 byte mentah, atau null bila placeholder/kosong/tidak valid (fail-closed) */
    public static function raw(?string $hex = null): ?string
    {
        $hex ??= self::PUBLIC_KEY_HEX;
        if (preg_match('/^[a-f0-9]{64}$/D', $hex) !== 1 || trim($hex, '0') === '') {
            return null;
        }
        $bin = hex2bin($hex);
        return is_string($bin) && strlen($bin) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES ? $bin : null;
    }

    public static function configured(): bool
    {
        return self::raw() !== null;
    }
}
