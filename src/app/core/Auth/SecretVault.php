<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use InvalidArgumentException;

/**
 * Enkripsi rahasia di database (secret TOTP) dengan sodium secretbox. Kunci diturunkan (HKDF) dari
 * APP_KEY per konteks sehingga ciphertext satu konteks tidak bisa dipakai di konteks lain.
 */
final class SecretVault
{
    public function __construct(#[\SensitiveParameter] private readonly string $appKey)
    {
        if (strlen($appKey) < 32) {
            throw new InvalidArgumentException('APP_KEY terlalu pendek');
        }
    }

    public function seal(#[\SensitiveParameter] string $plain, string $context): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $box = sodium_crypto_secretbox($plain, $nonce, $this->key($context));
        return 'v1.' . rtrim(strtr(base64_encode($nonce . $box), '+/', '-_'), '=');
    }

    public function open(string $sealed, string $context): ?string
    {
        if (!str_starts_with($sealed, 'v1.')) {
            return null;
        }
        $raw = base64_decode(strtr(substr($sealed, 3), '-_', '+/'), true);
        if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES) {
            return null;
        }
        $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $plain = sodium_crypto_secretbox_open(substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $nonce, $this->key($context));
        return $plain === false ? null : $plain;
    }

    /** HMAC dengan kunci turunan konteks (mis. hash kode pemulihan). */
    public function mac(string $data, string $context): string
    {
        return hash_hmac('sha256', $data, $this->key($context));
    }

    private function key(string $context): string
    {
        return hash_hkdf('sha256', $this->appKey, SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 'bf-vault-v1|' . $context);
    }
}
