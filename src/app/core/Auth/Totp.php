<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

/** AUTH-07: TOTP RFC 6238 (HMAC-SHA1, 6 digit, langkah 30 dtk), jendela toleransi +/-1 langkah. */
final class Totp
{
    public const PERIOD = 30;
    public const DIGITS = 6;
    private const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /** Secret 160-bit dalam base32. */
    public static function generateSecret(): string
    {
        return self::base32Encode(random_bytes(20));
    }

    public static function code(string $secret, int $step): string
    {
        $key = self::base32Decode($secret);
        if ($key === null || $key === '' || $step < 0) {
            return '';
        }
        $hmac = hash_hmac('sha1', pack('J', $step), $key, true);
        $o = ord($hmac[19]) & 0x0F;
        $bin = ((ord($hmac[$o]) & 0x7F) << 24) | (ord($hmac[$o + 1]) << 16) | (ord($hmac[$o + 2]) << 8) | ord($hmac[$o + 3]);
        return str_pad((string) ($bin % 1_000_000), self::DIGITS, '0', STR_PAD_LEFT);
    }

    public static function stepAt(int $time): int
    {
        return intdiv($time, self::PERIOD);
    }

    /** Stateless (tanpa anti-replay); gunakan matchStep() untuk login. */
    public static function verify(string $secret, string $code, ?int $time = null): bool
    {
        return self::matchStep($secret, $code, $time ?? time(), null) !== null;
    }

    /**
     * Langkah yang cocok (dalam jendela) dan lebih baru dari $lastStep, atau null. Semua kandidat
     * dibandingkan tanpa keluar dini (hash_equals) agar waktu tidak membocorkan langkah mana yang cocok.
     */
    public static function matchStep(string $secret, string $code, int $time, ?int $lastStep, int $window = 1): ?int
    {
        $code = str_replace(' ', '', $code);
        if (preg_match('/^[0-9]{6}$/D', $code) !== 1) {
            return null;
        }
        $now = self::stepAt($time);
        $found = null;
        for ($s = $now - $window; $s <= $now + $window; $s++) {
            $expected = self::code($secret, $s);
            if ($expected !== '' && hash_equals($expected, $code) && ($lastStep === null || $s > $lastStep)) {
                $found = $found === null || $s > $found ? $s : $found;
            }
        }
        return $found;
    }

    public static function uri(string $secret, string $account, string $issuer): string
    {
        $label = rawurlencode($issuer) . ':' . rawurlencode($account);
        return 'otpauth://totp/' . $label . '?secret=' . $secret . '&issuer=' . rawurlencode($issuer)
            . '&algorithm=SHA1&digits=6&period=30';
    }

    public static function base32Encode(string $raw): string
    {
        $bits = '';
        foreach (str_split($raw) as $c) {
            $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $out .= self::B32[bindec(str_pad($chunk, 5, '0'))];
        }
        return $out;
    }

    public static function base32Decode(string $s): ?string
    {
        $s = strtoupper(rtrim(str_replace(' ', '', $s), '='));
        if ($s === '' || preg_match('/^[A-Z2-7]+$/D', $s) !== 1) {
            return null;
        }
        $bits = '';
        foreach (str_split($s) as $c) {
            $bits .= str_pad(decbin((int) strpos(self::B32, $c)), 5, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $out .= chr((int) bindec($byte));
            }
        }
        return $out;
    }
}
