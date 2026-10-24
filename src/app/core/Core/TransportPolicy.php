<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

/**
 * Penentuan "apakah request ini HTTPS" (SEC-SESS-03, S9). Default: hanya flag HTTPS dari SAPI; header proxy
 * tidak dipercaya. Dua penambahan eksplisit (dipasang index.php dari konfigurasi):
 *  - APP_URL berskema https memaksa HTTPS (cookie Secure/__Host-, HSTS) walau TLS diputus di proxy/CDN;
 *  - TRUSTED_PROXIES (daftar IP/CIDR): X-Forwarded-Proto: https dipercaya hanya bila REMOTE_ADDR cocok.
 */
final class TransportPolicy
{
    private static bool $forceHttps = false;
    /** @var list<string> */
    private static array $proxies = [];

    /** @param mixed $trustedProxies array atau string dipisah koma; entri tak valid diabaikan */
    public static function configure(string $appUrl, mixed $trustedProxies = []): void
    {
        self::$forceHttps = self::isHttpsUrl($appUrl);
        if (is_string($trustedProxies)) {
            $trustedProxies = explode(',', $trustedProxies);
        }
        $list = [];
        foreach (is_array($trustedProxies) ? $trustedProxies : [] as $p) {
            if (is_string($p) && self::parseCidr(trim($p)) !== null) {
                $list[] = trim($p);
            }
        }
        self::$proxies = $list;
    }

    public static function reset(): void
    {
        self::$forceHttps = false;
        self::$proxies = [];
    }

    public static function isHttpsUrl(string $url): bool
    {
        return preg_match('#^https://#i', $url) === 1;
    }

    public static function forced(): bool
    {
        return self::$forceHttps;
    }

    /** @param array<string,mixed> $server */
    public static function isHttps(array $server): bool
    {
        if (self::$forceHttps) {
            return true;
        }
        $https = $server['HTTPS'] ?? '';
        if (is_string($https) && $https !== '' && strtolower($https) !== 'off') {
            return true;
        }
        $addr = $server['REMOTE_ADDR'] ?? '';
        $proto = $server['HTTP_X_FORWARDED_PROTO'] ?? '';
        if (self::$proxies !== [] && is_string($addr) && is_string($proto) && self::isTrusted($addr)) {
            // Nilai pertama diisi klien; proxy tepercaya menambahkan di belakang: pakai nilai TERAKHIR, nilai tak dikenal ditolak.
            $parts = explode(',', $proto);
            return strtolower(trim($parts[count($parts) - 1])) === 'https';
        }
        return false;
    }

    public static function isTrusted(string $ip): bool
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return false;
        }
        foreach (self::$proxies as $entry) {
            $c = self::parseCidr($entry);
            if ($c === null || strlen($c[0]) !== strlen($bin)) {
                continue;
            }
            if (self::match($bin, $c[0], $c[1])) {
                return true;
            }
        }
        return false;
    }

    /** @return array{0:string,1:int}|null */
    private static function parseCidr(string $s): ?array
    {
        $parts = explode('/', $s, 2);
        $bin = @inet_pton($parts[0]);
        if ($bin === false) {
            return null;
        }
        $max = strlen($bin) * 8;
        if (!isset($parts[1])) {
            return [$bin, $max];
        }
        if (preg_match('/^[0-9]{1,3}$/D', $parts[1]) !== 1 || (int) $parts[1] > $max) {
            return null;
        }
        return [$bin, (int) $parts[1]];
    }

    private static function match(string $ip, string $net, int $bits): bool
    {
        $bytes = intdiv($bits, 8);
        if ($bytes > 0 && substr($ip, 0, $bytes) !== substr($net, 0, $bytes)) {
            return false;
        }
        $rest = $bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rest)) & 0xFF;
        return (ord($ip[$bytes]) & $mask) === (ord($net[$bytes]) & $mask);
    }
}
