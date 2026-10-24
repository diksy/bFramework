<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

/** Penentu alamat IP publik (perlindungan SSRF). */
final class IpPolicy
{
    /** @var list<array{0:string,1:int}> rentang IPv4 yang ditolak (jaringan, panjang prefiks) */
    private const V4_BLOCKED = [
        ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
        ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
        ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
    ];

    public static function isPublic(string $ip): bool
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return false;
        }
        if (strlen($bin) === 4) {
            return self::publicV4($bin);
        }
        // IPv6: ::, ::1, IPv4-mapped/compatible, NAT64, 6to4 diperiksa lewat IPv4 tertanam.
        if (str_starts_with($bin, str_repeat("\0", 12))) {
            return false; // ::, ::1, ::/96 (compatible)
        }
        if (str_starts_with($bin, str_repeat("\0", 10) . "\xff\xff")) {
            return self::publicV4(substr($bin, 12, 4));
        }
        if (str_starts_with($bin, "\x00\x64\xff\x9b" . str_repeat("\0", 8))) {
            return self::publicV4(substr($bin, 12, 4));
        }
        if (str_starts_with($bin, "\x20\x02")) {
            return self::publicV4(substr($bin, 2, 4));
        }
        $b0 = ord($bin[0]);
        $b1 = ord($bin[1]);
        if (($b0 & 0xFE) === 0xFC) {
            return false; // fc00::/7 (ULA, termasuk metadata AWS fd00:ec2::254)
        }
        if ($b0 === 0xFE && ($b1 & 0xC0) >= 0x80) {
            return false; // fe80::/10 link-local dan fec0::/10 site-local
        }
        if ($b0 === 0xFF) {
            return false; // multicast
        }
        if ($b0 === 0x20 && $b1 === 0x01 && ord($bin[2]) === 0x0D && ord($bin[3]) === 0xB8) {
            return false; // dokumentasi
        }
        return true;
    }

    private static function publicV4(string $bin): bool
    {
        $n = unpack('N', $bin);
        $addr = is_array($n) ? (int) $n[1] : 0;
        foreach (self::V4_BLOCKED as [$net, $len]) {
            $base = (int) ip2long($net);
            $mask = (0xFFFFFFFF << (32 - $len)) & 0xFFFFFFFF;
            if (($addr & $mask) === ($base & $mask)) {
                return false;
            }
        }
        return true;
    }
}
