<?php

declare(strict_types=1);

namespace bFramework\Install;

defined('APP_BOOTED') || exit;

/** Penurunan host yang diizinkan dari APP_URL (SEC-REQ-03 fail-closed; menutup fail-open review M10). */
final class HostPolicy
{
    /** @return array{scheme:string,host:string,authority:string}|null null bila bukan origin sederhana */
    public static function parse(string $url): ?array
    {
        $url = rtrim($url, '/');
        if (preg_match('#^(https?)://([A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)(:([0-9]{1,5}))?$#D', $url, $m) !== 1) {
            return null;
        }
        if (isset($m[4]) && ((int) $m[4] < 1 || (int) $m[4] > 65535)) {
            return null;
        }
        $host = strtolower($m[2]);
        if ($m[1] === 'http' && !in_array($host, ['localhost', '127.0.0.1'], true)) {
            return null; // HTTP hanya untuk loopback
        }
        return ['scheme' => $m[1], 'host' => $host, 'authority' => $host . (isset($m[3]) ? $m[3] : '')];
    }

    /**
     * Daftar host untuk HostGuard: entri terkonfigurasi yang valid; bila kosong, authority dari APP_URL.
     *
     * @param mixed $configured nilai ALLOWED_HOSTS dari config
     * @return list<string>
     */
    public static function allowed(mixed $configured, string $appUrl): array
    {
        $out = [];
        foreach (is_array($configured) ? $configured : [] as $h) {
            if (is_string($h) && self::validHost($h)) {
                $out[] = strtolower($h);
            }
        }
        if ($out === []) {
            $p = self::parse($appUrl);
            if ($p !== null) {
                $out[] = $p['authority'];
            }
        }
        return array_values(array_unique($out));
    }

    public static function validHost(string $h): bool
    {
        return preg_match('/^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(:[0-9]{1,5})?$/D', $h) === 1;
    }
}
