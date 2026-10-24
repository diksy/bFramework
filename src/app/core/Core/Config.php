<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

use RuntimeException;

final class Config
{
    /** @var array<string,mixed> */
    private static array $data = [];

    /** @param array<string,mixed> $data */
    public static function set(array $data): void
    {
        self::$data = $data;
    }

    /** Muat file PHP yang mengembalikan array (app/config/config.php). Tidak ada = konfigurasi kosong. */
    public static function load(string $file): void
    {
        if (!is_file($file)) {
            self::$data = [];
            return;
        }
        $d = (static function (string $f): mixed {
            return require $f;
        })($file);
        if (!is_array($d)) {
            throw new RuntimeException('config.php harus mengembalikan array');
        }
        /** @var array<string,mixed> $d */
        self::$data = $d;
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        return array_key_exists($key, self::$data) ? self::$data[$key] : $default;
    }

    /** Nilai APP_ENV yang berarti mode dev (allowlist; fail-closed). */
    public const DEV_ENVS = ['dev', 'development', 'local', 'test'];

    /**
     * Satu-satunya penentu mode dev. Allowlist: hanya nilai (trim + lowercase) di DEV_ENVS = dev;
     * tidak terset, kosong, bukan string, atau nilai lain apa pun = produksi.
     */
    public static function isDevEnv(mixed $value): bool
    {
        return is_string($value) && in_array(strtolower(trim($value)), self::DEV_ENVS, true);
    }

    /** Mode dev dari environment variable APP_ENV; bila tidak terset, dari config APP_ENV. */
    public static function devMode(): bool
    {
        $env = getenv('APP_ENV');
        return self::isDevEnv($env !== false ? $env : self::get('APP_ENV'));
    }

    /**
     * Salinan aman untuk ekspor/log: tanpa kunci *_PASSWORD, *_SECRET, APP_KEY (tidak peka huruf besar-kecil).
     *
     * @return array<string,mixed>
     */
    public static function exportable(): array
    {
        return self::scrub(self::$data);
    }

    /**
     * @param array<mixed> $in
     * @return array<mixed>
     */
    private static function scrub(array $in): array
    {
        $out = [];
        foreach ($in as $k => $v) {
            if (is_string($k) && preg_match('/(_PASSWORD|_SECRET)$|^APP_KEY$/i', $k) === 1) {
                continue;
            }
            $out[$k] = is_array($v) ? self::scrub($v) : $v;
        }
        return $out;
    }
}
