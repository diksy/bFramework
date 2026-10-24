<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Clock;

/**
 * Cache JSON kecil di storage/ (SSO-07) untuk discovery + JWKS. Bukan file PHP (menghindari OPcache basi),
 * tulis atomik (tmp + rename), izin 0600. `claim()` adalah pembatas laju berbasis flock lintas request.
 */
final class FileCache
{
    public function __construct(private readonly string $dir, private readonly Clock $clock)
    {
    }

    /** @return array<mixed>|null */
    public function get(string $key): ?array
    {
        $raw = @file_get_contents($this->path($key));
        $d = is_string($raw) ? json_decode($raw, true) : null;
        return is_array($d) ? $d : null;
    }

    /** @param array<mixed> $data */
    public function put(string $key, array $data): void
    {
        $this->ensure();
        $p = $this->path($key);
        $tmp = $p . '.' . bin2hex(random_bytes(6)) . '.tmp';
        $old = umask(0177);
        try {
            $ok = file_put_contents($tmp, json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), LOCK_EX) !== false;
        } finally {
            umask($old);
        }
        if (!$ok || !@rename($tmp, $p)) {
            @unlink($tmp);
            throw new \RuntimeException('Gagal menulis cache SSO');
        }
    }

    /** Atomik: true bila sudah lewat $interval detik sejak klaim terakhir, lalu mencatat klaim baru. */
    public function claim(string $key, int $interval): bool
    {
        $this->ensure();
        $p = $this->path($key . '.claim');
        $fh = fopen($p, 'c+');
        if ($fh === false) {
            return false;
        }
        try {
            if (!flock($fh, LOCK_EX)) {
                return false;
            }
            @chmod($p, 0600);
            $last = (int) trim((string) stream_get_contents($fh));
            $now = $this->clock->now()->getTimestamp();
            if ($last !== 0 && $now - $last < $interval && $now >= $last) {
                return false;
            }
            ftruncate($fh, 0);
            rewind($fh);
            fwrite($fh, (string) $now);
            fflush($fh);
            return true;
        } finally {
            fclose($fh);
        }
    }

    private function path(string $key): string
    {
        if (preg_match('/^[a-z0-9_.-]{1,64}$/D', $key) !== 1) {
            throw new \InvalidArgumentException('Kunci cache tidak valid');
        }
        return $this->dir . '/' . $key . '.json';
    }

    private function ensure(): void
    {
        if (!is_dir($this->dir) && !@mkdir($this->dir, 0700, true) && !is_dir($this->dir)) {
            throw new \RuntimeException('Direktori cache SSO tidak dapat dibuat');
        }
    }
}
