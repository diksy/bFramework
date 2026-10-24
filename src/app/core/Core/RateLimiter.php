<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Clock;
use InvalidArgumentException;
use RuntimeException;

/**
 * SEC-REQ-02: rate limit jendela geser berbasis file (flock). hit() mengembalikan true bila
 * masih dalam batas (percobaan dicatat), false bila melewati batas (pemanggil melempar TooManyRequests).
 * Kunci di-hash sehingga tidak ada data mentah (email/IP) di nama file.
 */
final class RateLimiter
{
    public function __construct(private readonly string $dir, private readonly ?Clock $clock = null)
    {
        if ($dir === '') {
            throw new InvalidArgumentException('Direktori rate limit kosong');
        }
    }

    public function hit(string $key, int $max, int $windowSec): bool
    {
        if ($max < 1 || $windowSec < 1) {
            throw new InvalidArgumentException('max dan window harus positif');
        }
        if (!is_dir($this->dir) && !@mkdir($this->dir, 0700, true) && !is_dir($this->dir)) {
            throw new RuntimeException('Direktori rate limit tidak dapat dibuat');
        }
        $now = $this->clock !== null ? $this->clock->now()->getTimestamp() : time();
        $file = rtrim($this->dir, '/\\') . '/rl_' . hash('sha256', $key) . '.json';
        $fh = fopen($file, 'c+');
        if ($fh === false) {
            throw new RuntimeException('Berkas rate limit tidak dapat dibuka');
        }
        try {
            if (!flock($fh, LOCK_EX)) {
                throw new RuntimeException('Kunci rate limit gagal');
            }
            @chmod($file, 0600);
            $raw = stream_get_contents($fh);
            $decoded = is_string($raw) && $raw !== '' ? json_decode($raw, true) : [];
            $stamps = [];
            foreach (is_array($decoded) ? $decoded : [] as $t) {
                if (is_int($t) && $t > $now - $windowSec) {
                    $stamps[] = $t;
                }
            }
            $allowed = count($stamps) < $max;
            if ($allowed) {
                $stamps[] = $now;
            }
            ftruncate($fh, 0);
            rewind($fh);
            fwrite($fh, json_encode($stamps, JSON_THROW_ON_ERROR));
            fflush($fh);
            flock($fh, LOCK_UN);
            return $allowed;
        } finally {
            fclose($fh);
        }
    }
}
