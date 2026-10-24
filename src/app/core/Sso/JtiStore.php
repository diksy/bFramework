<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Clock;

/** SSO-15: jti logout token yang sama ditolak dalam jendela replay. Satu file per jti (nama = hash), atomik via flock. */
final class JtiStore
{
    public function __construct(private readonly string $dir, private readonly Clock $clock, private readonly int $ttl = 300)
    {
    }

    /** true bila jti baru (dicatat); false bila replay. */
    public function firstUse(string $jti): bool
    {
        if (!is_dir($this->dir) && !@mkdir($this->dir, 0700, true) && !is_dir($this->dir)) {
            return false; // tak bisa menjamin anti-replay: tolak
        }
        $now = $this->clock->now()->getTimestamp();
        $p = $this->dir . '/jti_' . hash('sha256', $jti);
        $fh = fopen($p, 'c+');
        if ($fh === false) {
            return false;
        }
        try {
            if (!flock($fh, LOCK_EX)) {
                return false;
            }
            @chmod($p, 0600);
            $exp = (int) trim((string) stream_get_contents($fh));
            if ($exp > $now) {
                return false;
            }
            ftruncate($fh, 0);
            rewind($fh);
            fwrite($fh, (string) ($now + $this->ttl));
            fflush($fh);
        } finally {
            fclose($fh);
        }
        if (random_int(1, 25) === 1) {
            $this->gc($now);
        }
        return true;
    }

    private function gc(int $now): void
    {
        foreach (glob($this->dir . '/jti_*') ?: [] as $f) {
            $exp = (int) @file_get_contents($f);
            if ($exp !== 0 && $exp <= $now) {
                @unlink($f);
            }
        }
    }
}
