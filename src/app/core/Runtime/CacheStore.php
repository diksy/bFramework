<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use RuntimeException;

/**
 * Penyimpanan cache compile (CACHE-03..05, 08, 09).
 * Struktur: <dir>/current (teks) + <dir>/v_<12 hex>/... File data = `<?php defined('APP_BOOTED') || exit; return [...];`.
 */
final class CacheStore
{
    public const VERSION_RE = '/^v_[0-9a-f]{12}$/D';
    private const SEGMENT_RE = '/^[A-Za-z0-9_-]{1,64}$/D';

    public function __construct(private readonly string $dir)
    {
    }

    public function dir(): string
    {
        return $this->dir;
    }

    /** Versi aktif; dibaca dengan file_get_contents (bukan include) agar lolos dari OPcache (CACHE-04). */
    public function current(): ?string
    {
        $raw = @file_get_contents($this->dir . '/current');
        if ($raw === false) {
            return null;
        }
        $v = trim($raw);
        return preg_match(self::VERSION_RE, $v) === 1 && is_dir($this->dir . '/' . $v) ? $v : null;
    }

    /**
     * Tulis file data secara atomik (tmp + rename). $rel relatif ke dir cache, mis. `v_ab12.../models/produk.php`.
     *
     * @param array<mixed> $data hanya array dan skalar (CACHE-08)
     */
    public function writeAtomic(string $rel, array $data): void
    {
        $path = $this->path($rel);
        self::assertPlain($data, '$');
        $dir = dirname($path);
        if (!is_dir($dir) && !@mkdir($dir, 0750, true) && !is_dir($dir)) {
            throw new RuntimeException('Folder cache tidak dapat dibuat');
        }
        $code = "<?php\n\ndeclare(strict_types=1);\n\ndefined('APP_BOOTED') || exit;\n\nreturn " . var_export($data, true) . ";\n";
        $this->atomicWrite($path, $code);
    }

    /**
     * Muat file data cache. Null bila tidak ada.
     *
     * @return array<mixed>|null
     */
    public function read(string $rel): ?array
    {
        $path = $this->path($rel);
        if (!is_file($path)) {
            return null;
        }
        $d = include $path;
        if (!is_array($d)) {
            throw new RuntimeException('File cache rusak');
        }
        return $d;
    }

    /** Jadikan versi aktif (atomik). Versi harus ada dan lengkap (punya manifest). */
    public function activate(string $version): void
    {
        if (preg_match(self::VERSION_RE, $version) !== 1 || !is_file($this->dir . '/' . $version . '/manifest.php')) {
            throw new RuntimeException('Versi cache tidak valid');
        }
        $this->atomicWrite($this->dir . '/current', $version);
        @touch($this->dir . '/' . $version);
    }

    /**
     * Hapus versi lama: pertahankan versi aktif + $keepOld terbaru lainnya (CACHE-05: lama dihapus setelah dua build berikutnya)
     * dan staging yatim lebih tua dari 1 jam.
     */
    public function gc(int $keepOld = 2): int
    {
        $cur = $this->current();
        $versions = [];
        $removed = 0;
        foreach (@scandir($this->dir) ?: [] as $n) {
            $p = $this->dir . '/' . $n;
            if (is_link($p) || !is_dir($p)) {
                continue;
            }
            if (preg_match(self::VERSION_RE, $n) === 1 && $n !== $cur) {
                $versions[$n] = (int) filemtime($p);
            } elseif (preg_match('/^s_[0-9a-f]{16}$/D', $n) === 1 && (int) filemtime($p) < time() - 3600) {
                self::rmTree($p);
                $removed++;
            }
        }
        uksort($versions, static fn(string $a, string $b): int => [$versions[$b], $b] <=> [$versions[$a], $a]);
        foreach (array_slice(array_keys($versions), max(0, $keepOld)) as $n) {
            self::rmTree($this->dir . '/' . $n);
            $removed++;
        }
        return $removed;
    }

    /** Validasi $rel ketat: segmen [A-Za-z0-9_-], akhiran .php; tidak ada `..`, titik, atau pemisah ganda. */
    public function path(string $rel): string
    {
        $parts = explode('/', $rel);
        $last = array_pop($parts);
        if ($parts === [] || !is_string($last) || !str_ends_with($last, '.php')
            || preg_match(self::SEGMENT_RE, substr($last, 0, -4)) !== 1) {
            throw new RuntimeException('Path cache tidak valid');
        }
        foreach ($parts as $s) {
            if (preg_match(self::SEGMENT_RE, $s) !== 1) {
                throw new RuntimeException('Path cache tidak valid');
            }
        }
        return $this->dir . '/' . $rel;
    }

    public function ensureDir(): void
    {
        if (!is_dir($this->dir) && !@mkdir($this->dir, 0750, true) && !is_dir($this->dir)) {
            throw new RuntimeException('Folder cache tidak dapat dibuat');
        }
    }

    private function atomicWrite(string $path, string $content): void
    {
        $tmp = dirname($path) . '/.tmp_' . bin2hex(random_bytes(8));
        if (file_put_contents($tmp, $content, LOCK_EX) === false) {
            @unlink($tmp);
            throw new RuntimeException('Gagal menulis file cache');
        }
        @chmod($tmp, 0640);
        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            throw new RuntimeException('Gagal mengganti file cache');
        }
    }

    /** CACHE-08: hanya array dan skalar (int, float hingga, string, bool, null). */
    private static function assertPlain(mixed $v, string $at): void
    {
        if (is_array($v)) {
            foreach ($v as $k => $x) {
                self::assertPlain($x, $at . '/' . $k);
            }
            return;
        }
        if ($v === null || is_string($v) || is_int($v) || is_bool($v)) {
            return;
        }
        if (is_float($v) && is_finite($v)) {
            return;
        }
        throw new RuntimeException('Cache hanya menerima array dan skalar (CACHE-08), ditemukan ' . get_debug_type($v) . ' di ' . $at);
    }

    public static function rmTree(string $p): void
    {
        if (is_link($p) || is_file($p)) {
            @unlink($p);
            return;
        }
        foreach (@scandir($p) ?: [] as $n) {
            if ($n !== '.' && $n !== '..') {
                self::rmTree($p . '/' . $n);
            }
        }
        @rmdir($p);
    }
}
