<?php

declare(strict_types=1);

namespace bFramework\Cache;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Logger;
use bFramework\Core\Request;
use bFramework\Core\SafeHtml;
use bFramework\Runtime\PageCacheSink;

/**
 * Cache halaman publik sebagai HTML statis (F8, CACHE-12/13/14).
 *
 * - Kunci berkas diturunkan dari RUTE ter-whitelist (halaman `cache: true` + access `*` dari definisi ter-compile),
 *   bukan dari URL mentah: `<route>.html` di bawah _pc/. Rute lolos ROUTE_RE (huruf kecil/angka/_/-), panjang dibatasi,
 *   sehingga `..`, NUL, `%2F`, dan query liar tidak pernah mencapai sistem berkas. .htaccess memetakan URL ke berkas
 *   yang sama hanya untuk GET tanpa query dan tanpa cookie sesi/ingat-saya.
 * - HTML yang memuat nonce CSP, token CSRF, atau form ber-token TIDAK disimpan (fail-closed). Set-Cookie bukan bagian berkas.
 * - Invalidasi per tag model memakai generasi: store() yang mengambil snapshot sebelum render ditolak bila tag dinaikkan
 *   sesudahnya (race simpan-lama vs invalidasi). Invalidasi dan store berbagi satu flock.
 * - Metadata (indeks tag, generasi) di luar docroot ($stateDir); di _pc/ hanya berkas .html (izin 0644), ditulis atomik.
 */
final class PageCache implements PageCacheSink
{
    public const MAX_ROUTE_LEN = 120;
    private const ROUTE_RE = '#^/[a-z0-9_-]+(/[a-z0-9_-]+)*$#D';
    private const TAG_RE = '/^[A-Za-z0-9_]{1,64}$/D';
    private const COOKIE_RE = '/(^|;\s*)(__Host-)?bf_(sid|remember)=/';
    private const ALL = '_all';

    /** @var array<string,bool>|null */
    private ?array $routes = null;

    /**
     * @param \Closure():list<string> $routeSource rute halaman `cache: true` dan access `*` dari definisi ter-compile
     * @param array{maxFiles?:int,maxFileBytes?:int,maxTotalBytes?:int,ttl?:int} $limits
     */
    public function __construct(
        private readonly string $cacheDir,
        private readonly string $stateDir,
        private readonly \Closure $routeSource,
        private readonly ?Logger $logger = null,
        private readonly array $limits = [],
    ) {
    }

    /** Path relatif berkas untuk rute, atau null bila rute tidak aman/terlalu panjang. */
    public static function keyFor(string $route): ?string
    {
        if (strlen($route) > self::MAX_ROUTE_LEN || preg_match(self::ROUTE_RE, $route) !== 1) {
            return null;
        }
        return substr($route, 1) . '.html';
    }

    public function eligible(Request $r): bool
    {
        if ($r->method !== 'GET' || $r->query !== [] || $r->post !== []) {
            return false;
        }
        if (($r->header('authorization') ?? '') !== '') {
            return false;
        }
        if (preg_match(self::COOKIE_RE, $r->header('cookie') ?? '') === 1) {
            return false; // cookie sesi/ingat-saya: jangan sajikan/simpan dari cache
        }
        return isset($this->routes()[$r->path]) && self::keyFor($r->path) !== null;
    }

    public function snapshot(array $tags): array
    {
        $snap = [self::ALL => $this->gen(self::ALL)];
        foreach ($tags as $t) {
            if (preg_match(self::TAG_RE, $t) === 1) {
                $snap[$t] = $this->gen('t_' . $t);
            }
        }
        return $snap;
    }

    public function store(string $route, SafeHtml $html, array $tags, ?array $snapshot = null): bool
    {
        $key = self::keyFor($route);
        $body = $html->toString();
        if ($key === null || !isset($this->routes()[$route]) || !$this->bodySafe($body)) {
            return false;
        }
        foreach ($tags as $t) {
            if (preg_match(self::TAG_RE, $t) !== 1) {
                return false;
            }
        }
        $maxFile = $this->limit('maxFileBytes', 262144);
        if (strlen($body) > $maxFile) {
            return false;
        }
        try {
            return $this->locked(function () use ($key, $body, $tags, $snapshot): bool {
                // Cek generasi di dalam kunci yang sama dengan invalidate(): tidak ada celah di antaranya.
                $expect = $snapshot ?? $this->snapshot($tags);
                if (($expect[self::ALL] ?? null) !== $this->gen(self::ALL)) {
                    return false;
                }
                foreach ($tags as $t) {
                    if (!isset($expect[$t]) || $expect[$t] !== $this->gen('t_' . $t)) {
                        return false;
                    }
                }
                $idx = $this->readIndex();
                $id = hash('sha256', $key);
                if (!isset($idx[$id])) {
                    $total = 0;
                    foreach ($idx as $e) {
                        $total += $e['s'];
                    }
                    if (count($idx) >= $this->limit('maxFiles', 500) || $total + strlen($body) > $this->limit('maxTotalBytes', 20971520)) {
                        return false;
                    }
                }
                $path = $this->cacheDir . '/' . $key;
                $this->ensureDir(dirname($path));
                $tmp = $this->cacheDir . '/.tmp-' . bin2hex(random_bytes(8));
                if (file_put_contents($tmp, $body, LOCK_EX) === false) {
                    @unlink($tmp);
                    return false;
                }
                @chmod($tmp, 0644);
                if (!@rename($tmp, $path)) {
                    @unlink($tmp);
                    return false;
                }
                $meta = json_encode(['k' => $key, 'tags' => array_values($tags), 't' => time(), 's' => strlen($body)], JSON_THROW_ON_ERROR);
                $this->atomicWrite($this->stateDir . '/idx/' . $id . '.json', $meta);
                return true;
            });
        } catch (\Throwable $e) {
            $this->logger?->error('PageCache store gagal', ['ex' => $e::class]);
            return false;
        }
    }

    public function invalidate(string $model): void
    {
        try {
            if (preg_match(self::TAG_RE, $model) !== 1) {
                $this->purgeAll();
                return;
            }
            $this->locked(function () use ($model): void {
                $this->bump('t_' . $model); // lebih dulu: store() yang sedang berjalan menjadi basi dan ditolak
                foreach ($this->readIndex() as $id => $e) {
                    if (in_array($model, $e['tags'], true)) {
                        $this->drop($id, $e['k']);
                    }
                }
            });
        } catch (\Throwable $e) {
            $this->logger?->error('PageCache invalidate gagal; mencoba purge total', ['ex' => $e::class]);
            try {
                $this->purgeAll(); // jangan biarkan data basi disajikan
            } catch (\Throwable $e2) {
                $this->logger?->error('PageCache purge total gagal', ['ex' => $e2::class]);
                throw new \RuntimeException('Invalidasi cache halaman gagal', 0, $e2);
            }
        }
    }

    /** Hapus semua halaman cache (definisi berubah, halaman berubah akses, fallback). */
    public function purgeAll(): void
    {
        $this->locked(function (): void {
            $this->bump(self::ALL);
            foreach ($this->readIndex() as $id => $e) {
                $this->drop($id, $e['k']);
            }
            foreach ($this->htmlFiles() as $f) {
                @unlink($f);
            }
        });
    }

    /** Pembersihan: kedaluwarsa (ttl), yatim, dan tmp usang. Dipanggil probabilistik oleh index.php. */
    public function gc(): int
    {
        $n = 0;
        $ttl = $this->limit('ttl', 86400);
        $this->locked(function () use (&$n, $ttl): void {
            $known = [];
            foreach ($this->readIndex() as $id => $e) {
                if (time() - $e['t'] > $ttl || !is_file($this->cacheDir . '/' . $e['k'])) {
                    $this->drop($id, $e['k']);
                    $n++;
                } else {
                    $known[$e['k']] = true;
                }
            }
            foreach ($this->htmlFiles() as $f) {
                if (!isset($known[substr($f, strlen($this->cacheDir) + 1)])) {
                    @unlink($f);
                    $n++;
                }
            }
            foreach (glob($this->cacheDir . '/.tmp-*') ?: [] as $t) {
                if (is_file($t) && time() - (int) filemtime($t) > 3600) {
                    @unlink($t);
                }
            }
        });
        return $n;
    }

    // ---------- internal ----------

    /** @return array<string,bool> */
    private function routes(): array
    {
        if ($this->routes === null) {
            $this->routes = [];
            try {
                foreach (($this->routeSource)() as $r) {
                    if (self::keyFor($r) !== null) {
                        $this->routes[$r] = true;
                    }
                }
            } catch (\Throwable) {
                $this->routes = []; // definisi belum ter-compile: tidak ada yang di-cache
            }
        }
        return $this->routes;
    }

    private function bodySafe(string $body): bool
    {
        return preg_match('/\bnonce\s*=/i', $body) !== 1
            && !str_contains($body, '_csrf')
            && preg_match('/name=["\']csrf-token["\']\s+content=["\'][^"\']/i', $body) !== 1;
    }

    private function limit(string $k, int $default): int
    {
        $v = $this->limits[$k] ?? $default;
        return is_int($v) && $v > 0 ? $v : $default;
    }

    private function ensureDir(string $dir): void
    {
        if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
            throw new \RuntimeException('Folder cache tidak dapat dibuat');
        }
    }

    /**
     * @template T
     * @param \Closure():T $fn
     * @return T
     */
    private function locked(\Closure $fn): mixed
    {
        $this->ensureDir($this->stateDir);
        $this->ensureDir($this->stateDir . '/idx');
        $this->ensureDir($this->stateDir . '/gen');
        $this->ensureDir($this->cacheDir);
        $h = fopen($this->stateDir . '/lock', 'c');
        if ($h === false || !flock($h, LOCK_EX)) {
            throw new \RuntimeException('Kunci cache tidak diperoleh');
        }
        try {
            return $fn();
        } finally {
            flock($h, LOCK_UN);
            fclose($h);
        }
    }

    private function gen(string $name): int
    {
        $raw = @file_get_contents($this->stateDir . '/gen/' . $name);
        return is_string($raw) && ctype_digit(trim($raw)) ? (int) trim($raw) : 0;
    }

    private function bump(string $name): void
    {
        $this->atomicWrite($this->stateDir . '/gen/' . $name, (string) ($this->gen($name) + 1));
    }

    private function atomicWrite(string $path, string $content): void
    {
        $tmp = $path . '.' . bin2hex(random_bytes(6)) . '.tmp';
        if (file_put_contents($tmp, $content) === false || !@rename($tmp, $path)) {
            @unlink($tmp);
            throw new \RuntimeException('Tulis atomik gagal');
        }
    }

    /** @return array<string,array{k:string,tags:list<string>,t:int,s:int}> */
    private function readIndex(): array
    {
        $out = [];
        foreach (glob($this->stateDir . '/idx/*.json') ?: [] as $f) {
            $d = json_decode((string) @file_get_contents($f), true);
            $id = basename($f, '.json');
            if (!is_array($d) || !is_string($d['k'] ?? null) || self::keyFor('/' . substr($d['k'], 0, -5)) === null
                || !is_array($d['tags'] ?? null) || preg_match('/^[a-f0-9]{64}$/D', $id) !== 1) {
                @unlink($f); // indeks rusak: buang (berkas yatimnya dibersihkan gc)
                continue;
            }
            $out[$id] = [
                'k' => $d['k'],
                'tags' => array_values(array_filter($d['tags'], 'is_string')),
                't' => is_int($d['t'] ?? null) ? $d['t'] : 0,
                's' => is_int($d['s'] ?? null) ? $d['s'] : 0,
            ];
        }
        return $out;
    }

    private function drop(string $id, string $key): void
    {
        @unlink($this->cacheDir . '/' . $key);
        @unlink($this->stateDir . '/idx/' . $id . '.json');
    }

    /** @return list<string> */
    private function htmlFiles(): array
    {
        $out = [];
        if (!is_dir($this->cacheDir)) {
            return $out;
        }
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->cacheDir, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if ($f instanceof \SplFileInfo && $f->isFile() && !$f->isLink() && $f->getExtension() === 'html') {
                $out[] = $f->getPathname();
            }
        }
        return $out;
    }
}
