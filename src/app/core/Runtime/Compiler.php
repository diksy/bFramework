<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Dialect;
use Closure;
use JsonException;
use RuntimeException;
use Throwable;

/**
 * Compile definisi JSON menjadi cache PHP (F7): Load, Validate, Resolve, Optimize, Emit, Activate.
 * Build dikunci flock (CACHE-07); setiap build ke folder versi baru v_<hash> lewat staging + rename
 * (CACHE-03/05) sehingga kegagalan di tengah jalan tidak mengubah versi aktif.
 * Compiler tidak pernah membaca Config/environment, jadi rahasia tidak mungkin ikut (CACHE-11).
 */
final class Compiler
{
    public const FORMAT = 1;
    private const MAX_BYTES = 1048576;
    private const LOCK_WAIT_SEC = 15;

    private readonly string $extDir;
    private readonly string $pcDir;

    /**
     * @param ?string $extDir folder extensions (default: saudara `definitions/`)
     * @param ?Closure(string):void $onEmit seam tes: dipanggil setelah tiap file ditulis
     * @param ?Closure():void $onBuilt buang cache halaman (F8/CACHE-13); dipanggil sebelum dan sesudah aktivasi.
     *        Gagal -> fallback hapus `*.html` di $pcDir; masih gagal -> build gagal (fail-closed). Bila kegagalan terjadi
     *        SETELAH aktivasi, versi sebelumnya diaktifkan kembali (atau tidak ada versi aktif bila sebelumnya kosong),
     *        purge diulang, dan bila tetap gagal $pcDir dikarantina (rename ke nama berawalan titik yang diblokir 403)
     *        sehingga Apache tidak menyajikan halaman basi.
     * @param ?string $pcDir folder cache halaman statis; default `<app>/../public_html/_pc` dari lokasi CacheStore,
     *        sehingga pemanggil tanpa $onBuilt tetap tidak meninggalkan halaman basi.
     */
    public function __construct(
        private readonly CacheStore $store,
        ?string $extDir = null,
        private readonly ?Closure $onEmit = null,
        private readonly ?Closure $onBuilt = null,
        private readonly ?\bFramework\Contracts\Logger $logger = null,
        ?string $pcDir = null,
    ) {
        $this->extDir = $extDir ?? '';
        $this->pcDir = $pcDir ?? dirname($store->dir(), 3) . '/public_html/_pc';
    }

    public function build(string $defDir, Dialect $dialect): BuildResult
    {
        $lock = null;
        $stage = null;
        try {
            $this->store->ensureDir();
            $lock = $this->lock();

            [$src, $errors] = $this->load($defDir);
            $schema = new DefinitionSchema();
            foreach ($errors as $e) {
                $schema->error($e->src, $e->msg);
            }
            [$models, $pages, $auth] = $this->validate($schema, $src);
            $schema->resolve($models, $pages);
            $this->checkHooks($schema, $models, $defDir);
            if ($schema->errors() !== []) {
                return new BuildResult(null, $schema->errors());
            }

            $hash = self::sourceHash($src, $dialect);
            $version = 'v_' . substr($hash, 0, 12);
            $final = $this->store->dir() . '/' . $version;
            if (!is_file($final . '/manifest.php')) {
                $stage = 's_' . bin2hex(random_bytes(8));
                $this->emit($stage, $dialect, $hash, $version, $models, $pages, $auth);
                if (is_dir($final)) {
                    CacheStore::rmTree($final); // sisa tak lengkap (tanpa manifest)
                }
                if (!@rename($this->store->dir() . '/' . $stage, $final)) {
                    throw new RuntimeException('Gagal menempatkan versi baru');
                }
                $stage = null;
            }
            // CACHE-13: buang halaman statis SEBELUM aktivasi (gagal -> belum ada yang berubah, versi lama tetap aktif)
            // dan sesudahnya (menutup halaman yang tersimpan di sela waktu). Bila purge kedua gagal, aktivasi
            // dibatalkan (rollback ke $prev) dan build gagal. Tidak boleh ada halaman basi yang tersisa.
            $prev = $this->store->current();
            $this->purgePages();
            if ($prev !== $version) {
                $this->store->activate($version);
            }
            try {
                $this->purgePages();
            } catch (Throwable $e) {
                if ($prev !== $version) {
                    $this->rollback($prev);
                }
                throw $e;
            }
            $this->store->gc();
            return new BuildResult($version);
        } catch (Throwable $e) {
            // Pesan generik: jangan bocorkan path server; detail ada di tipe exception saja.
            return new BuildResult(null, [new CompileError('(build)', 'Build gagal: ' . $e::class)]);
        } finally {
            if ($stage !== null) {
                CacheStore::rmTree($this->store->dir() . '/' . $stage);
            }
            if (is_resource($lock)) {
                flock($lock, LOCK_UN);
                fclose($lock);
            }
        }
    }

    /**
     * CACHE-13: batalkan aktivasi setelah purge kedua gagal. Kembalikan versi sebelumnya (null -> tidak ada versi aktif),
     * lalu purge ulang; bila masih gagal, karantina $pcDir agar Apache tidak menyajikan halaman yang tersisa.
     */
    private function rollback(?string $prev): void
    {
        try {
            if ($prev !== null) {
                $this->store->activate($prev);
            } elseif (is_file($this->store->dir() . '/current') && !@unlink($this->store->dir() . '/current')) {
                throw new RuntimeException('Versi aktif tidak dapat dinonaktifkan');
            }
        } catch (Throwable $e) {
            $this->logger?->error('Rollback versi cache gagal', ['ex' => $e::class]);
        }
        try {
            $this->purgePages();
            return;
        } catch (Throwable) {
            // lanjut ke karantina
        }
        $this->quarantinePages();
    }

    /**
     * Pindahkan $pcDir ke folder saudara berawalan titik (diblokir `.htaccess` root: 403) lalu buat ulang $pcDir
     * kosong beserta `.htaccess`-nya. Gagal -> hanya dilog; build tetap dilaporkan gagal oleh pemanggil.
     */
    private function quarantinePages(): void
    {
        if (!is_dir($this->pcDir)) {
            return;
        }
        $q = dirname($this->pcDir) . '/.pc_stale_' . bin2hex(random_bytes(6));
        if (!@rename($this->pcDir, $q)) {
            $this->logger?->error('Karantina cache halaman gagal; halaman basi mungkin masih tersaji', []);
            return;
        }
        $this->logger?->error('Cache halaman dikarantina setelah purge gagal', []);
        if (@mkdir($this->pcDir, 0755) && is_file($q . '/.htaccess')) {
            @copy($q . '/.htaccess', $this->pcDir . '/.htaccess');
        }
    }

    /** @throws RuntimeException bila halaman statis basi tidak dapat dibuang */
    private function purgePages(): void
    {
        if ($this->onBuilt !== null) {
            try {
                ($this->onBuilt)();
                return;
            } catch (Throwable $e) {
                $this->logger?->error('Purge cache halaman gagal; mencoba hapus langsung', ['ex' => $e::class]);
            }
        }
        $left = 0;
        if (is_dir($this->pcDir)) {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->pcDir, \FilesystemIterator::SKIP_DOTS));
            foreach ($it as $f) {
                if ($f instanceof \SplFileInfo && !$f->isDir() && $f->getExtension() === 'html' && !@unlink($f->getPathname()) && file_exists($f->getPathname())) {
                    $left++;
                }
            }
        }
        if ($left > 0) {
            $this->logger?->error('Fallback purge cache halaman gagal', ['sisa' => $left]);
            throw new RuntimeException('Cache halaman tidak dapat dibuang');
        }
    }

    /** Mode development: True bila sumber berubah sejak versi aktif dibuat (bandingkan hash isi, bukan mtime). */
    public function isStale(string $defDir, Dialect $dialect): bool
    {
        [$src, $errors] = $this->load($defDir);
        $cur = $this->store->current();
        if ($errors !== [] || $cur === null) {
            return true;
        }
        $m = $this->store->read($cur . '/manifest.php');
        return ($m['sourceHash'] ?? null) !== self::sourceHash($src, $dialect);
    }

    /** @return resource */
    private function lock()
    {
        $h = fopen($this->store->dir() . '/build.lock', 'c');
        if ($h === false) {
            throw new RuntimeException('Kunci build tidak dapat dibuka');
        }
        $deadline = microtime(true) + self::LOCK_WAIT_SEC;
        while (!flock($h, LOCK_EX | LOCK_NB)) {
            if (microtime(true) > $deadline) {
                fclose($h);
                throw new RuntimeException('Build lain sedang berjalan');
            }
            usleep(50000);
        }
        return $h;
    }

    /**
     * @return array{0:array{models:array<string,string>,pages:array<string,string>,auth:?string},1:list<CompileError>}
     */
    private function load(string $defDir): array
    {
        $errors = [];
        $out = ['models' => [], 'pages' => [], 'auth' => null];
        $base = realpath($defDir);
        if ($base === false || !is_dir($base)) {
            return [$out, [new CompileError('definitions', 'Folder definisi tidak ditemukan')]];
        }
        foreach (['models', 'pages'] as $kind) {
            $dir = $base . '/' . $kind;
            foreach (is_dir($dir) ? (scandir($dir) ?: []) : [] as $f) {
                if ($f === '.' || $f === '..' || !str_ends_with($f, '.json')) {
                    continue;
                }
                $name = substr($f, 0, -5);
                if (preg_match('/^[a-z][a-z0-9_-]{0,40}$/D', $name) !== 1) {
                    $errors[] = new CompileError("$kind/(nama-file)", 'Nama file definisi tidak valid');
                    continue;
                }
                $raw = $this->readFile("$dir/$f", $base, "$kind/$name.json", $errors);
                if ($raw !== null) {
                    $out[$kind][$name] = $raw;
                }
            }
        }
        if (is_file($base . '/auth.json') || is_link($base . '/auth.json')) {
            $out['auth'] = $this->readFile($base . '/auth.json', $base, 'auth.json', $errors);
        }
        return [$out, $errors];
    }

    /** @param list<CompileError> $errors */
    private function readFile(string $path, string $base, string $src, array &$errors): ?string
    {
        $real = realpath($path);
        if (is_link($path) || $real === false || !str_starts_with($real, $base . '/') || !is_file($real)) {
            $errors[] = new CompileError($src, 'Berkas harus file biasa di dalam folder definisi');
            return null;
        }
        $size = filesize($real);
        $raw = $size !== false && $size <= self::MAX_BYTES ? file_get_contents($real) : false;
        if ($raw === false) {
            $errors[] = new CompileError($src, 'Berkas tidak terbaca atau lebih dari 1 MiB');
            return null;
        }
        return $raw;
    }

    /**
     * @param array{models:array<string,string>,pages:array<string,string>,auth:?string} $src
     * @return array{0:array<string,array<string,mixed>>,1:array<string,array<string,mixed>>,2:?array<string,mixed>}
     */
    private function validate(DefinitionSchema $schema, array $src): array
    {
        $models = [];
        $pages = [];
        $auth = null;
        foreach ($src['models'] as $n => $raw) {
            $d = $this->decode($raw, "models/$n.json", $schema);
            if ($d !== null && ($m = $schema->model($n, $d)) !== null) {
                $models[$n] = $m;
            }
        }
        foreach ($src['pages'] as $n => $raw) {
            $d = $this->decode($raw, "pages/$n.json", $schema);
            if ($d !== null && ($p = $schema->page($n, $d)) !== null) {
                $pages[$n] = $p;
            }
        }
        if ($src['auth'] !== null) {
            $d = $this->decode($src['auth'], 'auth.json', $schema);
            $auth = $d !== null ? $schema->auth($d) : null;
        }
        return [$models, $pages, $auth];
    }

    /** @return array<mixed>|null */
    private function decode(string $raw, string $src, DefinitionSchema $schema): ?array
    {
        try {
            $d = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            $schema->error($src, 'JSON tidak valid');
            return null;
        }
        if (!is_array($d) || ($d !== [] && array_is_list($d))) {
            $schema->error($src, 'Root harus objek');
            return null;
        }
        return $d;
    }

    /**
     * Pastikan class + method hook ada tanpa meng-include kode ekstensi (analisis teks).
     *
     * @param array<string,array<string,mixed>> $models
     */
    private function checkHooks(DefinitionSchema $schema, array $models, string $defDir): void
    {
        $ext = $this->extDir !== '' ? $this->extDir : dirname($defDir) . '/extensions';
        $extReal = realpath($ext);
        foreach ($models as $m) {
            foreach ($m['hooks'] as $h) {
                $file = $extReal !== false ? $extReal . '/' . $h['class'] . '.php' : '';
                $real = $file !== '' ? realpath($file) : false;
                $code = $real !== false && !is_link($file) && str_starts_with($real, $extReal . '/')
                    ? file_get_contents($real) : false;
                if (!is_string($code)
                    || preg_match('/\bclass\s+' . preg_quote($h['class'], '/') . '\b/', $code) !== 1
                    || preg_match('/\bpublic\s+static\s+function\s+' . preg_quote($h['method'], '/') . '\s*\(/', $code) !== 1) {
                    $schema->error($h['_src'], 'Hook tidak ditemukan: ' . $h['ref']);
                }
            }
        }
    }

    /** @param array{models:array<string,string>,pages:array<string,string>,auth:?string} $src */
    private static function sourceHash(array $src, Dialect $dialect): string
    {
        $h = hash_init('sha256');
        hash_update($h, 'f' . self::FORMAT . "\0" . $dialect->value . "\0");
        foreach (['models', 'pages'] as $k) {
            foreach ($src[$k] as $n => $raw) {
                hash_update($h, "$k/$n\0" . hash('sha256', $raw) . "\0");
            }
        }
        hash_update($h, 'auth' . "\0" . ($src['auth'] === null ? '-' : hash('sha256', $src['auth'])));
        return hash_final($h);
    }

    /**
     * @param array<string,array<string,mixed>> $models
     * @param array<string,array<string,mixed>> $pages
     * @param ?array<string,mixed> $auth
     */
    private function emit(string $stage, Dialect $dialect, string $hash, string $version, array $models, array $pages, ?array $auth): void
    {
        $grammar = $dialect === Dialect::MySql ? new MySqlGrammar() : new SqliteGrammar();
        $write = function (string $rel, array $data) use ($stage): void {
            $this->store->writeAtomic($stage . '/' . $rel, $data);
            if ($this->onEmit !== null) {
                ($this->onEmit)($rel);
            }
        };
        $access = ['models' => [], 'pages' => []];
        foreach ($models as $n => $m) {
            $write("models/$n.php", $m);
            $access['models'][$n] = $m['access'];
            // CACHE-02: SQL hanya untuk dialek aktif.
            $spec = Definitions::tableSpec($m);
            $write("sql/{$dialect->value}/$n.php", ['create' => $grammar->createTable($spec), '_src' => $m['_src']]);
        }
        $routes = [];
        foreach ($pages as $n => $p) {
            $write("pages/$n.php", $p);
            $access['pages'][$n] = ['access' => $p['access'], 'route' => $p['route'], '_src' => $p['_src']];
            array_push($routes, ...self::routesFor($p));
        }
        $write('routes.php', $routes);
        $write('access.php', $access);
        if ($auth !== null) {
            $write('auth.php', $auth);
        }
        $write('manifest.php', [
            'version' => $version,
            'format' => self::FORMAT,
            'dialect' => $dialect->value,
            'sourceHash' => $hash,
            'builtAt' => gmdate('c'),
            'models' => array_keys($models),
            'pages' => array_keys($pages),
            'hasAuth' => $auth !== null,
        ]);
    }

    /**
     * @param array<string,mixed> $p
     * @return list<array<string,mixed>>
     */
    private static function routesFor(array $p): array
    {
        $h = 'bFramework\\Runtime\\PageController::';
        $r = (string) $p['route'];
        $name = (string) $p['page'];
        $row = static fn(string $m, string $pat, string $fn, string $act): array => [
            'method' => $m, 'pattern' => $pat, 'handler' => $h . $fn, 'csrf' => true,
            'name' => $name . '.' . $act, 'page' => $name, '_src' => $p['_src'],
        ];
        $rows = [$row('GET', $r, 'index', 'index')];
        $editable = false;
        foreach ($p['layout'] as $c) {
            $editable = $editable || in_array($c['component'], ['table', 'form'], true);
        }
        if ($editable) {
            array_push(
                $rows,
                $row('GET', $r . '/baru', 'form', 'baru'),
                $row('POST', $r, 'save', 'simpan'),
                $row('GET', $r . '/{id}/ubah', 'form', 'ubah'),
                $row('POST', $r . '/{id}', 'save', 'perbarui'),
                $row('POST', $r . '/{id}/hapus', 'delete', 'hapus'),
            );
        }
        return $rows;
    }
}
