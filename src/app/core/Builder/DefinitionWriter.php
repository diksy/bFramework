<?php

declare(strict_types=1);

namespace bFramework\Builder;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Dialect;
use bFramework\Contracts\Logger;
use bFramework\Core\Json;
use bFramework\Runtime\CacheStore;
use bFramework\Runtime\Compiler;
use bFramework\Runtime\DefinitionSchema;
use JsonException;

/**
 * Satu-satunya penulis berkas builder (BLD-09): hanya `.json` di `definitions/{models,pages}/` dan `auth.json`,
 * nama berkas whitelist, realpath terkunci, tulis atomik (tmp + rename), deteksi konflik lewat hash (BLD-05).
 * Setiap tulis divalidasi dengan Compiler M8 pada salinan sementara SEBELUM berkas diganti; kompilasi ulang
 * nyata terjadi sesudahnya. Gagal di mana pun = berkas lama dan versi cache aktif tetap.
 */
final class DefinitionWriter
{
    public const MAX_BYTES = 262144;
    private const MAX_DEPTH = 12;
    private const MODEL_KEYS = ['model', 'fields', 'hooks', 'access'];
    private const FIELD_KEYS = ['type', 'label', 'target', 'required', 'min', 'max', 'default', 'format', 'guarded', 'unique', 'precision', 'scale', 'upload'];
    private const ACCESS_KEYS = ['read', 'create', 'update', 'delete', 'write', 'owner', 'ownerExempt', 'requireAmr'];
    private const PAGE_KEYS = ['page', 'route', 'title', 'icon', 'group', 'order', 'access', 'cache', 'layout'];
    private const COMPONENT_KEYS = ['component', 'span', 'title', 'label', 'text', 'agg', 'field', 'columns', 'fields', 'actions', 'source', 'kind', 'src', 'alt'];
    private const SOURCE_KEYS = ['model', 'filter', 'sort', 'perPage'];
    private const AUTH_KEYS = ['driver', 'sso'];
    private const SSO_KEYS = ['issuer', 'client_id', 'provisioning', 'default_role', 'offline_access', 'session_check_minutes'];

    public function __construct(
        private readonly string $defDir,
        private readonly Compiler $compiler,
        private readonly Dialect $dialect,
        private readonly string $extDir,
        private readonly ?Logger $logger = null,
    ) {
    }

    /** Path kanonik berkas definisi, atau null bila jenis/nama tidak lolos whitelist. */
    public function path(string $kind, string $name): ?string
    {
        return match ($kind) {
            'model' => preg_match(DefinitionSchema::NAME_RE, $name) === 1 ? $this->defDir . "/models/$name.json" : null,
            'page' => preg_match(DefinitionSchema::PAGE_RE, $name) === 1 ? $this->defDir . "/pages/$name.json" : null,
            'auth' => $this->defDir . '/auth.json',
            default => null,
        };
    }

    /** @return list<string> nama definisi yang ada (lolos whitelist, berkas biasa) */
    public function names(string $kind): array
    {
        if ($kind !== 'model' && $kind !== 'page') {
            return [];
        }
        $dir = $this->defDir . '/' . ($kind === 'model' ? 'models' : 'pages');
        $out = [];
        foreach (is_dir($dir) ? (scandir($dir) ?: []) : [] as $f) {
            if (!str_ends_with($f, '.json')) {
                continue;
            }
            $n = substr($f, 0, -5);
            $p = $this->path($kind, $n);
            if ($p !== null && is_file($p) && !is_link($p)) {
                $out[] = $n;
            }
        }
        sort($out);
        return $out;
    }

    public function hashOf(string $file): string
    {
        $raw = is_file($file) && !is_link($file) ? @file_get_contents($file) : false;
        return is_string($raw) ? hash('sha256', $raw) : '';
    }

    /**
     * @return array{0:?array<mixed>,1:string} [data atau null bila tak ada/rusak, hash isi mentah]
     */
    public function read(string $file): array
    {
        $raw = is_file($file) && !is_link($file) && (int) filesize($file) <= self::MAX_BYTES ? @file_get_contents($file) : false;
        if (!is_string($raw)) {
            return [null, ''];
        }
        try {
            $d = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return [null, hash('sha256', $raw)];
        }
        return [is_array($d) ? $d : null, hash('sha256', $raw)];
    }

    /**
     * Rapikan input UI menjadi bentuk kanonik (urutan key stabil, BLD-03) lalu validasi bentuk per jenis.
     *
     * @param array<mixed> $data
     * @return array{0:?array<mixed>,1:?string} [data, pesan error]
     */
    public function normalize(string $kind, array $data, ?string $name = null): array
    {
        if (!self::shapeOk($data, 0)) {
            return [null, 'Data terlalu dalam atau berisi tipe yang tidak didukung.'];
        }
        $data = self::clean($data);
        $out = match ($kind) {
            'model' => self::model($data),
            'page' => self::page($data),
            'auth' => self::auth($data),
            default => null,
        };
        if ($out === null) {
            return [null, 'Jenis definisi tidak dikenal.'];
        }
        $label = $kind === 'auth' ? 'auth' : (string) ($name ?? ($kind === 'model' ? ($out['model'] ?? '') : ($out['page'] ?? '')));
        $schema = new DefinitionSchema();
        $ok = match ($kind) {
            'model' => $schema->model($label, $out),
            'page' => $schema->page($label, $out),
            default => $schema->auth($out),
        };
        if ($ok === null || $schema->errors() !== []) {
            $msgs = array_map(static fn($e): string => $e->src . ': ' . $e->msg, array_slice($schema->errors(), 0, 5));
            return [null, implode(' | ', $msgs) ?: 'Definisi tidak valid.'];
        }
        return [$out, null];
    }

    /**
     * @param array<mixed> $data hasil normalize()
     * @return string hash baru berkas
     * @throws WriteConflict|WriteRejected
     */
    public function write(string $file, array $data, string $expectedHash): string
    {
        $data = self::objectify($data);
        try {
            $json = Json::pretty($data);
        } catch (JsonException) {
            throw new WriteRejected('Data tidak dapat dikodekan sebagai JSON', [], 422);
        }
        if (strlen($json) > self::MAX_BYTES) {
            throw new WriteRejected('Definisi melebihi batas ukuran', [], 413);
        }
        return $this->commit($file, $json, $expectedHash);
    }

    /** Hapus definisi (tetap divalidasi: sisa definisi harus tetap bisa di-compile). */
    public function delete(string $file, string $expectedHash): void
    {
        $this->commit($file, null, $expectedHash);
    }

    // ---------- inti ----------

    private function commit(string $file, ?string $bytes, string $expectedHash): string
    {
        [$base, $rel] = $this->locate($file);
        $lock = @fopen($base . '/.builder.lock', 'c');
        if ($lock === false) {
            throw new WriteRejected('Kunci penulisan tidak dapat dibuka', [], 500);
        }
        try {
            $deadline = microtime(true) + 5;
            while (!flock($lock, LOCK_EX | LOCK_NB)) {
                if (microtime(true) > $deadline) {
                    throw new WriteRejected('Penulisan lain sedang berjalan', [], 409);
                }
                usleep(50000);
            }
            $target = $base . '/' . $rel;
            $old = is_file($target) ? @file_get_contents($target) : null;
            $old = is_string($old) ? $old : null;
            $diskHash = $old === null ? '' : hash('sha256', $old);
            if ($diskHash !== $expectedHash) {
                throw new WriteConflict($this->read($target)[0], $diskHash);
            }
            if ($bytes === null && $old === null) {
                throw new WriteRejected('Berkas tidak ada', [], 404);
            }
            $this->dryRun($base, $rel, $bytes);
            if ($bytes === null) {
                if (!@unlink($target)) {
                    throw new WriteRejected('Berkas tidak dapat dihapus', [], 500);
                }
            } else {
                $this->atomicWrite($target, $bytes);
            }
            $res = $this->compiler->build($base, $this->dialect);
            if (!$res->ok()) {
                // Seharusnya tak terjadi setelah dry-run; pulihkan berkas lama agar disk = versi aktif.
                $this->restore($target, $old);
                $this->logger?->error('Kompilasi ulang builder gagal setelah dry-run lolos');
                throw new WriteRejected('Kompilasi ulang gagal; perubahan dibatalkan', array_map(
                    static fn($e): string => $e->src . ': ' . $e->msg,
                    array_slice($res->errors, 0, 5),
                ));
            }
            return $bytes === null ? '' : hash('sha256', $bytes);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /**
     * Kembalikan berkas ke isi sebelumnya (dipakai controller bila migrasi gagal setelah tulis). Memicu build ulang.
     *
     * @throws WriteRejected
     */
    public function rollback(string $file, ?string $oldBytes): void
    {
        [$base, $rel] = $this->locate($file);
        $this->restore($base . '/' . $rel, $oldBytes);
        $this->compiler->build($base, $this->dialect);
    }

    /** Isi mentah saat ini (untuk rollback), atau null bila belum ada. */
    public function raw(string $file): ?string
    {
        [$base, $rel] = $this->locate($file);
        $raw = is_file($base . '/' . $rel) ? @file_get_contents($base . '/' . $rel) : false;
        return is_string($raw) ? $raw : null;
    }

    private function restore(string $target, ?string $old): void
    {
        if ($old === null) {
            @unlink($target);
        } else {
            $this->atomicWrite($target, $old);
        }
    }

    /**
     * Pastikan $file adalah berkas whitelist di dalam definitions/ (BLD-09). Mengembalikan [base realpath, relatif].
     *
     * @return array{0:string,1:string}
     */
    private function locate(string $file): array
    {
        $base = realpath($this->defDir);
        if ($base === false || !is_dir($base)) {
            throw new WriteRejected('Folder definisi tidak tersedia', [], 500);
        }
        if (str_contains($file, "\0")) {
            throw new WriteRejected('Builder hanya boleh menulis JSON whitelist di definitions/', [], 400);
        }
        $name = basename($file);
        $parent = dirname($file);
        $bad = static fn(): WriteRejected => new WriteRejected('Builder hanya boleh menulis JSON whitelist di definitions/', [], 400);
        if (!str_ends_with($name, '.json')) {
            throw $bad();
        }
        if ($name === 'auth.json') {
            $parentReal = realpath($parent);
            if ($parentReal !== $base) {
                throw $bad();
            }
            $rel = 'auth.json';
        } else {
            $sub = basename($parent);
            $rx = $sub === 'models' ? DefinitionSchema::NAME_RE : ($sub === 'pages' ? DefinitionSchema::PAGE_RE : null);
            if ($rx === null || preg_match($rx, substr($name, 0, -5)) !== 1 || realpath(dirname($parent)) !== $base) {
                throw $bad();
            }
            $dir = $base . '/' . $sub;
            if (is_link($dir)) {
                throw $bad();
            }
            if (!is_dir($dir) && !@mkdir($dir, 0750) && !is_dir($dir)) {
                throw new WriteRejected('Folder definisi tidak dapat dibuat', [], 500);
            }
            $rel = "$sub/$name";
        }
        if (is_link($base . '/' . $rel) || (file_exists($base . '/' . $rel) && !is_file($base . '/' . $rel))) {
            throw $bad();
        }
        return [$base, $rel];
    }

    /** Compile salinan sementara (seluruh definisi dengan perubahan ini) memakai Compiler M8; error = tolak. */
    private function dryRun(string $base, string $rel, ?string $bytes): void
    {
        $tmp = sys_get_temp_dir() . '/bfb_' . bin2hex(random_bytes(8));
        try {
            if (!@mkdir($tmp . '/defs/models', 0700, true) || !@mkdir($tmp . '/defs/pages', 0700, true)) {
                throw new WriteRejected('Ruang kerja sementara tidak tersedia', [], 500);
            }
            $files = [];
            foreach (['models', 'pages'] as $k) {
                foreach (is_dir("$base/$k") ? (scandir("$base/$k") ?: []) : [] as $f) {
                    if (str_ends_with($f, '.json')) {
                        $files["$k/$f"] = "$base/$k/$f";
                    }
                }
            }
            $files['auth.json'] = "$base/auth.json";
            foreach ($files as $r => $path) {
                if ($r === $rel || is_link($path) || !is_file($path) || (int) filesize($path) > 1048576) {
                    continue;
                }
                $raw = @file_get_contents($path);
                if (is_string($raw)) {
                    file_put_contents($tmp . '/defs/' . $r, $raw);
                }
            }
            if ($bytes !== null) {
                file_put_contents($tmp . '/defs/' . $rel, $bytes);
            }
            $res = (new Compiler(new CacheStore($tmp . '/cache'), $this->extDir))->build($tmp . '/defs', $this->dialect);
            if (!$res->ok()) {
                throw new WriteRejected('Definisi tidak valid', array_map(
                    static fn($e): string => $e->src . ': ' . $e->msg,
                    array_slice($res->errors, 0, 10),
                ));
            }
        } finally {
            CacheStore::rmTree($tmp);
        }
    }

    private function atomicWrite(string $target, string $bytes): void
    {
        $tmp = dirname($target) . '/.' . basename($target) . '.' . bin2hex(random_bytes(6)) . '.tmp';
        if (@file_put_contents($tmp, $bytes, LOCK_EX) !== strlen($bytes)) {
            @unlink($tmp);
            throw new WriteRejected('Berkas tidak dapat ditulis', [], 500);
        }
        @chmod($tmp, 0640);
        if (!@rename($tmp, $target)) {
            @unlink($tmp);
            throw new WriteRejected('Berkas tidak dapat diganti', [], 500);
        }
    }

    // ---------- normalisasi ----------

    private static function shapeOk(mixed $v, int $depth): bool
    {
        if ($depth > self::MAX_DEPTH) {
            return false;
        }
        if (is_array($v)) {
            if (count($v) > 500) {
                return false;
            }
            foreach ($v as $x) {
                if (!self::shapeOk($x, $depth + 1)) {
                    return false;
                }
            }
            return true;
        }
        return $v === null || is_scalar($v) && (!is_float($v) || is_finite($v)) && (!is_string($v) || strlen($v) <= 4096);
    }

    /** Buang nilai kosong/null pada objek (bukan pada daftar). */
    private static function clean(mixed $v): mixed
    {
        if (!is_array($v)) {
            return $v;
        }
        $list = array_is_list($v);
        $out = [];
        foreach ($v as $k => $x) {
            $x = self::clean($x);
            if (!$list && ($x === null || $x === '')) {
                continue;
            }
            $out[$k] = $x;
        }
        return $out;
    }

    /**
     * @param array<mixed> $a
     * @param list<string> $order
     * @return array<mixed>
     */
    private static function ordered(array $a, array $order): array
    {
        $out = [];
        foreach ($order as $k) {
            if (array_key_exists($k, $a)) {
                $out[$k] = $a[$k];
            }
        }
        $rest = array_diff_key($a, $out);
        ksort($rest);
        return $out + $rest;
    }

    /**
     * @param array<mixed> $d
     * @return array<mixed>
     */
    private static function model(array $d): array
    {
        $fields = [];
        if (is_array($d['fields'] ?? null)) {
            foreach ($d['fields'] as $n => $f) {
                $fields[$n] = is_array($f) ? self::field($f) : $f;
            }
        }
        $d['fields'] = $fields;
        if (is_array($d['hooks'] ?? null)) {
            ksort($d['hooks']);
        }
        if (is_array($d['access'] ?? null)) {
            $d['access'] = self::ordered($d['access'], self::ACCESS_KEYS);
        }
        return self::ordered($d, self::MODEL_KEYS);
    }

    /**
     * @param array<mixed> $f
     * @return array<mixed>
     */
    private static function field(array $f): array
    {
        if (is_array($f['upload'] ?? null)) {
            $f['upload'] = self::ordered($f['upload'], ['mimes', 'maxBytes']);
        }
        return self::ordered($f, self::FIELD_KEYS);
    }

    /**
     * @param array<mixed> $d
     * @return array<mixed>
     */
    private static function page(array $d): array
    {
        if (is_array($d['layout'] ?? null) && array_is_list($d['layout'])) {
            $d['layout'] = array_map(static function (mixed $c): mixed {
                if (!is_array($c)) {
                    return $c;
                }
                if (is_array($c['source'] ?? null)) {
                    $c['source'] = self::ordered($c['source'], self::SOURCE_KEYS);
                }
                return self::ordered($c, self::COMPONENT_KEYS);
            }, $d['layout']);
        }
        return self::ordered($d, self::PAGE_KEYS);
    }

    /**
     * @param array<mixed> $d
     * @return array<mixed>
     */
    private static function auth(array $d): array
    {
        if (is_array($d['sso'] ?? null)) {
            $d['sso'] = self::ordered($d['sso'], self::SSO_KEYS);
        }
        return self::ordered($d, self::AUTH_KEYS);
    }

    /**
     * @param array<mixed> $d
     * @return array<mixed>
     */
    private static function objectify(array $d): array
    {
        if (array_key_exists('fields', $d) && $d['fields'] === []) {
            $d['fields'] = new \stdClass();
        }
        return $d;
    }
}
