<?php

declare(strict_types=1);

namespace bFramework\Upload;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Logger;
use bFramework\Core\RateLimiter;
use bFramework\Runtime\FileRefs;
use bFramework\Runtime\Query;
use bFramework\Runtime\Where;

/**
 * SEC-FILE-01/02. Simpan upload di luar docroot dengan nama acak (CSPRNG) tanpa ekstensi; tipe ditentukan
 * finfo atas isi (bukan Content-Type/ekstensi klien); whitelist dari UploadPolicy; gambar dicek polyglot lalu
 * di-encode ulang dengan GD (tanpa GD gambar ditolak, fail-closed). Nama asli hanya metadata.
 */
final class UploadService implements FileRefs
{
    public const ID_RE = '/^[a-f0-9]{32}$/D';
    private const IMAGES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    private const MAX_PIXELS = 10000000; // ~40 MB bitmap GD, aman di memory_limit 128 MB
    private const IMAGE_MAX_BYTES = 33554432;
    private const SCAN_CHUNK = 1048576;

    private readonly string $dir;
    private readonly int $maxFiles;
    private readonly int $maxTotalBytes;
    private readonly int $rateMax;
    private readonly int $rateWindow;
    /** @var \Closure(string):bool */
    private readonly \Closure $isUploaded;
    /** @var \Closure(string,string):bool */
    private readonly \Closure $mover;

    /**
     * @param array<string,mixed> $opts maxFilesPerOwner(200), maxBytesPerOwner(200 MB), rateMax(30), rateWindow(60 dtk)
     * @param string|null $docroot bila diberikan, $dir tidak boleh berada di dalamnya
     * @param (\Closure(string):bool)|null $isUploaded hanya untuk tes; default is_uploaded_file
     * @param (\Closure(string,string):bool)|null $mover hanya untuk tes; default move_uploaded_file
     */
    public function __construct(
        private readonly Query $query,
        string $dir,
        array $opts = [],
        ?string $docroot = null,
        private readonly ?RateLimiter $limiter = null,
        private readonly ?Logger $logger = null,
        ?\Closure $isUploaded = null,
        ?\Closure $mover = null,
    ) {
        if ($dir === '' || str_contains($dir, "\0")) {
            throw new \InvalidArgumentException('Direktori upload tidak valid');
        }
        $this->dir = rtrim($dir, '/\\');
        self::ensureDir($this->dir);
        if ($docroot !== null) {
            $d = realpath($this->dir);
            $r = realpath($docroot);
            if ($d === false || ($r !== false && ($d === $r || str_starts_with($d . '/', $r . '/')))) {
                throw new \InvalidArgumentException('Direktori upload tidak boleh di dalam docroot');
            }
        }
        $this->writeGuard();
        $int = static fn(mixed $v, int $d): int => is_int($v) && $v > 0 ? $v : $d;
        $this->maxFiles = $int($opts['maxFilesPerOwner'] ?? null, 200);
        $this->maxTotalBytes = $int($opts['maxBytesPerOwner'] ?? null, 209715200);
        $this->rateMax = $int($opts['rateMax'] ?? null, 30);
        $this->rateWindow = $int($opts['rateWindow'] ?? null, 60);
        $this->isUploaded = $isUploaded ?? static fn(string $f): bool => is_uploaded_file($f);
        $this->mover = $mover ?? static fn(string $a, string $b): bool => move_uploaded_file($a, $b);
    }

    /**
     * @param bool $allowOwnerless hanya pemanggil internal tepercaya; ownerId null tanpa flag ini ditolak
     */
    public function store(UploadedFile $file, UploadPolicy $policy, ?int $ownerId = null, ?string $model = null, ?int $refId = null, bool $allowOwnerless = false): StoredFile
    {
        if ($ownerId === null && !$allowOwnerless) {
            throw new UploadRejected('Unggahan memerlukan pemilik', 'no_owner', 403);
        }
        $this->checkError($file->error);
        $this->hitRate($ownerId);
        $tmp = $file->tmpName;
        if ($tmp === '' || str_contains($tmp, "\0") || !($this->isUploaded)($tmp)) {
            throw new UploadRejected('Berkas upload tidak valid', 'not_uploaded', 400);
        }
        $size = @filesize($tmp);
        if ($size === false || $size < 1) {
            throw new UploadRejected('Berkas kosong atau tidak terbaca', 'empty');
        }
        if ($size > $policy->maxBytes) {
            throw new UploadRejected('Ukuran berkas melebihi batas', 'too_large', 413);
        }
        $fi = new \finfo(FILEINFO_MIME_TYPE);
        $mime = $fi->file($tmp);
        if (!is_string($mime) || !in_array($mime, $policy->mimes, true)) {
            throw new UploadRejected('Tipe berkas tidak diizinkan', 'mime');
        }
        $isImage = str_starts_with($mime, 'image/');
        $data = null;
        if ($isImage) {
            if ($size > self::IMAGE_MAX_BYTES) {
                throw new UploadRejected('Ukuran berkas melebihi batas', 'too_large', 413);
            }
            $data = file_get_contents($tmp);
            if ($data === false || strlen($data) !== $size) {
                throw new UploadRejected('Berkas tidak terbaca', 'read');
            }
            $this->scan(true, $data);
        } else {
            $this->scanFile($tmp); // dialirkan per potongan, tanpa memuat seluruh berkas
        }

        $fid = bin2hex(random_bytes(16));
        $path = $this->path($fid);
        if ($data !== null) {
            $data = $this->reencode($mime, $data);
            if (strlen($data) > $policy->maxBytes) {
                throw new UploadRejected('Ukuran berkas melebihi batas', 'too_large', 413);
            }
            if (file_put_contents($path, $data, LOCK_EX) === false) {
                throw new UploadRejected('Penyimpanan gagal', 'io', 500);
            }
            $size = strlen($data);
        } elseif (!($this->mover)($tmp, $path)) {
            throw new UploadRejected('Penyimpanan gagal', 'io', 500);
        }
        @chmod($path, 0600);
        // Cek kuota + insert metadata atomik di bawah flock per owner (request paralel tak bisa lolos kuota).
        $lock = null;
        try {
            $lock = $this->lock($ownerId);
            $this->checkQuota($ownerId);
            $this->query->insert(FilesTable::NAME, [
                'fid' => $fid, 'mime' => $mime, 'size' => $size, 'orig_name' => self::cleanName($file->name),
                'owner_id' => $ownerId, 'model' => $model, 'ref_id' => $refId, 'created_at' => time(),
            ]);
        } catch (UploadRejected $e) {
            @unlink($path);
            throw $e;
        } catch (\Throwable $e) {
            @unlink($path);
            $this->logger?->error('upload: simpan metadata gagal', ['ex' => $e::class]);
            throw new UploadRejected('Penyimpanan gagal', 'db', 500);
        } finally {
            if ($lock !== null) {
                $this->unlock($lock);
            }
        }
        $this->logger?->info('upload: tersimpan', ['mime' => $mime, 'size' => $size]);
        return new StoredFile($fid, $mime, $size);
    }

    /** @return array<string,mixed>|null metadata; null bila id tidak valid / tidak ada */
    public function find(string $id): ?array
    {
        if (preg_match(self::ID_RE, $id) !== 1) {
            return null;
        }
        $rows = $this->query->select(FilesTable::NAME, ['id', 'fid', 'mime', 'size', 'orig_name', 'owner_id', 'model', 'ref_id'], new Where([['fid', '=', $id]]), null, 1, 0);
        return $rows[0] ?? null;
    }

    /** Path fisik; id wajib 32 hex (cegah path traversal). */
    public function path(string $id): string
    {
        if (preg_match(self::ID_RE, $id) !== 1) {
            throw new \InvalidArgumentException('Id berkas tidak valid');
        }
        return $this->dir . '/' . $id;
    }

    /** @return array{owner_id:?int, model:?string, ref_id:?int, mime:string, size:int}|null */
    public function meta(string $fid): ?array
    {
        $m = $this->find($fid);
        if ($m === null) {
            return null;
        }
        $int = static fn(mixed $v): ?int => is_int($v) ? $v : (is_string($v) && ctype_digit($v) ? (int) $v : null);
        return [
            'owner_id' => $int($m['owner_id'] ?? null),
            'model' => is_string($m['model'] ?? null) ? $m['model'] : null,
            'ref_id' => $int($m['ref_id'] ?? null),
            'mime' => (string) ($m['mime'] ?? ''),
            'size' => $int($m['size'] ?? null) ?? 0,
        ];
    }

    /** UPDATE bersyarat atomik: hanya berhasil bila fid milik $userId dan belum ter-attach. */
    public function claim(string $fid, int $userId, string $model, int $refId): bool
    {
        if (preg_match(self::ID_RE, $fid) !== 1 || $model === '' || $refId < 1) {
            return false;
        }
        $n = $this->query->update(
            FilesTable::NAME,
            ['model' => $model, 'ref_id' => $refId],
            new Where([['fid', '=', $fid], ['owner_id', '=', $userId], ['model', 'null']]),
        );
        return $n === 1;
    }

    /** Alias claim() dengan cek kepemilikan wajib (pemanggil internal tidak lagi bisa meng-attach file orang lain). */
    public function attach(string $id, string $model, int $refId, int $userId): bool
    {
        return $this->claim($id, $userId, $model, $refId);
    }

    public function release(string $fid): void
    {
        $this->delete($fid);
    }

    /** Hapus file yang belum ter-attach dan lebih tua dari $maxAge detik (orphan upload tanpa form disubmit). */
    public function purgeOrphans(int $maxAge = 86400): int
    {
        $n = 0;
        for ($i = 0; $i < 1000; $i++) {
            $rows = $this->query->select(FilesTable::NAME, ['fid'], new Where([['model', 'null'], ['created_at', '<', time() - max(60, $maxAge)]]), null, 200, 0);
            if ($rows === []) {
                break;
            }
            foreach ($rows as $r) {
                $this->delete((string) $r['fid']);
                $n++;
            }
        }
        return $n;
    }

    public function delete(string $id): void
    {
        if (preg_match(self::ID_RE, $id) !== 1) {
            return;
        }
        $this->query->delete(FilesTable::NAME, new Where([['fid', '=', $id]]));
        $p = $this->path($id);
        if (is_file($p)) {
            @unlink($p);
        }
    }

    /** Dipanggil saat baris yang mereferensikan file dihapus; berulang sampai habis. */
    public function deleteForRef(string $model, int $refId): int
    {
        $total = 0;
        for ($i = 0; $i < 100000; $i++) {
            $rows = $this->query->select(FilesTable::NAME, ['fid'], new Where([['model', '=', $model], ['ref_id', '=', $refId]]), null, 500, 0);
            if ($rows === []) {
                break;
            }
            $fids = array_values(array_filter(array_map(static fn(array $r): string => (string) $r['fid'], $rows), static fn(string $f): bool => preg_match(self::ID_RE, $f) === 1));
            if ($fids === []) {
                break; // baris tak valid tidak boleh membuat loop tak berujung
            }
            $this->query->delete(FilesTable::NAME, new Where([['fid', 'in', $fids]]));
            foreach ($fids as $f) {
                @unlink($this->path($f));
            }
            $total += count($fids);
        }
        return $total;
    }

    private function checkError(int $err): void
    {
        match ($err) {
            UPLOAD_ERR_OK => null,
            UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => throw new UploadRejected('Ukuran berkas melebihi batas', 'too_large', 413),
            UPLOAD_ERR_NO_FILE => throw new UploadRejected('Tidak ada berkas diunggah', 'no_file', 400),
            default => throw new UploadRejected('Unggah gagal', 'upload_error', 400),
        };
    }

    /** Polyglot gambar: tag PHP, tag script/HTML. Tag `<?=` terlalu sering muncul acak di data terkompresi; re-encode GD menetralkan sisanya. */
    private function scan(bool $image, string $data): void
    {
        $bad = preg_match($image ? '/<\?php/i' : '/<\?(?:php|=)/i', $data) === 1
            || ($image && preg_match('/<script|<svg|<html|javascript:|<!doctype\s+html/i', $data) === 1);
        if ($bad) {
            throw new UploadRejected('Isi berkas mencurigakan', 'polyglot');
        }
    }

    /** Non-gambar: pindai tag PHP per potongan 1 MiB dengan tumpang tindih agar tag di batas potongan tertangkap. */
    private function scanFile(string $tmp): void
    {
        $fh = @fopen($tmp, 'rb');
        if ($fh === false) {
            throw new UploadRejected('Berkas tidak terbaca', 'read');
        }
        try {
            $tail = '';
            while (!feof($fh)) {
                $chunk = fread($fh, self::SCAN_CHUNK);
                if ($chunk === false) {
                    throw new UploadRejected('Berkas tidak terbaca', 'read');
                }
                if ($chunk === '') {
                    break;
                }
                $buf = $tail . $chunk;
                $this->scan(false, $buf);
                $tail = substr($buf, -8);
            }
        } finally {
            fclose($fh);
        }
    }

    private function reencode(string $mime, string $data): string
    {
        if (!in_array($mime, self::IMAGES, true) || !function_exists('imagecreatefromstring')) {
            throw new UploadRejected('Tipe gambar tidak dapat diproses', 'image_unsupported');
        }
        $info = @getimagesizefromstring($data);
        if ($info === false || $info[0] < 1 || $info[1] < 1 || $info[0] * $info[1] > self::MAX_PIXELS) {
            throw new UploadRejected('Gambar tidak valid atau terlalu besar', 'image_invalid');
        }
        $im = @imagecreatefromstring($data);
        if ($im === false) {
            throw new UploadRejected('Gambar tidak valid', 'image_invalid');
        }
        ob_start();
        $ok = match ($mime) {
            'image/jpeg' => imagejpeg($im, null, 90),
            'image/png' => (function () use ($im): bool {
                imagealphablending($im, false);
                imagesavealpha($im, true);
                return imagepng($im);
            })(),
            'image/gif' => imagegif($im),
            default => function_exists('imagewebp') ? imagewebp($im, null, 90) : false,
        };
        $out = (string) ob_get_clean();
        if (!$ok || $out === '') {
            throw new UploadRejected('Gambar tidak dapat diproses', 'image_invalid');
        }
        return $out;
    }

    private function hitRate(?int $ownerId): void
    {
        $key = 'upload:' . ($ownerId ?? 'system');
        if ($this->limiter !== null && !$this->limiter->hit($key, $this->rateMax, $this->rateWindow)) {
            throw new UploadRejected('Terlalu banyak unggahan, coba lagi nanti', 'rate', 429);
        }
    }

    /** Dipanggil di bawah flock owner. Owner null (internal) memakai ember kuota "tanpa owner". */
    private function checkQuota(?int $ownerId): void
    {
        $w = new Where([$ownerId === null ? ['owner_id', 'null'] : ['owner_id', '=', $ownerId]]);
        $n = $this->query->count(FilesTable::NAME, $w);
        $sum = (int) ($this->query->aggregate(FilesTable::NAME, 'sum', 'size', $w) ?? 0);
        if ($n >= $this->maxFiles || $sum >= $this->maxTotalBytes) {
            throw new UploadRejected('Kuota penyimpanan penuh', 'quota', 413);
        }
    }

    /** @return resource */
    private function lock(?int $ownerId)
    {
        $d = $this->dir . '/.lock';
        if (!is_dir($d) && !@mkdir($d, 0700, true) && !is_dir($d)) {
            throw new UploadRejected('Penyimpanan gagal', 'io', 500);
        }
        $fh = @fopen($d . '/' . ($ownerId === null ? 'system' : (string) $ownerId), 'c');
        if ($fh === false || !flock($fh, LOCK_EX)) {
            throw new UploadRejected('Penyimpanan gagal', 'io', 500);
        }
        return $fh;
    }

    /** @param resource $fh */
    private function unlock($fh): void
    {
        flock($fh, LOCK_UN);
        fclose($fh);
    }

    /** Nama asli: hanya metadata; buang kontrol/CRLF/null/pemisah path, batasi panjang. Di-escape saat ditampilkan. */
    public static function cleanName(string $name): string
    {
        if (preg_match('//u', $name) !== 1) {
            $name = '';
        }
        $name = preg_replace('/[\x00-\x1F\x7F\\\\\/]+/u', '', $name) ?? '';
        $name = trim($name);
        return mb_substr($name, 0, 200);
    }

    private static function ensureDir(string $d): void
    {
        if (!is_dir($d) && !@mkdir($d, 0700, true) && !is_dir($d)) {
            throw new \RuntimeException('Direktori upload tidak dapat dibuat');
        }
        @chmod($d, 0700);
    }

    /** Cadangan bila direktori ternyata terjangkau web: tolak akses dan matikan PHP. */
    private function writeGuard(): void
    {
        $f = $this->dir . '/.htaccess';
        if (!is_file($f)) {
            $rules = "Require all denied\n<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n"
                . "<IfModule mod_php.c>\nphp_flag engine off\n</IfModule>\nRemoveHandler .php .phtml .phar\nOptions -ExecCGI\n";
            @file_put_contents($f, $rules);
            @chmod($f, 0640);
        }
    }
}
