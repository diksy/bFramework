<?php

declare(strict_types=1);

namespace bFramework\Update;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Logger;
use Closure;
use ZipArchive;

/**
 * Paket update = zip { manifest.json, manifest.sig, <file sesuai manifest> } (SEC-UPD-01).
 *
 * verify(): TANPA menyentuh target. Urutan: kunci valid (placeholder = tolak) -> batas ukuran zip -> daftar entri
 * (nama aman, bukan symlink/direktori, tanpa duplikat huruf besar/kecil, total ukuran/rasio) -> tanda tangan
 * Ed25519 atas byte manifest.json -> manifest ketat -> entri zip == manifest (tepat) -> sha256 tiap file
 * (hash_equals) -> versi > terpasang (anti-downgrade/replay) dan min_version <= terpasang.
 *
 * apply(): salin zip ke storage privat lalu verifikasi ulang SALINAN itu (tanpa TOCTOU), flock (satu update),
 * cadangan, staging, swap per file (rename atomik), cek hash pasca-apply, migrasi (UpdateMigrations), simpan versi,
 * rebuild. Kegagalan mana pun sebelum selesai = rollback file dari cadangan. Detail teknis hanya di log.
 */
final class UpdatePackage
{
    public const MAX_ZIP = 52428800;
    public const MAX_TOTAL = 52428800;
    public const MAX_FILE = 10485760;
    private const SIG_FILE = 'manifest.sig';
    private const MANIFEST_JSON = 'manifest.json';
    private const MAINTENANCE = 'maintenance';

    private readonly string $root;
    private readonly string $storage;

    /**
     * @param ?string $publicKey 32 byte mentah; null/tidak valid = fail-closed (semua paket ditolak)
     * @param ?Closure(string):void $opcache dipanggil dengan jalur file yang diganti (default: opcache_invalidate)
     * @param ?Closure(string,string):void $onStep seam tes: ($tahap, $jalur) sebelum tiap swap; boleh melempar
     */
    public function __construct(
        string $root,
        private readonly ?string $publicKey,
        private readonly ?Logger $logger = null,
        private readonly ?Closure $opcache = null,
        private readonly ?Closure $onStep = null,
    ) {
        $this->root = rtrim($root, '/');
        $this->storage = $this->root . '/app/storage';
    }

    public function installedVersion(): string
    {
        return CoreVersion::installed($this->storage);
    }

    public function keyReady(): bool
    {
        return $this->publicKey !== null && strlen($this->publicKey) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES;
    }

    /** @throws UpdateException */
    public function verify(string $zipPath): UpdateManifest
    {
        [$manifest, $zip] = $this->open($zipPath);
        $zip->close();
        return $manifest;
    }

    /**
     * @param ?Closure():void $rebuild Compiler rebuild + purge _pc; gagal = peringatan
     * @throws UpdateException
     */
    public function apply(string $zipPath, ?UpdateMigrations $migrations = null, ?Closure $rebuild = null): UpdateResult
    {
        if (!$this->keyReady()) {
            throw new UpdateException('kunci_belum_ditanam');
        }
        if (!is_file($this->storage . '/installed.lock')) {
            throw new UpdateException('belum_terpasang');
        }
        $dir = $this->storage . '/update';
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new UpdateException('storage');
        }
        $lock = @fopen($dir . '/update.lock', 'c');
        if ($lock === false || !flock($lock, LOCK_EX | LOCK_NB)) {
            if (is_resource($lock)) {
                fclose($lock);
            }
            throw new UpdateException('sedang_berjalan');
        }
        $work = $dir . '/work-' . bin2hex(random_bytes(8));
        $maintenance = false;
        $done = [];
        $createdDirs = [];
        try {
            if (!@mkdir($work, 0700) || !@copy($zipPath, $work . '/pkg.zip')) {
                throw new UpdateException('salin_paket');
            }
            @chmod($work . '/pkg.zip', 0600);
            [$manifest, $zip] = $this->open($work . '/pkg.zip');
            try {
                if ($manifest->migrations !== [] && $migrations === null) {
                    throw new UpdateException('migrasi_tak_tersedia');
                }
                $targets = array_merge(array_keys($manifest->files), $manifest->delete);
                foreach ($targets as $rel) {
                    $this->assertTargetSafe($rel);
                }
                // Staging (isi diverifikasi ulang saat dibaca) + cadangan semua yang akan berubah.
                foreach ($manifest->files as $rel => $hash) {
                    $data = $this->read($zip, $rel);
                    if ($data === null || !hash_equals($hash, hash('sha256', $data))) {
                        throw new UpdateException('hash_salah');
                    }
                    $this->put($work . '/stage/' . $rel, $data, 0644);
                }
                foreach ($targets as $rel) {
                    if (is_file($this->root . '/' . $rel)) {
                        $this->put($work . '/backup/' . $rel, (string) file_get_contents($this->root . '/' . $rel), 0600);
                    }
                }
                if ($migrations !== null) {
                    $migrations->ensureTable();
                }
                $this->setMaintenance(true);
                $maintenance = true;
                foreach ($manifest->files as $rel => $_) {
                    $this->step('swap', $rel);
                    $done[] = $rel;
                    $this->swapIn($work . '/stage/' . $rel, $rel, $createdDirs);
                    $this->invalidate($rel);
                }
                foreach ($manifest->delete as $rel) {
                    $this->step('delete', $rel);
                    if (is_file($this->root . '/' . $rel)) {
                        $done[] = $rel;
                        if (!@unlink($this->root . '/' . $rel)) {
                            throw new UpdateException('hapus_gagal');
                        }
                    }
                }
                $this->postCheck($manifest);
                $ran = $migrations !== null ? $migrations->run($manifest->migrations) : [];
                $this->writeVersion($manifest->version);
            } catch (\Throwable $e) {
                $this->rollback($done, $work . '/backup', $createdDirs);
                $this->resetOpcache();
                $this->logger?->error('Update gagal; file dipulihkan', ['ex' => $e::class, 'reason' => $e instanceof UpdateException ? $e->reason : 'internal']);
                throw $e instanceof UpdateException ? $e : new UpdateException('gagal_diterapkan');
            } finally {
                $zip->close();
            }
            $this->resetOpcache();
            $warnings = [];
            if ($rebuild !== null) {
                try {
                    $rebuild();
                } catch (\Throwable $e) {
                    $this->logger?->error('Rebuild/purge setelah update gagal', ['ex' => $e::class]);
                    $warnings[] = 'Rebuild cache atau pembuangan cache halaman gagal; jalankan ulang build definisi dan kosongkan public_html/_pc.';
                }
            }
            $this->logger?->info('Update diterapkan', ['version' => $manifest->version, 'files' => count($manifest->files)]);
            return new UpdateResult($manifest->version, count($manifest->files), $ran, $warnings);
        } finally {
            if ($maintenance) {
                $this->setMaintenance(false);
            }
            $this->removeTree($work);
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    // ---------- verifikasi ----------

    /** @return array{0:UpdateManifest,1:ZipArchive} zip terbuka (pemanggil menutup) */
    private function open(string $zipPath): array
    {
        if (!$this->keyReady()) {
            throw new UpdateException('kunci_belum_ditanam');
        }
        $size = is_file($zipPath) && !is_link($zipPath) ? filesize($zipPath) : false;
        if ($size === false || $size <= 0 || $size > self::MAX_ZIP) {
            throw new UpdateException('ukuran_zip');
        }
        $zip = new ZipArchive();
        if ($zip->open($zipPath, ZipArchive::RDONLY | ZipArchive::CHECKCONS) !== true) {
            throw new UpdateException('zip_rusak');
        }
        try {
            $names = $this->listEntries($zip);
            $sigRaw = $this->read($zip, self::SIG_FILE);
            $json = $this->read($zip, self::MANIFEST_JSON);
            if ($sigRaw === null || $json === null || strlen($sigRaw) > 128 || $json === '') {
                throw new UpdateException('tanpa_tanda_tangan');
            }
            $sig = base64_decode(trim($sigRaw), true);
            if ($sig === false || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES) {
                throw new UpdateException('tanda_tangan_format');
            }
            $pk = $this->publicKey;
            if ($pk === null || $pk === '' || !sodium_crypto_sign_verify_detached($sig, $json, $pk)) {
                throw new UpdateException('tanda_tangan_salah');
            }
            $m = UpdateManifest::parse($json);
            $expected = array_keys($m->files);
            $expected[] = self::SIG_FILE;
            $expected[] = self::MANIFEST_JSON;
            sort($expected);
            $have = $names;
            sort($have);
            if ($expected !== $have) {
                throw new UpdateException('isi_zip_beda_manifest'); // file ekstra atau hilang
            }
            foreach ($m->files as $rel => $hash) {
                $data = $this->read($zip, $rel);
                if ($data === null || !hash_equals($hash, hash('sha256', $data))) {
                    throw new UpdateException('hash_salah');
                }
            }
            $installed = $this->installedVersion();
            if (version_compare($m->version, $installed, '<=')) {
                throw new UpdateException('versi_tidak_baru'); // downgrade / replay / sama
            }
            if (version_compare($m->minVersion, $installed, '>')) {
                throw new UpdateException('versi_terpasang_terlalu_lama');
            }
            return [$m, $zip];
        } catch (\Throwable $e) {
            $zip->close();
            throw $e instanceof UpdateException ? $e : new UpdateException('verifikasi_gagal');
        }
    }

    /** @return list<string> nama entri tervalidasi */
    private function listEntries(ZipArchive $zip): array
    {
        if ($zip->numFiles < 3 || $zip->numFiles > UpdateManifest::MAX_FILES + 2) {
            throw new UpdateException('jumlah_entri');
        }
        $names = [];
        $seen = [];
        $total = 0;
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $st = $zip->statIndex($i);
            if ($st === false) {
                throw new UpdateException('zip_rusak');
            }
            $n = $st['name'];
            $ok = $n === self::SIG_FILE || $n === self::MANIFEST_JSON || UpdatePaths::allowed($n);
            if (!$ok || isset($seen[strtolower($n)])) {
                throw new UpdateException('nama_entri'); // ../, absolut, null byte, aneh, duplikat huruf
            }
            $seen[strtolower($n)] = true;
            $opsys = 0;
            $attr = 0;
            if ($zip->getExternalAttributesIndex($i, $opsys, $attr) && $opsys === ZipArchive::OPSYS_UNIX) {
                $type = ($attr >> 16) & 0170000;
                if ($type !== 0 && $type !== 0100000) {
                    throw new UpdateException('entri_bukan_file'); // symlink, perangkat, direktori
                }
            }
            $size = (int) $st['size'];
            $comp = max(1, (int) $st['comp_size']);
            if ($size > self::MAX_FILE || ($size > 1048576 && intdiv($size, $comp) > 200)) {
                throw new UpdateException('zip_bomb');
            }
            $total += $size;
            if ($total > self::MAX_TOTAL) {
                throw new UpdateException('zip_bomb');
            }
            $names[] = $n;
        }
        return $names;
    }

    /** Membaca entri dengan batas ukuran sebenarnya (bukan hanya yang dideklarasikan). */
    private function read(ZipArchive $zip, string $name): ?string
    {
        $st = $zip->statName($name);
        if ($st === false) {
            return null;
        }
        $size = (int) $st['size'];
        if ($size > self::MAX_FILE) {
            throw new UpdateException('zip_bomb');
        }
        $data = $zip->getFromName($name, $size + 1);
        if ($data === false || strlen($data) !== $size) {
            throw new UpdateException('zip_bomb');
        }
        return $data;
    }

    // ---------- penerapan ----------

    private function assertTargetSafe(string $rel): void
    {
        if (!UpdatePaths::allowed($rel)) {
            throw new UpdateException('jalur_terlarang');
        }
        $cur = $this->root;
        $parts = explode('/', $rel);
        $last = array_pop($parts);
        foreach ($parts as $p) {
            $cur .= '/' . $p;
            if (is_link($cur) || (file_exists($cur) && !is_dir($cur))) {
                throw new UpdateException('target_symlink');
            }
        }
        $t = $cur . '/' . $last;
        if (is_link($t) || is_dir($t)) {
            throw new UpdateException('target_symlink');
        }
    }

    private function put(string $path, string $data, int $mode): void
    {
        $d = dirname($path);
        if (!is_dir($d) && !@mkdir($d, 0700, true) && !is_dir($d)) {
            throw new UpdateException('tulis_staging');
        }
        if (file_put_contents($path, $data, LOCK_EX) !== strlen($data)) {
            throw new UpdateException('tulis_staging');
        }
        @chmod($path, $mode);
    }

    /** @param list<string> $createdDirs */
    private function swapIn(string $stage, string $rel, array &$createdDirs): void
    {
        $target = $this->root . '/' . $rel;
        $dir = dirname($target);
        if (!is_dir($dir)) {
            $missing = [];
            for ($d = $dir; !is_dir($d); $d = dirname($d)) {
                array_unshift($missing, $d);
            }
            if (!@mkdir($dir, 0755, true) && !is_dir($dir)) {
                throw new UpdateException('buat_folder');
            }
            foreach ($missing as $m) {
                $createdDirs[] = $m;
            }
        }
        $mode = is_file($target) ? ((int) fileperms($target) & 0777) : 0644;
        $tmp = $dir . '/.upd-' . bin2hex(random_bytes(6));
        if (!@copy($stage, $tmp)) {
            @unlink($tmp);
            throw new UpdateException('salin_target');
        }
        @chmod($tmp, $mode);
        if (!@rename($tmp, $target)) {
            @unlink($tmp);
            throw new UpdateException('rename_gagal');
        }
    }

    private function postCheck(UpdateManifest $m): void
    {
        foreach ($m->files as $rel => $hash) {
            $f = $this->root . '/' . $rel;
            if (!is_file($f) || !hash_equals($hash, (string) hash_file('sha256', $f))) {
                throw new UpdateException('cek_pasca_apply');
            }
        }
        foreach ($m->delete as $rel) {
            if (file_exists($this->root . '/' . $rel)) {
                throw new UpdateException('cek_pasca_apply');
            }
        }
    }

    /**
     * @param list<string> $done jalur yang sudah/sedang diganti
     * @param list<string> $createdDirs
     */
    private function rollback(array $done, string $backupDir, array $createdDirs): void
    {
        foreach (array_reverse($done) as $rel) {
            $target = $this->root . '/' . $rel;
            $bak = $backupDir . '/' . $rel;
            try {
                if (is_file($bak)) {
                    $tmp = dirname($target) . '/.rbk-' . bin2hex(random_bytes(6));
                    if (@copy($bak, $tmp)) {
                        @chmod($tmp, 0644);
                        if (!@rename($tmp, $target)) {
                            @unlink($tmp);
                        }
                    }
                } elseif (is_file($target)) {
                    @unlink($target);
                }
                $this->invalidate($rel);
            } catch (\Throwable) {
                $this->logger?->error('Rollback satu file gagal', ['path' => $rel]);
            }
        }
        foreach (array_reverse($createdDirs) as $d) {
            @rmdir($d);
        }
    }

    private function step(string $stage, string $rel): void
    {
        if ($this->onStep !== null) {
            ($this->onStep)($stage, $rel);
        }
    }

    private function invalidate(string $rel): void
    {
        if ($this->opcache !== null) {
            ($this->opcache)($this->root . '/' . $rel);
        } elseif (function_exists('opcache_invalidate') && str_ends_with($rel, '.php')) {
            @opcache_invalidate($this->root . '/' . $rel, true);
        }
    }

    private function resetOpcache(): void
    {
        if (function_exists('opcache_reset')) {
            @opcache_reset();
        }
    }

    private function writeVersion(string $version): void
    {
        $f = $this->storage . '/' . CoreVersion::STATE_FILE;
        $tmp = $f . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (file_put_contents($tmp, $version . "\n") === false || !@rename($tmp, $f)) {
            @unlink($tmp);
            throw new UpdateException('simpan_versi');
        }
    }

    private function setMaintenance(bool $on): void
    {
        $f = $this->storage . '/' . self::MAINTENANCE;
        if ($on) {
            @file_put_contents($f, (string) time());
        } else {
            @unlink($f);
        }
    }

    private function removeTree(string $dir): void
    {
        if (!is_dir($dir) || is_link($dir)) {
            return;
        }
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) {
            $f->isDir() && !$f->isLink() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
        }
        @rmdir($dir);
    }
}
