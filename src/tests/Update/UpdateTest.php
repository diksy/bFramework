<?php

declare(strict_types=1);

namespace bFramework\Tests\Update;

use bFramework\Core\RateLimiter;
use bFramework\Core\Router;
use bFramework\Auth\AuthKit;
use bFramework\Runtime\Authorizer;
use bFramework\Runtime\Connection;
use bFramework\Core\Template;
use bFramework\Tests\Fixtures\AuthHarness;
use bFramework\Tests\Fixtures\CaptureLogger;
use bFramework\Update\CoreManifest;
use bFramework\Update\CoreVersion;
use bFramework\Update\UpdateController;
use bFramework\Update\UpdateException;
use bFramework\Update\UpdateKey;
use bFramework\Update\UpdateMigrations;
use bFramework\Update\UpdatePackage;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../../tools/gen-update-key.php';
require_once __DIR__ . '/../../../tools/sign-update.php';

/** M17 (SEC-UPD-01/02, ARCH-08): verifikasi, apply atomik, diff. Kunci uji dibangkitkan per tes; hanya data dummy. */
final class UpdateTest extends TestCase
{
    private string $tmp;
    private string $root;
    private string $pk;
    private string $sk;
    private CaptureLogger $log;

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . '/upd_' . bin2hex(random_bytes(6));
        $this->root = $this->tmp . '/site';
        foreach (['app/core', 'app/config', 'app/storage', 'app/definitions', 'app/extensions', 'public_html/assets'] as $d) {
            mkdir($this->root . '/' . $d, 0755, true);
        }
        file_put_contents($this->root . '/app/storage/installed.lock', 'lock');
        file_put_contents($this->root . '/app/config/config.php', "<?php return ['APP_KEY' => 'rahasia-dummy'];");
        file_put_contents($this->root . '/app/storage/sess_x', 'sesi');
        file_put_contents($this->root . '/app/definitions/a.json', '{}');
        file_put_contents($this->root . '/app/core/A.php', "<?php // A lama\n");
        file_put_contents($this->root . '/app/core/Old.php', "<?php // lama\n");
        file_put_contents($this->root . '/public_html/index.php', "<?php // index lama\n");
        file_put_contents($this->root . '/public_html/assets/app.css', 'a{}');
        $kp = sodium_crypto_sign_keypair();
        $this->pk = sodium_crypto_sign_publickey($kp);
        $this->sk = sodium_crypto_sign_secretkey($kp);
        $this->log = new CaptureLogger();
    }

    protected function tearDown(): void
    {
        $this->rm($this->tmp);
    }

    private function rm(string $d): void
    {
        if (is_link($d) || is_file($d)) {
            @unlink($d);
            return;
        }
        foreach (glob($d . '/{,.}*', GLOB_BRACE) ?: [] as $f) {
            if (basename($f) !== '.' && basename($f) !== '..') {
                $this->rm($f);
            }
        }
        @rmdir($d);
    }

    /**
     * Membuat paket ditandatangani. $o: version, min, delete, migrations, key (secret lain), sigRaw, tamper (callable json=>json),
     * extra (entri tambahan di zip), zipFiles (isi zip berbeda dari manifest), attr (symlink: nama=>atribut).
     *
     * @param array<string,string> $files
     * @param array<string,mixed> $o
     */
    private function pkg(array $files, array $o = []): string
    {
        $files += ['MANIFEST.sha256' => hash('sha256', 'x') . "  app/core/A.php\n"];
        $hashes = [];
        foreach ($files as $p => $c) {
            $hashes[$p] = hash('sha256', $c);
        }
        $manifest = json_encode([
            'format' => 1, 'version' => $o['version'] ?? '1.1.0', 'min_version' => $o['min'] ?? '1.0.0', 'date' => '2026-01-31',
            'files' => $hashes, 'delete' => $o['delete'] ?? [], 'migrations' => $o['migrations'] ?? [],
        ], JSON_UNESCAPED_SLASHES);
        $sig = $o['sigRaw'] ?? base64_encode(sodium_crypto_sign_detached($manifest, $o['key'] ?? $this->sk)) . "\n";
        if (isset($o['tamper'])) {
            $manifest = $o['tamper']($manifest);
        }
        $path = $this->tmp . '/p_' . bin2hex(random_bytes(4)) . '.zip';
        $z = new \ZipArchive();
        $z->open($path, \ZipArchive::CREATE);
        if (!($o['noManifest'] ?? false)) {
            $z->addFromString('manifest.json', $manifest);
        }
        if (!($o['noSig'] ?? false)) {
            $z->addFromString('manifest.sig', $sig);
        }
        foreach ($o['zipFiles'] ?? $files as $p => $c) {
            $z->addFromString($p, $c);
        }
        foreach ($o['extra'] ?? [] as $p => $c) {
            $z->addFromString($p, $c);
        }
        foreach ($o['attr'] ?? [] as $p => $a) {
            $z->setExternalAttributesName($p, \ZipArchive::OPSYS_UNIX, $a << 16);
        }
        $z->close();
        return $path;
    }

    private function up(?string $key = null, ?\Closure $opcache = null, ?\Closure $step = null): UpdatePackage
    {
        return new UpdatePackage($this->root, $key ?? $this->pk, $this->log, $opcache ?? static function (string $p): void {
        }, $step);
    }

    private function snapshot(): string
    {
        $out = [];
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->root, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if ($f->isFile() && !str_contains($f->getPathname(), '/storage/update')) {
                $out[$f->getPathname()] = md5_file($f->getPathname());
            }
        }
        foreach (glob($this->root . '/{,*/,*/*/,*/*/*/}', GLOB_BRACE) ?: [] as $d) {
            if (!str_contains($d, '/storage/update')) {
                $out[$d] = 'dir';
            }
        }
        ksort($out);
        return json_encode($out, JSON_THROW_ON_ERROR);
    }

    private function reason(callable $f): string
    {
        try {
            $f();
        } catch (UpdateException $e) {
            return $e->reason;
        }
        self::fail('UpdateException diharapkan');
    }

    private function good(): array
    {
        return ['app/core/A.php' => "<?php // A baru\n", 'app/core/New/B.php' => "<?php // B\n", 'public_html/assets/app.css' => 'b{}'];
    }

    // ---------- verify ----------

    public function test_SEC_UPD_01_paket_sah_lolos_dan_tidak_menyentuh_disk(): void
    {
        $before = $this->snapshot();
        $m = $this->up()->verify($this->pkg($this->good()));
        self::assertSame('1.1.0', $m->version);
        self::assertSame($before, $this->snapshot());
    }

    public function test_SEC_UPD_01_tanda_tangan_salah_kosong_terpotong_dan_tanpa_tanda_tangan(): void
    {
        $other = sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair());
        $valid = base64_encode(str_repeat("\1", 64));
        $cases = [
            'kunci lain' => ['key' => $other],
            'kosong' => ['sigRaw' => ''],
            'terpotong' => ['sigRaw' => substr(base64_encode(str_repeat("\1", 64)), 0, 40)],
            'bukan base64' => ['sigRaw' => '!!!###'],
            'bit acak' => ['sigRaw' => $valid],
            'tanpa berkas sig' => ['noSig' => true],
            'tanpa manifest' => ['noManifest' => true],
        ];
        foreach ($cases as $label => $o) {
            $before = $this->snapshot();
            $zip = $this->pkg($this->good(), $o);
            $up = $this->up();
            self::assertNotSame('', $this->reason(fn() => $up->verify($zip)), $label);
            $this->reason(fn() => $up->apply($zip));
            self::assertSame($before, $this->snapshot(), $label);
        }
    }

    public function test_SEC_UPD_01_manifest_dimodifikasi_setelah_ditandatangani(): void
    {
        $zip = $this->pkg($this->good(), ['tamper' => static fn(string $j): string => str_replace('1.1.0', '9.9.9', $j)]);
        self::assertSame('tanda_tangan_salah', $this->reason(fn() => $this->up()->verify($zip)));
    }

    public function test_SEC_UPD_01_file_dimodifikasi_setelah_ditandatangani_dan_file_ekstra_atau_hilang(): void
    {
        $files = $this->good();
        $evil = $files;
        $evil['app/core/A.php'] = "<?php system('id');";
        $zip = $this->pkg($files, ['zipFiles' => $evil + ['MANIFEST.sha256' => hash('sha256', 'x') . "  app/core/A.php\n"]]);
        self::assertSame('hash_salah', $this->reason(fn() => $this->up()->verify($zip)));
        $zip = $this->pkg($files, ['extra' => ['app/core/Backdoor.php' => '<?php']]);
        self::assertSame('isi_zip_beda_manifest', $this->reason(fn() => $this->up()->verify($zip)));
        $less = $files;
        unset($less['app/core/A.php']);
        $zip = $this->pkg($files, ['zipFiles' => $less + ['MANIFEST.sha256' => hash('sha256', 'x') . "  app/core/A.php\n"]]);
        self::assertSame('isi_zip_beda_manifest', $this->reason(fn() => $this->up()->verify($zip)));
    }

    public function test_SEC_UPD_01_zip_slip_dan_jalur_terlarang_ditolak_tanpa_menulis(): void
    {
        $bad = ['app/core/../../../escape.php', '../escape.php', '/etc/cron.d/x', 'app\\core\\X.php', 'app/core//X.php', 'app/core/./X.php',
            'app/config/config.php', 'app/storage/installed.lock', 'app/storage/x.php', 'app/definitions/a.json', 'app/extensions/H.php',
            'app/core/installed.lock', 'public_html/.htaccess', 'public_html/assets/x.php', 'app/core/x.sh', "app/core/a\0b.php", 'app/core/' . str_repeat('a', 200) . '.php'];
        foreach ($bad as $p) {
            $before = $this->snapshot();
            $zip = $this->pkg($this->good() + [$p => 'x']);
            $up = $this->up();
            $this->reason(fn() => $up->verify($zip));
            $this->reason(fn() => $up->apply($zip));
            self::assertSame($before, $this->snapshot(), $p);
        }
        self::assertFileDoesNotExist($this->tmp . '/escape.php');
        self::assertFileDoesNotExist($this->root . '/escape.php');
        self::assertStringContainsString('rahasia-dummy', (string) file_get_contents($this->root . '/app/config/config.php'));
    }

    public function test_SEC_UPD_01_symlink_dan_nama_ganda_beda_huruf_ditolak(): void
    {
        $zip = $this->pkg($this->good() + ['app/core/Link.php' => 'target'], ['attr' => ['app/core/Link.php' => 0120777]]);
        self::assertSame('entri_bukan_file', $this->reason(fn() => $this->up()->verify($zip)));
        $zip = $this->pkg($this->good() + ['app/core/Dup.php' => '1', 'app/core/dup.php' => '2']);
        $this->reason(fn() => $this->up()->verify($zip));
    }

    public function test_SEC_UPD_01_target_symlink_di_disk_ditolak(): void
    {
        $outside = $this->tmp . '/luar';
        mkdir($outside);
        symlink($outside, $this->root . '/app/core/New');
        $before = $this->snapshot();
        $this->reason(fn() => $this->up()->apply($this->pkg($this->good())));
        self::assertSame($before, $this->snapshot());
        self::assertSame([], glob($outside . '/*') ?: []);
    }

    public function test_SEC_UPD_01_downgrade_versi_sama_dan_min_version(): void
    {
        file_put_contents($this->root . '/app/storage/core.version', "1.5.0\n");
        self::assertSame('1.5.0', CoreVersion::installed($this->root . '/app/storage'));
        self::assertSame('versi_tidak_baru', $this->reason(fn() => $this->up()->verify($this->pkg($this->good(), ['version' => '1.4.0']))));
        self::assertSame('versi_tidak_baru', $this->reason(fn() => $this->up()->verify($this->pkg($this->good(), ['version' => '1.5.0']))));
        self::assertSame('versi_terpasang_terlalu_lama', $this->reason(fn() => $this->up()->verify($this->pkg($this->good(), ['version' => '2.0.0', 'min' => '1.9.0']))));
        self::assertSame('2.0.0', $this->up()->verify($this->pkg($this->good(), ['version' => '2.0.0']))->version);
    }

    public function test_SEC_UPD_01_zip_bomb_ditolak(): void
    {
        $zip = $this->pkg($this->good() + ['app/core/Big.php' => str_repeat("\0", 11 * 1024 * 1024)]);
        self::assertSame('zip_bomb', $this->reason(fn() => $this->up()->verify($zip)));
        $zip = $this->pkg($this->good() + ['app/core/Big.php' => str_repeat('A', 3 * 1024 * 1024)]);
        self::assertSame('zip_bomb', $this->reason(fn() => $this->up()->verify($zip))); // rasio kompresi
    }

    public function test_SEC_UPD_01_key_placeholder_atau_kosong_menolak_semua_fail_closed(): void
    {
        self::assertNull(UpdateKey::raw());
        self::assertFalse(UpdateKey::configured());
        self::assertNull(UpdateKey::raw(str_repeat('0', 64)));
        self::assertNull(UpdateKey::raw(''));
        self::assertNull(UpdateKey::raw('zz' . str_repeat('a', 62)));
        self::assertNotNull(UpdateKey::raw(bin2hex($this->pk)));
        $zip = $this->pkg($this->good());
        $before = $this->snapshot();
        foreach ([null, '', 'pendek'] as $k) {
            $up = new UpdatePackage($this->root, $k, $this->log);
            self::assertFalse($up->keyReady());
            self::assertSame('kunci_belum_ditanam', $this->reason(fn() => $up->verify($zip)));
            self::assertSame('kunci_belum_ditanam', $this->reason(fn() => $up->apply($zip)));
        }
        self::assertSame($before, $this->snapshot());
    }

    public function test_SEC_UPD_01_manifest_format_ketat(): void
    {
        $sign = fn(string $json): string => $this->pkgRaw($json);
        $ok = json_decode((string) json_encode([
            'format' => 1, 'version' => '1.1.0', 'min_version' => '1.0.0', 'date' => '2026-01-31',
            'files' => ['MANIFEST.sha256' => str_repeat('a', 64)], 'delete' => [], 'migrations' => [],
        ]), true);
        foreach ([
            ['kunci tambahan', $ok + ['x' => 1]], ['format 2', ['format' => 2] + $ok], ['versi buruk', ['version' => '1.1'] + $ok],
            ['tanggal buruk', ['date' => '2026-13-45'] + $ok], ['hash buruk', ['files' => ['MANIFEST.sha256' => 'zz']] + $ok],
            ['tanpa MANIFEST', ['files' => ['app/core/A.php' => str_repeat('a', 64)]] + $ok],
            ['migrasi dengan ;', ['migrations' => [['id' => '0001', 'sql' => ['sqlite' => ['SELECT 1; SELECT 2']]]]] + $ok],
            ['migrasi tak urut', ['migrations' => [['id' => '0002', 'sql' => []], ['id' => '0001', 'sql' => []]]] + $ok],
        ] as [$label, $data]) {
            $json = (string) json_encode($data);
            self::assertSame(1, preg_match('/^manifest_/', $this->reason(fn() => $this->up()->verify($sign($json)))), $label);
        }
        $this->reason(fn() => $this->up()->verify($sign(str_repeat(' ', 300000) . '{}')));
        $this->reason(fn() => $this->up()->verify($sign('[1,2')));
    }

    private function pkgRaw(string $json): string
    {
        $path = $this->tmp . '/r_' . bin2hex(random_bytes(4)) . '.zip';
        $z = new \ZipArchive();
        $z->open($path, \ZipArchive::CREATE);
        $z->addFromString('manifest.json', $json);
        $z->addFromString('manifest.sig', base64_encode(sodium_crypto_sign_detached($json, $this->sk)));
        $z->addFromString('MANIFEST.sha256', 'x');
        $z->close();
        return $path;
    }

    // ---------- apply ----------

    public function test_SEC_UPD_01_apply_sukses_hanya_whitelist_dan_config_storage_tak_tersentuh(): void
    {
        $touched = [];
        $rebuilt = 0;
        $up = $this->up(null, function (string $p) use (&$touched): void {
            $touched[] = $p;
        });
        $cfg = md5_file($this->root . '/app/config/config.php');
        $res = $up->apply($this->pkg($this->good(), ['delete' => ['app/core/Old.php']]), null, function () use (&$rebuilt): void {
            $rebuilt++;
        });
        self::assertSame('1.1.0', $res->version);
        self::assertSame("<?php // A baru\n", file_get_contents($this->root . '/app/core/A.php'));
        self::assertSame("<?php // B\n", file_get_contents($this->root . '/app/core/New/B.php'));
        self::assertSame('b{}', file_get_contents($this->root . '/public_html/assets/app.css'));
        self::assertFileDoesNotExist($this->root . '/app/core/Old.php');
        self::assertSame($cfg, md5_file($this->root . '/app/config/config.php'));
        self::assertSame('sesi', file_get_contents($this->root . '/app/storage/sess_x'));
        self::assertSame('lock', file_get_contents($this->root . '/app/storage/installed.lock'));
        self::assertSame('{}', file_get_contents($this->root . '/app/definitions/a.json'));
        self::assertSame('1.1.0', CoreVersion::installed($this->root . '/app/storage'));
        self::assertFileDoesNotExist($this->root . '/app/storage/maintenance');
        self::assertSame([], glob($this->root . '/app/storage/update/work-*') ?: []);
        self::assertSame(1, $rebuilt);
        self::assertContains($this->root . '/app/core/A.php', $touched); // OPcache dipanggil
        self::assertContains($this->root . '/app/core/New/B.php', $touched);
        self::assertSame([], glob($this->root . '/app/core/.upd-*') ?: []);
        // paket yang sama tidak bisa diputar ulang
        self::assertSame('versi_tidak_baru', $this->reason(fn() => $up->apply($this->pkg($this->good()))));
    }

    public function test_SEC_UPD_01_rebuild_gagal_hanya_peringatan(): void
    {
        $res = $this->up()->apply($this->pkg($this->good()), null, static function (): void {
            throw new \RuntimeException('x');
        });
        self::assertCount(1, $res->warnings);
    }

    public function test_SEC_UPD_01_gagal_di_tengah_rollback_tanpa_file_setengah_jadi(): void
    {
        $before = $this->snapshot();
        $n = 0;
        $up = $this->up(null, null, function (string $stage, string $rel) use (&$n): void {
            if ($stage === 'swap' && ++$n === 3) {
                throw new \RuntimeException('disk penuh (simulasi)');
            }
        });
        $zip = $this->pkg($this->good(), ['delete' => ['app/core/Old.php']]);
        self::assertSame('gagal_diterapkan', $this->reason(fn() => $up->apply($zip)));
        self::assertSame($before, $this->snapshot());
        self::assertFileDoesNotExist($this->root . '/app/core/New');
        self::assertFileDoesNotExist($this->root . '/app/storage/maintenance');
        self::assertFileDoesNotExist($this->root . '/app/storage/core.version');
        self::assertSame([], glob($this->root . '/app/storage/update/work-*') ?: []);
    }

    public function test_SEC_UPD_01_gagal_saat_hapus_rollback_file_terhapus(): void
    {
        $before = $this->snapshot();
        $up = $this->up(null, null, static function (string $stage, string $rel): void {
            if ($stage === 'delete') {
                throw new \RuntimeException('simulasi');
            }
        });
        $this->reason(fn() => $up->apply($this->pkg($this->good(), ['delete' => ['app/core/Old.php']])));
        self::assertSame($before, $this->snapshot());
    }

    public function test_SEC_UPD_01_konkurensi_dua_update_sekaligus_ditolak(): void
    {
        mkdir($this->root . '/app/storage/update', 0700, true);
        $fh = fopen($this->root . '/app/storage/update/update.lock', 'c');
        self::assertNotFalse($fh);
        self::assertTrue(flock($fh, LOCK_EX | LOCK_NB));
        $before = $this->snapshot();
        self::assertSame('sedang_berjalan', $this->reason(fn() => $this->up()->apply($this->pkg($this->good()))));
        self::assertSame($before, $this->snapshot());
        flock($fh, LOCK_UN);
        fclose($fh);
        self::assertSame('1.1.0', $this->up()->apply($this->pkg($this->good()))->version);
    }

    public function test_SEC_UPD_01_belum_terpasang_ditolak(): void
    {
        unlink($this->root . '/app/storage/installed.lock');
        self::assertSame('belum_terpasang', $this->reason(fn() => $this->up()->apply($this->pkg($this->good()))));
    }

    // ---------- migrasi ----------

    private function conn(): Connection
    {
        return Connection::sqlite($this->tmp . '/db.sqlite');
    }

    /** @return array<string,mixed> */
    private function mig(string $id, string $sql): array
    {
        return ['id' => $id, 'sql' => ['sqlite' => [$sql], 'mysql' => [$sql]]];
    }

    public function test_SEC_UPD_01_migrasi_berjalan_idempoten_dan_tercatat(): void
    {
        $conn = $this->conn();
        $mg = new UpdateMigrations($conn, $this->log);
        $res = $this->up()->apply($this->pkg($this->good(), ['migrations' => [$this->mig('0001_a', 'CREATE TABLE ext_a (x INTEGER)')]]), $mg);
        self::assertSame(['0001_a'], $res->migrations);
        self::assertSame(['0001_a'], $mg->applied());
        // jalankan ulang daftar yang sama: tidak ada yang dieksekusi lagi (idempoten)
        self::assertSame([], $mg->run([$this->mig('0001_a', 'CREATE TABLE ext_a (x INTEGER)')]));
        $res = $this->up()->apply($this->pkg($this->good(), ['version' => '1.2.0', 'migrations' => [$this->mig('0001_a', 'CREATE TABLE ext_a (x INTEGER)'), $this->mig('0002_b', 'CREATE TABLE ext_b (x INTEGER)')]]), $mg);
        self::assertSame(['0002_b'], $res->migrations);
    }

    public function test_SEC_UPD_01_migrasi_gagal_atau_destruktif_rollback_file(): void
    {
        $conn = $this->conn();
        $mg = new UpdateMigrations($conn, $this->log);
        $mg->ensureTable();
        $before = $this->snapshot();
        foreach ([$this->mig('0001_a', 'CREATE TABLE'), $this->mig('0001_a', 'DROP TABLE migrations')] as $m) {
            $zip = $this->pkg($this->good(), ['migrations' => [$m]]);
            self::assertSame('migrasi_gagal', $this->reason(fn() => $this->up()->apply($zip, $mg)));
            self::assertSame($before, $this->snapshot());
        }
        self::assertSame([], $mg->applied());
        // migrasi tanpa penjalan migrasi: ditolak sebelum menyentuh disk
        self::assertSame('migrasi_tak_tersedia', $this->reason(fn() => $this->up()->apply($this->pkg($this->good(), ['migrations' => [$this->mig('0001_a', 'SELECT 1')]]))));
        self::assertSame($before, $this->snapshot());
    }

    // ---------- SEC-UPD-02 diff ----------

    private function installManifest(): void
    {
        $lines = '';
        foreach (['app/core/A.php', 'app/core/Old.php', 'public_html/index.php', 'public_html/assets/app.css', 'app/config/config.example.php'] as $p) {
            $lines .= (is_file($this->root . '/' . $p) ? hash_file('sha256', $this->root . '/' . $p) : str_repeat('c', 64)) . '  ' . $p . "\n";
        }
        file_put_contents($this->root . '/MANIFEST.sha256', $lines);
    }

    public function test_SEC_UPD_02_diff_bersih_lalu_deteksi_diubah_hilang_tambahan(): void
    {
        $this->installManifest();
        $cm = new CoreManifest($this->root);
        self::assertTrue($cm->diff()->clean());
        file_put_contents($this->root . '/app/core/A.php', "<?php // dibobol\n");
        unlink($this->root . '/app/core/Old.php');
        file_put_contents($this->root . '/app/core/Shell.php', '<?php');
        file_put_contents($this->root . '/app/config/config.php', 'diubah pemilik'); // di luar lingkup
        file_put_contents($this->root . '/app/definitions/a.json', '{"x":1}');
        $d = $cm->diff();
        self::assertFalse($d->clean());
        self::assertSame(['app/core/A.php'], $d->changed);
        self::assertSame(['app/core/Old.php'], $d->missing);
        self::assertSame(['app/core/Shell.php'], $d->extra);
    }

    public function test_SEC_UPD_02_manifest_hilang_atau_rusak_tidak_tersedia(): void
    {
        $cm = new CoreManifest($this->root);
        self::assertFalse($cm->diff()->available);
        file_put_contents($this->root . '/MANIFEST.sha256', "bukan manifest\n");
        self::assertFalse($cm->diff()->available);
        file_put_contents($this->root . '/MANIFEST.sha256', str_repeat('a', 64) . "  ../etc/passwd\n");
        self::assertFalse($cm->diff()->available);
    }

    // ---------- halaman status ----------

    public function test_SEC_UPD_02_halaman_status_hanya_admin_tanpa_isi_file(): void
    {
        $this->installManifest();
        file_put_contents($this->root . '/app/core/A.php', "<?php // RAHASIA-ISI\n");
        $h = new AuthHarness();
        $h->extraRoutes = function (Router $router, AuthKit $kit) use ($h): void {
            (new UpdateController(
                $kit->manager,
                new Authorizer(),
                $kit->csrf,
                $kit->session,
                new Template(dirname(__DIR__, 2) . '/app/core/Update/views', $h->dir . '/views'),
                new Template(dirname(__DIR__, 2) . '/app/core/Core/views', $h->dir . '/views'),
                new RateLimiter($h->dir . '/rl2', $h->clock),
                new CoreManifest($this->root),
                new UpdatePackage($this->root, null),
                static fn(): array => [],
                $h->logger,
            ))->registerRoutes($router);
        };
        $anon = $h->browser()->get('/admin/pembaruan');
        self::assertSame(302, $anon->status);
        $h->user('staf@contoh.test', roles: ['staf']);
        $b = $h->browser();
        $b->login('staf@contoh.test');
        self::assertSame(403, $b->get('/admin/pembaruan')->status);
        $h->user('admin@contoh.test', roles: ['admin']);
        $a = $h->browser('203.0.113.9');
        $a->login('admin@contoh.test');
        $res = $a->get('/admin/pembaruan');
        self::assertSame(200, $res->status);
        self::assertStringContainsString('app/core/A.php', $res->body);
        self::assertStringContainsString('belum ditanam', $res->body); // peringatan kunci placeholder
        self::assertStringNotContainsString('RAHASIA-ISI', $res->body);
        self::assertSame('no-store', $res->headers['Cache-Control'] ?? '');
    }

    // ---------- alat ----------

    public function test_SEC_UPD_01_alat_gen_key_dan_sign_menghasilkan_paket_yang_lolos(): void
    {
        $priv = $this->tmp . '/keys/update.key';
        mkdir($this->tmp . '/keys', 0700);
        $pubHex = \generateUpdateKey($priv, dirname(__DIR__, 3));
        self::assertSame(64, strlen($pubHex));
        self::assertSame('0600', substr(sprintf('%o', fileperms($priv)), -4));
        self::assertStringNotContainsString($pubHex, (string) file_get_contents($priv));
        $this->expectKeyRefused(fn() => \generateUpdateKey($priv, dirname(__DIR__, 3))); // tidak menimpa
        $this->expectKeyRefused(fn() => \generateUpdateKey(dirname(__DIR__, 3) . '/tools/k.key', dirname(__DIR__, 3))); // di dalam repo
        $this->expectKeyRefused(fn() => \loadUpdateSecret(dirname(__DIR__, 3) . '/composer.json', dirname(__DIR__, 3)));
        chmod($priv, 0644);
        $this->expectKeyRefused(fn() => \loadUpdateSecret($priv, dirname(__DIR__, 3)));
        chmod($priv, 0600);
        $secret = \loadUpdateSecret($priv, dirname(__DIR__, 3));
        // zip rilis palsu
        $rel = $this->tmp . '/release.zip';
        $z = new \ZipArchive();
        $z->open($rel, \ZipArchive::CREATE);
        $z->addFromString('app/core/A.php', "<?php // baru\n");
        $z->addFromString('app/config/config.php', 'RAHASIA');
        $z->addFromString('app/config/config.example.php', '<?php');
        $z->addFromString('MANIFEST.sha256', hash('sha256', "<?php // baru\n") . "  app/core/A.php\n");
        $z->close();
        $out = $this->tmp . '/update.zip';
        $list = \buildUpdatePackage($rel, $secret, '1.3.0', '1.0.0', '2026-02-01', [], [], $out);
        self::assertSame(['MANIFEST.sha256', 'app/core/A.php'], $list);
        $za = new \ZipArchive();
        $za->open($out);
        self::assertFalse($za->locateName('app/config/config.php'));
        $za->close();
        $pk = hex2bin($pubHex);
        self::assertSame('1.3.0', (new UpdatePackage($this->root, $pk))->verify($out)->version);
        self::assertSame('tanda_tangan_salah', $this->reason(fn() => $this->up()->verify($out))); // kunci lain
    }

    private function expectKeyRefused(callable $f): void
    {
        try {
            $f();
        } catch (\RuntimeException) {
            self::assertTrue(true);
            return;
        }
        self::fail('RuntimeException diharapkan');
    }
}
