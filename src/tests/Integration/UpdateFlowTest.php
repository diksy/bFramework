<?php

declare(strict_types=1);

namespace bFramework\Tests\Integration;

use bFramework\Tests\Fixtures\KernelApp;
use bFramework\Update\UpdatePaths;
use PHPUnit\Framework\TestCase;

/**
 * INT-09 (F14 update, SEC-UPD-01/02): paket Ed25519 diterapkan lewat CLI app/cli/update.php nyata terhadap sandbox yang
 * juga dilayani index.php. Kunci uji ditanam di salinan UpdateKey milik sandbox (seperti pemilik menanam kunci sendiri).
 */
final class UpdateFlowTest extends TestCase
{
    private ?KernelApp $app = null;
    private string $pk = '';
    private string $sk = '';

    protected function tearDown(): void
    {
        $this->app?->destroy();
        $this->app = null;
    }

    private function boot(bool $plantKey = true): KernelApp
    {
        $a = $this->app = KernelApp::installed();
        $kp = sodium_crypto_sign_keypair();
        $this->pk = sodium_crypto_sign_publickey($kp);
        $this->sk = sodium_crypto_sign_secretkey($kp);
        if ($plantKey) {
            $f = $a->root . '/app/core/Update/UpdateKey.php';
            $src = (string) file_get_contents($f);
            $new = (string) preg_replace("/PUBLIC_KEY_HEX = '[^']*'/", "PUBLIC_KEY_HEX = '" . bin2hex($this->pk) . "'", $src);
            self::assertNotSame($src, $new);
            file_put_contents($f, $new);
        }
        file_put_contents($a->root . '/app/core/Obsolete.txt', "lama\n");
        file_put_contents($a->root . '/MANIFEST.sha256', $this->manifestOf($a->root, []));
        return $a;
    }

    /**
     * MANIFEST.sha256 seperti tools/build-release.php untuk sandbox setelah $overrides ('' = dihapus).
     *
     * @param array<string,string> $overrides
     */
    private function manifestOf(string $root, array $overrides): string
    {
        require_once dirname(__DIR__, 3) . '/tools/build-release.php';
        $files = [];
        foreach (\releaseFiles($root) as $rel) { // sama dengan tools/build-release.php: semua file rilis, bukan hanya lingkup updater
            if (!UpdatePaths::inManifest($rel)) {
                continue; // sama dengan \releaseManifest()
            }
            $files[$rel] = hash_file('sha256', $root . '/' . $rel);
        }
        foreach ($overrides as $rel => $content) {
            if ($content === '') {
                unset($files[$rel]);
            } else {
                $files[$rel] = hash('sha256', $content);
            }
        }
        ksort($files);
        $out = '';
        foreach ($files as $rel => $h) {
            $out .= $h . '  ' . $rel . "\n";
        }
        return $out;
    }

    /** Status core bersih (tanpa DIUBAH/HILANG/TAMBAHAN). */
    private function assertCoreClean(string $status): void
    {
        $rest = $status;
        foreach (['DIUBAH', 'HILANG', 'TAMBAHAN'] as $w) {
            self::assertStringNotContainsString($w . ':', $rest);
        }
        self::assertStringNotContainsString('MANIFEST.sha256 tidak tersedia', $rest);
    }

    /**
     * @param array<string,string> $files isi baru (relatif ke root instalasi)
     * @param array<string,mixed> $o version, min, delete, migrations, key, tamper(callable), zipFiles
     */
    private function package(KernelApp $a, array $files, array $o = []): string
    {
        $over = $files;
        foreach ($o['delete'] ?? [] as $d) {
            $over[$d] = '';
        }
        $files[UpdatePaths::MANIFEST_FILE] = $this->manifestOf($a->root, $over);
        $hashes = [];
        foreach ($files as $p => $c) {
            $hashes[$p] = hash('sha256', $c);
        }
        ksort($hashes);
        $manifest = (string) json_encode([
            'format' => 1, 'version' => $o['version'] ?? '1.1.0', 'min_version' => '1.0.0', 'date' => '2026-10-01',
            'files' => $hashes, 'delete' => $o['delete'] ?? [], 'migrations' => $o['migrations'] ?? [],
        ], JSON_UNESCAPED_SLASHES);
        $sig = base64_encode(sodium_crypto_sign_detached($manifest, $o['key'] ?? $this->sk)) . "\n";
        if (isset($o['tamper'])) {
            $manifest = $o['tamper']($manifest);
        }
        $path = $a->root . '/pkg_' . bin2hex(random_bytes(4)) . '.zip';
        $z = new \ZipArchive();
        $z->open($path, \ZipArchive::CREATE);
        $z->addFromString('manifest.json', $manifest);
        $z->addFromString('manifest.sig', $sig);
        foreach ($o['zipFiles'] ?? $files as $p => $c) {
            $z->addFromString($p, $c);
        }
        $z->close();
        return $path;
    }

    /** @return array{0:int,1:string} */
    private function cli(KernelApp $a, string ...$args): array
    {
        $cmd = escapeshellarg(PHP_BINARY) . ' -d opcache.enable=0 ' . escapeshellarg($a->root . '/app/cli/update.php') . ' ' . implode(' ', array_map('escapeshellarg', $args)) . ' 2>&1';
        $out = [];
        exec('cd ' . escapeshellarg($a->root) . ' && ' . $cmd, $out, $code);
        return [$code, implode("\n", $out)];
    }

    /** Sidik jari area yang tak boleh tersentuh update. */
    private function guarded(KernelApp $a): string
    {
        $parts = [];
        foreach (['app/config', 'app/definitions', 'app/extensions'] as $d) {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($a->root . '/' . $d, \FilesystemIterator::SKIP_DOTS));
            foreach ($it as $f) {
                if ($f instanceof \SplFileInfo && $f->isFile()) {
                    $parts[$f->getPathname()] = md5_file($f->getPathname());
                }
            }
        }
        $parts['lock'] = md5_file($a->root . '/app/storage/installed.lock');
        $parts['sessions'] = implode(',', array_map('basename', glob($a->root . '/app/storage/sessions/*') ?: []));
        $parts['users'] = (string) $a->pdo()->query('SELECT GROUP_CONCAT(email) FROM users')->fetchColumn();
        ksort($parts);
        return json_encode($parts, JSON_THROW_ON_ERROR);
    }

    /** Sidik jari file core (kode yang boleh ditimpa). */
    private function coreState(KernelApp $a): string
    {
        return $this->manifestOf($a->root, []) . '|' . (string) @file_get_contents($a->root . '/app/storage/core.version');
    }

    private function newCss(): string
    {
        return "/* paket 1.1.0 */\nbody{margin:0}\n";
    }

    public function test_INT_09a_paket_bertanda_tangan_diterapkan_config_storage_tak_tersentuh(): void
    {
        $a = $this->boot();
        $adm = $a->loggedIn();
        self::assertSame(200, $adm->get('/produk')->status);
        [, $status] = $this->cli($a, 'status');
        self::assertStringContainsString('Versi terpasang: 1.0.0', $status);
        self::assertStringContainsString('Kunci penandatangan: tertanam', $status);
        $this->assertCoreClean($status);

        $guard = $this->guarded($a);
        $cssOld = (string) file_get_contents($a->root . '/public_html/assets/app.css');
        $ver = (string) file_get_contents($a->root . '/app/core/Update/CoreVersion.php');
        $files = [
            'public_html/assets/app.css' => $this->newCss(),
            'app/core/Update/CoreVersion.php' => str_replace("'1.0.0'", "'1.1.0'", $ver),
            'app/core/Baru.txt' => "berkas baru\n",
        ];
        $pkg = $this->package($a, $files, [
            'delete' => ['app/core/Obsolete.txt'],
            'migrations' => [['id' => '0001_jejak', 'sql' => ['mysql' => ['CREATE TABLE jejak_update (id INT PRIMARY KEY)'], 'sqlite' => ['CREATE TABLE "jejak_update" ("id" INTEGER PRIMARY KEY)']]]],
        ]);
        [$code, $out] = $this->cli($a, 'verify', $pkg);
        self::assertSame(0, $code, $out);
        self::assertSame($cssOld, (string) file_get_contents($a->root . '/public_html/assets/app.css'), 'verify tidak mengubah apa pun');

        [$code, $out] = $this->cli($a, 'apply', $pkg, '--yes');
        self::assertSame(0, $code, $out);
        self::assertStringContainsString('Update ke 1.1.0 selesai', $out);
        self::assertSame($this->newCss(), (string) file_get_contents($a->root . '/public_html/assets/app.css'));
        self::assertSame("berkas baru\n", (string) file_get_contents($a->root . '/app/core/Baru.txt'));
        self::assertFileDoesNotExist($a->root . '/app/core/Obsolete.txt');
        clearstatcache();
        self::assertFileDoesNotExist($a->root . '/app/storage/maintenance', 'mode pemeliharaan dicabut');
        self::assertSame('1.1.0', trim((string) file_get_contents($a->root . '/app/storage/core.version')));
        self::assertSame(1, (int) $a->pdo()->query("SELECT COUNT(*) FROM migrations WHERE version = '0001_jejak'")->fetchColumn());
        self::assertSame(0, (int) $a->pdo()->query('SELECT COUNT(*) FROM jejak_update')->fetchColumn());
        self::assertSame($guard, $this->guarded($a), 'config, definitions, extensions, sesi, lock, data tidak tersentuh');

        // Situs tetap melayani dengan sesi lama; halaman pembaruan menampilkan versi baru dan core bersih.
        self::assertSame(200, $adm->get('/produk')->status);
        $page = $adm->get('/admin/pembaruan');
        self::assertSame(200, $page->status);
        self::assertStringContainsString('1.1.0', $page->body);
        [, $status] = $this->cli($a, 'status');
        self::assertStringContainsString('Versi terpasang: 1.1.0', $status);
        $this->assertCoreClean($status);
        // Pemutaran ulang paket yang sama (replay/downgrade) ditolak.
        $before = $this->coreState($a);
        [$code] = $this->cli($a, 'apply', $pkg, '--yes');
        self::assertSame(1, $code);
        self::assertSame($before, $this->coreState($a));
    }

    public function test_INT_09b_paket_palsu_ditolak_dan_tidak_ada_yang_berubah(): void
    {
        $a = $this->boot();
        $before = $this->coreState($a);
        $guard = $this->guarded($a);
        $other = sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair());
        $good = ['public_html/assets/app.css' => $this->newCss()];
        $cases = [
            'kunci lain' => $this->package($a, $good, ['key' => $other]),
            'manifest diubah setelah ditandatangani' => $this->package($a, $good, ['tamper' => static fn(string $m): string => str_replace('1.1.0', '9.9.9', $m)]),
            'isi zip beda dari hash' => $this->package($a, $good, ['zipFiles' => ['public_html/assets/app.css' => "body{background:url(//jahat)}", 'MANIFEST.sha256' => 'x']]),
            'versi tidak naik' => $this->package($a, $good, ['version' => '1.0.0']),
            'menimpa config' => $this->package($a, $good + ['app/config/config.php' => "<?php return ['APP_KEY'=>'x'];"]),
            'menimpa storage' => $this->package($a, $good + ['app/storage/installed.lock' => 'x']),
            'traversal' => $this->package($a, $good + ['app/core/../../../tmp/jahat.php' => '<?php']),
            'php di assets' => $this->package($a, ['public_html/assets/shell.php' => '<?php system($_GET["c"]);']),
            'menghapus config' => $this->package($a, $good, ['delete' => ['app/config/config.php']]),
        ];
        foreach ($cases as $name => $pkg) {
            [$code, $out] = $this->cli($a, 'apply', $pkg, '--yes');
            self::assertSame(1, $code, "$name: $out");
            self::assertSame($before, $this->coreState($a), "$name: core tak berubah");
            self::assertSame($guard, $this->guarded($a), "$name: area terjaga tak berubah");
            self::assertFileDoesNotExist($a->root . '/public_html/assets/shell.php');
        }
        self::assertFileDoesNotExist('/tmp/jahat.php');
        // Output kegagalan generik: tidak membocorkan jalur absolut sandbox.
        [, $out] = $this->cli($a, 'apply', $cases['kunci lain'], '--yes');
        self::assertStringNotContainsString($a->root, $out);
        // Tanpa kunci tertanam (placeholder) semua paket ditolak, walau tanda tangan benar.
        $b = KernelApp::installed();
        try {
            $kf = $b->root . '/app/core/Update/UpdateKey.php';
            $ksrc = (string) file_get_contents($kf);
            $knew = (string) preg_replace("/PUBLIC_KEY_HEX = '[^']*'/", "PUBLIC_KEY_HEX = 'PLACEHOLDER_UJI'", $ksrc);
            self::assertNotSame($ksrc, $knew);
            file_put_contents($kf, $knew);
            file_put_contents($b->root . '/MANIFEST.sha256', $this->manifestOf($b->root, []));
            $pkg = $this->package($b, $good);
            [$code, $out] = $this->cli($b, 'apply', $pkg, '--yes');
            self::assertSame(1, $code);
            self::assertStringContainsString('kunci', strtolower($out));
            [, $st] = $this->cli($b, 'status');
            self::assertStringContainsString('PERINGATAN', $st);
        } finally {
            $b->destroy();
        }
    }

    public function test_INT_09c_kegagalan_di_tengah_apply_memulihkan_semua_file(): void
    {
        $a = $this->boot();
        $adm = $a->loggedIn();
        $before = $this->coreState($a);
        $guard = $this->guarded($a);
        $cssOld = (string) file_get_contents($a->root . '/public_html/assets/app.css');
        $pkg = $this->package($a, ['public_html/assets/app.css' => $this->newCss(), 'app/core/Baru.txt' => "baru\n"], [
            'delete' => ['app/core/Obsolete.txt'],
            // File sudah ditukar saat migrasi dijalankan; migrasi gagal -> rollback seluruh file.
            'migrations' => [['id' => '0002_rusak', 'sql' => ['mysql' => ['CREATE TABLE x (id INT)'], 'sqlite' => ['CREATE TABL "rusak" (id)']]]],
        ]);
        [$code, $out] = $this->cli($a, 'apply', $pkg, '--yes');
        self::assertSame(1, $code, $out);
        self::assertSame($cssOld, (string) file_get_contents($a->root . '/public_html/assets/app.css'));
        self::assertFileDoesNotExist($a->root . '/app/core/Baru.txt');
        self::assertFileExists($a->root . '/app/core/Obsolete.txt');
        self::assertSame($before, $this->coreState($a), 'versi tidak naik, file kembali');
        self::assertSame($guard, $this->guarded($a));
        clearstatcache();
        self::assertFileDoesNotExist($a->root . '/app/storage/maintenance');
        self::assertSame(0, (int) $a->pdo()->query("SELECT COUNT(*) FROM migrations WHERE version = '0002_rusak'")->fetchColumn());
        self::assertSame(200, $adm->get('/produk')->status, 'situs tetap hidup setelah rollback');
        [, $status] = $this->cli($a, 'status');
        $this->assertCoreClean($status);
    }

    public function test_INT_09d_mode_pemeliharaan_503_selama_update_dan_halaman_status_hanya_admin(): void
    {
        $a = $this->boot();
        // Halaman status hanya admin.
        self::assertSame(302, $a->browser('198.51.100.95')->get('/admin/pembaruan')->status);
        $a->newUser('staf@contoh.test');
        $staf = $a->loggedIn('staf@contoh.test', '198.51.100.96');
        self::assertSame(403, $staf->get('/admin/pembaruan')->status);
        // Penanda pemeliharaan (dibuat updater saat apply) menghasilkan 503 + Retry-After untuk semua rute.
        file_put_contents($a->root . '/app/storage/maintenance', '1');
        $r = $a->browser('198.51.100.97')->get('/login');
        self::assertSame(503, $r->status);
        self::assertSame('60', $r->header('retry-after'));
        unlink($a->root . '/app/storage/maintenance');
        self::assertSame(200, $a->browser('198.51.100.98')->get('/login')->status);
    }

    /** INT-F3: manifest keluaran tools/build-release.php lolos load() dan rilis baru diff-nya bersih; vendor LICENSE dikenali. */
    public function test_INT_09e_rilis_baru_dilaporkan_bersih_oleh_status_core(): void
    {
        $a = $this->boot();
        require_once dirname(__DIR__, 3) . '/tools/build-release.php';
        $m = \releaseManifest($a->root, \releaseFiles($a->root));
        self::assertStringNotContainsString('storage', $m);
        self::assertStringContainsString('  app/core/vendor/firebase-php-jwt/LICENSE', $m);
        file_put_contents($a->root . '/MANIFEST.sha256', $m);
        [, $status] = $this->cli($a, 'status');
        self::assertStringContainsString('File core cocok dengan MANIFEST.sha256', $status);
        $this->assertCoreClean($status);
    }

    public function test_INT_09f_perubahan_penghapusan_dan_tambahan_sungguhan_terdeteksi(): void
    {
        $a = $this->boot();
        require_once dirname(__DIR__, 3) . '/tools/build-release.php';
        file_put_contents($a->root . '/MANIFEST.sha256', \releaseManifest($a->root, \releaseFiles($a->root)));
        file_put_contents($a->root . '/app/core/vendor/firebase-php-jwt/LICENSE', "diubah\n");
        unlink($a->root . '/app/core/Obsolete.txt');
        file_put_contents($a->root . '/app/core/Tambahan.php', "<?php\n");
        [, $status] = $this->cli($a, 'status');
        self::assertStringContainsString('DIUBAH: app/core/vendor/firebase-php-jwt/LICENSE', $status);
        self::assertStringContainsString('HILANG: app/core/Obsolete.txt', $status);
        self::assertStringContainsString('TAMBAHAN: app/core/Tambahan.php', $status);
        self::assertStringNotContainsString('storage', $status);
    }
}
