<?php

declare(strict_types=1);

namespace bFramework\Tests\Install;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../../tools/build-release.php';

final class ReleaseZipTest extends TestCase
{
    private string $tmp;

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . '/rel_' . bin2hex(random_bytes(6));
        mkdir($this->tmp, 0700, true);
    }

    protected function tearDown(): void
    {
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->tmp, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) {
            $f->isDir() && !$f->isLink() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
        }
        @rmdir($this->tmp);
    }

    /** @return list<string> */
    private function entries(\ZipArchive $z): array
    {
        $o = [];
        for ($i = 0; $i < $z->numFiles; $i++) {
            $o[] = (string) $z->getNameIndex($i);
        }
        sort($o);
        return $o;
    }

    public function test_SEC_CONF_zip_dari_sumber_palsu_isi_tepat_tanpa_rahasia(): void
    {
        $s = $this->tmp . '/src';
        foreach (['public_html/_pc/a', 'app/core', 'app/config', 'app/storage/logs', 'app/storage/sessions', 'app/core/vendor/lib', 'public_html/assets', 'tests', 'tools', 'docs', '.git', '.claude'] as $d) {
            mkdir($s . '/' . $d, 0755, true);
        }
        $ok = ['app/bootstrap.php', 'app/.htaccess', 'app/core/A.php', 'app/core/vendor/lib/L.php', 'app/config/config.example.php',
            'app/storage/.gitkeep', 'public_html/index.php', 'public_html/.htaccess', 'public_html/assets/app.css', 'public_html/_pc/.htaccess'];
        $bad = ['app/config/config.php', 'app/.env', 'app/.env.local', 'app/storage/app.sqlite', 'app/storage/install_token', 'app/storage/installed.lock',
            'app/storage/sessions/sess_x', 'app/storage/logs/app.log', 'tests/T.php', 'tools/t.php', 'docs/spec.md', '.git/config', '.claude/s.json',
            'app/core/server.key', 'app/core/id.pem', 'public_html/.env', 'public_html/backup.sqlite', 'public_html/_pc/produk.html', 'public_html/_pc/a/b.html', 'app/storage/install_token_0123456789abcdef', 'app/storage/canary_00.txt', 'composer.json', 'public_html/.git'];
        foreach (array_merge($ok, $bad) as $f) {
            @mkdir(dirname($s . '/' . $f), 0755, true);
            file_put_contents($s . '/' . $f, "dummy $f\n");
        }
        $zipFile = $this->tmp . '/out.zip';
        buildRelease($s, $zipFile);
        $z = new \ZipArchive();
        self::assertTrue($z->open($zipFile));
        $want = array_merge($ok, ['MANIFEST.sha256']);
        sort($want);
        self::assertSame($want, $this->entries($z));
        $this->assertManifest($z);
    }

    public function test_SEC_CONF_zip_dari_repo_asli_bersih_dan_manifest_cocok(): void
    {
        $zipFile = $this->tmp . '/real.zip';
        buildRelease(__DIR__ . '/../..', $zipFile);
        $z = new \ZipArchive();
        self::assertTrue($z->open($zipFile));
        $names = $this->entries($z);
        self::assertContains('app/bootstrap.php', $names);
        self::assertContains('public_html/index.php', $names);
        self::assertContains('app/core/Install/Installer.php', $names);
        self::assertContains('MANIFEST.sha256', $names);
        foreach ($names as $n) {
            self::assertMatchesRegularExpression('#^(app|public_html)/|^MANIFEST\.sha256$#', $n);
            self::assertDoesNotMatchRegularExpression('#(^|/)(tests|tools|prototype|docs|vendor/phpunit|\.git|\.claude)(/|$)#', $n, $n);
            self::assertDoesNotMatchRegularExpression('#config/config\.php$|\.env|\.sqlite|install_token|installed\.lock|\.key$|\.pem$#', $n, $n);
        }
        $this->assertManifest($z);
    }

    public function test_S16_gerbang_rilis_kunci_placeholder_gagal_kecuali_flag_uji(): void
    {
        // Gerbang diuji dengan kunci terinjeksi, tidak bergantung pada kunci di repo.
        $bad = ['PLACEHOLDER_GANTI_DENGAN_64_HEKS', '', str_repeat('0', 64), str_repeat('z', 64), str_repeat('a', 63), str_repeat('a', 66)];
        foreach ($bad as $hex) {
            self::assertFalse(releaseKeyConfigured($hex), $hex);
            [$rc, $msg] = releaseGate($hex, false);
            self::assertSame(1, $rc, $hex);
            self::assertStringContainsString('placeholder', $msg);
            [$rc, $msg] = releaseGate($hex, true);
            self::assertSame(0, $rc, $hex);
            self::assertStringContainsString('JANGAN dirilis', $msg);
        }
        $good = bin2hex(sodium_crypto_sign_publickey(sodium_crypto_sign_keypair()));
        self::assertTrue(releaseKeyConfigured($good));
        self::assertSame([0, ''], releaseGate($good, false));
        self::assertSame([0, ''], releaseGate($good, true));

        $script = dirname(__DIR__, 3) . '/tools/build-release.php';
        $zip = $this->tmp . '/gate.zip';
        $out = [];
        exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($script) . ' --allow-placeholder-key ' . escapeshellarg($zip) . ' 2>&1', $out, $rc);
        self::assertSame(0, $rc, implode("\n", $out));
        self::assertFileExists($zip);
        $z = new \ZipArchive();
        self::assertTrue($z->open($zip));
        foreach ($this->entries($z) as $n) {
            self::assertDoesNotMatchRegularExpression('#^public_html/_pc/.+\.html$#', $n);
        }
    }

    public function test_S16_kunci_publik_repo_valid_gerbang_rilis(): void
    {
        self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/D', \bFramework\Update\UpdateKey::PUBLIC_KEY_HEX);
        self::assertTrue(\bFramework\Update\UpdateKey::configured());
        self::assertTrue(releaseKeyConfigured());
    }

    private function assertManifest(\ZipArchive $z): void
    {
        $m = (string) $z->getFromName('MANIFEST.sha256');
        $listed = [];
        foreach (explode("\n", trim($m)) as $line) {
            self::assertMatchesRegularExpression('/^[a-f0-9]{64}  \S.*$/', $line);
            [$hash, $path] = explode('  ', $line, 2);
            self::assertSame($hash, hash('sha256', (string) $z->getFromName($path)), $path);
            $listed[] = $path;
        }
        // Aturan manifest = UpdatePaths::inManifest (sama dengan CoreManifest); mis. storage/.gitkeep tidak ikut.
        $files = array_values(array_filter(
            array_diff($this->entries($z), ['MANIFEST.sha256']),
            static fn(string $f): bool => \bFramework\Update\UpdatePaths::inManifest($f),
        ));
        self::assertNotContains('app/storage/.gitkeep', $listed);
        sort($listed);
        self::assertSame($files, $listed);
    }
}
