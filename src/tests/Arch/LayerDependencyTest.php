<?php

declare(strict_types=1);

namespace bFramework\Tests\Arch;

use PHPUnit\Framework\TestCase;

final class LayerDependencyTest extends TestCase
{
    /** Setara (Auth/Upload/Cache, Install/Builder) juga tidak boleh saling `use`. Folder tak terdaftar = tes gagal. */
    private const LAYERS = ['Contracts' => 0, 'Core' => 1, 'Runtime' => 2, 'Auth' => 3, 'Upload' => 3, 'Install' => 4, 'Builder' => 4, 'Sso' => 4, 'Cache' => 3];

    public function test_ARCH_03_tidak_ada_use_dari_lapisan_bawah_ke_atas(): void
    {
        $violations = self::violations(__DIR__ . '/../../app/core');
        self::assertSame([], $violations, implode("\n", $violations));
    }

    public function test_ARCH_03_pendeteksi_menangkap_pelanggaran(): void
    {
        $dir = sys_get_temp_dir() . '/arch03_' . bin2hex(random_bytes(4));
        mkdir($dir . '/Core', 0700, true);
        file_put_contents(
            $dir . '/Core/Bad.php',
            "<?php\nnamespace bFramework\\Core;\nuse bFramework\\Runtime\\Thing;\nfinal class Bad {}\n"
        );
        $v = self::violations($dir);
        unlink($dir . '/Core/Bad.php');
        rmdir($dir . '/Core');
        rmdir($dir);
        self::assertCount(1, $v);
    }

    public function test_ARCH_03_lapisan_setara_dan_folder_tak_terdaftar_ditangkap(): void
    {
        $dir = sys_get_temp_dir() . '/arch03b_' . bin2hex(random_bytes(4));
        mkdir($dir . '/Upload', 0700, true);
        mkdir($dir . '/Aneh', 0700, true);
        file_put_contents($dir . '/Upload/Bad.php', "<?php\nnamespace bFramework\\Upload;\nuse bFramework\\Auth\\Thing;\nfinal class Bad {}\n");
        file_put_contents($dir . '/Aneh/X.php', "<?php\nfinal class X {}\n");
        $v = self::violations($dir);
        array_map('unlink', [$dir . '/Upload/Bad.php', $dir . '/Aneh/X.php']);
        rmdir($dir . '/Upload');
        rmdir($dir . '/Aneh');
        rmdir($dir);
        self::assertCount(2, $v, implode("\n", $v));
    }

    public function test_ARCH_03_runtime_tidak_use_upload(): void
    {
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(__DIR__ . '/../../app/core/Runtime', \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if ($f->getExtension() === 'php') {
                self::assertStringNotContainsString('bFramework\\Upload', (string) file_get_contents($f->getPathname()), $f->getPathname());
            }
        }
    }

    public function test_ARCH_02_setiap_file_php_app_punya_guard_APP_BOOTED(): void
    {
        $root = realpath(__DIR__ . '/../../app');
        self::assertNotFalse($root);
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            // core/vendor: pustaka pihak ketiga dipertahankan persis seperti rilis resmi (hash di decisions.md) agar dapat
            // diverifikasi; hanya mendeklarasikan kelas (tanpa efek samping) dan berada di bawah app/ yang deny-all (ARCH-01).
            if ($f->getExtension() !== 'php' || $f->getFilename() === 'bootstrap.php' || str_contains($f->getPathname(), '/core/vendor/')) {
                continue;
            }
            self::assertStringContainsString(
                "defined('APP_BOOTED') || exit;",
                (string) file_get_contents($f->getPathname()),
                $f->getPathname()
            );
        }
    }

    /** @return list<string> */
    private static function violations(string $coreDir): array
    {
        $out = [];
        $coreDir = rtrim($coreDir, '/');
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($coreDir, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if ($f->getExtension() !== 'php') {
                continue;
            }
            $rel = substr($f->getPathname(), strlen($coreDir) + 1);
            $parts = explode('/', $rel);
            $layer = $parts[0];
            if (count($parts) < 2 || $layer === 'vendor') {
                continue; // berkas di akar core/ (Autoloader) atau pustaka pihak ketiga
            }
            if (!isset(self::LAYERS[$layer])) {
                $out[] = "$rel: folder $layer tidak terdaftar di LAYERS (ARCH-03)";
                continue;
            }
            $src = (string) file_get_contents($f->getPathname());
            preg_match_all('/\\\\?bFramework\\\\([A-Za-z]+)\\\\[A-Za-z0-9_\\\\]+/', $src, $q, PREG_SET_ORDER);
            foreach ($q as $hit) {
                $target = $hit[1];
                if (!isset(self::LAYERS[$target]) || $target === $layer || self::LAYERS[$target] < self::LAYERS[$layer]) {
                    continue;
                }
                $name = ltrim($hit[0], '\\');
                $out[] = "$rel ($layer) bergantung ke lapisan atas/setara $target: $name";
            }
        }
        return array_values(array_unique($out));
    }
}
