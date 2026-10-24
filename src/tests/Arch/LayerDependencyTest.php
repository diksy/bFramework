<?php

declare(strict_types=1);

namespace bFramework\Tests\Arch;

use PHPUnit\Framework\TestCase;

final class LayerDependencyTest extends TestCase
{
    private const LAYERS = ['Contracts' => 0, 'Core' => 1, 'Runtime' => 2, 'Auth' => 3, 'Builder' => 4];

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

    public function test_ARCH_02_setiap_file_php_app_punya_guard_APP_BOOTED(): void
    {
        $root = realpath(__DIR__ . '/../../app');
        self::assertNotFalse($root);
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if ($f->getExtension() !== 'php' || $f->getFilename() === 'bootstrap.php') {
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
            $layer = explode('/', $rel)[0];
            if (!isset(self::LAYERS[$layer])) {
                continue;
            }
            $src = (string) file_get_contents($f->getPathname());
            preg_match_all('/\\\\?bFramework\\\\([A-Za-z]+)\\\\[A-Za-z0-9_\\\\]+/', $src, $q, PREG_SET_ORDER);
            foreach ($q as $hit) {
                $target = $hit[1];
                if (!isset(self::LAYERS[$target]) || self::LAYERS[$target] <= self::LAYERS[$layer]) {
                    continue;
                }
                $name = ltrim($hit[0], '\\');
                $out[] = "$rel ($layer) bergantung ke lapisan atas $target: $name";
            }
        }
        return array_values(array_unique($out));
    }
}
