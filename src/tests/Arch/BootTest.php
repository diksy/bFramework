<?php

declare(strict_types=1);

namespace bFramework\Tests\Arch;

use PHPUnit\Framework\TestCase;

final class BootTest extends TestCase
{
    private const SRC = __DIR__ . '/../..';

    public function test_ARCH_01_docroot_hanya_index_dan_assets(): void
    {
        $allowed = ['index.php', 'assets', '.htaccess', '_pc']; // _pc = cache halaman statis (M16)
        $found = array_values(array_diff((array) scandir(self::SRC . '/public_html'), ['.', '..']));
        self::assertSame([], array_values(array_diff($found, $allowed)));
    }

    public function test_ARCH_01_app_dikunci_deny_all(): void
    {
        $h = (string) file_get_contents(self::SRC . '/app/.htaccess');
        self::assertStringContainsString('Require all denied', $h);
        self::assertStringContainsString('Deny from all', $h);
    }

    public function test_ARCH_02_file_php_tanpa_bootstrap_tidak_mengeksekusi_kode(): void
    {
        $out = [];
        exec(
            escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(self::SRC . '/app/core/Core/Kernel.php') . ' 2>&1',
            $out
        );
        self::assertSame([], $out);
    }

    public function test_ARCH_07_request_statis_kurang_dari_2MB(): void
    {
        $script = sys_get_temp_dir() . '/arch07_' . bin2hex(random_bytes(4)) . '.php';
        file_put_contents($script, '<?php
$_SERVER = ["REQUEST_METHOD" => "GET", "REQUEST_URI" => "/", "REMOTE_ADDR" => "127.0.0.1"];
$base = memory_get_usage();
ob_start();
require ' . var_export(realpath(self::SRC . '/public_html/index.php'), true) . ';
ob_end_clean();
fwrite(STDOUT, (string) (memory_get_peak_usage() - 0));');
        $peak = (int) shell_exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($script));
        unlink($script);
        self::assertGreaterThan(0, $peak);
        self::assertLessThan(2 * 1024 * 1024, $peak);
    }

    public function test_ARCH_07_modul_dimuat_lazy(): void
    {
        $script = sys_get_temp_dir() . '/arch07b_' . bin2hex(random_bytes(4)) . '.php';
        file_put_contents($script, '<?php
require ' . var_export(realpath(self::SRC . '/app/bootstrap.php'), true) . ';
fwrite(STDOUT, class_exists("bFramework\\\\Core\\\\Router", false) ? "loaded" : "lazy");');
        $out = shell_exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($script));
        unlink($script);
        self::assertSame('lazy', $out);
    }

    public function test_ARCH_08_tanpa_composer_di_runtime(): void
    {
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(self::SRC . '/app', \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if ($f->getExtension() === 'php') {
                self::assertStringNotContainsString('vendor/autoload.php', (string) file_get_contents($f->getPathname()), $f->getPathname());
            }
        }
    }
}
