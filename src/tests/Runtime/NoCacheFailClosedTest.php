<?php

declare(strict_types=1);

namespace bFramework\Tests\Runtime;

use bFramework\Runtime\CacheStore;
use bFramework\Runtime\Definitions;
use bFramework\Runtime\InvalidIdentifier;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/** INT-F1: tanpa cache compile, perakitan tetap jalan tetapi akses data gagal tertutup. */
final class NoCacheFailClosedTest extends TestCase
{
    public function test_allowlist_kosong_dan_model_ditolak_tanpa_cache(): void
    {
        $dir = sys_get_temp_dir() . '/nc_' . bin2hex(random_bytes(6));
        mkdir($dir, 0700, true);
        $d = new Definitions(new CacheStore($dir));
        self::assertFalse($d->built());
        $al = $d->allowlist();
        try {
            $this->expectException(InvalidIdentifier::class);
            $al->table('produk');
        } finally {
            @rmdir($dir);
        }
    }

    public function test_definisi_tetap_melempar_tanpa_cache(): void
    {
        $dir = sys_get_temp_dir() . '/nc_' . bin2hex(random_bytes(6));
        mkdir($dir, 0700, true);
        $d = new Definitions(new CacheStore($dir));
        try {
            $this->expectException(RuntimeException::class);
            $d->routes();
        } finally {
            @rmdir($dir);
        }
    }
}
