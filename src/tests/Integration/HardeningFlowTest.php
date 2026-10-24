<?php

declare(strict_types=1);

namespace bFramework\Tests\Integration;

use bFramework\Tests\Fixtures\KernelApp;
use PHPUnit\Framework\TestCase;

/** SEC-4 S6: halaman data untuk pengguna login no-store; halaman publik anonim cache:true tetap di-cache. */
final class HardeningFlowTest extends TestCase
{
    private static KernelApp $app;

    public static function setUpBeforeClass(): void
    {
        self::$app = KernelApp::installed();
        self::$app->defineProdukOwner();
    }

    public static function tearDownAfterClass(): void
    {
        self::$app->destroy();
    }

    public function test_SEC_4_S6_halaman_login_no_store_halaman_publik_anonim_tetap_bisa_dicache(): void
    {
        $adm = self::$app->loggedIn();
        foreach (['/produk', '/katalog'] as $p) {
            $r = $adm->get($p);
            self::assertSame(200, $r->status, $p);
            self::assertStringContainsString('no-store', $r->header('cache-control'), $p);
        }
        @unlink(self::$app->root . '/public_html/_pc/katalog.html');
        $anon = self::$app->browser('198.51.100.60');
        $first = $anon->get('/katalog');
        self::assertSame(200, $first->status);
        self::assertStringNotContainsString('no-store', $first->header('cache-control'));
        clearstatcache();
        self::assertFileExists(self::$app->root . '/public_html/_pc/katalog.html');
        self::assertTrue($anon->get('/katalog')->fromStatic);
    }
}
