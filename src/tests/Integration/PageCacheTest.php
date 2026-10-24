<?php

declare(strict_types=1);

namespace bFramework\Tests\Integration;

use bFramework\Tests\Fixtures\KernelApp;
use bFramework\Tests\Fixtures\KernelBrowser;
use PHPUnit\Framework\TestCase;

/** INT-06 (F8 cache halaman, F5 runtime, F3 sesi): halaman publik `cache: true` lewat index.php nyata. */
final class PageCacheTest extends TestCase
{
    private static KernelApp $app;
    private static KernelBrowser $adm;

    public static function setUpBeforeClass(): void
    {
        self::$app = KernelApp::installed();
        self::$app->defineProdukOwner();
        self::$adm = self::$app->loggedIn();
    }

    public static function tearDownAfterClass(): void
    {
        self::$app->destroy();
    }

    private function pc(string $name = 'katalog'): string
    {
        return self::$app->root . '/public_html/_pc/' . $name . '.html';
    }

    private function cached(): bool
    {
        clearstatcache();
        return is_file($this->pc());
    }

    private function anon(): KernelBrowser
    {
        return self::$app->browser('198.51.100.40');
    }

    private function adminArtikel(string $judul): void
    {
        self::$adm->get('/kelola-artikel/baru');
        $r = self::$adm->post('/kelola-artikel', ['judul' => $judul]);
        self::assertSame(302, $r->status, substr(strip_tags($r->body), 0, 200));
    }

    public function test_INT_06_halaman_publik_dilayani_dari_cache_tanpa_php_dan_terhapus_saat_data_berubah(): void
    {
        $app = self::$app;
        @unlink($this->pc());
        $b = $this->anon();
        $hits0 = $app->phpHits;
        $first = $b->get('/katalog');
        self::assertSame(200, $first->status);
        self::assertSame($hits0 + 1, $app->phpHits);
        self::assertSame([], $first->headers['set-cookie'] ?? [], 'halaman anonim ber-cache tidak membuat sesi/cookie');
        self::assertTrue($this->cached(), 'halaman disimpan ke _pc');
        self::assertStringNotContainsString('name="_csrf"', (string) file_get_contents($this->pc()));
        self::assertStringNotContainsString('Keluar', (string) file_get_contents($this->pc()));
        self::assertSame([], $first->securityIssues());

        // Permintaan kedua: dari berkas statis (tanpa PHP).
        $hits = $app->phpHits;
        $second = $b->get('/katalog');
        self::assertTrue($second->fromStatic);
        self::assertSame($hits, $app->phpHits, 'tidak ada request ke PHP');
        self::assertSame(200, $second->status);
        self::assertStringContainsString('Katalog', $second->body);
        self::assertStringNotContainsString('Artikel Satu', $second->body);

        // Ubah data lewat CRUD admin -> cache terhapus (CACHE-13) dan halaman berikutnya memuat data baru.
        $this->adminArtikel('Artikel Satu');
        self::assertFalse($this->cached(), 'cache harus dihapus saat model sumber berubah');
        $third = $b->get('/katalog');
        self::assertFalse($third->fromStatic);
        self::assertStringContainsString('Artikel Satu', $third->body);
        self::assertTrue($this->cached());
        self::assertTrue($b->get('/katalog')->fromStatic);

        // Update dan hapus juga menginvalidasi.
        $id = (int) $app->pdo()->query("SELECT id FROM artikel WHERE judul = 'Artikel Satu'")->fetchColumn();
        self::$adm->get("/kelola-artikel/$id/ubah");
        self::assertSame(302, self::$adm->post("/kelola-artikel/$id", ['judul' => 'Artikel Satu Revisi'])->status);
        self::assertFalse($this->cached());
        self::assertStringContainsString('Artikel Satu Revisi', $b->get('/katalog')->body);
        self::assertTrue($this->cached());
        self::assertSame(302, self::$adm->post("/kelola-artikel/$id/hapus")->status);
        self::assertFalse($this->cached());
        self::assertStringNotContainsString('Artikel Satu Revisi', $b->get('/katalog')->body);
    }

    public function test_INT_06b_halaman_ber_login_tak_pernah_di_cache_dan_tidak_melayani_dari_cache(): void
    {
        $app = self::$app;
        @unlink($this->pc());
        // Admin ber-sesi membuka halaman publik: dilayani PHP, tidak disimpan ke cache.
        $r = self::$adm->get('/katalog');
        self::assertSame(200, $r->status);
        self::assertFalse($r->fromStatic);
        self::assertFalse($this->cached(), 'respons untuk pengguna login tidak boleh dicache');
        // Isi cache anonim ada; permintaan ber-cookie sesi tetap ke PHP (aturan .htaccess).
        $this->anon()->get('/katalog');
        self::assertTrue($this->cached());
        $hits = $app->phpHits;
        $withSession = self::$adm->get('/katalog');
        self::assertFalse($withSession->fromStatic);
        self::assertSame($hits + 1, $app->phpHits);
        self::assertStringContainsString('Keluar', $withSession->body, 'pengguna login mendapat halaman personal, bukan cache');
        // Query string dan POST juga tidak dari cache.
        self::assertFalse($this->anon()->get('/katalog?x=1')->fromStatic);
        // Hanya halaman access '*' + cache:true yang pernah ditulis ke _pc.
        foreach (['/produk', '/kelola-artikel', '/admin/pengguna', '/login'] as $p) {
            $this->anon()->get($p);
            clearstatcache();
            self::assertFalse(is_file($this->pc(trim($p, '/'))), "$p tidak boleh di-cache");
        }
        self::$adm->get('/produk');
        self::$adm->get('/kelola-artikel');
        $files = array_map('basename', glob(self::$app->root . '/public_html/_pc/*.html') ?: []);
        self::assertSame(['katalog.html'], $files);
        // Rute cache tidak memperluas akses: path traversal ke _pc ditolak.
        self::assertSame(404, self::$app->send('GET', '/_pc/katalog.html', [], [], ['X-Int-Remote' => '198.51.100.41'], true)->status, 'PHP tidak melayani _pc langsung');
    }

    public function test_INT_06c_ubah_definisi_halaman_membuang_semua_cache(): void
    {
        $this->anon()->get('/katalog');
        self::assertTrue($this->cached());
        $adm = self::$adm;
        $adm->get('/');
        // Hanya bisa lewat builder (mode dev); aktifkan dev sementara.
        self::$app->mergeConfig(['APP_ENV' => 'dev']);
        try {
            $adm->get('/_builder');
            [$data, $hash] = $this->readDef('pages', 'katalog');
            $data['title'] = 'Katalog Baru';
            $r = $adm->json('POST', '/_builder/api/save', ['kind' => 'page', 'name' => 'katalog', 'data' => $data, 'baseHash' => $hash]);
            self::assertSame(200, $r->status, $r->body);
        } finally {
            self::$app->mergeConfig(['APP_ENV' => 'production']);
        }
        self::assertFalse($this->cached(), 'compile ulang membuang cache halaman');
        self::assertStringContainsString('Katalog Baru', $this->anon()->get('/katalog')->body);
    }

    /** @return array{0:array<string,mixed>,1:string} */
    private function readDef(string $kind, string $name): array
    {
        $f = self::$app->root . "/app/definitions/$kind/$name.json";
        $raw = (string) file_get_contents($f);
        /** @var array<string,mixed> $d */
        $d = json_decode($raw, true);
        return [$d, hash('sha256', $raw)];
    }
}
