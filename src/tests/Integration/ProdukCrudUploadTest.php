<?php

declare(strict_types=1);

namespace bFramework\Tests\Integration;

use bFramework\Tests\Fixtures\KernelApp;
use bFramework\Tests\Fixtures\KernelBrowser;
use bFramework\Tests\Fixtures\KernelResp;
use PHPUnit\Framework\TestCase;

/**
 * INT-04 (F5 runtime, F3 authz owner, F6 escape, F2 header/CSRF, F10 error) dan INT-05 (F9 upload) untuk aplikasi
 * 'produk' dari definisi, lewat index.php nyata. Satu sandbox dipakai bersama; tiap tes membuat barisnya sendiri.
 */
final class ProdukCrudUploadTest extends TestCase
{
    private static KernelApp $app;
    private static KernelBrowser $a;
    private static KernelBrowser $b;
    private static KernelBrowser $adm;
    private static int $uidA;
    private static int $uidB;

    public static function setUpBeforeClass(): void
    {
        self::$app = KernelApp::installed();
        self::$app->defineProdukOwner();
        self::$uidA = self::$app->newUser('a@contoh.test');
        self::$uidB = self::$app->newUser('b@contoh.test');
        self::$a = self::$app->loggedIn('a@contoh.test', '198.51.100.11');
        self::$b = self::$app->loggedIn('b@contoh.test', '198.51.100.12');
        self::$adm = self::$app->loggedIn(KernelApp::ADMIN_EMAIL, '198.51.100.13');
    }

    public static function tearDownAfterClass(): void
    {
        self::$app->destroy();
    }

    /** @param array<string,mixed> $data */
    private function create(KernelBrowser $u, array $data): int
    {
        $u->get('/produk/baru');
        $r = $u->post('/produk', $data);
        self::assertSame(302, $r->status, "create gagal: " . implode(" ", array_map("trim", array_filter(explode("\n", strip_tags(substr($r->body, (int) strpos($r->body, "<form")))), static fn(string $l): bool => trim($l) !== ""))));
        return (int) self::$app->pdo()->query('SELECT MAX(id) FROM produk')->fetchColumn();
    }

    /** @return array<string,mixed> */
    private function row(int $id): array
    {
        $st = self::$app->pdo()->prepare('SELECT * FROM produk WHERE id = ?');
        $st->execute([$id]);
        $r = $st->fetch(\PDO::FETCH_ASSOC);
        return is_array($r) ? $r : [];
    }

    // ---------- INT-04 ----------

    public function test_INT_04a_owner_user_B_tak_bisa_baca_ubah_hapus_baris_user_A(): void
    {
        $id = $this->create(self::$a, ['nama' => 'Milik A rahasia', 'stok' => '5', 'pemilik' => (string) self::$uidB]);
        $row = $this->row($id);
        self::assertSame(self::$uidA, (int) $row['pemilik'], 'owner dipaksa dari sesi, bukan dari input');

        self::$b->get('/produk');
        self::assertSame(404, self::$b->get("/produk/$id/ubah")->status);
        $upd = self::$b->post("/produk/$id", ['nama' => 'Dibajak B', 'stok' => '1']);
        self::assertSame(404, $upd->status);
        self::assertSame(404, self::$b->post("/produk/$id/hapus")->status);
        $after = $this->row($id);
        self::assertSame('Milik A rahasia', $after['nama']);
        self::assertSame(5, (int) $after['stok']);
        self::assertStringNotContainsString('Milik A rahasia', self::$b->get('/produk')->body, 'daftar B tidak memuat baris A');
        self::assertStringContainsString('Milik A rahasia', self::$a->get('/produk')->body);
        // admin (ownerExempt) melihat baris semua orang
        self::assertStringContainsString('Milik A rahasia', self::$adm->get('/produk')->body);
        self::assertSame(200, self::$adm->get("/produk/$id/ubah")->status);

        // A boleh mengubah miliknya, dan pemilik tidak bisa dipindah lewat update.
        self::$a->get("/produk/$id/ubah");
        $ok = self::$a->post("/produk/$id", ['nama' => 'Milik A v2', 'stok' => '6', 'pemilik' => (string) self::$uidB]);
        self::assertSame(302, $ok->status);
        $row = $this->row($id);
        self::assertSame('Milik A v2', $row['nama']);
        self::assertSame(self::$uidA, (int) $row['pemilik']);
        // Hapus oleh pemilik berhasil.
        self::assertSame(302, self::$a->post("/produk/$id/hapus")->status);
        self::assertSame([], $this->row($id));
    }

    public function test_INT_04b_relasi_lintas_pemilik_ditolak(): void
    {
        self::$b->get('/produk');
        $kb = $this->createKategori(self::$b, 'Kategori milik B');
        $ka = $this->createKategori(self::$a, 'Kategori milik A');
        self::$a->get('/produk/baru');
        $before = (int) self::$app->pdo()->query('SELECT COUNT(*) FROM produk')->fetchColumn();
        $r = self::$a->post('/produk', ['nama' => 'Relasi asing', 'kategori' => (string) $kb]);
        self::assertSame(422, $r->status);
        self::assertSame($before, (int) self::$app->pdo()->query('SELECT COUNT(*) FROM produk')->fetchColumn());
        self::assertStringNotContainsString('Kategori milik B', self::$a->get('/produk/baru')->body, 'opsi relasi hanya milik sendiri');
        $id = $this->create(self::$a, ['nama' => 'Relasi sendiri', 'kategori' => (string) $ka]);
        self::assertSame($ka, (int) $this->row($id)['kategori']);
        // Update ke kategori milik B juga ditolak.
        self::$a->get("/produk/$id/ubah");
        self::assertSame(422, self::$a->post("/produk/$id", ['nama' => 'Relasi asing', 'kategori' => (string) $kb])->status);
        self::assertSame($ka, (int) $this->row($id)['kategori']);
    }

    private function createKategori(KernelBrowser $u, string $nama): int
    {
        // kategori tidak punya halaman sendiri: isi lewat model langsung (pemilik = pengguna), hanya data uji.
        $uid = $u === self::$a ? self::$uidA : self::$uidB;
        $pdo = self::$app->pdo();
        $st = $pdo->prepare('INSERT INTO kategori (nama, pemilik) VALUES (?, ?)');
        $st->execute([$nama, $uid]);
        return (int) $pdo->lastInsertId();
    }

    public function test_INT_04c_validasi_hook_dan_mass_assignment(): void
    {
        self::$a->get('/produk/baru');
        $n = static fn(): int => (int) self::$app->pdo()->query('SELECT COUNT(*) FROM produk')->fetchColumn();
        $c0 = $n();
        $empty = self::$a->post('/produk', ['nama' => '', 'stok' => '1']);
        self::assertSame(422, $empty->status);
        self::assertStringContainsString('csrf', strtolower($empty->body), 'form dirender ulang dengan token');
        self::assertSame(422, self::$a->post('/produk', ['nama' => str_repeat('x', 101)])->status);
        self::assertSame(422, self::$a->post('/produk', ['nama' => 'ok', 'stok' => '-3'])->status);
        self::assertSame(422, self::$a->post('/produk', ['nama' => 'ok', 'stok' => 'abc'])->status);
        $hook = self::$a->post('/produk', ['nama' => 'ok', 'stok' => '20000']);
        self::assertSame(422, $hook->status);
        self::assertStringContainsString('kapasitas gudang', $hook->body);
        self::assertSame($c0, $n(), 'tidak ada baris tersimpan dari input tak valid');

        // Mass assignment: id, pemilik, kolom asing, dan nilai non-fid untuk field file diabaikan/ditolak.
        $id = $this->create(self::$a, ['nama' => 'Massal', 'stok' => '2', 'id' => '9999', 'pemilik' => '1', 'isadmin' => '1', 'created_at' => '2000-01-01']);
        $row = $this->row($id);
        self::assertNotSame(9999, (int) $row['id']);
        self::assertSame(self::$uidA, (int) $row['pemilik']);
        self::assertArrayNotHasKey('isadmin', $row);
        $r = self::$a->post('/produk', ['nama' => 'Berkas liar', 'berkas' => '../../etc/passwd']);
        self::assertTrue($r->status === 422 || ($r->status === 302 && ($this->row((int) self::$app->pdo()->query('SELECT MAX(id) FROM produk')->fetchColumn())['berkas'] ?? null) !== '../../etc/passwd'));

        // Metode/id tidak valid.
        self::assertSame(404, self::$a->get('/produk/abc/ubah')->status);
        self::assertSame(404, self::$a->get('/produk/0/ubah')->status);
        self::assertSame(404, self::$a->get('/produk/99999/ubah')->status);
        // CSRF: tanpa token / token salah -> 419 dan tidak ada efek.
        self::assertSame(419, self::$a->post('/produk', ['nama' => 'Tanpa csrf'], false)->status);
        self::assertSame(419, self::$a->post('/produk', ['nama' => 'Csrf salah', '_csrf' => str_repeat('0', 64)], false)->status);
        self::assertSame(0, (int) self::$app->pdo()->query("SELECT COUNT(*) FROM produk WHERE nama IN ('Tanpa csrf','Csrf salah')")->fetchColumn());
        // Anonim: dialihkan ke login, tidak membaca data.
        $anon = self::$app->browser('198.51.100.30');
        $g = $anon->get('/produk');
        self::assertSame(302, $g->status);
        self::assertSame('/login', $g->location());
        self::assertStringNotContainsString('Massal', $g->body);
    }

    public function test_INT_04d_payload_xss_di_field_tampil_ter_escape(): void
    {
        $nama = '"><img src=x onerror=alert(1)>';
        $cat = '</textarea><script>alert("catatan")</script>';
        $id = $this->create(self::$a, ['nama' => $nama, 'catatan' => $cat, 'stok' => '1']);
        foreach (['/produk', "/produk/$id/ubah"] as $path) {
            $r = self::$a->get($path);
            self::assertSame(200, $r->status);
            self::assertStringNotContainsString('<img src=x', $r->body, $path);
            self::assertStringNotContainsString('<script>alert("catatan")', $r->body, $path);
            self::assertStringNotContainsString('</textarea><script>', $r->body, $path);
            self::assertStringContainsString('&lt;', $r->body, $path);
            self::assertSame([], $r->securityIssues());
            // Satu-satunya <script> di body hanya yang bernonce dari server (atau src= ke aset sendiri).
            preg_match_all('/<script\b([^>]*)>/i', $r->body, $m);
            foreach ($m[1] as $attrs) {
                self::assertTrue(str_contains($attrs, 'nonce=') || str_contains($attrs, 'src="/assets/'), 'script tak dikenal: ' . $attrs);
            }
        }
        // Nilai yang sama utuh di DB (escape terjadi di output, bukan merusak data).
        self::assertSame($nama, $this->row($id)['nama']);
        // Payload di query string tidak dipantulkan mentah.
        $q = self::$a->get('/produk?sort=' . rawurlencode('<script>alert(9)</script>') . '&page=' . rawurlencode('"><svg onload=1>'));
        self::assertStringNotContainsString('<script>alert(9)', $q->body);
        self::assertStringNotContainsString('<svg onload', $q->body);
    }

    public function test_INT_04e_header_keamanan_dan_nonce_di_semua_respons_termasuk_error(): void
    {
        $nonces = [];
        $rs = [];
        $rs['s200'] = self::$a->get('/produk');
        $rs['s404'] = self::$a->get('/tidak-ada-halaman');
        $rs['s404b'] = self::$a->get('/produk/99999/ubah');
        $rs['s403'] = self::$a->get('/admin/pengguna');
        $rs['s419'] = self::$a->post('/produk', ['nama' => 'x'], false);
        $rs['s302'] = self::$app->browser('198.51.100.31')->get('/produk');
        $rs['slogin'] = self::$app->browser('198.51.100.32')->get('/login');
        // Host asing: 400 dan tetap membawa header.
        $rs['s400'] = self::$app->send('GET', '/produk', [], [], ['Host' => 'evil.example'], true);
        // 500: rusak tabel sementara lalu pulihkan.
        $pdo = self::$app->pdo();
        $pdo->exec('ALTER TABLE produk RENAME TO produk_x');
        try {
            $rs['s500'] = self::$a->get('/produk');
        } finally {
            $pdo->exec('ALTER TABLE produk_x RENAME TO produk');
        }
        $expect = ['s200' => 200, 's404' => 404, 's404b' => 404, 's403' => 403, 's419' => 419, 's302' => 302, 'slogin' => 200, 's500' => 500];
        foreach ($rs as $k => $r) {
            if ($k !== 's400') {
                self::assertSame($expect[$k], $r->status, $k);
            }
            self::assertSame([], $r->securityIssues(), "respons $k: " . implode(',', $r->securityIssues()));
            preg_match("/nonce-([a-f0-9]{32})/", $r->header('content-security-policy'), $m);
            $nonces[] = $m[1] ?? '';
        }
        self::assertSame(400, $rs['s400']->status);
        self::assertSame(count($nonces), count(array_unique($nonces)), 'nonce unik per respons');
        // 500 generik: tanpa detail internal.
        $body500 = $rs['s500']->body;
        foreach (['SQLSTATE', 'PDOException', 'produk_x', '.php', 'Stack trace', '/storage/', 'no such table'] as $leak) {
            self::assertStringNotContainsString($leak, $body500, 'kebocoran di 500: ' . $leak);
        }
        self::assertStringContainsString('Terjadi kesalahan', $body500);
        self::assertStringContainsString('"lvl":"error"', self::$app->appLog());
        self::assertSame(200, self::$a->get('/produk')->status, 'pulih setelah tabel dikembalikan');
        // X-Powered-By tidak membocorkan versi PHP (bila diset oleh SAPI, harus kosong di produksi).
    }

    // ---------- INT-05 ----------

    private function png(): string
    {
        $im = imagecreatetruecolor(8, 8);
        ob_start();
        imagepng($im);
        $d = (string) ob_get_clean();
        $f = self::$app->root . '/in_' . bin2hex(random_bytes(4)) . '.png';
        file_put_contents($f, $d);
        return $f;
    }

    private function upload(KernelBrowser $u, string $path, string $field = 'berkas'): KernelResp
    {
        $u->get('/produk/baru');
        return $u->request('POST', '/files', ['model' => 'produk', 'field' => $field, '_csrf' => $u->csrf], false, ['file' => $path]);
    }

    /** @return list<string> */
    private function uploadFiles(): array
    {
        return array_values(array_map('basename', array_filter(glob(self::$app->root . '/app/storage/uploads/*') ?: [], 'is_file')));
    }

    public function test_INT_05a_upload_form_fid_serve_dengan_izin_dan_hapus_baris_menghapus_file(): void
    {
        $r = $this->upload(self::$a, $this->png());
        self::assertSame(201, $r->status, $r->body);
        /** @var array{id:string,mime:string} $j */
        $j = json_decode($r->body, true);
        self::assertSame('image/png', $j['mime']);
        $fid = $j['id'];
        self::assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $fid);
        self::assertContains($fid, $this->uploadFiles(), 'berkas ada di storage/uploads (luar docroot)');
        self::assertSame([], glob(self::$app->root . '/public_html/*' . $fid . '*') ?: []);

        // Sebelum dilampirkan: hanya pengunggah (atau admin).
        $own = self::$a->get('/files/' . $fid);
        self::assertSame(200, $own->status);
        self::assertSame('image/png', $own->header('content-type'));
        self::assertSame('nosniff', $own->header('x-content-type-options'));
        self::assertStringStartsWith("\x89PNG", $own->body);
        self::assertSame(404, self::$b->get('/files/' . $fid)->status);
        self::assertSame(404, self::$app->browser('198.51.100.33')->get('/files/' . $fid)->status, 'anonim 404 seragam');

        // Lampirkan lewat form dengan fid.
        $id = $this->create(self::$a, ['nama' => 'Dengan berkas', 'berkas' => $fid]);
        self::assertSame($fid, $this->row($id)['berkas']);
        $meta = self::$app->pdo()->query("SELECT model, ref_id FROM files WHERE fid = '$fid'")->fetch(\PDO::FETCH_ASSOC);
        self::assertSame(['model' => 'produk', 'ref_id' => $id], $meta);
        self::assertSame(200, self::$a->get('/files/' . $fid)->status);
        self::assertSame(404, self::$b->get('/files/' . $fid)->status, 'user lain: scope owner baris induk');
        self::assertSame(200, self::$adm->get('/files/' . $fid)->status);
        self::assertStringContainsString('/files/' . $fid, self::$a->get("/produk/$id/ubah")->body);

        // fid milik orang lain tidak bisa dilampirkan ke baris sendiri.
        $other = $this->upload(self::$b, $this->png());
        /** @var array{id:string} $oj */
        $oj = json_decode($other->body, true);
        self::$a->get('/produk/baru');
        $steal = self::$a->post('/produk', ['nama' => 'Curi fid', 'berkas' => $oj['id']]);
        self::assertSame(422, $steal->status);
        self::assertSame(0, (int) self::$app->pdo()->query("SELECT COUNT(*) FROM produk WHERE nama = 'Curi fid'")->fetchColumn());

        // Hapus baris -> metadata dan berkas fisik hilang; serve 404.
        self::assertSame(302, self::$a->post("/produk/$id/hapus")->status);
        self::assertNotContains($fid, $this->uploadFiles());
        self::assertSame(0, (int) self::$app->pdo()->query("SELECT COUNT(*) FROM files WHERE fid = '$fid'")->fetchColumn());
        self::assertSame(404, self::$a->get('/files/' . $fid)->status);
    }

    /** Bug: SecurityHeaders menimpa CSP `default-src 'none'; sandbox` milik FileController pada respons /files/{id}. */
    public function test_INT_05c_serve_file_mempertahankan_csp_sandbox(): void
    {
        $r = $this->upload(self::$a, $this->png());
        /** @var array{id:string} $j */
        $j = json_decode($r->body, true);
        $own = self::$a->get('/files/' . $j['id']);
        self::assertSame(200, $own->status);
        self::assertStringContainsString('sandbox', $own->header('content-security-policy'));
    }

    public function test_INT_05b_webshell_dan_jenis_terlarang_ditolak(): void
    {
        $before = $this->uploadFiles();
        $dir = self::$app->root;
        $cases = [];
        file_put_contents($dir . '/shell.php', '<?php system($_GET["c"]); ?>');
        $cases['php'] = $dir . '/shell.php';
        file_put_contents($dir . '/shell.png', '<?php system($_GET["c"]); ?>');
        $cases['php-berekstensi-png'] = $dir . '/shell.png';
        file_put_contents($dir . '/x.svg', '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
        $cases['svg'] = $dir . '/x.svg';
        file_put_contents($dir . '/x.html', '<html><script>alert(1)</script></html>');
        $cases['html'] = $dir . '/x.html';
        foreach ($cases as $name => $f) {
            $r = $this->upload(self::$a, $f);
            self::assertGreaterThanOrEqual(400, $r->status, $name);
            self::assertLessThan(500, $r->status, $name);
            self::assertStringNotContainsString('"id"', $r->body, $name);
        }
        self::assertSame($before, $this->uploadFiles(), 'tidak ada berkas tersimpan dari unggahan terlarang');
        self::assertSame([], glob($dir . '/public_html/*.php') === false ? [] : array_values(array_diff(array_map('basename', glob($dir . '/public_html/*.php') ?: []), ['index.php'])));
        // field yang bukan field file / model tak dikenal / tanpa login / tanpa CSRF
        self::assertSame(404, $this->upload(self::$a, $this->png(), 'nama')->status);
        $u = self::$app->browser('198.51.100.34');
        $u->get('/login');
        self::assertSame(403, $u->request('POST', '/files', ['model' => 'produk', 'field' => 'berkas', '_csrf' => $u->csrf], false, ['file' => $this->png()])->status);
        self::assertSame(419, self::$a->request('POST', '/files', ['model' => 'produk', 'field' => 'berkas'], false, ['file' => $this->png()])->status);
        // Path traversal pada id.
        self::assertSame(404, self::$a->get('/files/..%2f..%2fconfig%2fconfig.php')->status);
        self::assertSame(404, self::$a->get('/files/' . str_repeat('a', 32))->status);
    }
}
