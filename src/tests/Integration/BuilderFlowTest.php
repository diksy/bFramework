<?php

declare(strict_types=1);

namespace bFramework\Tests\Integration;

use bFramework\Tests\Fixtures\KernelApp;
use bFramework\Tests\Fixtures\KernelBrowser;
use PHPUnit\Framework\TestCase;

/** INT-07 (F15 builder, F7 compile cache, F4 migrasi, F5 runtime): builder dev lewat index.php nyata. */
final class BuilderFlowTest extends TestCase
{
    private static KernelApp $app;
    private static KernelBrowser $adm;

    public static function setUpBeforeClass(): void
    {
        self::$app = KernelApp::installed();
        self::$app->newUser('staf@contoh.test');
        self::$adm = self::$app->loggedIn();
    }

    public static function tearDownAfterClass(): void
    {
        self::$app->destroy();
    }

    protected function setUp(): void
    {
        self::$app->mergeConfig(['APP_ENV' => 'production']);
    }

    private function dev(): void
    {
        self::$app->mergeConfig(['APP_ENV' => 'dev']);
        self::$adm->get('/_builder'); // ambil token CSRF
    }

    /** @param array<string,mixed> $data */
    private function save(string $kind, string $name, array $data, string $base = '', bool $confirm = false): \bFramework\Tests\Fixtures\KernelResp
    {
        return self::$adm->json('POST', '/_builder/api/save', ['kind' => $kind, 'name' => $name, 'data' => $data, 'baseHash' => $base, 'confirmLoss' => $confirm]);
    }

    private function fileHash(string $kind, string $name): string
    {
        $f = self::$app->root . "/app/definitions/$kind/$name.json";
        clearstatcache();
        return is_file($f) ? hash('sha256', (string) file_get_contents($f)) : '';
    }

    /** @return list<string> */
    private function columns(string $table): array
    {
        return array_map(static fn(array $c): string => (string) $c['name'], self::$app->pdo()->query("PRAGMA table_info($table)")->fetchAll(\PDO::FETCH_ASSOC));
    }

    public function test_INT_07a_produksi_builder_404_untuk_semua_termasuk_admin(): void
    {
        $adm = self::$adm;
        $adm->get('/');
        foreach (['/_builder', '/_builder/login', '/_builder/api/state', '/_builder/api/etag'] as $p) {
            $r = $adm->get($p);
            self::assertSame(404, $r->status, $p);
            self::assertSame([], $r->securityIssues(), $p);
            self::assertStringNotContainsString('builder', strtolower(strip_tags($r->body)), $p . ' tidak membocorkan keberadaan builder');
        }
        $before = $this->fileHash('models', 'produk');
        $r = $adm->json('POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => ['model' => 'produk', 'fields' => ['x' => ['type' => 'string']]], 'baseHash' => $before]);
        self::assertSame(404, $r->status);
        self::assertSame($before, $this->fileHash('models', 'produk'), 'definisi tak berubah');
        self::assertSame(404, self::$app->browser('198.51.100.90')->get('/_builder')->status);
        // Opsi "unsafe" saja (tanpa whitelist IP dan hash password) tidak cukup.
        self::$app->mergeConfig(['builder' => ['unsafeBuilderInProduction' => true]]);
        self::assertSame(404, $adm->get('/_builder')->status);
        self::$app->mergeConfig(['builder' => ['unsafeBuilderInProduction' => false]]);
        // Nilai APP_ENV tidak dikenal = produksi (fail-closed).
        foreach (['Production', 'staging', 'devel', ''] as $env) {
            self::$app->mergeConfig(['APP_ENV' => $env]);
            self::assertSame(404, $adm->get('/_builder')->status, "APP_ENV=$env");
        }
    }

    public function test_INT_07b_mode_dev_hanya_admin_login_yang_boleh(): void
    {
        $this->dev();
        $anon = self::$app->browser('198.51.100.91');
        self::assertSame(302, $anon->get('/_builder')->status);
        self::assertSame(401, $anon->get('/_builder/api/state')->status);
        $staf = self::$app->loggedIn('staf@contoh.test', '198.51.100.92');
        self::assertSame(403, $staf->get('/_builder')->status);
        self::assertSame(403, $staf->get('/_builder/api/state')->status);
        $r = self::$adm->get('/_builder');
        self::assertSame(200, $r->status);
        self::assertSame([], $r->securityIssues());
        $st = self::$adm->get('/_builder/api/state');
        self::assertSame(200, $st->status);
        /** @var array{models:array<string,mixed>,dev:bool} $j */
        $j = json_decode($st->body, true);
        self::assertTrue($j['dev']);
        self::assertArrayHasKey('produk', $j['models']);
        // Tanpa CSRF: 419 dan tidak ada efek.
        $before = $this->fileHash('models', 'produk');
        $x = self::$app->send('POST', '/_builder/api/save', [], [], ['Cookie' => 'bf_sid=' . (self::$adm->sessionId() ?? ''), 'X-Int-Remote' => '198.51.100.10'], false, '{"kind":"model","name":"produk","data":{},"baseHash":""}');
        self::assertSame(419, $x->status);
        self::assertSame($before, $this->fileHash('models', 'produk'));
    }

    public function test_INT_07c_buat_model_baru_migrasi_compile_dan_dipakai_halaman(): void
    {
        $this->dev();
        $model = [
            'model' => 'pelanggan',
            'fields' => ['nama' => ['type' => 'string', 'label' => 'Nama', 'required' => true, 'max' => 50]],
            'access' => ['read' => ['admin'], 'write' => ['admin']],
        ];
        $prev = self::$adm->json('POST', '/_builder/api/migration', ['kind' => 'model', 'name' => 'pelanggan', 'data' => $model, 'baseHash' => '']);
        self::assertSame(200, $prev->status, $prev->body);
        self::assertStringContainsString('CREATE TABLE', $prev->body);
        self::assertSame([], $this->columns('pelanggan'), 'pratinjau tidak mengubah DB');
        self::assertFalse(is_file(self::$app->root . '/app/definitions/models/pelanggan.json'));

        $r = $this->save('model', 'pelanggan', $model);
        self::assertSame(200, $r->status, $r->body);
        self::assertContains('nama', $this->columns('pelanggan'));
        self::assertNotSame('', $this->fileHash('models', 'pelanggan'));
        $page = ['page' => 'daftar-pelanggan', 'route' => '/pelanggan', 'title' => 'Pelanggan', 'access' => ['admin'],
            'layout' => [['component' => 'table', 'span' => 12, 'actions' => ['edit', 'hapus'], 'columns' => ['nama'], 'source' => ['model' => 'pelanggan', 'perPage' => 10]]]];
        $rp = $this->save('page', 'daftar-pelanggan', $page);
        self::assertSame(200, $rp->status, $rp->body);

        // Model baru langsung berfungsi lewat runtime (compile otomatis).
        $adm = self::$adm;
        self::assertSame(200, $adm->get('/pelanggan')->status);
        $adm->get('/pelanggan/baru');
        self::assertSame(302, $adm->post('/pelanggan', ['nama' => 'Budi Dummy'])->status);
        self::assertStringContainsString('Budi Dummy', $adm->get('/pelanggan')->body);
        self::assertSame(422, $adm->post('/pelanggan', ['nama' => ''])->status);
        self::assertSame(1, (int) self::$app->pdo()->query('SELECT COUNT(*) FROM pelanggan')->fetchColumn());
        // Menu navigasi memuat halaman baru.
        self::assertStringContainsString('href="/pelanggan"', $adm->get('/produk')->body);
        // Audit tercatat.
        $audit = (string) self::$app->pdo()->query("SELECT GROUP_CONCAT(action) FROM audit_log")->fetchColumn();
        self::assertStringContainsString('builder.save', $audit);

        // Tambah field -> ALTER (data lama utuh).
        $hash = $this->fileHash('models', 'pelanggan');
        $model['fields']['telepon'] = ['type' => 'string', 'label' => 'Telepon', 'max' => 20];
        $r2 = $this->save('model', 'pelanggan', $model, $hash);
        self::assertSame(200, $r2->status, $r2->body);
        self::assertContains('telepon', $this->columns('pelanggan'));
        self::assertSame('Budi Dummy', self::$app->pdo()->query('SELECT nama FROM pelanggan')->fetchColumn());

        // Hapus field = berpotensi kehilangan data: butuh konfirmasi (409), file tak berubah; dengan konfirmasi berhasil.
        $hash = $this->fileHash('models', 'pelanggan');
        unset($model['fields']['telepon']);
        $loss = $this->save('model', 'pelanggan', $model, $hash);
        self::assertSame(409, $loss->status);
        self::assertStringContainsString('confirm_loss', $loss->body);
        self::assertSame($hash, $this->fileHash('models', 'pelanggan'));
        self::assertContains('telepon', $this->columns('pelanggan'));
        self::assertSame(200, $this->save('model', 'pelanggan', $model, $hash, true)->status);
        self::assertNotContains('telepon', $this->columns('pelanggan'));
    }

    public function test_INT_07d_konflik_hash_409_dan_hash_basi_ditolak(): void
    {
        $this->dev();
        $m = ['model' => 'catatan_x', 'fields' => ['judul' => ['type' => 'string', 'max' => 30]], 'access' => ['read' => ['admin'], 'write' => ['admin']]];
        self::assertSame(200, $this->save('model', 'catatan_x', $m)->status);
        $h1 = $this->fileHash('models', 'catatan_x');
        // Berkas diubah di luar builder (mis. editor / git pull).
        $f = self::$app->root . '/app/definitions/models/catatan_x.json';
        $ext = $m;
        $ext['fields']['dari_luar'] = ['type' => 'string', 'max' => 10];
        file_put_contents($f, json_encode($ext));
        $disk = (string) file_get_contents($f);
        $m['fields']['dari_builder'] = ['type' => 'string', 'max' => 10];
        $r = $this->save('model', 'catatan_x', $m, $h1);
        self::assertSame(409, $r->status);
        self::assertStringContainsString('conflict', $r->body);
        self::assertSame($disk, (string) file_get_contents($f), 'perubahan luar tidak ditimpa');
        self::assertNotContains('dari_builder', $this->columns('catatan_x'));
        // Membuat berkas baru dengan nama yang sudah ada (baseHash kosong) juga konflik.
        self::assertSame(409, $this->save('model', 'catatan_x', $m, '')->status);
        // Hash tak berformat ditolak 422.
        self::assertSame(422, $this->save('model', 'catatan_x', $m, 'bukan-hash')->status);
        // Dengan hash terkini berhasil.
        self::assertSame(200, $this->save('model', 'catatan_x', $m, hash('sha256', $disk))->status);
    }

    public function test_INT_07e_hook_berbahaya_dan_nama_dicadangkan_ditolak(): void
    {
        $this->dev();
        file_put_contents(self::$app->root . '/app/extensions/EvilHooks.php', "<?php\n\ndeclare(strict_types=1);\n\ndefined('APP_BOOTED') || exit;\n\nfinal class EvilHooks\n{\n    /** @param array<string,mixed> \$d @return list<string> */\n    public static function jahat(array \$d): array\n    {\n        system('id');\n        return [];\n    }\n}\n");
        $st = json_decode(self::$adm->get('/_builder/api/state')->body, true);
        $evil = array_values(array_filter($st['hooks'], static fn(array $h): bool => $h['class'] === 'EvilHooks'));
        self::assertTrue($evil[0]['blocked'] ?? false, 'scanner menandai kelas berbahaya');

        $m = ['model' => 'barang', 'fields' => ['nama' => ['type' => 'string', 'max' => 30]], 'hooks' => ['beforeSave' => 'EvilHooks::jahat'], 'access' => ['read' => ['admin'], 'write' => ['admin']]];
        $r = $this->save('model', 'barang', $m);
        self::assertSame(422, $r->status);
        self::assertStringContainsString('berbahaya', $r->body);
        self::assertSame('', $this->fileHash('models', 'barang'), 'definisi tidak ditulis');
        self::assertSame([], $this->columns('barang'));
        // Hook ke kelas/method tak ada atau berformat aneh.
        foreach (['TidakAda::x', '../../etc/passwd', 'ProdukHooks::tidakAda', 'system'] as $ref) {
            $m['hooks'] = ['beforeSave' => $ref];
            self::assertGreaterThanOrEqual(400, $this->save('model', 'barang', $m)->status, $ref);
        }
        self::assertSame('', $this->fileHash('models', 'barang'));
        // Hook sah diterima.
        $m['hooks'] = ['beforeSave' => 'ProdukHooks::validasiStok'];
        self::assertSame(200, $this->save('model', 'barang', $m)->status);

        // Nama dicadangkan / traversal.
        foreach (['users', 'roles', 'files', 'bf_x', 'audit_log'] as $name) {
            $mm = ['model' => $name, 'fields' => ['a' => ['type' => 'string']], 'access' => ['read' => ['admin'], 'write' => ['admin']]];
            self::assertGreaterThanOrEqual(400, $this->save('model', $name, $mm)->status, $name);
            self::assertSame('', $this->fileHash('models', $name));
        }
        self::assertSame(422, $this->save('model', '../../app/config/config', ['model' => 'x', 'fields' => []])->status);
        self::assertSame(1, (int) self::$app->pdo()->query('SELECT COUNT(*) FROM users WHERE id = 1')->fetchColumn());
        // Rute halaman dicadangkan ditolak.
        $p = ['page' => 'cadangan', 'route' => '/admin/x', 'title' => 'x', 'access' => ['admin'], 'layout' => [['component' => 'table', 'span' => 12, 'columns' => ['nama'], 'source' => ['model' => 'barang']]]];
        self::assertGreaterThanOrEqual(400, $this->save('page', 'cadangan', $p)->status);
    }
}
