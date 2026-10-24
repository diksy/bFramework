<?php

declare(strict_types=1);

namespace bFramework\Tests\Upload;

use bFramework\Contracts\Dialect;
use bFramework\Contracts\Identity;
use bFramework\Core\Csrf;
use bFramework\Core\CsrfMiddleware;
use bFramework\Core\Kernel;
use bFramework\Core\RateLimiter;
use bFramework\Core\Request;
use bFramework\Core\Router;
use bFramework\Runtime\Authorizer;
use bFramework\Runtime\CacheStore;
use bFramework\Runtime\Compiler;
use bFramework\Runtime\Connection;
use bFramework\Runtime\CurrentIdentity;
use bFramework\Runtime\Definitions;
use bFramework\Runtime\HookRunner;
use bFramework\Runtime\Migrator;
use bFramework\Runtime\ModelRepository;
use bFramework\Runtime\Query;
use bFramework\Runtime\SqliteGrammar;
use bFramework\Runtime\Validator;
use bFramework\Runtime\Where;
use bFramework\Tests\Fixtures\ArraySessionStore;
use bFramework\Upload\FileController;
use bFramework\Upload\FilesTable;
use bFramework\Upload\UploadedFile;
use bFramework\Upload\UploadPolicy;
use bFramework\Upload\UploadRejected;
use bFramework\Upload\UploadService;
use PHPUnit\Framework\TestCase;

/** M12b: SEC-FILE-01..05 pada integrasi field file (definisi -> Validator -> ModelRepository -> UploadService). */
final class UploadIntegrasiTest extends TestCase
{
    private string $root;
    private Definitions $defs;
    private Connection $conn;
    private Query $mq;
    private Query $fq;
    private UploadService $svc;
    private FileController $ctl;
    private ArraySessionStore $session;
    private CurrentIdentity $cur;
    private int $n = 0;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/upi_' . bin2hex(random_bytes(6));
        $def = $this->root . '/definitions';
        mkdir($def . '/models', 0700, true);
        mkdir($def . '/pages', 0700, true);
        mkdir($this->root . '/ext', 0700, true);
        mkdir($this->root . '/in', 0700, true);
        file_put_contents($def . '/models/dokumen.json', json_encode(self::model()));
        $cache = new CacheStore($this->root . '/cache');
        $r = (new Compiler($cache, $this->root . '/ext'))->build($def, Dialect::Sqlite);
        self::assertSame([], $r->errors, json_encode($r->errors) ?: '');
        $this->defs = new Definitions($cache);
        $this->conn = Connection::sqlite($this->root . '/db.sqlite');
        $g = new SqliteGrammar();
        $m = new Migrator($this->conn, $g);
        foreach ($this->defs->tables() as $t) {
            $m->apply($m->planCreate($t));
        }
        $m->apply($m->planCreate(FilesTable::spec()));
        $this->mq = new Query($this->conn, $g, $this->defs->allowlist());
        $this->fq = new Query($this->conn, $g, FilesTable::allowlist());
        $this->svc = $this->service(['maxFilesPerOwner' => 5, 'rateMax' => 100]);
        $this->session = new ArraySessionStore();
        $this->session->start();
        $this->cur = new CurrentIdentity($this->session);
        $this->ctl = new FileController($this->svc, $this->cur, new Authorizer(), fn(string $n): ?array => $this->defs->model($n), $this->mq, ['admin']);
    }

    protected function tearDown(): void
    {
        unset($this->conn, $this->mq, $this->fq, $this->svc);
        CacheStore::rmTree($this->root);
    }

    /** @return array<string,mixed> */
    private static function model(): array
    {
        return [
            'model' => 'dokumen',
            'fields' => [
                'judul' => ['type' => 'string', 'required' => true, 'max' => 50],
                'berkas' => ['type' => 'string', 'label' => 'Berkas', 'upload' => ['mimes' => ['image/png'], 'maxBytes' => 100000]],
                'pemilik' => ['type' => 'integer', 'required' => true],
            ],
            'access' => ['read' => ['user', 'admin'], 'write' => ['user', 'admin'], 'owner' => 'pemilik', 'ownerExempt' => ['admin']],
        ];
    }

    /** @param array<string,mixed> $opts */
    private function service(array $opts): UploadService
    {
        return new UploadService(
            $this->fq,
            $this->root . '/storage/uploads',
            $opts,
            $this->root . '/public_html',
            new RateLimiter($this->root . '/rl'),
            null,
            static fn(string $f): bool => is_file($f),
            static fn(string $a, string $b): bool => rename($a, $b),
        );
    }

    private function id(int $uid, string $role = 'user'): Identity
    {
        return new Identity($uid, [$role], $role, ['pwd']);
    }

    private function as(int $uid, string $role = 'user'): void
    {
        $this->cur->set($this->id($uid, $role));
    }

    private function repo(?Identity $who, ?\bFramework\Runtime\FileRefs $files = null): ModelRepository
    {
        $d = $this->defs->model('dokumen');
        self::assertNotNull($d);
        return new ModelRepository($d, $this->mq, new Authorizer(), $who, new HookRunner($this->root . '/ext'), null, fn(string $m): ?array => $this->defs->model($m), false, null, $files ?? $this->svc);
    }

    private function png(): string
    {
        $im = imagecreatetruecolor(4, 4);
        ob_start();
        imagepng($im);
        return (string) ob_get_clean();
    }

    private function tmp(string $content, string $name = 'x.png'): UploadedFile
    {
        $f = $this->root . '/in/t' . (++$this->n);
        file_put_contents($f, $content);
        return new UploadedFile($name, $f, UPLOAD_ERR_OK, strlen($content));
    }

    private function up(int $owner): string
    {
        return $this->svc->store($this->tmp($this->png()), new UploadPolicy(['image/png'], 100000), $owner)->id;
    }

    private function fisik(string $fid): bool
    {
        return is_file($this->root . '/storage/uploads/' . $fid);
    }

    private function meta(string $fid): int
    {
        return $this->fq->count(FilesTable::NAME, new Where([['fid', '=', $fid]]));
    }

    /** @return list<string> */
    private function errs(\bFramework\Runtime\Result $r, string $f = 'berkas'): array
    {
        return $r->errors[$f] ?? [];
    }

    // ---------- SEC-FILE-02: validasi definisi saat compile ----------

    /** @param array<string,mixed> $field */
    private function compileErrors(array $field): int
    {
        $m = self::model();
        $m['fields']['berkas'] = $field;
        $def = $this->root . '/d2';
        @mkdir($def . '/models', 0700, true);
        file_put_contents($def . '/models/dokumen.json', json_encode($m));
        return count((new Compiler(new CacheStore($this->root . '/c2'), $this->root . '/ext'))->build($def, Dialect::Sqlite)->errors);
    }

    public function test_SEC_FILE_02_definisi_tak_valid_ditolak_compile(): void
    {
        $ok = ['mimes' => ['image/png'], 'maxBytes' => 1000];
        self::assertSame(0, $this->compileErrors(['type' => 'string', 'upload' => $ok]));
        $bad = [
            'svg' => ['type' => 'string', 'upload' => ['mimes' => ['image/svg+xml'], 'maxBytes' => 1000]],
            'html' => ['type' => 'string', 'upload' => ['mimes' => ['text/html'], 'maxBytes' => 1000]],
            'php' => ['type' => 'string', 'upload' => ['mimes' => ['application/x-httpd-php'], 'maxBytes' => 1000]],
            'wildcard' => ['type' => 'string', 'upload' => ['mimes' => ['image/*'], 'maxBytes' => 1000]],
            'mimes kosong' => ['type' => 'string', 'upload' => ['mimes' => [], 'maxBytes' => 1000]],
            'tanpa maxBytes' => ['type' => 'string', 'upload' => ['mimes' => ['image/png']]],
            'maxBytes terlalu besar' => ['type' => 'string', 'upload' => ['mimes' => ['image/png'], 'maxBytes' => 104857601]],
            'maxBytes nol' => ['type' => 'string', 'upload' => ['mimes' => ['image/png'], 'maxBytes' => 0]],
            'kunci asing' => ['type' => 'string', 'upload' => $ok + ['extra' => 1]],
            'bukan string' => ['type' => 'integer', 'upload' => $ok],
            'text' => ['type' => 'text', 'upload' => $ok],
            'unique' => ['type' => 'string', 'unique' => true, 'upload' => $ok],
            'default' => ['type' => 'string', 'default' => 'abc', 'upload' => $ok],
            'max' => ['type' => 'string', 'max' => 10, 'upload' => $ok],
            'bukan objek' => ['type' => 'string', 'upload' => 'ya'],
        ];
        foreach ($bad as $nama => $f) {
            self::assertGreaterThan(0, $this->compileErrors($f), $nama);
        }
    }

    public function test_SEC_FILE_02_field_upload_tak_boleh_owner_sort_filter_agregat(): void
    {
        $m = self::model();
        $m['access']['owner'] = 'berkas';
        self::assertGreaterThan(0, $this->compileWith($m, []));
        $page = static fn(array $c): array => ['page' => 'dok', 'route' => '/dok', 'title' => 'D', 'access' => ['user'], 'layout' => [$c]];
        self::assertGreaterThan(0, $this->compileWith(self::model(), $page(['component' => 'table', 'source' => ['model' => 'dokumen', 'sort' => 'berkas']])));
        self::assertGreaterThan(0, $this->compileWith(self::model(), $page(['component' => 'table', 'source' => ['model' => 'dokumen', 'filter' => ['berkas' => 'x']]])));
        self::assertGreaterThan(0, $this->compileWith(self::model(), $page(['component' => 'stat', 'agg' => 'count', 'field' => 'berkas', 'source' => ['model' => 'dokumen']])));
        self::assertSame(0, $this->compileWith(self::model(), $page(['component' => 'table', 'columns' => ['judul', 'berkas'], 'source' => ['model' => 'dokumen']])));
    }

    /**
     * @param array<string,mixed> $model
     * @param array<string,mixed> $page
     */
    private function compileWith(array $model, array $page): int
    {
        $def = $this->root . '/d3' . (++$this->n);
        mkdir($def . '/models', 0700, true);
        mkdir($def . '/pages', 0700, true);
        file_put_contents($def . '/models/dokumen.json', json_encode($model));
        if ($page !== []) {
            file_put_contents($def . '/pages/dok.json', json_encode($page));
        }
        return count((new Compiler(new CacheStore($def . '/c'), $this->root . '/ext'))->build($def, Dialect::Sqlite)->errors);
    }

    public function test_kolom_field_file_string_32_nullable(): void
    {
        $d = $this->defs->model('dokumen');
        self::assertNotNull($d);
        self::assertSame(32, $d['columns']['berkas']['length']);
        self::assertTrue($d['columns']['berkas']['nullable']);
        self::assertSame('string', $d['fields']['berkas']['type']);
    }

    // ---------- Validator ----------

    public function test_Validator_fid_harus_32_hex_kosong_jadi_null(): void
    {
        $d = $this->defs->model('dokumen');
        self::assertNotNull($d);
        [$c, $e] = Validator::validate($d, ['judul' => 'a', 'berkas' => str_repeat('a', 32), 'pemilik' => 1]);
        self::assertSame([], $e);
        self::assertSame(str_repeat('a', 32), $c['berkas']);
        foreach (['../../etc/passwd', str_repeat('A', 32), str_repeat('a', 31), str_repeat('g', 32)] as $bad) {
            [, $e] = Validator::validate($d, ['judul' => 'a', 'berkas' => $bad, 'pemilik' => 1]);
            self::assertArrayHasKey('berkas', $e, $bad);
        }
        [$c, $e] = Validator::validate($d, ['judul' => 'a', 'berkas' => '', 'pemilik' => 1]);
        self::assertSame([], $e);
        self::assertNull($c['berkas']);
    }

    // ---------- SEC-FILE-03: IDOR fid ----------

    public function test_SEC_FILE_03_klaim_fid_milik_user_lain_gagal_generik_identik_dengan_tak_ada(): void
    {
        $milikB = $this->up(2);
        $repo = $this->repo($this->id(1));
        $a = $repo->create(['judul' => 'x', 'berkas' => $milikB]);
        $b = $repo->create(['judul' => 'x', 'berkas' => str_repeat('0', 32)]);
        self::assertNull($a->id);
        self::assertNull($b->id);
        self::assertSame($this->errs($a), $this->errs($b));
        self::assertNotSame([], $this->errs($a));
        self::assertSame(0, $this->mq->count('dokumen', Where::none()));
        $meta = $this->svc->meta($milikB);
        self::assertNotNull($meta);
        self::assertNull($meta['model']); // tidak ter-attach
        self::assertSame(2, $meta['owner_id']);
    }

    public function test_SEC_FILE_03_fid_sudah_ter_attach_ditolak(): void
    {
        $fid = $this->up(1);
        $repo = $this->repo($this->id(1));
        $r = $repo->create(['judul' => 'satu', 'berkas' => $fid]);
        self::assertNotNull($r->id);
        $r2 = $repo->create(['judul' => 'dua', 'berkas' => $fid]);
        self::assertNull($r2->id);
        self::assertNotSame([], $this->errs($r2));
        self::assertSame(1, $this->mq->count('dokumen', Where::none()));
    }

    public function test_SEC_FILE_03_double_claim_hanya_satu_menang(): void
    {
        $fid = $this->up(1);
        self::assertTrue($this->svc->claim($fid, 1, 'dokumen', 10));
        self::assertFalse($this->svc->claim($fid, 1, 'dokumen', 11));
        $lain = $this->up(1);
        self::assertFalse($this->svc->claim($lain, 2, 'dokumen', 12), 'bukan pemilik');
        self::assertFalse($this->svc->claim('bukan-hex', 1, 'dokumen', 12));
        self::assertFalse($this->svc->attach($lain, 'dokumen', 12, 2), 'attach() cek kepemilikan');
        self::assertTrue($this->svc->attach($lain, 'dokumen', 12, 1));
    }

    public function test_SEC_FILE_03_race_antara_cek_dan_claim_membatalkan_baris(): void
    {
        $fid = $this->up(1);
        $real = $this->svc;
        // Penyerang meng-claim fid setelah fileErrors() lolos: simulasi lewat FileRefs yang claim-nya kalah.
        $refs = new class ($real) implements \bFramework\Runtime\FileRefs {
            public function __construct(private readonly UploadService $s)
            {
            }
            public function meta(string $fid): ?array
            {
                return $this->s->meta($fid);
            }
            public function claim(string $fid, int $userId, string $model, int $refId): bool
            {
                $this->s->claim($fid, $userId, 'dokumen', 999); // pemenang lain
                return $this->s->claim($fid, $userId, $model, $refId);
            }
            public function release(string $fid): void
            {
                $this->s->release($fid);
            }
            public function deleteForRef(string $model, int $refId): int
            {
                return $this->s->deleteForRef($model, $refId);
            }
        };
        $r = $this->repo($this->id(1), $refs)->create(['judul' => 'x', 'berkas' => $fid]);
        self::assertNull($r->id);
        self::assertNotSame([], $this->errs($r));
        self::assertSame(0, $this->mq->count('dokumen', Where::none()), 'baris dibatalkan');
    }

    public function test_SEC_FILE_03_tanpa_FileRefs_atau_anonim_nilai_file_ditolak_fail_closed(): void
    {
        $fid = $this->up(1);
        $d = $this->defs->model('dokumen');
        self::assertNotNull($d);
        $repo = new ModelRepository($d, $this->mq, new Authorizer(), $this->id(1), new HookRunner($this->root . '/ext'));
        $r = $repo->create(['judul' => 'x', 'berkas' => $fid]);
        self::assertNull($r->id);
        self::assertNotSame([], $this->errs($r));
    }

    public function test_SEC_FILE_03_mime_dan_ukuran_dicek_ke_policy_field(): void
    {
        // File teks sah untuk policy lain, tetapi bukan untuk field ini.
        $txt = $this->svc->store($this->tmp('halo', 'a.txt'), new UploadPolicy(['text/plain'], 1000), 1)->id;
        $r = $this->repo($this->id(1))->create(['judul' => 'x', 'berkas' => $txt]);
        self::assertNull($r->id);
        self::assertNotSame([], $this->errs($r));
        $besar = $this->svc->store($this->tmp($this->png()), new UploadPolicy(['image/png'], 100000), 1)->id;
        $this->fq->update(FilesTable::NAME, ['size' => 100001], new Where([['fid', '=', $besar]]));
        self::assertNull($this->repo($this->id(1))->create(['judul' => 'x', 'berkas' => $besar])->id);
    }

    // ---------- SEC-FILE-05: siklus hidup ----------

    public function test_SEC_FILE_05_create_attach_hapus_baris_menghapus_file(): void
    {
        $fid = $this->up(1);
        $repo = $this->repo($this->id(1));
        $r = $repo->create(['judul' => 'x', 'berkas' => $fid]);
        self::assertNotNull($r->id);
        $meta = $this->svc->meta($fid);
        self::assertSame(['dokumen', $r->id], [$meta['model'] ?? null, $meta['ref_id'] ?? null]);
        self::assertTrue($this->fisik($fid));
        $repo->delete($r->id);
        self::assertSame(0, $this->meta($fid));
        self::assertFalse($this->fisik($fid));
    }

    public function test_SEC_FILE_05_deleteForRef_menghapus_lebih_dari_1000(): void
    {
        $this->conn->pdo()->beginTransaction();
        for ($i = 0; $i < 1100; $i++) {
            $this->fq->insert(FilesTable::NAME, [
                'fid' => bin2hex(random_bytes(16)), 'mime' => 'image/png', 'size' => 1, 'orig_name' => null,
                'owner_id' => 1, 'model' => 'dokumen', 'ref_id' => 77, 'created_at' => time(),
            ]);
        }
        $this->conn->pdo()->commit();
        self::assertSame(1100, $this->svc->deleteForRef('dokumen', 77));
        self::assertSame(0, $this->fq->count(FilesTable::NAME, new Where([['ref_id', '=', 77]])));
    }

    public function test_SEC_FILE_05_ganti_file_lama_terhapus_tanpa_field_tetap_kosongkan_hapus(): void
    {
        $a = $this->up(1);
        $repo = $this->repo($this->id(1));
        $id = $repo->create(['judul' => 'x', 'berkas' => $a])->id;
        self::assertNotNull($id);
        // update tanpa field berkas: tetap
        self::assertTrue($repo->update($id, ['judul' => 'y'])->ok());
        self::assertTrue($this->fisik($a));
        self::assertSame($a, $repo->find($id)['berkas']);
        // kirim ulang fid yang sama: tetap
        self::assertTrue($repo->update($id, ['judul' => 'y', 'berkas' => $a])->ok());
        self::assertTrue($this->fisik($a));
        // ganti
        $b = $this->up(1);
        self::assertTrue($repo->update($id, ['judul' => 'y', 'berkas' => $b])->ok());
        self::assertFalse($this->fisik($a));
        self::assertSame(0, $this->meta($a));
        self::assertTrue($this->fisik($b));
        self::assertSame($b, $repo->find($id)['berkas']);
        // kosongkan
        self::assertTrue($repo->update($id, ['judul' => 'y', 'berkas' => ''])->ok());
        self::assertFalse($this->fisik($b));
        self::assertNull($repo->find($id)['berkas']);
    }

    public function test_SEC_FILE_05_update_dengan_fid_milik_baris_lain_ditolak(): void
    {
        $repo = $this->repo($this->id(1));
        $f1 = $this->up(1);
        $f2 = $this->up(1);
        $r1 = $repo->create(['judul' => 'a', 'berkas' => $f1])->id;
        $r2 = $repo->create(['judul' => 'b', 'berkas' => $f2])->id;
        self::assertNotNull($r1);
        self::assertNotNull($r2);
        $res = $repo->update($r2, ['judul' => 'b', 'berkas' => $f1]);
        self::assertNotSame([], $this->errs($res));
        self::assertTrue($this->fisik($f1));
        self::assertTrue($this->fisik($f2));
    }

    public function test_SEC_FILE_05_orphan_dibersihkan_yang_ter_attach_tidak(): void
    {
        $orphan = $this->up(1);
        $dipakai = $this->up(1);
        self::assertNotNull($this->repo($this->id(1))->create(['judul' => 'x', 'berkas' => $dipakai])->id);
        $baru = $this->up(1);
        $this->fq->update(FilesTable::NAME, ['created_at' => time() - 90000], new Where([['fid', 'in', [$orphan, $dipakai]]]));
        self::assertSame(1, $this->svc->purgeOrphans(86400));
        self::assertFalse($this->fisik($orphan));
        self::assertTrue($this->fisik($dipakai));
        self::assertTrue($this->fisik($baru), 'orphan baru belum kedaluwarsa');
    }

    public function test_field_file_tidak_bisa_di_sort_filter_agregat_repo(): void
    {
        $repo = $this->repo($this->id(1));
        $this->expectException(\InvalidArgumentException::class);
        $repo->normalizeSort('berkas');
    }

    // ---------- SEC-FILE-04: endpoint POST /files ----------

    /** @param array<string,mixed> $post */
    private function post(array $post, ?string $content = null, string $name = 'a.png'): \bFramework\Core\Response
    {
        $files = [];
        if ($content !== null) {
            $u = $this->tmp($content, $name);
            $files['file'] = ['name' => $u->name, 'tmp_name' => $u->tmpName, 'error' => 0, 'size' => $u->size];
        }
        return $this->ctl->upload(new Request('POST', '/files', post: $post, files: $files));
    }

    public function test_SEC_FILE_04_sukses_201_json_dan_file_milik_pengunggah_belum_ter_attach(): void
    {
        $this->as(1);
        $r = $this->post(['model' => 'dokumen', 'field' => 'berkas'], $this->png(), "evil\r\n../a.png");
        self::assertSame(201, $r->status);
        $j = json_decode($r->body, true);
        self::assertIsArray($j);
        self::assertMatchesRegularExpression('/^[a-f0-9]{32}$/D', $j['id']);
        self::assertSame('image/png', $j['mime']);
        self::assertStringNotContainsString("\n", $j['name']);
        $meta = $this->svc->meta($j['id']);
        self::assertNotNull($meta);
        self::assertSame([1, null], [$meta['owner_id'], $meta['model']]);
    }

    public function test_SEC_FILE_04_anonim_403_tanpa_hak_model_403_model_atau_field_salah_404(): void
    {
        self::assertSame(403, $this->post(['model' => 'dokumen', 'field' => 'berkas'], $this->png())->status);
        $this->as(5, 'tamu');
        self::assertSame(403, $this->post(['model' => 'dokumen', 'field' => 'berkas'], $this->png())->status);
        $this->as(1);
        self::assertSame(404, $this->post(['model' => 'dokumen', 'field' => 'judul'], $this->png())->status, 'bukan field file');
        self::assertSame(404, $this->post(['model' => 'dokumen', 'field' => 'tidak_ada'], $this->png())->status);
        self::assertSame(404, $this->post(['model' => 'tidak_ada', 'field' => 'berkas'], $this->png())->status);
        self::assertSame(404, $this->post(['model' => '../x', 'field' => 'berkas'], $this->png())->status);
        self::assertSame(404, $this->post(['model' => ['a'], 'field' => 'berkas'], $this->png())->status);
        self::assertSame([], glob($this->root . '/storage/uploads/*[0-9a-f]') ?: []);
    }

    public function test_SEC_FILE_04_tanpa_csrf_419_lewat_middleware(): void
    {
        $router = new Router();
        $this->ctl->registerRoutes($router);
        $k = new Kernel($router, [new CsrfMiddleware($router, new Csrf($this->session), $this->session)]);
        $this->as(1);
        self::assertSame(419, $k->handle(new Request('POST', '/files', post: ['model' => 'dokumen', 'field' => 'berkas']))->status);
        self::assertSame(419, $k->handle(new Request('POST', '/files', post: ['model' => 'dokumen', 'field' => 'berkas', '_csrf' => 'salah']))->status);
        $t = (new Csrf($this->session))->token();
        self::assertNotSame(419, $k->handle(new Request('POST', '/files', post: ['model' => 'dokumen', 'field' => 'berkas', '_csrf' => $t]))->status);
    }

    public function test_SEC_FILE_02_policy_dari_definisi_bukan_dari_klien(): void
    {
        $this->as(1);
        // Klien mencoba menyisipkan policy sendiri: diabaikan.
        $post = ['model' => 'dokumen', 'field' => 'berkas', 'mimes' => ['text/plain'], 'maxBytes' => 99999999, 'upload' => ['mimes' => ['text/plain']]];
        self::assertSame(422, $this->post($post, 'teks biasa', 'a.png')->status);
        self::assertSame(422, $this->post($post, "<?php system('id'); ?>", 'shell.jpg')->status);
        self::assertSame(422, $this->post($post, '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', 'a.png')->status);
        self::assertSame([], glob($this->root . '/storage/uploads/*[0-9a-f]') ?: []);
        // ukuran: policy field 100000 byte
        $im = imagecreatetruecolor(400, 400);
        for ($i = 0; $i < 4000; $i++) {
            imagesetpixel($im, random_int(0, 399), random_int(0, 399), random_int(0, 0xFFFFFF));
        }
        ob_start();
        imagepng($im, null, 0);
        $big = (string) ob_get_clean();
        self::assertGreaterThan(100000, strlen($big));
        self::assertSame(413, $this->post(['model' => 'dokumen', 'field' => 'berkas'], $big)->status);
    }

    public function test_SEC_FILE_04_rate_limit_429_dan_kuota_413(): void
    {
        $this->as(1);
        $svc = $this->service(['maxFilesPerOwner' => 100, 'rateMax' => 2, 'rateWindow' => 60]);
        $ctl = new FileController($svc, $this->cur, new Authorizer(), fn(string $n): ?array => $this->defs->model($n), $this->mq);
        $codes = [];
        for ($i = 0; $i < 3; $i++) {
            $u = $this->tmp($this->png());
            $codes[] = $ctl->upload(new Request('POST', '/files', post: ['model' => 'dokumen', 'field' => 'berkas'], files: ['file' => ['name' => 'a.png', 'tmp_name' => $u->tmpName, 'error' => 0, 'size' => $u->size]]))->status;
        }
        self::assertSame([201, 201, 429], $codes);

        $this->as(2);
        for ($i = 0; $i < 5; $i++) {
            self::assertSame(201, $this->post(['model' => 'dokumen', 'field' => 'berkas'], $this->png())->status);
        }
        self::assertSame(413, $this->post(['model' => 'dokumen', 'field' => 'berkas'], $this->png())->status);
    }

    public function test_kuota_atomik_berlaku_untuk_ownerless_dan_ditolak_tanpa_flag(): void
    {
        $p = new UploadPolicy(['image/png'], 100000);
        try {
            $this->svc->store($this->tmp($this->png()), $p, null);
            self::fail('ownerId null tanpa flag harus ditolak');
        } catch (UploadRejected $e) {
            self::assertSame(403, $e->getCode());
        }
        for ($i = 0; $i < 5; $i++) {
            $this->svc->store($this->tmp($this->png()), $p, null, null, null, true);
        }
        $this->expectException(UploadRejected::class);
        $this->svc->store($this->tmp($this->png()), $p, null, null, null, true);
    }

    public function test_kuota_berkas_ditolak_tidak_meninggalkan_file_fisik(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->up(3);
        }
        $before = glob($this->root . '/storage/uploads/*[0-9a-f]') ?: [];
        try {
            $this->up(3);
            self::fail('kuota');
        } catch (UploadRejected $e) {
            self::assertSame('quota', $e->reason);
        }
        self::assertSame(count($before), count(glob($this->root . '/storage/uploads/*[0-9a-f]') ?: []));
        self::assertDirectoryExists($this->root . '/storage/uploads/.lock');
    }

    public function test_file_besar_non_gambar_dipindai_per_potongan_tag_php_di_batas_potongan_tertangkap(): void
    {
        $isi = str_repeat('a', 1048576 - 3) . '<?php echo 1;' . str_repeat('b', 100);
        try {
            $this->svc->store($this->tmp($isi, 'x.txt'), new UploadPolicy(['text/plain'], 5000000), 1);
            self::fail('polyglot');
        } catch (UploadRejected $e) {
            self::assertSame('polyglot', $e->reason);
        }
    }

    public function test_serve_dialirkan_dari_berkas_bukan_body_di_memori(): void
    {
        $fid = $this->up(1);
        $this->as(1);
        $r = $this->ctl->serve($fid);
        self::assertSame(200, $r->status);
        self::assertSame('', $r->body);
        self::assertNotNull($r->file);
        self::assertSame((string) filesize((string) $r->file), $r->headers['Content-Length']);
        ob_start();
        $r->send();
        $out = (string) ob_get_clean();
        self::assertSame(file_get_contents($this->root . '/storage/uploads/' . $fid), $out);
    }
}
