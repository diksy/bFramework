<?php

declare(strict_types=1);

namespace bFramework\Tests\Runtime;

use bFramework\Contracts\Action;
use bFramework\Contracts\Dialect;
use bFramework\Contracts\Forbidden;
use bFramework\Contracts\Identity;
use bFramework\Contracts\NotFound;
use bFramework\Core\Config;
use bFramework\Core\Csrf;
use bFramework\Core\Request;
use bFramework\Core\Router;
use bFramework\Core\Template;
use bFramework\Runtime\Authorizer;
use bFramework\Runtime\CacheStore;
use bFramework\Runtime\Compiler;
use bFramework\Runtime\ComponentRenderer;
use bFramework\Runtime\CurrentIdentity;
use bFramework\Runtime\Definitions;
use bFramework\Runtime\Format;
use bFramework\Runtime\HookError;
use bFramework\Runtime\HookRejected;
use bFramework\Runtime\HookRunner;
use bFramework\Runtime\Migrator;
use bFramework\Runtime\ModelRepository;
use bFramework\Runtime\Navigation;
use bFramework\Runtime\PageController;
use bFramework\Runtime\Query;
use bFramework\Runtime\Connection;
use bFramework\Runtime\SqliteGrammar;
use bFramework\Runtime\Validator;
use bFramework\Runtime\Where;
use bFramework\Tests\Fixtures\ArraySessionStore;
use PHPUnit\Framework\TestCase;

/** Tes ber-ID untuk M9: SEC-AUTHZ-01/02, SEC-DATA-01/02, SEC-OUT-01/02, CACHE-10, hook runtime. */
final class RuntimeTest extends TestCase
{
    private string $root;
    private string $ext;
    private Connection $conn;
    private Query $q;
    private Definitions $defs;
    private HookRunner $hooks;
    private ArraySessionStore $session;
    private Authorizer $az;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/rt_' . bin2hex(random_bytes(6));
        $def = $this->root . '/definitions';
        $this->ext = $this->root . '/extensions';
        mkdir($def . '/models', 0700, true);
        mkdir($def . '/pages', 0700, true);
        mkdir($this->ext, 0700, true);
        $sfx = bin2hex(random_bytes(4));
        file_put_contents($this->ext . '/CatatanHooks' . $sfx . '.php', "<?php\nclass CatatanHooks{$sfx} {\n public static function cek(array \$d): array { return (\$d['isi'] ?? '') === 'terlarang' ? ['Isi dilarang'] : []; }\n public static function hapus(array \$d): array { return (\$d['isi'] ?? '') === 'kunci' ? ['Dikunci'] : []; }\n}\n");
        $w = static fn(string $rel, array $d) => file_put_contents($def . '/' . $rel, json_encode($d));
        $w('models/catatan.json', [
            'model' => 'catatan',
            'fields' => [
                'isi' => ['type' => 'string', 'label' => 'Isi', 'required' => true, 'max' => 50],
                'harga' => ['type' => 'decimal', 'min' => 0],
                'rahasia' => ['type' => 'string', 'guarded' => true],
                'pemilik' => ['type' => 'integer', 'required' => true],
            ],
            'hooks' => ['beforeSave' => 'CatatanHooks' . $sfx . '::cek', 'beforeDelete' => 'CatatanHooks' . $sfx . '::hapus'],
            'access' => ['read' => ['user', 'admin'], 'write' => ['user', 'admin'], 'owner' => 'pemilik', 'ownerExempt' => ['admin']],
        ]);
        $w('models/publik.json', [
            'model' => 'publik',
            'fields' => ['judul' => ['type' => 'string', 'required' => true, 'max' => 80], 'angka' => ['type' => 'integer']],
            'access' => ['read' => '*', 'write' => ['admin']],
        ]);
        $w('models/tugas.json', [
            'model' => 'tugas',
            'fields' => [
                'nama' => ['type' => 'string', 'required' => true, 'max' => 50],
                'catatan' => ['type' => 'relasi', 'target' => 'catatan', 'label' => 'Catatan'],
                'pub' => ['type' => 'relasi', 'target' => 'publik'],
                'pemilik' => ['type' => 'integer', 'required' => true],
            ],
            'access' => ['read' => ['user', 'admin'], 'write' => ['user', 'admin'], 'owner' => 'pemilik'],
        ]);
        $w('pages/catatan.json', [
            'page' => 'catatan', 'route' => '/catatan', 'title' => 'Catatan', 'access' => ['user', 'admin'],
            'layout' => [['component' => 'table', 'actions' => ['edit', 'hapus'], 'source' => ['model' => 'catatan', 'perPage' => 2]]],
        ]);
        $w('pages/depan.json', [
            'page' => 'depan', 'route' => '/depan', 'title' => 'Depan', 'access' => '*', 'order' => 1,
            'layout' => [
                ['component' => 'table', 'columns' => ['judul'], 'source' => ['model' => 'publik', 'perPage' => 50]],
                ['component' => 'stat', 'agg' => 'sum', 'field' => 'angka', 'label' => '<b>x</b>', 'source' => ['model' => 'publik']],
                ['component' => 'text', 'text' => '<script>alert(1)</script>'],
                ['component' => 'image', 'src' => '/assets/a.png', 'alt' => '" onerror="x'],
            ],
        ]);
        $cache = new CacheStore($this->root . '/cache');
        $r = (new Compiler($cache, $this->ext))->build($def, Dialect::Sqlite);
        self::assertSame([], $r->errors, json_encode($r->errors) ?: '');
        $this->defs = new Definitions($cache);
        $this->conn = Connection::sqlite($this->root . '/db.sqlite');
        $m = new Migrator($this->conn, new SqliteGrammar());
        foreach ($this->defs->tables() as $t) {
            $m->apply($m->planCreate($t));
        }
        $this->q = new Query($this->conn, new SqliteGrammar(), $this->defs->allowlist());
        $this->hooks = new HookRunner($this->ext);
        $this->session = new ArraySessionStore();
        $this->session->start();
        $this->az = new Authorizer();
    }

    protected function tearDown(): void
    {
        CacheStore::rmTree($this->root);
    }

    private function id(int $uid, string $role = 'user'): Identity
    {
        return new Identity($uid, [$role], $role);
    }

    private function repo(string $model, ?Identity $who): ModelRepository
    {
        $d = $this->defs->model($model);
        self::assertNotNull($d);
        return new ModelRepository($d, $this->q, $this->az, $who, $this->hooks, null, fn(string $m): ?array => $this->defs->model($m));
    }

    /** Dua catatan milik user 1 dan satu milik user 2; kembalikan id catatan user 2. */
    private function seed(): int
    {
        $this->q->insert('catatan', ['isi' => 'a1', 'pemilik' => 1]);
        $this->q->insert('catatan', ['isi' => 'a2', 'pemilik' => 1]);
        return $this->q->insert('catatan', ['isi' => 'b1', 'pemilik' => 2]);
    }

    // ---------- SEC-AUTHZ: IDOR & scope ----------

    public function test_SEC_AUTHZ_02_find_milik_user_lain_adalah_NotFound(): void
    {
        $b = $this->seed();
        $this->expectException(NotFound::class);
        $this->repo('catatan', $this->id(1))->find($b);
    }

    public function test_SEC_AUTHZ_02_update_dan_delete_milik_user_lain_NotFound_dan_data_utuh(): void
    {
        $b = $this->seed();
        $r = $this->repo('catatan', $this->id(1));
        foreach ([fn() => $r->update($b, ['isi' => 'diretas', 'pemilik' => 1]), fn() => $r->delete($b)] as $act) {
            try {
                $act();
                self::fail('Harus NotFound');
            } catch (NotFound) {
            }
        }
        $row = $this->repo('catatan', $this->id(2))->find($b);
        self::assertSame('b1', $row['isi']);
        self::assertSame(2, (int) $row['pemilik']);
    }

    public function test_SEC_AUTHZ_02_paginate_count_dan_aggregate_hanya_baris_sendiri(): void
    {
        $this->seed();
        $r = $this->repo('catatan', $this->id(1));
        $res = $r->paginate(null, 1, 10);
        self::assertSame(2, $res['total']);
        self::assertCount(2, $res['rows']);
        self::assertSame('2', $r->aggregate('count', null));
        self::assertSame('2', $r->aggregate('count', 'isi'));
        // filter pemilik=2 tidak menembus scope
        self::assertSame(0, $r->paginate(null, 1, 10, ['pemilik' => 2])['total']);
        // admin (ownerExempt) melihat semua
        self::assertSame(3, $this->repo('catatan', $this->id(9, 'admin'))->paginate(null, 1, 10)['total']);
    }

    public function test_SEC_AUTHZ_02_create_memaksa_owner_dan_update_tak_memindahkan(): void
    {
        $r = $this->repo('catatan', $this->id(1));
        $res = $r->create(['isi' => 'baru', 'pemilik' => 2]);
        self::assertTrue($res->ok());
        self::assertNotNull($res->id);
        $row = $r->find($res->id);
        self::assertSame(1, (int) $row['pemilik']);
        $r->update($res->id, ['isi' => 'ubah', 'pemilik' => 2]);
        self::assertSame(1, (int) $r->find($res->id)['pemilik']);
        self::assertSame('ubah', $r->find($res->id)['isi']);
    }

    public function test_SEC_AUTHZ_01_aksi_tanpa_izin_dan_anonim_ditolak(): void
    {
        $this->seed();
        $pub = $this->q->insert('publik', ['judul' => 'x']);
        $staf = $this->repo('publik', $this->id(1, 'staf'));
        self::assertSame('x', $staf->find($pub)['judul']); // read '*'
        foreach ([fn() => $staf->create(['judul' => 'y']), fn() => $staf->update($pub, ['judul' => 'z']), fn() => $staf->delete($pub)] as $act) {
            try {
                $act();
                self::fail('Harus Forbidden');
            } catch (Forbidden) {
            }
        }
        $anon = $this->repo('publik', null);
        self::assertSame(1, $anon->paginate(null, 1, 10)['total']);
        $this->expectException(Forbidden::class);
        $anon->create(['judul' => 'anon']);
    }

    public function test_SEC_AUTHZ_01_anonim_tak_bisa_baca_model_berowner(): void
    {
        $this->seed();
        $this->expectException(Forbidden::class);
        $this->repo('catatan', null)->paginate(null, 1, 10);
    }

    // ---------- SEC-DATA ----------

    public function test_SEC_DATA_02_mass_assignment_guarded_dan_kunci_asing_dibuang(): void
    {
        $r = $this->repo('catatan', $this->id(1));
        $res = $r->create(['isi' => 'x', 'rahasia' => 'bocor', 'id' => 999, 'role' => 'admin', 'pemilik' => 7]);
        self::assertTrue($res->ok());
        $row = $r->find((int) $res->id);
        self::assertNull($row['rahasia']);
        self::assertNotSame(999, (int) $row['id']);
        [$clean] = Validator::validate((array) $this->defs->model('catatan'), ['isi' => 'x', 'rahasia' => 'y', 'role' => 'admin', 'pemilik' => 1]);
        self::assertArrayNotHasKey('rahasia', $clean);
        self::assertArrayNotHasKey('role', $clean);
    }

    public function test_SEC_DATA_02_decimal_numeric_string_bukan_float(): void
    {
        $def = (array) $this->defs->model('catatan');
        [$c, $e] = Validator::validate($def, ['isi' => 'x', 'pemilik' => '1', 'harga' => '1500,50']);
        self::assertSame([], $e);
        self::assertSame('1500.5', $c['harga']);
        self::assertIsString($c['harga']);
        [, $e] = Validator::validate($def, ['isi' => 'x', 'pemilik' => '1', 'harga' => '1e3']);
        self::assertArrayHasKey('harga', $e);
        [, $e] = Validator::validate($def, ['isi' => 'x', 'pemilik' => '1', 'harga' => '-5']);
        self::assertArrayHasKey('harga', $e);
        [, $e] = Validator::validate($def, ['isi' => 'x', 'pemilik' => '1', 'harga' => '1.123']);
        self::assertArrayHasKey('harga', $e);
        [, $e] = Validator::validate($def, ['isi' => ['arr'], 'pemilik' => '1']);
        self::assertArrayHasKey('isi', $e);
    }

    public function test_SEC_AUTHZ_02_relasi_fk_lintas_pemilik_dan_tak_ada_pesan_identik(): void
    {
        $b = $this->seed(); // catatan milik user 2
        $own = (int) $this->q->insert('catatan', ['isi' => 'mine', 'pemilik' => 1]);
        $r = $this->repo('tugas', $this->id(1));
        $lain = $r->create(['nama' => 't', 'catatan' => $b]);
        $nihil = $r->create(['nama' => 't', 'catatan' => 99999]);
        self::assertFalse($lain->ok());
        self::assertFalse($nihil->ok());
        self::assertSame($nihil->errors, $lain->errors);
        self::assertSame(['catatan' => ['Catatan tidak valid.']], $lain->errors);
        self::assertSame(0, $this->q->count('tugas', Where::none()));
        $nol = $r->create(['nama' => 't', 'catatan' => '']);
        self::assertTrue($nol->ok());
        $ok = $r->create(['nama' => 't2', 'catatan' => $own, 'pub' => $this->q->insert('publik', ['judul' => 'p'])]);
        self::assertTrue($ok->ok());
        // update: FK berubah ke baris orang lain ditolak, ke milik sendiri diterima
        self::assertFalse($r->update((int) $ok->id, ['nama' => 't2', 'catatan' => $b])->ok());
        self::assertSame($own, (int) $r->find((int) $ok->id)['catatan']);
        $own2 = (int) $this->q->insert('catatan', ['isi' => 'mine2', 'pemilik' => 1]);
        self::assertTrue($r->update((int) $ok->id, ['nama' => 't2', 'catatan' => $own2])->ok());
        self::assertSame($own2, (int) $r->find((int) $ok->id)['catatan']);
    }

    public function test_SEC_AUTHZ_02_relasi_tanpa_resolver_atau_anonim_ditolak(): void
    {
        $own = (int) $this->q->insert('catatan', ['isi' => 'mine', 'pemilik' => 1]);
        $d = $this->defs->model('tugas');
        self::assertNotNull($d);
        $r = new ModelRepository($d, $this->q, $this->az, $this->id(1), $this->hooks);
        self::assertFalse($r->create(['nama' => 't', 'catatan' => $own])->ok());
        $this->expectException(Forbidden::class);
        $this->repo('tugas', null)->create(['nama' => 't', 'catatan' => $own]);
    }

    public function test_aggregate_menolak_field_guarded(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->repo('catatan', $this->id(1))->aggregate('count', 'rahasia');
    }

    public function test_CACHE_10_error_validasi_memuat_path_sumber(): void
    {
        [, $e] = Validator::validate((array) $this->defs->model('catatan'), ['pemilik' => 1], true);
        self::assertStringContainsString('models/catatan.json#/fields/isi', $e['isi'][0]);
        [, $e] = Validator::validate((array) $this->defs->model('catatan'), ['pemilik' => 1]);
        self::assertStringNotContainsString('models/', $e['isi'][0]);
    }

    public function test_SEC_DATA_01_sort_dan_filter_injection_ditolak(): void
    {
        $this->seed();
        $r = $this->repo('catatan', $this->id(1));
        foreach (['isi; DROP TABLE catatan', 'rahasia', '-rahasia', 'tidakada', "isi' OR '1'='1", '(select 1)'] as $bad) {
            try {
                $r->paginate($bad, 1, 10);
                self::fail("Sort lolos: $bad");
            } catch (\InvalidArgumentException) {
            }
        }
        $asc = $r->paginate('-isi', 1, 10)['rows'];
        self::assertSame('a2', $asc[0]['isi']);
        foreach ([['tidakada' => 1], ['rahasia' => 'x'], ["isi' OR 1=1 --" => 'x'], ['isi' => ['a']], ['isi' => 1.5]] as $f) {
            try {
                $r->paginate(null, 1, 10, $f);
                self::fail('Filter lolos');
            } catch (\InvalidArgumentException) {
            }
        }
        // nilai berbahaya hanya sebagai data (binding)
        self::assertSame(0, $r->paginate(null, 1, 10, ['isi' => "x' OR '1'='1"])['total']);
        self::assertSame(2, $this->q->count('catatan', new \bFramework\Runtime\Where([['pemilik', '=', 1]])));
    }

    public function test_paginasi_batas(): void
    {
        $this->seed();
        $r = $this->repo('catatan', $this->id(1));
        self::assertCount(2, $r->paginate(null, -5, 0)['rows'] === [] ? [1, 2] : $r->paginate(null, -5, 1000)['rows']);
        self::assertSame([], $r->paginate(null, 99999999, 10)['rows']);
        self::assertCount(1, $r->paginate(null, 1, 1)['rows']);
        self::assertSame(2, $r->paginate(null, 1, 1)['total']);
    }

    // ---------- hook ----------

    public function test_hook_before_save_menolak_dan_delete_ditolak(): void
    {
        $r = $this->repo('catatan', $this->id(1));
        $res = $r->create(['isi' => 'terlarang']);
        self::assertFalse($res->ok());
        self::assertSame(['Isi dilarang'], $res->formErrors);
        self::assertSame(0, $r->paginate(null, 1, 10)['total']);
        $id = (int) $r->create(['isi' => 'kunci'])->id;
        $this->expectException(HookRejected::class);
        $r->delete($id);
    }

    public function test_hook_event_tanpa_hook_kosong(): void
    {
        self::assertSame([], $this->hooks->run((array) $this->defs->model('publik'), 'beforeSave', []));
    }

    /** @return array<string,mixed> */
    private function hookDef(string $class, string $method = 'cek'): array
    {
        return ['hooks' => ['beforeSave' => ['ref' => "$class::$method", 'class' => $class, 'method' => $method, '_src' => 'x']]];
    }

    public function test_hook_palsu_kelas_tak_ada_dan_namespace(): void
    {
        file_put_contents($this->ext . '/RtNs.php', "<?php\nnamespace Evil;\nclass RtNs { public static function cek(array \$d): array { return []; } }\n");
        file_put_contents($this->ext . '/RtGlobalKosong.php', "<?php\n// kosong\n");
        foreach (['RtTidakAda', 'RtNs', 'RtGlobalKosong'] as $c) {
            try {
                $this->hooks->run($this->hookDef($c), 'beforeSave', []);
                self::fail("Hook lolos: $c");
            } catch (HookError) {
            }
        }
    }

    public function test_hook_method_harus_public_static_dan_hasil_list_string(): void
    {
        file_put_contents($this->ext . '/RtBentuk.php', "<?php\nclass RtBentuk {\n public function inst(array \$d): array { return []; }\n private static function priv(array \$d): array { return []; }\n public static function bukanList(array \$d): array { return ['a' => 'b']; }\n public static function bukanString(array \$d): array { return [1]; }\n public static function boom(array \$d): array { throw new \\RuntimeException('rahasia'); }\n public static function ok(array \$d): array { return ['pesan']; }\n}\n");
        foreach (['inst', 'priv', 'bukanList', 'bukanString', 'boom', 'tidakAda'] as $m) {
            try {
                $this->hooks->run($this->hookDef('RtBentuk', $m), 'beforeSave', []);
                self::fail("Hook lolos: $m");
            } catch (HookError) {
            }
        }
        self::assertSame(['pesan'], $this->hooks->run($this->hookDef('RtBentuk', 'ok'), 'beforeSave', []));
    }

    public function test_hook_symlink_dan_di_luar_extDir_ditolak(): void
    {
        $out = $this->root . '/luar';
        mkdir($out);
        file_put_contents($out . '/RtLuar.php', "<?php\nclass RtLuar { public static function cek(array \$d): array { return []; } }\n");
        file_put_contents($this->ext . '/RtAsli.php', "<?php\nclass RtAsli { public static function cek(array \$d): array { return []; } }\n");
        if (!@symlink($out . '/RtLuar.php', $this->ext . '/RtLuar.php') || !@symlink($this->ext . '/RtAsli.php', $this->ext . '/RtAlias.php')) {
            self::markTestSkipped('symlink tidak didukung');
        }
        foreach (['RtLuar', 'RtAlias', '../luar/RtLuar', 'a/b'] as $c) {
            try {
                $this->hooks->run($this->hookDef($c), 'beforeSave', []);
                self::fail("Hook lolos: $c");
            } catch (HookError) {
            }
        }
        self::assertFalse(class_exists('RtLuar', false));
    }

    // ---------- Router, PageController, XSS ----------

    private function configure(?Identity $who, bool $dev = false, ?\bFramework\Contracts\Logger $log = null): void
    {
        $s = $this->session;
        $ci = new CurrentIdentity($s);
        $who === null ? $ci->clear() : $ci->set($who);
        $app = dirname(__DIR__, 2) . '/app';
        $views = $this->root . '/viewcache';
        PageController::configure(
            $this->defs,
            $this->q,
            $this->az,
            $this->hooks,
            new Template($app . '/core/Runtime/views', $views),
            new Template($app . '/core/Core/views', $views),
            $s,
            $ci,
            new Csrf($s),
            $dev,
            $log,
        );
    }

    private function router(): Router
    {
        return Router::fromCompiled($this->defs->routes());
    }

    /** @param array<string,mixed> $post */
    private function req(string $method, string $path, array $post = [], array $query = []): Request
    {
        return new Request($method, $path, $query, $post);
    }

    public function test_router_meneruskan_page_sebagai_argumen_ketiga(): void
    {
        $seen = null;
        $r = Router::fromCompiled([[
            'method' => 'GET', 'pattern' => '/x', 'handler' => self::class . '::spy', 'csrf' => true, 'name' => 'n', 'page' => 'abc',
        ]]);
        self::$spy = static function (Request $q, array $p, string $page) use (&$seen): void {
            $seen = $page;
        };
        $r->dispatch($this->req('GET', '/x'));
        self::assertSame('abc', $seen);
        $this->expectException(\InvalidArgumentException::class);
        Router::fromCompiled([['method' => 'GET', 'pattern' => '/x', 'handler' => self::class . '::spy', 'page' => '../x']]);
    }

    /** @var \Closure|null */
    private static $spy;

    /** @param array<string,string> $p */
    public static function spy(Request $r, array $p, string $page = ''): \bFramework\Core\Response
    {
        (self::$spy)($r, $p, $page);
        return \bFramework\Core\Response::html('ok');
    }

    public function test_halaman_anonim_redirect_login_dan_peran_salah_403(): void
    {
        $this->configure(null);
        $res = $this->router()->dispatch($this->req('GET', '/catatan'));
        self::assertSame(302, $res->status);
        self::assertSame('/login', $res->headers['Location']);
        $this->configure($this->id(1, 'staf'));
        $this->expectException(Forbidden::class);
        $this->router()->dispatch($this->req('GET', '/catatan'));
    }

    public function test_SEC_AUTHZ_02_idor_lewat_rute_ubah_hapus(): void
    {
        $b = $this->seed();
        $this->configure($this->id(1));
        foreach ([['GET', "/catatan/$b/ubah"], ['POST', "/catatan/$b"], ['POST', "/catatan/$b/hapus"]] as [$m, $p]) {
            try {
                $this->router()->dispatch($this->req($m, $p, ['isi' => 'x']));
                self::fail("IDOR lolos: $p");
            } catch (NotFound) {
            }
        }
        self::assertSame('b1', $this->repo('catatan', $this->id(2))->find($b)['isi']);
        foreach (['/catatan/abc/ubah', '/catatan/0/ubah', '/catatan/1;DROP/ubah', '/catatan/99999999999999999999/ubah'] as $p) {
            try {
                $this->router()->dispatch($this->req('GET', $p));
                self::fail("Id lolos: $p");
            } catch (NotFound) {
            }
        }
    }

    public function test_alur_tambah_dan_hapus_lewat_rute(): void
    {
        $this->configure($this->id(1));
        $res = $this->router()->dispatch($this->req('POST', '/catatan', ['isi' => 'lewat rute', 'pemilik' => 5, 'rahasia' => 'x']));
        self::assertSame(302, $res->status);
        $rows = $this->repo('catatan', $this->id(1))->paginate(null, 1, 10)['rows'];
        self::assertSame('lewat rute', $rows[0]['isi']);
        self::assertSame(1, (int) $rows[0]['pemilik']);
        self::assertNull($rows[0]['rahasia']);
        $bad = $this->router()->dispatch($this->req('POST', '/catatan', ['isi' => '']));
        self::assertSame(422, $bad->status);
        self::assertStringContainsString('wajib diisi', $bad->body);
        $del = $this->router()->dispatch($this->req('POST', '/catatan/' . $rows[0]['id'] . '/hapus'));
        self::assertSame(302, $del->status);
        self::assertSame(0, $this->repo('catatan', $this->id(1))->paginate(null, 1, 10)['total']);
    }

    private function memLogger(): object
    {
        return new class () implements \bFramework\Contracts\Logger {
            /** @var list<string> */
            public array $lines = [];

            public function error(string $msg, array $ctx = []): void
            {
                $this->lines[] = $msg;
            }

            public function warning(string $msg, array $ctx = []): void
            {
                $this->lines[] = $msg;
            }

            public function info(string $msg, array $ctx = []): void
            {
                $this->lines[] = $msg;
            }
        };
    }

    public function test_SRC_01_produksi_tidak_memuat_src_di_body_tapi_di_log(): void
    {
        $log = $this->memLogger();
        $this->configure($this->id(1), false, $log);
        $bad = $this->router()->dispatch($this->req('POST', '/catatan', ['isi' => '']));
        self::assertSame(422, $bad->status);
        self::assertStringContainsString('wajib diisi', $bad->body);
        self::assertStringNotContainsString('models/', $bad->body);
        self::assertStringNotContainsString('#/fields', $bad->body);
        self::assertMatchesRegularExpression('~models/.*#/fields~', implode("\n", $log->lines));
    }

    /** @return array<string,array{0:string|null|false}> */
    public static function envProduksi(): array
    {
        return [
            'tidak terset' => [false], 'kosong' => [''], 'production' => ['production'], 'prod' => ['prod'],
            'prodution' => ['prodution'], 'live' => ['live'], 'Production spasi' => ['Production '], 'staging' => ['staging'],
        ];
    }

    /** @return array<string,array{0:string}> */
    public static function envDev(): array
    {
        return ['dev' => ['dev'], ' DEV ' => [' DEV '], 'development' => ['development'], 'local' => ['local'], 'test' => ['test']];
    }

    private function withEnv(string|false $v, callable $fn): mixed
    {
        $old = getenv('APP_ENV');
        putenv($v === false ? 'APP_ENV' : 'APP_ENV=' . $v);
        Config::set([]);
        try {
            return $fn();
        } finally {
            putenv($old === false ? 'APP_ENV' : 'APP_ENV=' . $old);
        }
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('envProduksi')]
    public function test_SRC_03_APP_ENV_selain_allowlist_dev_adalah_produksi(string|false $v): void
    {
        self::assertFalse($this->withEnv($v, static fn (): bool => Config::devMode()));
        self::assertFalse(Config::isDevEnv($v === false ? null : $v));
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('envDev')]
    public function test_SRC_04_APP_ENV_allowlist_dev_adalah_dev(string $v): void
    {
        self::assertTrue($this->withEnv($v, static fn (): bool => Config::devMode()));
        self::assertTrue(Config::isDevEnv($v));
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('envProduksi')]
    public function test_SRC_05_produksi_dari_APP_ENV_tidak_memuat_src_di_body(string|false $v): void
    {
        $this->configure($this->id(1), $this->withEnv($v, static fn (): bool => Config::devMode()));
        $bad = $this->router()->dispatch($this->req('POST', '/catatan', ['isi' => '']));
        self::assertSame(422, $bad->status);
        self::assertStringNotContainsString('models/', $bad->body);
        self::assertStringNotContainsString('#/fields', $bad->body);
    }

    public function test_SRC_02_dev_memuat_src_di_body(): void
    {
        $this->configure($this->id(1), true);
        $bad = $this->router()->dispatch($this->req('POST', '/catatan', ['isi' => '']));
        self::assertSame(422, $bad->status);
        self::assertMatchesRegularExpression('~#/fields~', $bad->body);
    }

    public function test_SEC_OUT_01_xss_di_data_dan_komponen_ter_escape(): void
    {
        $this->q->insert('publik', ['judul' => '<script>alert(1)</script>"><img src=x onerror=alert(2)>', 'angka' => 3]);
        $this->configure(null);
        $html = $this->router()->dispatch($this->req('GET', '/depan'))->body;
        self::assertStringNotContainsString('<script>alert', $html);
        self::assertStringNotContainsString('<img src=x', $html);
        self::assertStringContainsString('&lt;script&gt;alert(1)&lt;/script&gt;', $html);
        self::assertStringContainsString('&lt;b&gt;x&lt;/b&gt;', $html); // label stat
        self::assertStringNotContainsString('" onerror="x', $html);
        $tanpaNilai = preg_replace('/"[^"]*"/', '""', $html) ?? '';
        self::assertSame(0, preg_match('/<[^>]+\son\w+\s*=/i', $tanpaNilai));
    }

    public function test_SEC_OUT_02_gambar_url_berbahaya_tidak_dirender(): void
    {
        $page = (array) $this->defs->page('depan');
        $rend = new ComponentRenderer(
            $this->defs, $this->q, $this->az, $this->hooks,
            new Template(dirname(__DIR__, 2) . '/app/core/Runtime/views', $this->root . '/vc'),
            null, $page, [], 'tok',
        );
        foreach (['javascript:alert(1)', '//evil.test/a.png', 'data:text/html,x', '/a/../../etc/passwd', 'http://x.test/a.png'] as $src) {
            $h = $rend->render(['component' => 'image', 'src' => $src, 'alt' => 'a'])->toString();
            self::assertStringNotContainsString('<img', $h, $src);
        }
        self::assertStringContainsString('<img', $rend->render(['component' => 'image', 'src' => '/assets/ok.png'])->toString());
    }

    public function test_sort_dan_hal_dari_query_aman_di_halaman(): void
    {
        $this->seed();
        $this->configure($this->id(1));
        $res = $this->router()->dispatch($this->req('GET', '/catatan', [], ['sort' => 'rahasia; DROP', 'hal' => '-1']));
        self::assertSame(200, $res->status);
        $res = $this->router()->dispatch($this->req('GET', '/catatan', [], ['sort' => ['x'], 'hal' => '999999999']));
        self::assertSame(200, $res->status);
        // Nonce CSP dan token CSRF acak bisa memuat "a1"/"b1": buang nilainya sebelum assert.
        $strip = static fn(string $h): string => (string) preg_replace(['/nonce="[^"]*"/i', '/(name="_csrf" value|name="csrf-token" content|content)="[^"]*"/i'], ['', '$1=""'], $h);
        self::assertStringContainsString('a1', $strip($this->router()->dispatch($this->req('GET', '/catatan', [], ['sort' => 'isi']))->body));
        self::assertStringNotContainsString('b1', $strip($this->router()->dispatch($this->req('GET', '/catatan', [], ['hal' => '1']))->body));
    }

    // ---------- Navigation & Format ----------

    public function test_navigation_filter_peran_dan_admin_terakhir(): void
    {
        $pages = $this->defs->pages();
        $nav = Navigation::build($pages, $this->id(1, 'admin'));
        self::assertSame('Admin', $nav[count($nav) - 1]['group']);
        $nav = Navigation::build($pages, $this->id(1, 'staf'));
        $keys = array_merge(...array_map(static fn(array $g): array => array_column($g['items'], 'key'), $nav));
        self::assertSame(['depan'], $keys);
        self::assertNotContains('Admin', array_column($nav, 'group'));
        self::assertSame([], Navigation::build($pages, null));
    }

    public function test_format_id_ID(): void
    {
        self::assertSame('1.234.567,50', Format::number('1234567.50'));
        self::assertSame('Rp 1.500', Format::number('1500.00', 'rupiah'));
        self::assertSame('0', Format::number('0.00'));
        self::assertSame('-12,50', Format::number('-12.5'));
        self::assertSame('Ya', Format::cell(['type' => 'boolean'], 1));
        self::assertSame('25-12-2026', Format::cell(['type' => 'date'], '2026-12-25'));
        self::assertSame('-', Format::cell(['type' => 'string'], null));
    }

    public function test_can_mengikuti_authorizer(): void
    {
        self::assertTrue($this->repo('catatan', $this->id(1))->can(Action::Create));
        self::assertFalse($this->repo('catatan', null)->can(Action::Read));
    }

    public function test_skema_nama_dicadangkan_label_sah_dan_issuer(): void
    {
        foreach (['files', 'audit_log', 'sso_refresh_tokens', 'bf_apa'] as $n) {
            $sc = new \bFramework\Runtime\DefinitionSchema();
            self::assertNull($sc->model($n, ['model' => $n, 'fields' => []]), $n);
        }
        $base = ['page' => 'p', 'title' => 'T', 'access' => '*', 'layout' => []];
        foreach (['/api/x', '/uploads/x', '/_x/y'] as $route) {
            $sc = new \bFramework\Runtime\DefinitionSchema();
            self::assertNull($sc->page('p', ['route' => $route] + $base), $route);
        }
        $sc = new \bFramework\Runtime\DefinitionSchema();
        self::assertNotNull($sc->model('stok', ['model' => 'stok', 'fields' => ['a' => ['type' => 'string', 'label' => 'Update stok']]]));
        $sc = new \bFramework\Runtime\DefinitionSchema();
        self::assertNull($sc->auth(['driver' => 'local', 'sso' => ['issuer' => ['x']]]));
    }
}
