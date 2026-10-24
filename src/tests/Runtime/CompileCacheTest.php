<?php

declare(strict_types=1);

namespace bFramework\Tests\Runtime;

use bFramework\Contracts\Action;
use bFramework\Contracts\Dialect;
use bFramework\Contracts\Identity;
use bFramework\Core\Router;
use bFramework\Runtime\Authorizer;
use bFramework\Runtime\BuildResult;
use bFramework\Runtime\CacheStore;
use bFramework\Runtime\Compiler;
use bFramework\Runtime\Definitions;
use bFramework\Runtime\InvalidIdentifier;
use PHPUnit\Framework\TestCase;

final class CompileCacheTest extends TestCase
{
    private string $root;
    private string $def;
    private string $ext;
    private string $cache;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/cc_' . bin2hex(random_bytes(6));
        $this->def = $this->root . '/definitions';
        $this->ext = $this->root . '/extensions';
        $this->cache = $this->root . '/cache';
        mkdir($this->def . '/models', 0700, true);
        mkdir($this->def . '/pages', 0700, true);
        mkdir($this->ext, 0700, true);
        file_put_contents($this->ext . '/ProdukHooks.php', "<?php\nclass ProdukHooks {\n public static function cek(array \$d): array { return []; }\n}\n");
        $this->put('models/kategori.json', ['model' => 'kategori', 'fields' => ['nama' => ['type' => 'string', 'max' => 60, 'required' => true]], 'access' => ['read' => '*', 'write' => ['admin']]]);
        $this->put('models/produk.json', $this->produk());
        $this->put('pages/daftar-produk.json', $this->page());
    }

    protected function tearDown(): void
    {
        CacheStore::rmTree($this->root);
    }

    /** @return array<string,mixed> */
    private function produk(): array
    {
        return [
            'model' => 'produk',
            'fields' => [
                'nama' => ['type' => 'string', 'max' => 100, 'required' => true],
                'harga' => ['type' => 'decimal', 'min' => 0, 'format' => 'rupiah'],
                'stok' => ['type' => 'integer', 'default' => 0],
                'kategori' => ['type' => 'relasi', 'target' => 'kategori'],
                'pemilik' => ['type' => 'integer'],
                'aktif' => ['type' => 'boolean', 'default' => true],
            ],
            'hooks' => ['beforeSave' => 'ProdukHooks::cek'],
            'access' => ['read' => '*', 'write' => ['admin'], 'owner' => 'pemilik', 'ownerExempt' => ['admin']],
        ];
    }

    /** @return array<string,mixed> */
    private function page(): array
    {
        return [
            'page' => 'daftar-produk', 'route' => '/produk', 'title' => 'Produk', 'group' => 'Penjualan',
            'access' => ['admin', 'staf'],
            'layout' => [
                ['component' => 'stat', 'span' => 4, 'agg' => 'sum', 'field' => 'stok', 'source' => ['model' => 'produk']],
                ['component' => 'table', 'columns' => ['nama', 'harga'], 'actions' => ['edit'], 'source' => ['model' => 'produk', 'sort' => '-stok', 'perPage' => 5]],
            ],
        ];
    }

    /** @param array<string,mixed> $d */
    private function put(string $rel, array $d): void
    {
        file_put_contents($this->def . '/' . $rel, json_encode($d));
    }

    private function build(Dialect $d = Dialect::Sqlite): BuildResult
    {
        return (new Compiler(new CacheStore($this->cache), $this->ext))->build($this->def, $d);
    }

    private function ok(): string
    {
        $r = $this->build();
        self::assertSame([], $r->errors, json_encode($r->errors) ?: '');
        self::assertNotNull($r->version);
        return $r->version;
    }

    /** @return list<string> */
    private function versions(): array
    {
        return array_values(array_filter(scandir($this->cache) ?: [], static fn(string $n): bool => preg_match('/^v_/', $n) === 1));
    }

    private function errSrc(BuildResult $r): string
    {
        return implode('|', array_map(static fn($e): string => $e->src . ' ' . $e->msg, $r->errors));
    }

    public function test_build_dan_baca_definisi(): void
    {
        $v = $this->ok();
        $defs = new Definitions(new CacheStore($this->cache));
        self::assertSame($v, $defs->version());
        $m = $defs->model('produk');
        self::assertNotNull($m);
        self::assertSame('decimal', $m['fields']['harga']['type']);
        self::assertSame('ProdukHooks', $m['hooks']['beforeSave']['class']);
        self::assertNull($defs->model('../x'));
        self::assertNull($defs->model('tidakada'));
        self::assertSame('/produk', $defs->page('daftar-produk')['route'] ?? null);
        self::assertSame(['admin', 'staf'], $defs->access()['pages']['daftar-produk']['access']);
        self::assertSame(['admin'], $defs->access()['models']['produk']['write']);
        $tables = array_map(static fn($t): string => $t->name, $defs->tables());
        self::assertSame(['kategori', 'produk'], $tables);
    }

    public function test_CACHE_01_satu_file_per_model_lazy(): void
    {
        $v = $this->ok();
        self::assertFileExists("{$this->cache}/$v/models/produk.php");
        self::assertFileExists("{$this->cache}/$v/models/kategori.php");
        file_put_contents("{$this->cache}/$v/models/kategori.php", '<?php this is broken');
        $defs = new Definitions(new CacheStore($this->cache));
        self::assertNotNull($defs->model('produk'));
        self::assertNotContains("{$this->cache}/$v/models/kategori.php", get_included_files());
    }

    public function test_CACHE_02_sql_hanya_dialek_aktif(): void
    {
        $r = $this->build(Dialect::MySql);
        self::assertNotNull($r->version);
        self::assertDirectoryExists("{$this->cache}/{$r->version}/sql/mysql");
        self::assertDirectoryDoesNotExist("{$this->cache}/{$r->version}/sql/sqlite");
        $sql = (new Definitions(new CacheStore($this->cache)))->sql('produk');
        self::assertStringContainsString('CREATE TABLE `produk`', $sql['create'][0] ?? '');
    }

    public function test_CACHE_03_versi_baru_per_build_dan_tidak_menimpa(): void
    {
        $v1 = $this->ok();
        self::assertSame($v1, $this->ok());
        self::assertCount(1, $this->versions());
        $mtime = filemtime("{$this->cache}/$v1/manifest.php");
        $k = $this->produk();
        $k['fields']['stok']['default'] = 5;
        $this->put('models/produk.json', $k);
        $v2 = $this->ok();
        self::assertNotSame($v1, $v2);
        self::assertCount(2, $this->versions());
        self::assertSame($mtime, filemtime("{$this->cache}/$v1/manifest.php"));
        self::assertSame($v2, (new CacheStore($this->cache))->current());
    }

    public function test_CACHE_04_current_dibaca_tanpa_include(): void
    {
        $v1 = $this->ok();
        $k = $this->produk();
        $k['fields']['stok']['default'] = 9;
        $this->put('models/produk.json', $k);
        $v2 = $this->ok();
        $store = new CacheStore($this->cache);
        self::assertSame($v2, $store->current());
        file_put_contents($this->cache . '/current', $v1);
        self::assertSame($v1, $store->current());
        file_put_contents($this->cache . '/current', "v_../../etc");
        self::assertNull($store->current());
        self::assertStringNotContainsString('<?php', (string) file_get_contents($this->cache . '/current'));
    }

    public function test_CACHE_05_tulis_atomik_tanpa_sisa_tmp_dan_gc(): void
    {
        $seen = [];
        for ($i = 1; $i <= 5; $i++) {
            $k = $this->produk();
            $k['fields']['stok']['default'] = $i;
            $this->put('models/produk.json', $k);
            $seen[] = $this->ok();
            touch("{$this->cache}/{$seen[$i - 1]}", 1000000 + $i);
        }
        // Setelah build ke-5: aktif + 2 terbaru lain = 3 folder.
        self::assertLessThanOrEqual(3, count($this->versions()));
        self::assertContains($seen[4], $this->versions());
        $all = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->cache, \FilesystemIterator::SKIP_DOTS));
        foreach ($all as $f) {
            self::assertStringStartsNotWith('.tmp_', $f->getFilename());
        }
        self::assertSame([], glob($this->cache . '/s_*') ?: []);
    }

    public function test_kegagalan_di_tengah_build_versi_lama_tetap_aktif(): void
    {
        $v1 = $this->ok();
        $k = $this->produk();
        $k['fields']['stok']['default'] = 77;
        $this->put('models/produk.json', $k);
        $n = 0;
        $c = new Compiler(new CacheStore($this->cache), $this->ext, static function (string $rel) use (&$n): void {
            if (++$n === 3) {
                throw new \RuntimeException('disk penuh /rahasia/path');
            }
        });
        $r = $c->build($this->def, Dialect::Sqlite);
        self::assertNull($r->version);
        self::assertNotSame([], $r->errors);
        self::assertStringNotContainsString('rahasia', $this->errSrc($r));
        self::assertSame($v1, (new CacheStore($this->cache))->current());
        self::assertSame([$v1], $this->versions());
        self::assertSame([], glob($this->cache . '/s_*') ?: []);
        self::assertSame(100, (int) ((new Definitions(new CacheStore($this->cache)))->model('produk')['fields']['nama']['max'] ?? 0));
    }

    public function test_CACHE_06_ubah_sumber_tanpa_build_tidak_berpengaruh(): void
    {
        $this->ok();
        $defs = new Definitions(new CacheStore($this->cache));
        $before = $defs->model('produk');
        $k = $this->produk();
        $k['fields']['nama']['max'] = 5;
        $this->put('models/produk.json', $k);
        unlink($this->def . '/models/kategori.json');
        self::assertSame($before, (new Definitions(new CacheStore($this->cache)))->model('produk'));
        self::assertNotNull((new Definitions(new CacheStore($this->cache)))->model('kategori'));
        $c = new Compiler(new CacheStore($this->cache), $this->ext);
        self::assertTrue($c->isStale($this->def, Dialect::Sqlite));
    }

    public function test_isStale_false_setelah_build(): void
    {
        $this->ok();
        self::assertFalse((new Compiler(new CacheStore($this->cache), $this->ext))->isStale($this->def, Dialect::Sqlite));
    }

    public function test_CACHE_07_build_bersamaan_menghasilkan_satu_versi(): void
    {
        $procs = [];
        $pipes = [];
        $script = __DIR__ . '/../Fixtures/build_runner.php';
        mkdir($this->cache, 0750, true);
        for ($i = 0; $i < 4; $i++) {
            $p = proc_open([PHP_BINARY, $script, $this->def, $this->cache, $this->ext], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes[$i]);
            self::assertIsResource($p);
            $procs[$i] = $p;
        }
        $outs = [];
        foreach ($procs as $i => $p) {
            $outs[] = stream_get_contents($pipes[$i][1]);
            proc_close($p);
        }
        self::assertCount(1, array_unique($outs), implode(',', $outs));
        self::assertMatchesRegularExpression('/^v_[0-9a-f]{12}$/', $outs[0]);
        self::assertCount(1, $this->versions());
        self::assertSame($outs[0], (new CacheStore($this->cache))->current());
    }

    public function test_CACHE_08_objek_ditolak(): void
    {
        $s = new CacheStore($this->cache);
        foreach ([['o' => new \stdClass()], ['a' => ['b' => new \DateTimeImmutable()]], ['f' => NAN], ['r' => fopen('php://memory', 'r')]] as $bad) {
            try {
                $s->writeAtomic('v_aaaaaaaaaaaa/x.php', $bad);
                self::fail('harus ditolak');
            } catch (\RuntimeException $e) {
                self::assertStringContainsString('CACHE-08', $e->getMessage());
            }
        }
        self::assertFileDoesNotExist($this->cache . '/v_aaaaaaaaaaaa/x.php');
        $s->writeAtomic('v_aaaaaaaaaaaa/ok.php', ['a' => [1, 2.5, 'x\'"\\$y', true, null]]);
        self::assertSame(['a' => [1, 2.5, 'x\'"\\$y', true, null]], $s->read('v_aaaaaaaaaaaa/ok.php'));
    }

    public function test_path_cache_traversal_ditolak(): void
    {
        $s = new CacheStore($this->cache);
        foreach (['../x.php', 'v_a/../../x.php', '/abs.php', 'v_a/x.txt', 'x.php', 'v_a//x.php', "v_a/x\0.php", 'v_a/.hid.php', 'v_a/a b.php'] as $bad) {
            try {
                $s->writeAtomic($bad, []);
                self::fail("harus ditolak: $bad");
            } catch (\RuntimeException) {
                self::assertTrue(true);
            }
        }
        $this->expectException(\RuntimeException::class);
        $s->activate('v_../../etc');
    }

    public function test_CACHE_09_file_cache_tidak_mengembalikan_data_tanpa_bootstrap(): void
    {
        $v = $this->ok();
        $f = "{$this->cache}/$v/models/produk.php";
        self::assertStringContainsString("defined('APP_BOOTED') || exit;", (string) file_get_contents($f));
        $out = shell_exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg('$d = include ' . var_export($f, true) . '; echo "DATA";'));
        self::assertSame('', (string) $out);
    }

    public function test_CACHE_10_setiap_elemen_punya_src(): void
    {
        $this->ok();
        $defs = new Definitions(new CacheStore($this->cache));
        $m = $defs->model('produk');
        self::assertSame('models/produk.json#/fields/harga', $m['fields']['harga']['_src'] ?? null);
        self::assertSame('models/produk.json#', $m['_src']);
        self::assertSame('models/produk.json#/hooks/beforeSave', $m['hooks']['beforeSave']['_src']);
        $p = $defs->page('daftar-produk');
        self::assertSame('pages/daftar-produk.json#/layout/1', $p['layout'][1]['_src'] ?? null);
        foreach ($defs->routes() as $row) {
            self::assertSame('pages/daftar-produk.json#', $row['_src']);
        }
    }

    public function test_CACHE_11_rahasia_tidak_masuk_cache(): void
    {
        putenv('DB_PASSWORD=Sup3rS3cretPw!');
        $_ENV['DB_PASSWORD'] = 'Sup3rS3cretPw!';
        $this->put('auth.json', ['driver' => 'local']);
        $this->ok();
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->cache, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if ($f->isFile()) {
                self::assertStringNotContainsString('Sup3rS3cretPw!', (string) file_get_contents($f->getPathname()));
            }
        }
        putenv('DB_PASSWORD');
        unset($_ENV['DB_PASSWORD']);
        $this->put('auth.json', ['driver' => 'hybrid', 'sso' => ['issuer' => 'https://sso.contoh.test', 'client_id' => 'a', 'client_secret' => 'RAHASIA123']]);
        $r = $this->build();
        self::assertNotSame([], $r->errors);
        self::assertStringNotContainsString('RAHASIA123', $this->errSrc($r));
    }

    public function test_auth_valid_dikompilasi_tanpa_secret(): void
    {
        $this->put('auth.json', ['driver' => 'hybrid', 'sso' => ['issuer' => 'https://sso.contoh.test', 'client_id' => 'app', 'provisioning' => 'jit']]);
        $this->ok();
        $a = (new Definitions(new CacheStore($this->cache)))->auth();
        self::assertSame('hybrid', $a['driver'] ?? null);
        self::assertArrayNotHasKey('client_secret', $a['sso'] ?? []);
    }

    public function test_CACHE_14_halaman_login_dengan_cache_ditolak(): void
    {
        $p = $this->page();
        $p['cache'] = true;
        $this->put('pages/daftar-produk.json', $p);
        $r = $this->build();
        self::assertNull($r->version);
        self::assertStringContainsString('CACHE-14', $this->errSrc($r));
        $p['access'] = '*';
        $this->put('pages/daftar-produk.json', $p);
        self::assertNotNull($this->build()->version);
        $p['access'] = [];
        $this->put('pages/daftar-produk.json', $p);
        self::assertNull($this->build()->version);
    }

    /** @return array<string,array{0:string,1:array<string,mixed>,2:string}> */
    public static function invalidProvider(): array
    {
        $m = static fn(array $f, array $extra = []): array => $extra + ['model' => 'produk', 'fields' => $f];
        return [
            'tipe tak dikenal (ARCH-04)' => ['models/produk.json', $m(['a' => ['type' => 'float']]), '/fields/a/type'],
            'nama field SQL' => ['models/produk.json', $m(['a;drop' => ['type' => 'string']]), 'Nama field'],
            'field id' => ['models/produk.json', $m(['id' => ['type' => 'integer']]), 'dicadangkan'],
            'nama field huruf besar' => ['models/produk.json', $m(['Nama' => ['type' => 'string']]), 'Nama field'],
            'SQL di default (BLD-07)' => ['models/produk.json', $m(['a' => ['type' => 'string', 'default' => 'x; DROP TABLE t']]), 'BLD-07'],
            'SQL di format' => ['models/produk.json', $m(['a' => ['type' => 'string', 'format' => 'select 1']]), '/format'],
            'kunci tak dikenal (SQL mentah)' => ['models/produk.json', $m(['a' => ['type' => 'string', 'sql' => 'SELECT 1']]), 'Kunci tidak dikenal'],
            'default tak sesuai tipe' => ['models/produk.json', $m(['a' => ['type' => 'integer', 'default' => '1; --']]), 'Default'],
            'text dengan default' => ['models/produk.json', $m(['a' => ['type' => 'text', 'default' => 'x']]), 'text/json'],
            'relasi tanpa target' => ['models/produk.json', $m(['a' => ['type' => 'relasi']]), '/target'],
            'relasi target hilang' => ['models/produk.json', $m(['a' => ['type' => 'relasi', 'target' => 'hantu']]), 'tidak ditemukan'],
            'model beda dgn nama file' => ['models/produk.json', ['model' => '../../etc/passwd', 'fields' => []], '#/model'],
            'nama model dicadangkan' => ['models/users.json', ['model' => 'users', 'fields' => []], 'dicadangkan'],
            'hook tak ada' => ['models/produk.json', $m([], ['hooks' => ['beforeSave' => 'ProdukHooks::hilang']]), 'Hook tidak ditemukan'],
            'hook kelas tak ada' => ['models/produk.json', $m([], ['hooks' => ['beforeSave' => 'Hantu::x']]), 'Hook tidak ditemukan'],
            'hook path traversal' => ['models/produk.json', $m([], ['hooks' => ['beforeSave' => '../ProdukHooks::cek']]), 'Kelas::method'],
            'event hook asing' => ['models/produk.json', $m([], ['hooks' => ['onFoo' => 'ProdukHooks::cek']]), 'Event hook'],
            'owner salah bentuk' => ['models/produk.json', $m(['u' => ['type' => 'integer']], ['access' => ['read' => '*', 'owner' => ['u']]]), 'owner'],
            'owner injeksi' => ['models/produk.json', $m(['u' => ['type' => 'integer']], ['access' => ['owner' => 'u; DROP']]), 'owner'],
            'owner kolom tak ada' => ['models/produk.json', $m(['u' => ['type' => 'integer']], ['access' => ['owner' => 'zzz']]), 'tidak ada di model'],
            'owner bertipe string' => ['models/produk.json', $m(['u' => ['type' => 'string']], ['access' => ['owner' => 'u']]), 'integer atau relasi'],
            'requireAmr salah bentuk' => ['models/produk.json', $m([], ['access' => ['requireAmr' => 'mfa']]), 'requireAmr'],
            'requireAmr aksi asing' => ['models/produk.json', $m([], ['access' => ['requireAmr' => ['hack' => ['mfa']]]]), 'amr'],
            'rule bukan * atau daftar' => ['models/produk.json', $m([], ['access' => ['read' => 'semua']]), 'peran'],
            'grup Admin dicadangkan' => ['pages/daftar-produk.json', ['group' => ' ADMIN '] + self::basePage(), 'Admin'],
            'rute dicadangkan' => ['pages/daftar-produk.json', ['route' => '/admin/x'] + self::basePage(), 'dicadangkan'],
            'rute traversal' => ['pages/daftar-produk.json', ['route' => '/a/../b'] + self::basePage(), '#/route'],
            'komponen asing' => ['pages/daftar-produk.json', ['layout' => [['component' => 'script']]] + self::basePage(), 'Komponen'],
            'sort SQL' => ['pages/daftar-produk.json', ['layout' => [['component' => 'table', 'source' => ['model' => 'produk', 'sort' => 'id; DROP']]]] + self::basePage(), 'sort'],
            'filter SQL' => ['pages/daftar-produk.json', ['layout' => [['component' => 'table', 'source' => ['model' => 'produk', 'filter' => ['nama' => '1; DROP TABLE x']]]]] + self::basePage(), 'filter'],
            'sumber model hilang' => ['pages/daftar-produk.json', ['layout' => [['component' => 'table', 'source' => ['model' => 'hantu']]]] + self::basePage(), 'Model sumber'],
            'kolom tak ada' => ['pages/daftar-produk.json', ['layout' => [['component' => 'table', 'columns' => ['zzz'], 'source' => ['model' => 'produk']]]] + self::basePage(), 'zzz'],
            'src gambar javascript' => ['pages/daftar-produk.json', ['layout' => [['component' => 'image', 'src' => 'javascript:alert(1)']]] + self::basePage(), '/src'],
            'page beda nama file' => ['pages/daftar-produk.json', ['page' => 'lain'] + self::basePage(), '#/page'],
        ];
    }

    /** @return array<string,mixed> */
    private static function basePage(): array
    {
        return ['page' => 'daftar-produk', 'route' => '/produk', 'access' => ['admin'], 'layout' => []];
    }

    /**
     * @dataProvider invalidProvider
     * @param array<string,mixed> $data
     */
    public function test_definisi_berbahaya_ditolak(string $file, array $data, string $needle): void
    {
        $this->put($file, $data);
        $v1 = (new CacheStore($this->cache))->current();
        $r = $this->build();
        self::assertNull($r->version, $file);
        self::assertStringContainsString($needle, $this->errSrc($r));
        self::assertSame($v1, (new CacheStore($this->cache))->current());
        foreach ($r->errors as $e) {
            self::assertMatchesRegularExpression('#^[A-Za-z0-9_./\#?-]+$#', $e->src); // _src aman
        }
    }

    public function test_json_rusak_dan_nama_file_berbahaya_dan_symlink(): void
    {
        file_put_contents($this->def . '/models/rusak.json', '{nope');
        file_put_contents($this->def . '/models/Bad Name.json', '{}');
        file_put_contents($this->def . '/models/..hidden.json', '{}');
        file_put_contents($this->root . '/luar.json', json_encode(['model' => 'luar', 'fields' => []]));
        symlink($this->root . '/luar.json', $this->def . '/models/luar.json');
        $r = $this->build();
        self::assertNull($r->version);
        $s = $this->errSrc($r);
        self::assertStringContainsString('models/rusak.json JSON tidak valid', $s);
        self::assertStringContainsString('Nama file definisi tidak valid', $s);
        self::assertStringContainsString('models/luar.json Berkas harus file biasa', $s);
        self::assertStringNotContainsString('Bad Name', $s);
    }

    public function test_folder_definisi_tidak_ada(): void
    {
        $r = (new Compiler(new CacheStore($this->cache), $this->ext))->build($this->root . '/nope', Dialect::Sqlite);
        self::assertNull($r->version);
    }

    public function test_banyak_error_dilaporkan_sekaligus(): void
    {
        $this->put('models/produk.json', ['model' => 'produk', 'fields' => ['a' => ['type' => 'x'], 'b' => ['type' => 'y']]]);
        self::assertGreaterThanOrEqual(2, count($this->build()->errors));
    }

    public function test_allowlist_dari_definisi_compiled(): void
    {
        $this->ok();
        $al = (new Definitions(new CacheStore($this->cache)))->allowlist();
        self::assertSame('harga', $al->column('produk', 'harga'));
        self::assertTrue($al->isDecimal('produk', 'harga'));
        self::assertSame(2, $al->scale('produk', 'harga'));
        self::assertSame('id', $al->column('produk', 'id'));
        $this->expectException(InvalidIdentifier::class);
        $al->column('produk', 'password; DROP');
    }

    public function test_kompatibel_dengan_authorizer_dan_router(): void
    {
        $this->ok();
        $defs = new Definitions(new CacheStore($this->cache));
        $m = $defs->model('produk');
        self::assertNotNull($m);
        $a = new Authorizer();
        $staf = new Identity(5, ['staf'], 'staf', ['pwd'], null);
        self::assertTrue($a->can($m, Action::Read, $staf));
        self::assertFalse($a->can($m, Action::Update, $staf));
        self::assertSame([['pemilik', '=', 7]], $a->scope($m, Action::Read, new Identity(7, ['staf'], 'staf', ['pwd'], null))->conds);
        $router = Router::fromCompiled($defs->routes());
        self::assertInstanceOf(Router::class, $router);
        self::assertCount(6, $defs->routes());
    }

    public function test_definisi_sumber_src_app_valid(): void
    {
        $src = realpath(__DIR__ . '/../../app');
        self::assertNotFalse($src);
        $r = (new Compiler(new CacheStore($this->cache)))->build($src . '/definitions', Dialect::MySql);
        self::assertSame([], $r->errors, $this->errSrc($r));
        self::assertNotNull($r->version);
    }

    public function test_tanpa_build_definitions_melempar(): void
    {
        $this->expectException(\RuntimeException::class);
        (new Definitions(new CacheStore($this->cache)))->model('produk');
    }
}
