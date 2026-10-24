<?php

declare(strict_types=1);

namespace bFramework\Tests\Cache;

use bFramework\Cache\PageCache;
use bFramework\Contracts\Dialect;
use bFramework\Contracts\Identity;
use bFramework\Core\Csrf;
use bFramework\Core\Nonce;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\Router;
use bFramework\Core\SafeHtml;
use bFramework\Core\SkipMiddleware;
use bFramework\Core\Template;
use bFramework\Runtime\Authorizer;
use bFramework\Runtime\CacheStore;
use bFramework\Runtime\Compiler;
use bFramework\Runtime\Connection;
use bFramework\Runtime\CurrentIdentity;
use bFramework\Runtime\Definitions;
use bFramework\Runtime\HookRunner;
use bFramework\Runtime\Migrator;
use bFramework\Runtime\ModelRepository;
use bFramework\Runtime\PageCacheSink;
use bFramework\Runtime\PageController;
use bFramework\Runtime\Query;
use bFramework\Runtime\SqliteGrammar;
use bFramework\Tests\Fixtures\ArraySessionStore;
use bFramework\Tests\Fixtures\StuckPcWrapper;
use PHPUnit\Framework\TestCase;

/** Tes ber-ID M16 (F8): CACHE-12, CACHE-13, CACHE-14 + keamanan kunci/isi cache. */
final class PageCacheTest extends TestCase
{
    private string $root;
    private string $pc;
    private Definitions $defs;
    private Query $q;
    private PageCache $cache;
    private ArraySessionStore $session;
    private Compiler $compiler;
    private string $defDir;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/pc_' . bin2hex(random_bytes(6));
        $this->defDir = $this->root . '/definitions';
        mkdir($this->defDir . '/models', 0700, true);
        mkdir($this->defDir . '/pages', 0700, true);
        mkdir($this->root . '/ext', 0700, true);
        $this->pc = $this->root . '/public_html/_pc';
        $w = fn(string $rel, array $d) => file_put_contents($this->defDir . '/' . $rel, json_encode($d));
        $w('models/produk.json', [
            'model' => 'produk',
            'fields' => ['nama' => ['type' => 'string', 'required' => true, 'max' => 50]],
            'access' => ['read' => '*', 'write' => ['admin']],
        ]);
        $w('models/terbuka.json', [
            'model' => 'terbuka',
            'fields' => ['nama' => ['type' => 'string', 'required' => true, 'max' => 50]],
            'access' => ['read' => '*', 'write' => '*'],
        ]);
        $w('pages/katalog.json', [
            'page' => 'katalog', 'route' => '/katalog', 'title' => 'Katalog', 'access' => '*', 'cache' => true,
            'layout' => [['component' => 'table', 'columns' => ['nama'], 'source' => ['model' => 'produk', 'perPage' => 50]]],
        ]);
        $w('pages/tanpa.json', [
            'page' => 'tanpa', 'route' => '/tanpa', 'title' => 'Tanpa', 'access' => '*',
            'layout' => [['component' => 'table', 'columns' => ['nama'], 'source' => ['model' => 'produk']]],
        ]);
        $w('pages/bebas.json', [
            'page' => 'bebas', 'route' => '/bebas', 'title' => 'Bebas', 'access' => '*', 'cache' => true,
            'layout' => [['component' => 'table', 'columns' => ['nama'], 'actions' => ['hapus'], 'source' => ['model' => 'terbuka']]],
        ]);
        $w('pages/privat.json', [
            'page' => 'privat', 'route' => '/privat', 'title' => 'Privat', 'access' => ['admin'],
            'layout' => [['component' => 'text', 'text' => 'rahasia']],
        ]);
        $store = new CacheStore($this->root . '/cache');
        $this->compiler = new Compiler($store, $this->root . '/ext');
        $r = $this->compiler->build($this->defDir, Dialect::Sqlite);
        self::assertSame([], $r->errors, json_encode($r->errors) ?: '');
        $this->defs = new Definitions($store);
        $conn = Connection::sqlite($this->root . '/db.sqlite');
        $m = new Migrator($conn, new SqliteGrammar());
        foreach ($this->defs->tables() as $t) {
            $m->apply($m->planCreate($t));
        }
        $this->q = new Query($conn, new SqliteGrammar(), $this->defs->allowlist());
        $this->cache = $this->newCache();
        $this->session = new ArraySessionStore();
        $this->session->start();
        Nonce::reset();
    }

    protected function tearDown(): void
    {
        CacheStore::rmTree($this->root);
    }

    /** @param array<string,int> $limits */
    private function newCache(array $limits = []): PageCache
    {
        return new PageCache($this->pc, $this->root . '/state', fn(): array => ['/katalog', '/bebas', '/dalam/satu'], null, $limits);
    }

    private function configure(?Identity $who = null, ?PageCacheSink $sink = null): void
    {
        $ci = new CurrentIdentity($this->session);
        $who === null ? $ci->clear() : $ci->set($who);
        $app = dirname(__DIR__, 2) . '/app';
        $views = $this->root . '/viewcache';
        PageController::configure(
            $this->defs,
            $this->q,
            new Authorizer(),
            new HookRunner($this->root . '/ext'),
            new Template($app . '/core/Runtime/views', $views),
            new Template($app . '/core/Core/views', $views),
            $this->session,
            $ci,
            new Csrf($this->session),
            false,
            null,
            null,
            $sink ?? $this->cache,
        );
    }

    private function get(string $path, array $query = [], string $cookie = ''): Response
    {
        $h = $cookie === '' ? [] : ['cookie' => $cookie];
        return Router::fromCompiled($this->defs->routes())->dispatch(new Request('GET', $path, $query, [], $h));
    }

    private function file(): string
    {
        return $this->pc . '/katalog.html';
    }

    private function repo(?Identity $who, ?PageCacheSink $sink): ModelRepository
    {
        $d = $this->defs->model('produk');
        self::assertNotNull($d);
        return new ModelRepository($d, $this->q, new Authorizer(), $who, new HookRunner($this->root . '/ext'), null, null, false, null, null, $sink);
    }

    // ---------- CACHE-12 ----------

    public function test_CACHE_12_request_pertama_menyimpan_html_statis_dan_kedua_tak_perlu_php(): void
    {
        $this->q->insert('produk', ['nama' => 'Kopi']);
        $this->configure();
        $res = $this->get('/katalog');
        self::assertSame(200, $res->status);
        self::assertFileExists($this->file());
        self::assertSame($res->body, file_get_contents($this->file()));
        self::assertStringContainsString('Kopi', (string) file_get_contents($this->file()));
        self::assertSame('0644', substr(sprintf('%o', fileperms($this->file())), -4));
        // Berkas yang sama dipetakan .htaccess untuk request berikutnya (Apache tidak ada di CI: periksa aturan statis).
        $h = (string) file_get_contents(__DIR__ . '/../../public_html/.htaccess');
        self::assertMatchesRegularExpression('#RewriteCond %\{DOCUMENT_ROOT\}/_pc/\$1\.html -f#', $h);
        self::assertStringContainsString('RewriteCond %{REQUEST_METHOD} ^(GET|HEAD)$', $h);
        self::assertStringContainsString('RewriteCond %{QUERY_STRING} ^$', $h);
        self::assertMatchesRegularExpression('#HTTP_COOKIE\} !.*bf_\(sid\|remember\)#', $h);
        self::assertLessThan(strpos($h, 'RewriteRule !^index'), (int) strpos($h, '_pc/$1.html [L]'));
        self::assertStringNotContainsString('[END]', $h);
        self::assertStringContainsString('<IfModule mod_rewrite.c>', $h);
    }

    public function test_CACHE_12_halaman_tanpa_flag_cache_tidak_disimpan(): void
    {
        $this->configure();
        $this->get('/tanpa');
        self::assertSame([], glob($this->pc . '/*.html') ?: []);
    }

    public function test_CACHE_12_anonim_cache_tidak_membuat_sesi_dan_tanpa_nonce_csrf(): void
    {
        $this->configure();
        $res = $this->get('/katalog');
        self::assertSame('', $this->session->get('_csrf', ''), 'token CSRF tidak dibuat');
        $html = (string) file_get_contents($this->file());
        self::assertStringNotContainsString(Nonce::current(), $html);
        self::assertDoesNotMatchRegularExpression('/nonce\s*=/i', $html);
        self::assertStringNotContainsString('_csrf', $html);
        self::assertDoesNotMatchRegularExpression('/csrf-token" content="[^"]/', $html);
        self::assertStringNotContainsString('Set-Cookie', $html);
        self::assertSame([], $res->cookies);
        self::assertArrayNotHasKey('Set-Cookie', $res->headers);
        self::assertStringContainsString('/assets/app.js', $html); // skrip tetap termuat lewat script-src 'self'
    }

    public function test_CACHE_12_form_bertoken_di_halaman_cache_tidak_disimpan(): void
    {
        $this->q->insert('terbuka', ['nama' => 'x']);
        $this->configure();
        $res = $this->get('/bebas');
        self::assertSame(200, $res->status);
        self::assertFileDoesNotExist($this->pc . '/bebas.html');
    }

    public function test_CACHE_12_cookie_sesi_query_dan_metode_tidak_eligible(): void
    {
        $c = $this->cache;
        self::assertTrue($c->eligible(new Request('GET', '/katalog')));
        self::assertFalse($c->eligible(new Request('GET', '/katalog', ['x' => '1'])));
        self::assertFalse($c->eligible(new Request('POST', '/katalog')));
        self::assertFalse($c->eligible(new Request('GET', '/tanpa')));
        foreach (['bf_sid=abc', 'a=1; __Host-bf_sid=abc', 'bf_remember=x', 'z=1;bf_sid=q'] as $ck) {
            self::assertFalse($c->eligible(new Request('GET', '/katalog', [], [], ['cookie' => $ck])), $ck);
        }
        self::assertTrue($c->eligible(new Request('GET', '/katalog', [], [], ['cookie' => 'analytics=1'])));
        self::assertFalse($c->eligible(new Request('GET', '/katalog', [], [], ['authorization' => 'Bearer x'])));
    }

    public function test_CACHE_12_request_dengan_cookie_sesi_tidak_menyimpan_walau_halaman_cache(): void
    {
        $this->configure(new Identity(1, ['admin'], 'admin'));
        $this->get('/katalog', [], 'bf_sid=' . str_repeat('a', 40));
        self::assertFileDoesNotExist($this->file());
    }

    public function test_CACHE_12_skip_middleware_melewati_sesi_untuk_request_eligible(): void
    {
        $called = 0;
        $inner = new class ($called) implements \bFramework\Core\Middleware {
            public function __construct(private int &$n)
            {
            }

            public function process(Request $r, callable $next): Response
            {
                $this->n++;
                return $next($r);
            }
        };
        $mw = new SkipMiddleware($inner, $this->cache->eligible(...));
        $ok = static fn(Request $r): Response => Response::html('ok');
        $mw->process(new Request('GET', '/katalog'), $ok);
        self::assertSame(0, $called);
        $mw->process(new Request('GET', '/katalog', [], [], ['cookie' => 'bf_sid=x']), $ok);
        self::assertSame(1, $called);
    }

    public function test_CACHE_12_header_keamanan_dan_php_mati_di_pc_htaccess(): void
    {
        $h = (string) file_get_contents(__DIR__ . '/../../public_html/_pc/.htaccess');
        foreach (['X-Content-Type-Options "nosniff"', 'Referrer-Policy', 'X-Frame-Options "DENY"', 'Content-Security-Policy', 'Strict-Transport-Security'] as $k) {
            self::assertStringContainsString($k, $h);
        }
        self::assertStringContainsString("script-src 'self';", $h);
        self::assertStringNotContainsString('nonce-', $h);
        self::assertStringContainsString('php_flag engine off', $h);
        self::assertStringContainsString('RemoveHandler .php', $h);
        self::assertStringNotContainsString('expr=', $h);
        self::assertStringContainsString('env=BF_HTTPS', $h);
        foreach (['mod_mime.c', 'mod_headers.c'] as $m) {
            self::assertStringContainsString("<IfModule $m>", $h);
        }
        self::assertMatchesRegularExpression('#<IfModule mod_mime\.c>\s*RemoveHandler.*?RemoveType.*?</IfModule>#s', $h);
        self::assertMatchesRegularExpression('#<IfModule mod_mime\.c>\s*ForceType text/html\s*</IfModule>#', $h);
        self::assertStringContainsString('(?!.+\.html$)', $h);
    }

    // ---------- CACHE-13 ----------

    public function test_CACHE_13_ubah_data_menghapus_halaman_dan_halaman_menampilkan_data_baru(): void
    {
        $admin = new Identity(1, ['admin'], 'admin');
        $this->configure();
        $this->get('/katalog');
        self::assertFileExists($this->file());
        $res = $this->repo($admin, $this->cache)->create(['nama' => 'Teh Baru']);
        self::assertTrue($res->ok());
        self::assertFileDoesNotExist($this->file());
        self::assertStringContainsString('Teh Baru', $this->get('/katalog')->body);
        self::assertStringContainsString('Teh Baru', (string) file_get_contents($this->file()));

        $id = (int) $res->id;
        $this->repo($admin, $this->cache)->update($id, ['nama' => 'Teh Lama']);
        self::assertFileDoesNotExist($this->file());
        $this->get('/katalog');
        self::assertFileExists($this->file());
        $this->repo($admin, $this->cache)->delete($id);
        self::assertFileDoesNotExist($this->file());
        self::assertStringNotContainsString('Teh', $this->get('/katalog')->body);
    }

    public function test_CACHE_13_model_lain_tidak_menghapus_halaman(): void
    {
        $this->configure();
        $this->get('/katalog');
        $this->cache->invalidate('lain');
        self::assertFileExists($this->file());
        $this->cache->invalidate('produk');
        self::assertFileDoesNotExist($this->file());
    }

    public function test_CACHE_13_race_simpan_lama_setelah_invalidasi_ditolak(): void
    {
        $snap = $this->cache->snapshot(['produk']);          // request A mulai render dengan data lama
        $this->cache->invalidate('produk');                  // request B mengubah data
        $ok = $this->cache->store('/katalog', SafeHtml::fromTrusted('<p>lama</p>'), ['produk'], $snap);
        self::assertFalse($ok);
        self::assertFileDoesNotExist($this->file());
        $snap2 = $this->cache->snapshot(['produk']);
        self::assertTrue($this->cache->store('/katalog', SafeHtml::fromTrusted('<p>baru</p>'), ['produk'], $snap2));
    }

    public function test_CACHE_13_purge_total_membatalkan_snapshot_dan_menghapus_semua(): void
    {
        self::assertTrue($this->cache->store('/katalog', SafeHtml::fromTrusted('<p>a</p>'), ['produk']));
        $snap = $this->cache->snapshot(['produk']);
        $this->cache->purgeAll();
        self::assertFileDoesNotExist($this->file());
        self::assertFalse($this->cache->store('/katalog', SafeHtml::fromTrusted('<p>b</p>'), ['produk'], $snap));
    }

    public function test_CACHE_13_kegagalan_invalidasi_tidak_membatalkan_simpan_data_dan_dicatat(): void
    {
        $sink = new class implements PageCacheSink {
            public int $calls = 0;

            public function eligible(Request $r): bool
            {
                return false;
            }

            public function snapshot(array $tags): array
            {
                return [];
            }

            public function store(string $route, SafeHtml $html, array $tags, ?array $snapshot = null): bool
            {
                return false;
            }

            public function invalidate(string $model): void
            {
                $this->calls++;
                throw new \RuntimeException('gagal');
            }
        };
        $res = $this->repo(new Identity(1, ['admin'], 'admin'), $sink)->create(['nama' => 'X']);
        self::assertTrue($res->ok());
        self::assertGreaterThanOrEqual(2, $sink->calls, 'invalidasi dipanggil sebelum dan sesudah tulis');
    }

    public function test_CACHE_13_build_baru_membuang_semua_cache_halaman(): void
    {
        $purged = 0;
        $c = new Compiler(new CacheStore($this->root . '/cache'), $this->root . '/ext', null, function () use (&$purged): void {
            $purged++;
            $this->cache->purgeAll();
        });
        $this->configure();
        $this->get('/katalog');
        self::assertFileExists($this->file());
        file_put_contents($this->defDir . '/pages/katalog.json', json_encode([
            'page' => 'katalog', 'route' => '/katalog', 'title' => 'Katalog2', 'access' => '*', 'cache' => true,
            'layout' => [['component' => 'text', 'text' => 'x']],
        ]));
        self::assertSame([], $c->build($this->defDir, Dialect::Sqlite)->errors);
        self::assertSame(2, $purged); // sebelum dan sesudah aktivasi
        self::assertFileDoesNotExist($this->file());
    }

    public function test_CACHE_13_purge_gagal_fallback_hapus_langsung_dan_terlog(): void
    {
        $this->configure();
        $this->get('/katalog');
        self::assertFileExists($this->file());
        $logger = new class implements \bFramework\Contracts\Logger {
            public int $n = 0;
            public function error(string $msg, array $ctx = []): void { $this->n++; }
            public function warning(string $msg, array $ctx = []): void {}
            public function info(string $msg, array $ctx = []): void {}
        };
        $c = new Compiler(new CacheStore($this->root . '/cache3'), $this->root . '/ext', null, static function (): void {
            throw new \RuntimeException('purge rusak');
        }, $logger, $this->pc);
        self::assertSame([], $c->build($this->defDir, Dialect::Sqlite)->errors);
        self::assertGreaterThan(0, $logger->n);
        self::assertFileDoesNotExist($this->file());
    }

    public function test_CACHE_13_purge_dan_fallback_gagal_membuat_build_gagal_dan_versi_lama_tetap(): void
    {
        $store = new CacheStore($this->root . '/cache4');
        $old = $this->buildOld($store);
        // onBuilt melempar dan $pcDir berisi .html yang tak dapat dihapus (stream wrapper; berlaku juga untuk root).
        StuckPcWrapper::register();
        $r = (new Compiler($store, $this->root . '/ext', null, static function (): void {
            throw new \RuntimeException('x');
        }, null, StuckPcWrapper::DIR))->build($this->defDir, Dialect::Sqlite);
        self::assertFalse($r->ok());
        self::assertSame($old, $store->current());
    }

    public function test_CACHE_13_purge_kedua_gagal_setelah_aktivasi_rollback_ke_versi_lama(): void
    {
        $store = new CacheStore($this->root . '/cache6');
        $old = $this->buildOld($store);
        self::assertNotNull($old);
        $calls = 0;
        $r = $this->compilerFailingOnCall($store, 2, $calls)->build($this->defDir, Dialect::Sqlite);
        self::assertFalse($r->ok());
        self::assertNotSame([], $r->errors);
        self::assertSame($old, $store->current(), 'versi lama aktif kembali');
        self::assertSame(3, $calls, 'purge diulang setelah rollback');
        self::assertSame([], StuckPcWrapper::$renames, 'purge ulang berhasil: tidak perlu karantina');
    }

    public function test_CACHE_13_purge_kedua_gagal_tanpa_versi_sebelumnya_tidak_ada_versi_aktif(): void
    {
        $store = new CacheStore($this->root . '/cache7');
        self::assertNull($store->current());
        $calls = 0;
        $r = $this->compilerFailingOnCall($store, 2, $calls)->build($this->defDir, Dialect::Sqlite);
        self::assertFalse($r->ok());
        self::assertNotSame([], $r->errors);
        self::assertNull($store->current());
        self::assertSame(3, $calls);
    }

    public function test_CACHE_13_purge_ulang_setelah_rollback_gagal_mengkarantina_cache_halaman(): void
    {
        $store = new CacheStore($this->root . '/cache8');
        StuckPcWrapper::register();
        StuckPcWrapper::$renameOk = true;
        $calls = 0;
        $r = (new Compiler($store, $this->root . '/ext', null, static function () use (&$calls): void {
            if (++$calls >= 2) {
                throw new \RuntimeException('purge rusak');
            }
        }, null, StuckPcWrapper::DIR))->build($this->defDir, Dialect::Sqlite);
        self::assertFalse($r->ok());
        self::assertNull($store->current());
        self::assertCount(1, StuckPcWrapper::$renames);
        self::assertSame(StuckPcWrapper::DIR, StuckPcWrapper::$renames[0][0]);
        self::assertMatchesRegularExpression('#^stuckpc://root/\.pc_stale_[0-9a-f]{12}$#', StuckPcWrapper::$renames[0][1]);
    }

    private function buildOld(CacheStore $store): ?string
    {
        $first = (new Compiler($store, $this->root . '/ext', null, null, null, $this->root . '/tidak-ada'))->build($this->defDir, Dialect::Sqlite);
        self::assertTrue($first->ok());
        file_put_contents($this->defDir . '/pages/katalog.json', json_encode([
            'page' => 'katalog', 'route' => '/katalog', 'title' => 'Baru', 'access' => '*', 'cache' => true,
            'layout' => [['component' => 'text', 'text' => 'y']],
        ]));
        return $store->current();
    }

    /** onBuilt gagal hanya pada pemanggilan ke-$n; fallback juga gagal ($pcDir berisi .html yang tak terhapus). */
    private function compilerFailingOnCall(CacheStore $store, int $n, int &$calls): Compiler
    {
        StuckPcWrapper::register();
        return new Compiler($store, $this->root . '/ext', null, static function () use (&$calls, $n): void {
            if (++$calls === $n) {
                throw new \RuntimeException('purge rusak');
            }
        }, null, StuckPcWrapper::DIR);
    }

    public function test_CACHE_13_akses_diturunkan_dari_bintang_menghapus_file_cache(): void
    {
        $this->configure();
        $this->get('/katalog');
        self::assertFileExists($this->file());
        file_put_contents($this->defDir . '/pages/katalog.json', json_encode([
            'page' => 'katalog', 'route' => '/katalog', 'title' => 'K', 'access' => ['admin'],
            'layout' => [['component' => 'text', 'text' => 'x']],
        ]));
        // Tanpa sink sama sekali: fallback default Compiler harus tetap membuang _pc.
        $r = (new Compiler(new CacheStore($this->root . '/cache5'), $this->root . '/ext', null, null, null, $this->pc))->build($this->defDir, Dialect::Sqlite);
        self::assertTrue($r->ok());
        self::assertFileDoesNotExist($this->file());
    }

    // ---------- CACHE-14 ----------

    public function test_CACHE_14_halaman_butuh_login_dengan_cache_true_gagal_compile(): void
    {
        file_put_contents($this->defDir . '/pages/privat.json', json_encode([
            'page' => 'privat', 'route' => '/privat', 'title' => 'P', 'access' => ['admin'], 'cache' => true,
            'layout' => [['component' => 'text', 'text' => 'x']],
        ]));
        $r = (new Compiler(new CacheStore($this->root . '/cache2'), $this->root . '/ext'))->build($this->defDir, Dialect::Sqlite);
        self::assertNotSame([], $r->errors);
        self::assertStringContainsString('CACHE-14', json_encode($r->errors, JSON_UNESCAPED_SLASHES) ?: '');
    }

    public function test_CACHE_14_runtime_halaman_login_dan_privat_tidak_pernah_masuk_cache(): void
    {
        $this->configure(new Identity(1, ['admin'], 'admin'));
        $res = $this->get('/privat');
        self::assertSame(200, $res->status);
        self::assertFileDoesNotExist($this->pc . '/privat.html');
        // Sink yang (salah) menganggap /privat eligible tetap tidak menyimpan: akses bukan '*'.
        $c = new PageCache($this->pc, $this->root . '/state2', fn(): array => ['/privat'], null);
        $this->configure(null, $c);
        $this->get('/privat');
        self::assertFileDoesNotExist($this->pc . '/privat.html');
    }

    public function test_CACHE_14_pengguna_login_pada_halaman_publik_tidak_menyimpan(): void
    {
        $this->configure(new Identity(1, ['admin'], 'admin'));
        $this->get('/katalog', [], 'bf_sid=' . str_repeat('b', 40));
        self::assertFileDoesNotExist($this->file());
    }

    public function test_CACHE_14_store_menolak_rute_di_luar_whitelist(): void
    {
        self::assertFalse($this->cache->store('/tanpa', SafeHtml::fromTrusted('x'), []));
        self::assertFalse($this->cache->store('/privat', SafeHtml::fromTrusted('x'), []));
    }

    // ---------- kunci & isi aman ----------

    public function test_kunci_cache_aman_dari_traversal_nul_panjang_dan_query_liar(): void
    {
        foreach (['/../x', '/a/../b', '/a%00b', "/a\0b", '/a.b', '/A', '/a b', '//x', '/', '', 'x', '/a/', '/a\\b', '/' . str_repeat('a', 130)] as $r) {
            self::assertNull(PageCache::keyFor($r), $r);
            self::assertFalse($this->cache->store($r, SafeHtml::fromTrusted('x'), []), $r);
        }
        self::assertSame('katalog.html', PageCache::keyFor('/katalog'));
        self::assertSame('a/b-c_1.html', PageCache::keyFor('/a/b-c_1'));
        self::assertFalse($this->cache->eligible(new Request('GET', '/katalog', ['a' => ['b'], '../x' => '1'])));
        self::assertFalse($this->cache->eligible(new Request('GET', '/katalog/../../etc')));
        // tidak ada berkas di luar _pc/
        self::assertSame([], glob($this->root . '/public_html/*') === false ? [] : array_diff(glob($this->root . '/public_html/*') ?: [], [$this->pc]));
    }

    public function test_isi_berbahaya_nonce_csrf_atau_terlalu_besar_ditolak(): void
    {
        foreach ([
            '<script nonce="abc"></script>', '<input name="_csrf" value="t">',
            '<meta name="csrf-token" content="deadbeef">',
        ] as $h) {
            self::assertFalse($this->cache->store('/katalog', SafeHtml::fromTrusted($h), []), $h);
        }
        self::assertTrue($this->cache->store('/katalog', SafeHtml::fromTrusted('<meta name="csrf-token" content="">'), []));
        $small = $this->newCache(['maxFileBytes' => 10]);
        self::assertFalse($small->store('/katalog', SafeHtml::fromTrusted(str_repeat('a', 11)), []));
    }

    public function test_batas_jumlah_berkas_dan_gc(): void
    {
        $c = new PageCache($this->pc, $this->root . '/st', fn(): array => ['/katalog', '/bebas', '/dalam/satu'], null, ['maxFiles' => 2, 'ttl' => 60]);
        self::assertTrue($c->store('/katalog', SafeHtml::fromTrusted('a'), []));
        self::assertTrue($c->store('/bebas', SafeHtml::fromTrusted('b'), []));
        self::assertFalse($c->store('/dalam/satu', SafeHtml::fromTrusted('c'), []));
        self::assertTrue($c->store('/katalog', SafeHtml::fromTrusted('a2'), []), 'menimpa berkas yang sudah ada tetap boleh');
        // yatim + tmp usang
        file_put_contents($this->pc . '/yatim.html', 'x');
        file_put_contents($this->pc . '/.tmp-old', 'x');
        touch($this->pc . '/.tmp-old', time() - 7200);
        self::assertGreaterThanOrEqual(1, $c->gc());
        self::assertFileDoesNotExist($this->pc . '/yatim.html');
        self::assertFileDoesNotExist($this->pc . '/.tmp-old');
        self::assertFileExists($this->pc . '/katalog.html');
        // kedaluwarsa
        $c2 = new PageCache($this->pc, $this->root . '/st', fn(): array => ['/katalog'], null, ['ttl' => 1]);
        foreach (glob($this->root . '/st/idx/*.json') ?: [] as $f) {
            $d = json_decode((string) file_get_contents($f), true);
            $d['t'] = time() - 100;
            file_put_contents($f, json_encode($d));
        }
        $c2->gc();
        self::assertFileDoesNotExist($this->pc . '/katalog.html');
    }

    public function test_rute_bersarang_disimpan_di_subfolder_dan_diinvalidasi(): void
    {
        self::assertTrue($this->cache->store('/dalam/satu', SafeHtml::fromTrusted('x'), ['produk']));
        self::assertFileExists($this->pc . '/dalam/satu.html');
        $this->cache->invalidate('produk');
        self::assertFileDoesNotExist($this->pc . '/dalam/satu.html');
    }

    public function test_nama_model_tidak_valid_memicu_purge_total(): void
    {
        $this->cache->store('/katalog', SafeHtml::fromTrusted('x'), []);
        $this->cache->invalidate('../bad');
        self::assertFileDoesNotExist($this->file());
    }

    public function test_folder_pc_dikirim_dengan_htaccess_dan_tanpa_php(): void
    {
        self::assertFileExists(__DIR__ . '/../../public_html/_pc/.htaccess');
        self::assertSame([], glob(__DIR__ . '/../../public_html/_pc/*.php') ?: []);
    }
}
