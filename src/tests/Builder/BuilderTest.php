<?php

declare(strict_types=1);

namespace bFramework\Tests\Builder;

use bFramework\Builder\AuditLog;
use bFramework\Builder\BuilderController;
use bFramework\Builder\BuilderGate;
use bFramework\Builder\DefinitionWriter;
use bFramework\Builder\HookScanner;
use bFramework\Builder\Sampler;
use bFramework\Builder\WriteConflict;
use bFramework\Builder\WriteRejected;
use bFramework\Contracts\Dialect;
use bFramework\Contracts\Identity;
use bFramework\Core\Csrf;
use bFramework\Core\CsrfMiddleware;
use bFramework\Core\Kernel;
use bFramework\Core\Nonce;
use bFramework\Core\RateLimiter;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\Router;
use bFramework\Core\SecurityHeaders;
use bFramework\Core\Template;
use bFramework\Runtime\CacheStore;
use bFramework\Runtime\Compiler;
use bFramework\Runtime\Connection;
use bFramework\Runtime\CurrentIdentity;
use bFramework\Runtime\Definitions;
use bFramework\Runtime\Migrator;
use bFramework\Tests\Fixtures\ArraySessionStore;
use bFramework\Tests\Fixtures\CaptureLogger;
use bFramework\Tests\Fixtures\FakeClock;
use PHPUnit\Framework\TestCase;

/** M14 Builder: BLD-01..10 dan SEC-BLD-01. Hanya data dummy; seluruh file di folder sementara. */
final class BuilderTest extends TestCase
{
    private const PW = 'kata-sandi-builder-dummy-42';

    private string $root;
    private string $defs;
    private string $ext;
    private ArraySessionStore $session;
    private FakeClock $clock;
    private Connection $conn;
    private CaptureLogger $log;
    private CacheStore $store;
    private DefinitionWriter $writer;
    private Csrf $csrf;
    private AuditLog $audit;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/bld_' . bin2hex(random_bytes(6));
        $this->defs = $this->root . '/definitions';
        $this->ext = $this->root . '/extensions';
        mkdir($this->defs . '/models', 0700, true);
        mkdir($this->defs . '/pages', 0700, true);
        mkdir($this->ext, 0700, true);
        mkdir($this->root . '/ratelimit', 0700, true);
        mkdir($this->root . '/viewcache', 0700, true);
        $src = __DIR__ . '/../../app';
        foreach (['models/kategori.json', 'models/produk.json', 'pages/daftar-produk.json'] as $f) {
            copy("$src/definitions/$f", "$this->defs/$f");
        }
        copy("$src/extensions/ProdukHooks.php", "$this->ext/ProdukHooks.php");
        $this->store = new CacheStore($this->root . '/cache');
        $this->clock = new FakeClock();
        $this->log = new CaptureLogger();
        $this->conn = Connection::sqlite(':memory:');
        $compiler = new Compiler($this->store, $this->ext);
        self::assertTrue($compiler->build($this->defs, Dialect::Sqlite)->ok());
        $m = new Migrator($this->conn, $this->conn->grammar());
        $d = new Definitions($this->store);
        foreach ($d->tables() as $t) {
            $m->apply($m->planCreate($t));
        }
        $this->writer = new DefinitionWriter($this->defs, $compiler, Dialect::Sqlite, $this->ext, $this->log);
        $this->session = new ArraySessionStore();
        $this->session->start();
        $this->csrf = new Csrf($this->session);
        $this->audit = new AuditLog($this->conn, $this->clock, $this->log);
        $this->login('admin');
    }

    protected function tearDown(): void
    {
        CacheStore::rmTree($this->root);
    }

    private function login(string $role): void
    {
        (new CurrentIdentity($this->session))->set(new Identity(7, [$role, 'staf'], $role, ['pwd']));
    }

    /** @param array<string,mixed> $opts */
    private function kernel(bool $dev, array $opts = []): Kernel
    {
        $identity = new CurrentIdentity($this->session);
        $gate = new BuilderGate(
            $dev,
            $opts,
            $this->session,
            static fn(): ?Identity => $identity->get(),
            new RateLimiter($this->root . '/ratelimit', $this->clock),
            $this->clock,
            $this->log,
        );
        $ctl = new BuilderController(
            $gate,
            $this->writer,
            new HookScanner($this->ext),
            $this->audit,
            $this->conn,
            $this->csrf,
            new Template(__DIR__ . '/../../app/core/Builder/views', $this->root . '/viewcache'),
            new Template(__DIR__ . '/../../app/core/Core/views', $this->root . '/viewcache'),
            fn(string $n): ?array => (new Definitions($this->store))->model($n),
            static fn(): array => ['admin', 'staf'],
            static fn(Identity $w): array => [],
            $this->log,
        );
        $router = new Router();
        $ctl->registerRoutes($router);
        return new Kernel($router, [new SecurityHeaders(Nonce::current(...)), new CsrfMiddleware($router, $this->csrf, $this->session)], $this->log);
    }

    /** @param array<string,mixed>|null $json */
    private function req(Kernel $k, string $method, string $path, ?array $json = null, bool $csrf = true, string $ip = '203.0.113.7', array $post = []): Response
    {
        $headers = $csrf ? ['x-csrf-token' => $this->csrf->token()] : [];
        $q = [];
        if (str_contains($path, '?')) {
            [$path, $qs] = explode('?', $path, 2);
            parse_str($qs, $q);
        }
        if ($post !== [] && $csrf) {
            $post['_csrf'] = $this->csrf->token();
        }
        $r = new Request($method, $path, $q, $post, $headers, $json === null ? '' : json_encode($json, JSON_THROW_ON_ERROR), [], false, $ip);
        return $k->handle($r);
    }

    /** @return array<string,mixed> */
    private function body(Response $r): array
    {
        $d = json_decode($r->body, true);
        return is_array($d) ? $d : [];
    }

    /** @return array<string,mixed> */
    private function produk(): array
    {
        return (array) json_decode((string) file_get_contents($this->defs . '/models/produk.json'), true);
    }

    private function hashOf(string $rel): string
    {
        return hash('sha256', (string) file_get_contents($this->defs . '/' . $rel));
    }

    /** @return array{unsafeBuilderInProduction:bool,allowedIps:list<string>,passwordHash:string} */
    private function prodOpts(): array
    {
        return ['unsafeBuilderInProduction' => true, 'allowedIps' => ['203.0.113.0/24'], 'passwordHash' => password_hash(self::PW, PASSWORD_BCRYPT, ['cost' => 4])];
    }

    // ---------- SEC-BLD-01 ----------

    public function test_SEC_BLD_01_produksi_default_semua_rute_404(): void
    {
        $k = $this->kernel(false);
        foreach (['/_builder', '/_builder/login', '/_builder/api/state', '/_builder/api/etag'] as $p) {
            self::assertSame(404, $this->req($k, 'GET', $p)->status, $p);
        }
        self::assertSame(404, $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model'])->status);
    }

    public function test_SEC_BLD_01_produksi_flag_tanpa_whitelist_atau_sandi_tetap_404(): void
    {
        foreach ([['unsafeBuilderInProduction' => true], ['unsafeBuilderInProduction' => true, 'allowedIps' => ['203.0.113.7']],
            ['unsafeBuilderInProduction' => true, 'allowedIps' => ['203.0.113.7'], 'passwordHash' => 'bukan-hash'],
            ['allowedIps' => ['203.0.113.7'], 'passwordHash' => $this->prodOpts()['passwordHash']]] as $o) {
            self::assertSame(404, $this->req($this->kernel(false, $o), 'GET', '/_builder')->status);
        }
    }

    public function test_SEC_BLD_01_produksi_ip_luar_whitelist_dan_non_admin_404(): void
    {
        $k = $this->kernel(false, $this->prodOpts());
        self::assertSame(404, $this->req($k, 'GET', '/_builder', null, true, '198.51.100.9')->status);
        self::assertSame(404, $this->req($k, 'GET', '/_builder', null, true, '')->status);
        $this->login('staf');
        self::assertSame(404, $this->req($k, 'GET', '/_builder')->status);
        $this->session->forget('_identity');
        self::assertSame(404, $this->req($k, 'GET', '/_builder')->status);
    }

    public function test_SEC_BLD_01_produksi_butuh_login_builder_terpisah_dan_diaudit(): void
    {
        $k = $this->kernel(false, $this->prodOpts());
        $r = $this->req($k, 'GET', '/_builder');
        self::assertSame(302, $r->status);
        self::assertSame('/_builder/login', $r->headers['Location']);
        self::assertSame(401, $this->req($k, 'GET', '/_builder/api/state')->status);
        self::assertSame(401, $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'x'])->status);
        self::assertSame(200, $this->req($k, 'GET', '/_builder/login')->status);

        $bad = $this->req($k, 'POST', '/_builder/login', null, true, '203.0.113.7', ['password' => 'salah']);
        self::assertSame(401, $bad->status);
        self::assertSame(401, $this->req($k, 'GET', '/_builder/api/state')->status);

        $ok = $this->req($k, 'POST', '/_builder/login', null, true, '203.0.113.7', ['password' => self::PW]);
        self::assertSame(302, $ok->status);
        self::assertSame(200, $this->req($k, 'GET', '/_builder')->status);
        self::assertSame(200, $this->req($k, 'GET', '/_builder/api/state')->status);

        $actions = array_column($this->audit->recent(), 'action');
        self::assertContains('builder.login_failed', $actions);
        self::assertContains('builder.login', $actions);
        self::assertContains('builder.open', $actions);
        $dump = json_encode($this->audit->recent()) . $this->log->all();
        self::assertStringNotContainsString(self::PW, $dump);
        self::assertStringNotContainsString('salah', $dump);
    }

    public function test_SEC_BLD_01_login_builder_kedaluwarsa_terikat_user_dan_rate_limit(): void
    {
        $k = $this->kernel(false, $this->prodOpts() + ['loginTtl' => 120]);
        $this->req($k, 'POST', '/_builder/login', null, true, '203.0.113.7', ['password' => self::PW]);
        self::assertSame(200, $this->req($k, 'GET', '/_builder/api/etag')->status);
        $this->clock->advance(121);
        self::assertSame(401, $this->req($k, 'GET', '/_builder/api/etag')->status);

        $this->req($k, 'POST', '/_builder/login', null, true, '203.0.113.7', ['password' => self::PW]);
        (new CurrentIdentity($this->session))->set(new Identity(99, ['admin'], 'admin', ['pwd']));
        self::assertSame(401, $this->req($k, 'GET', '/_builder/api/etag')->status, 'sesi builder milik user lain');

        $limited = false;
        for ($i = 0; $i < 8; $i++) {
            $limited = $limited || $this->req($k, 'POST', '/_builder/login', null, true, '203.0.113.9', ['password' => 'x' . $i])->status === 429;
        }
        self::assertTrue($limited);
    }

    public function test_SEC_BLD_01_dev_butuh_identity_admin(): void
    {
        $k = $this->kernel(true);
        $rr = $this->req($k, 'GET', '/_builder');
        self::assertSame(200, $rr->status, $this->log->all());
        $this->login('staf');
        self::assertSame(403, $this->req($k, 'GET', '/_builder')->status);
        self::assertSame(403, $this->req($k, 'GET', '/_builder/api/state')->status);
        self::assertSame(403, $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'x'])->status);
        $this->session->forget('_identity');
        $r = $this->req($k, 'GET', '/_builder');
        self::assertSame(302, $r->status);
        self::assertSame('/login', $r->headers['Location']);
        self::assertSame(401, $this->req($k, 'GET', '/_builder/api/state')->status);
        self::assertSame(404, $this->req($k, 'GET', '/_builder/login')->status, 'login terpisah hanya produksi');
    }

    public function test_SEC_BLD_01_cidr_dan_ipv6(): void
    {
        $g = new BuilderGate(false, ['allowedIps' => ['10.1.2.0/24', '2001:db8::/32', '192.0.2.5', 'sampah', '10.0.0.0/99']], $this->session, static fn() => null, new RateLimiter($this->root . '/ratelimit'), $this->clock);
        self::assertTrue($g->ipAllowed('10.1.2.200'));
        self::assertFalse($g->ipAllowed('10.1.3.1'));
        self::assertTrue($g->ipAllowed('2001:db8:1::1'));
        self::assertFalse($g->ipAllowed('2001:db9::1'));
        self::assertTrue($g->ipAllowed('192.0.2.5'));
        self::assertFalse($g->ipAllowed('192.0.2.6'));
        self::assertFalse($g->ipAllowed('10.0.0.1'));
        self::assertFalse($g->ipAllowed(''));
    }

    // ---------- CSRF / UI ----------

    public function test_SEC_BLD_01_csrf_semua_post(): void
    {
        $k = $this->kernel(true);
        $before = $this->hashOf('models/produk.json');
        self::assertSame(419, $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $this->produk(), 'baseHash' => $before], false)->status);
        self::assertSame(419, $this->req($k, 'POST', '/_builder/api/delete', ['kind' => 'page', 'name' => 'daftar-produk'], false)->status);
        self::assertSame(419, $this->req($k, 'POST', '/_builder/api/migration', ['kind' => 'model', 'name' => 'produk'], false)->status);
        self::assertSame(419, $this->req($k, 'POST', '/_builder/logout', null, false)->status);
        self::assertSame($before, $this->hashOf('models/produk.json'));
    }

    public function test_BLD_01_halaman_template_nonce_csp_tanpa_inline(): void
    {
        $k = $this->kernel(true);
        $r = $this->req($k, 'GET', '/_builder');
        self::assertSame(200, $r->status);
        self::assertMatchesRegularExpression("/script-src 'self' 'nonce-[A-Za-z0-9+\\/=_-]+'/", $r->headers['Content-Security-Policy']);
        self::assertStringContainsString('/assets/builder.js', $r->body);
        self::assertDoesNotMatchRegularExpression('/\son[a-z]+\s*=/i', $r->body);
        self::assertDoesNotMatchRegularExpression('/<script(?![^>]*\bsrc=)/i', $r->body, 'tanpa script inline');
        self::assertStringContainsString('name="csrf-token"', $r->body);
        self::assertSame('no-store', $r->headers['Cache-Control']);
    }

    public function test_BLD_02_builder_js_tanpa_sink_berbahaya(): void
    {
        $js = (string) file_get_contents(__DIR__ . '/../../public_html/assets/builder.js');
        foreach (['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', "setAttribute('on", 'srcdoc'] as $bad) {
            self::assertStringNotContainsString($bad, $js, $bad);
        }
        self::assertStringContainsString('X-CSRF-Token', $js);
    }

    public function test_SEC_OUT_XSS_data_model_hanya_lewat_json_dan_tidak_masuk_html(): void
    {
        $k = $this->kernel(true);
        $m = $this->produk();
        $m['fields']['nama']['label'] = '<script>alert(1)</script>';
        $res = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $m, 'baseHash' => $this->hashOf('models/produk.json')]);
        self::assertSame(200, $res->status);
        $page = $this->req($k, 'GET', '/_builder');
        self::assertStringNotContainsString('alert(1)', $page->body);
        $st = $this->req($k, 'GET', '/_builder/api/state');
        self::assertStringStartsWith('application/json', $st->headers['Content-Type']);
        self::assertSame('nosniff', $st->headers['X-Content-Type-Options']);
        // nama model berbahaya ditolak di gerbang nama
        $bad = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => '<img src=x onerror=1>', 'data' => ['model' => 'x'], 'baseHash' => '']);
        self::assertSame(422, $bad->status);
        self::assertStringNotContainsString('<img', $bad->body);
    }

    // ---------- DefinitionWriter ----------

    public function test_BLD_09_path_traversal_dan_nama_berkas(): void
    {
        $k = $this->kernel(true);
        foreach (['../evil', '..%2Fevil', 'a/b', 'Produk', 'x.php', "x\0y", '', str_repeat('a', 60), '.', 'models/../../x', 'auth'] as $n) {
            $kind = $n === 'auth' ? 'page' : 'model';
            $r = $this->req($k, 'POST', '/_builder/api/save', ['kind' => $kind, 'name' => $n, 'data' => ['model' => $n], 'baseHash' => '']);
            self::assertContains($r->status, [422], "nama: $n");
        }
        self::assertSame(422, $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'php', 'name' => 'x', 'data' => [], 'baseHash' => ''])->status);
        self::assertSame(422, $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'x', 'data' => [], 'baseHash' => 'zzz'])->status);

        $compilerFile = [$this->root . '/evil.json', $this->defs . '/../evil.json', $this->defs . '/models/../../evil.json', $this->defs . '/models/x.php',
            $this->defs . '/models/.json', $this->defs . '/lain/x.json', $this->defs . '/models/Bad.json', $this->defs . '/models/a.json.php', '/etc/passwd', "$this->defs/models/x\0.json"];
        foreach ($compilerFile as $f) {
            try {
                $this->writer->write($f, ['model' => 'x', 'fields' => []], '');
                self::fail('harus ditolak: ' . addcslashes($f, "\0"));
            } catch (WriteRejected $e) {
                self::assertSame(400, $e->status);
            }
        }
        self::assertFileDoesNotExist($this->root . '/evil.json');
    }

    public function test_BLD_09_symlink_ditolak_dan_tidak_pernah_menulis_php(): void
    {
        $outside = $this->root . '/outside.json';
        file_put_contents($outside, '{}');
        symlink($outside, $this->defs . '/models/link.json');
        try {
            $this->writer->write($this->defs . '/models/link.json', ['model' => 'link', 'fields' => []], '');
            self::fail('symlink harus ditolak');
        } catch (WriteRejected) {
            self::assertSame('{}', file_get_contents($outside));
        }
        unlink($this->defs . '/models/link.json');
        // simpan beberapa jenis definisi lewat API lalu pastikan tidak ada .php/.tmp di definitions/
        $k = $this->kernel(true);
        $p = $this->produk();
        $h = $this->hashOf('models/produk.json');
        $h = (string) $this->body($this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $p, 'baseHash' => $h]))['hash'];
        $cr = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'catatan', 'data' => ['model' => 'catatan', 'fields' => ['isi' => ['type' => 'text']], 'access' => ['read' => ['admin']]], 'baseHash' => '']);
        self::assertSame(200, $cr->status, $cr->body . $this->log->all());
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->defs, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            self::assertDoesNotMatchRegularExpression('/\.(php|phtml|phar|tmp)$/i', $f->getFilename(), $f->getPathname());
        }
        self::assertFileExists($this->defs . '/models/catatan.json');
    }

    public function test_BLD_05_konflik_hash_tidak_menimpa(): void
    {
        $k = $this->kernel(true);
        $state = $this->body($this->req($k, 'GET', '/_builder/api/state'));
        $h = $state['models']['produk']['hash'];
        $tabA = $this->produk();
        $tabA['fields']['nama']['label'] = 'Dari tab A';
        $tabB = $this->produk();
        $tabB['fields']['nama']['label'] = 'Dari tab B';

        $a = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $tabA, 'baseHash' => $h]);
        self::assertSame(200, $a->status);
        $afterA = $this->hashOf('models/produk.json');
        $b = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $tabB, 'baseHash' => $h]);
        self::assertSame(409, $b->status);
        $body = $this->body($b);
        self::assertSame('conflict', $body['code']);
        self::assertSame($afterA, $body['diskHash']);
        self::assertSame('Dari tab A', $body['disk']['fields']['nama']['label']);
        self::assertSame($afterA, $this->hashOf('models/produk.json'), 'tidak boleh menimpa');

        // setelah memilih menimpa (hash disk dipakai ulang) berhasil
        $c = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $tabB, 'baseHash' => $body['diskHash']]);
        self::assertSame(200, $c->status);
        // edit manual di luar builder
        file_put_contents($this->defs . '/models/produk.json', str_replace('Dari tab B', 'Manual', (string) file_get_contents($this->defs . '/models/produk.json')));
        self::assertSame(409, $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $tabB, 'baseHash' => $this->body($c)['hash']])->status);
        // berkas baru tidak boleh menimpa berkas yang sudah ada
        $kat = (array) json_decode((string) file_get_contents($this->defs . '/models/kategori.json'), true);
        self::assertSame(409, $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'kategori', 'data' => $kat, 'baseHash' => ''])->status);
    }

    public function test_BLD_04_etag_berubah_saat_berkas_diedit_manual(): void
    {
        $k = $this->kernel(true);
        $e1 = $this->body($this->req($k, 'GET', '/_builder/api/etag'))['etag'];
        self::assertSame($e1, $this->body($this->req($k, 'GET', '/_builder/api/etag'))['etag']);
        file_put_contents($this->defs . '/pages/daftar-produk.json', str_replace('Produk', 'Produk X', (string) file_get_contents($this->defs . '/pages/daftar-produk.json')));
        self::assertNotSame($e1, $this->body($this->req($k, 'GET', '/_builder/api/etag'))['etag']);
    }

    public function test_BLD_03_json_deterministik_urutan_key_stabil(): void
    {
        $k = $this->kernel(true);
        $p = $this->produk();
        $r1 = $this->body($this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $p, 'baseHash' => $this->hashOf('models/produk.json')]));
        $bytes1 = (string) file_get_contents($this->defs . '/models/produk.json');
        // urutan key dibalik, nilai sama
        $rev = array_reverse($p, true);
        $rev['fields']['nama'] = array_reverse($rev['fields']['nama'], true);
        $r2 = $this->body($this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $rev, 'baseHash' => $r1['hash']]));
        self::assertSame($bytes1, file_get_contents($this->defs . '/models/produk.json'));
        self::assertSame($r1['hash'], $r2['hash']);
        self::assertStringEndsWith("}\n", $bytes1);
        self::assertSame('model', array_key_first(json_decode($bytes1, true)));
    }

    public function test_BLD_definisi_invalid_ditolak_tanpa_mengubah_file_dan_versi_aktif(): void
    {
        $k = $this->kernel(true);
        $version = $this->store->current();
        $fileHash = $this->hashOf('models/produk.json');
        $cases = [];
        $a = $this->produk();
        $a['fields']['aneh'] = ['type' => 'uuid'];
        $cases['tipe tidak dikenal'] = $a;
        $a = $this->produk();
        $a['fields']['rel'] = ['type' => 'relasi', 'target' => 'tidak_ada'];
        $cases['relasi ke model yang tidak ada'] = $a;
        $a = $this->produk();
        $a['hooks'] = ['beforeSave' => 'ProdukHooks::tidakAda'];
        $cases['hook tidak ada'] = $a;
        $a = $this->produk();
        $a['fields']['nama']['label'] = "x'; DROP TABLE produk; --";
        $cases['SQL mentah (BLD-07)'] = $a;
        $a = $this->produk();
        $a['rahasia'] = 'x';
        $cases['kunci tak dikenal'] = $a;
        $a = $this->produk();
        $a['model'] = 'lain';
        $cases['nama tak cocok'] = $a;
        foreach ($cases as $why => $data) {
            $r = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $data, 'baseHash' => $fileHash]);
            self::assertSame(422, $r->status, $why . ' ' . $r->body);
            self::assertSame($fileHash, $this->hashOf('models/produk.json'), $why);
            self::assertSame($version, $this->store->current(), $why);
        }
        // halaman yang merujuk model tak ada: lolos normalize tapi gagal compile (dry-run)
        $pg = (array) json_decode((string) file_get_contents($this->defs . '/pages/daftar-produk.json'), true);
        $pg['layout'][0]['source']['model'] = 'hantu';
        $ph = $this->hashOf('pages/daftar-produk.json');
        $r = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'page', 'name' => 'daftar-produk', 'data' => $pg, 'baseHash' => $ph]);
        self::assertSame(422, $r->status);
        self::assertSame($ph, $this->hashOf('pages/daftar-produk.json'));
        self::assertSame($version, $this->store->current());
        // sisa file sementara tidak ada
        self::assertSame([], glob($this->defs . '/models/.*.tmp') ?: []);
        self::assertSame([], glob(sys_get_temp_dir() . '/bfb_*') ?: []);
    }

    public function test_BLD_json_berbahaya_besar_dan_dalam(): void
    {
        $k = $this->kernel(true);
        $v = $this->store->current();
        $h = $this->hashOf('models/produk.json');
        // terlalu besar -> 413 sebelum diproses
        $big = $this->produk();
        $big['fields']['nama']['label'] = str_repeat('a', 400000);
        self::assertSame(413, $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $big, 'baseHash' => $h])->status);
        // terlalu dalam (> 32) -> 400 dari Request::json
        $deep = '{"kind":"model","name":"produk","baseHash":"","data":' . str_repeat('[', 40) . str_repeat(']', 40) . '}';
        $res = $this->kernel(true)->handle(new Request('POST', '/_builder/api/save', [], [], ['x-csrf-token' => $this->csrf->token()], $deep, [], false, '203.0.113.7'));
        self::assertSame(400, $res->status);
        // dalam tapi di bawah 32 -> ditolak normalize
        $nest = [];
        $ref = &$nest;
        for ($i = 0; $i < 20; $i++) {
            $ref['x'] = [];
            $ref = &$ref['x'];
        }
        unset($ref);
        $a = $this->produk();
        $a['fields']['nama']['label'] = $nest;
        self::assertSame(422, $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $a, 'baseHash' => $h])->status);
        // banyak field -> ditolak
        $many = $this->produk();
        for ($i = 0; $i < 600; $i++) {
            $many['fields']['f' . $i] = ['type' => 'string'];
        }
        self::assertSame(422, $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $many, 'baseHash' => $h])->status);
        // JSON rusak / bukan objek
        $bad = $this->kernel(true)->handle(new Request('POST', '/_builder/api/save', [], [], ['x-csrf-token' => $this->csrf->token()], '{rusak', [], false, '203.0.113.7'));
        self::assertSame(400, $bad->status);
        self::assertSame($h, $this->hashOf('models/produk.json'));
        self::assertSame($v, $this->store->current());
    }

    public function test_BLD_writer_batas_ukuran_langsung(): void
    {
        $d = ['model' => 'catatan', 'fields' => ['isi' => ['type' => 'string', 'label' => str_repeat('x', 100)]]];
        for ($i = 0; $i < 3000; $i++) {
            $d['fields']['f' . $i] = ['type' => 'string', 'label' => str_repeat('y', 100)];
        }
        try {
            $this->writer->write($this->defs . '/models/catatan.json', $d, '');
            self::fail('harus ditolak');
        } catch (WriteRejected $e) {
            self::assertSame(413, $e->status);
        }
        self::assertFileDoesNotExist($this->defs . '/models/catatan.json');
    }

    public function test_BLD_writer_konflik_melempar_dengan_isi_disk(): void
    {
        $f = $this->defs . '/models/kategori.json';
        $this->expectException(WriteConflict::class);
        $this->writer->write($f, (array) json_decode((string) file_get_contents($f), true), 'bukan-hash-yang-benar');
    }

    // ---------- BLD-08 migrasi ----------

    public function test_BLD_08_hapus_field_butuh_konfirmasi_dan_pratinjau(): void
    {
        $k = $this->kernel(true);
        $m = $this->produk();
        $m['fields']['tambahan'] = ['type' => 'string', 'max' => 20];
        $add = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $m, 'baseHash' => $this->hashOf('models/produk.json')]);
        self::assertSame(200, $add->status, $add->body);
        self::assertContains('tambahan', $this->columns('produk'));

        unset($m['fields']['tambahan']);
        $h = $this->hashOf('models/produk.json');
        $pv = $this->body($this->req($k, 'POST', '/_builder/api/migration', ['kind' => 'model', 'name' => 'produk', 'data' => $m, 'baseHash' => $h]));
        self::assertNotSame([], $pv['sql']);
        self::assertNotSame([], $pv['lossWarnings']);
        self::assertStringContainsString('tambahan', implode(' ', $pv['lossWarnings']));

        $no = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $m, 'baseHash' => $h]);
        self::assertSame(409, $no->status);
        self::assertSame('confirm_loss', $this->body($no)['code']);
        self::assertSame($h, $this->hashOf('models/produk.json'), 'tanpa konfirmasi file tidak berubah');
        self::assertContains('tambahan', $this->columns('produk'));

        $yes = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $m, 'baseHash' => $h, 'confirmLoss' => true]);
        self::assertSame(200, $yes->status, $yes->body);
        self::assertNotContains('tambahan', $this->columns('produk'));
        self::assertContains('builder.save', array_column($this->audit->recent(), 'action'));
    }

    public function test_BLD_08_model_baru_membuat_tabel_dan_perubahan_aman_tanpa_konfirmasi(): void
    {
        $k = $this->kernel(true);
        $new = ['model' => 'catatan', 'fields' => ['isi' => ['type' => 'text', 'label' => 'Isi']], 'access' => ['read' => ['admin'], 'write' => ['admin']]];
        $r = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'catatan', 'data' => $new, 'baseHash' => '']);
        self::assertSame(200, $r->status, $r->body . $this->log->all());
        self::assertContains('isi', $this->columns('catatan'));
        $new['fields']['judul'] = ['type' => 'string', 'max' => 50];
        $r2 = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'catatan', 'data' => $new, 'baseHash' => $this->body($r)['hash']]);
        self::assertSame(200, $r2->status, $r2->body . $this->log->all());
        self::assertContains('judul', $this->columns('catatan'));
    }

    public function test_BLD_08_migrasi_gagal_mengembalikan_definisi(): void
    {
        $k = $this->kernel(true);
        // tabel sudah ada di DB tapi model belum terdaftar -> CREATE gagal -> definisi dikembalikan
        $this->conn->pdo()->exec('CREATE TABLE "baru" ("id" INTEGER PRIMARY KEY, "x" TEXT)');
        $v = $this->store->current();
        $r = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'baru', 'data' => ['model' => 'baru', 'fields' => ['x' => ['type' => 'string']], 'access' => ['read' => ['admin']]], 'baseHash' => '']);
        self::assertSame(500, $r->status);
        self::assertFileDoesNotExist($this->defs . '/models/baru.json');
        self::assertNotNull($this->store->current());
        self::assertFalse(in_array('baru', (new Definitions($this->store))->modelNames(), true));
        self::assertNotSame('', $v);
        self::assertContains('builder.migrate_failed', array_column($this->audit->recent(), 'action'));
    }

    /** @return list<string> */
    private function columns(string $table): array
    {
        $rows = $this->conn->pdo()->query('PRAGMA table_info("' . $table . '")');
        return $rows === false ? [] : array_column($rows->fetchAll(), 'name');
    }

    // ---------- upload (M12b) ----------

    public function test_field_file_menghasilkan_string_plus_upload(): void
    {
        $k = $this->kernel(true);
        $m = $this->produk();
        $m['fields']['foto'] = ['type' => 'string', 'label' => 'Foto', 'upload' => ['maxBytes' => 2097152, 'mimes' => ['image/png', 'image/jpeg']]];
        $r = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $m, 'baseHash' => $this->hashOf('models/produk.json')]);
        self::assertSame(200, $r->status, $r->body);
        $saved = $this->produk();
        self::assertSame('string', $saved['fields']['foto']['type']);
        self::assertSame(['mimes' => ['image/png', 'image/jpeg'], 'maxBytes' => 2097152], $saved['fields']['foto']['upload']);
        self::assertSame(['type', 'label', 'upload'], array_keys($saved['fields']['foto']));
        // SVG/HTML ditolak oleh skema M8
        $m['fields']['foto']['upload']['mimes'] = ['image/svg+xml'];
        self::assertSame(422, $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $m, 'baseHash' => $this->body($r)['hash']])->status);
    }

    // ---------- hooks ----------

    public function test_HookScanner_menandai_kode_berbahaya_tanpa_mengeksekusi(): void
    {
        $marker = $this->root . '/DIEKSEKUSI';
        file_put_contents($this->ext . '/Jahat.php', "<?php\nfinal class Jahat {\n public static function a(array \$d): array { file_put_contents('$marker', '1'); eval('1;'); exec('x'); return []; }\n}\n");
        file_put_contents($this->ext . '/Backtick.php', "<?php\nfinal class Backtick {\n public static function a(array \$d): array { `ls`; return []; }\n}\n");
        file_put_contents($this->ext . '/Includer.php', "<?php\nfinal class Includer {\n public static function a(array \$d): array { include \$d['f']; return []; }\n}\n");
        file_put_contents($this->ext . '/Rusak.php', "<?php\nfinal class Rusak { public static function a( {\n");
        file_put_contents($this->ext . '/Aneh.php', "<?php\nfinal class Lain { public static function a(array \$d): array { return []; } }\n");
        file_put_contents($this->ext . '/Penulis.php', "<?php\nfinal class Penulis {\n /** Catat. */\n public static function catat(array \$d): array { unlink('/tmp/x'); return []; }\n private static function p(): void {}\n public function bukanStatic(): void {}\n}\n");
        $by = [];
        foreach ((new HookScanner($this->ext))->scan() as $c) {
            $by[$c['class']] = $c;
        }
        foreach (['Jahat', 'Backtick', 'Includer', 'Rusak', 'Aneh'] as $c) {
            self::assertTrue($by[$c]['blocked'], $c);
            self::assertSame([], $by[$c]['methods'], $c);
        }
        self::assertFileDoesNotExist($marker, 'scanner tidak boleh mengeksekusi kode');
        self::assertFalse($by['Penulis']['blocked']);
        self::assertSame(['Penulis::catat'], array_column($by['Penulis']['methods'], 'ref'));
        self::assertSame('Catat.', $by['Penulis']['methods'][0]['doc']);
        self::assertNotSame([], $by['Penulis']['warnings']);
        self::assertSame(['ProdukHooks::validasiStok', 'ProdukHooks::normalisasiNama'], array_slice(array_column($by['ProdukHooks']['methods'], 'ref'), 0, 2));
        self::assertFalse(class_exists('Jahat', false), 'kelas tidak boleh dimuat');
    }

    /** @return array<string,array{string}> */
    public static function bypassProvider(): array
    {
        return [
            'fully qualified exec' => ['return \exec("x");'],
            'fully qualified system' => ['\system("x"); return [];'],
            'qualified Ns\system' => ['Ns\system("x"); return [];'],
            'relative namespace\system' => ['namespace\system("x"); return [];'],
            'huruf besar' => ['SyStEm("x"); return [];'],
            'variabel sebagai fungsi' => ['$f = $d["f"]; $f("x"); return [];'],
            'string digabung' => ["('sys'.'tem')('x'); return [];"],
            'string literal dipanggil' => ["'system'('x'); return [];"],
            'hasil panggilan dipanggil' => ['$g = fn() => "x"; $g()("x"); return [];'],
            'elemen array dipanggil' => ['$a = ["x"]; $a[0]("x"); return [];'],
            'call_user_func' => ['call_user_func("strlen", "x"); return [];'],
            'call_user_func_array' => ['\call_user_func_array("strlen", ["x"]); return [];'],
            'array_map string berbahaya' => ['array_map("system", ["x"]); return [];'],
            'usort string berbahaya' => ['$a = [1]; usort($a, "\\\\exec"); return [];'],
            'backtick' => ['`ls`; return [];'],
            'new class' => ['new class { }; return [];'],
            'new dinamis' => ['$c = $d["c"]; new $c(); return [];'],
            'eval' => ['eval($d["x"]); return [];'],
            'include dinamis' => ['include $d["f"]; return [];'],
            'require dinamis' => ['require_once $d["f"]; return [];'],
            'assert' => ['assert($d["x"]); return [];'],
            'create_function' => ['create_function("", "x"); return [];'],
            'preg_replace /e' => ['preg_replace("/a/e", "x", "a"); return [];'],
            'preg_replace pola dinamis' => ['preg_replace($d["p"], "x", "a"); return [];'],
            'extract' => ['extract($d); return [];'],
            'variable-variable' => ['$n = "a"; $$n = 1; return [];'],
            'variable-variable kurung' => ['${"a"} = 1; return [];'],
            'unserialize' => ['unserialize($d["x"]); return [];'],
            'Closure::fromCallable' => ['\Closure::fromCallable("strlen"); return [];'],
            'ReflectionFunction' => ['(new \ReflectionFunction("strlen"))->invoke("x"); return [];'],
            'ReflectionMethod' => ['$r = new ReflectionMethod("A", "b"); return [];'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('bypassProvider')]
    public function test_HookScanner_bypass_panggilan_berbahaya_ditolak_422(string $body): void
    {
        $marker = $this->root . '/DIEKSEKUSI';
        file_put_contents($this->ext . '/Bypass.php', "<?php\nfinal class Bypass {\n public static function a(array \$d): array { $body }\n}\n");
        $r = HookScanner::inspect((string) file_get_contents($this->ext . '/Bypass.php'), 'Bypass');
        self::assertTrue($r['blocked'], $body);
        $k = $this->kernel(true);
        $m = $this->produk();
        $m['hooks'] = ['beforeSave' => 'Bypass::a'];
        $h = $this->hashOf('models/produk.json');
        $res = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $m, 'baseHash' => $h]);
        self::assertSame(422, $res->status, $body);
        self::assertSame($h, $this->hashOf('models/produk.json'));
        self::assertFileDoesNotExist($marker);
    }

    public function test_HookScanner_hook_sah_contoh_tetap_lolos(): void
    {
        $r = HookScanner::inspect((string) file_get_contents($this->ext . '/ProdukHooks.php'), 'ProdukHooks');
        self::assertFalse($r['blocked'], implode('; ', $r['warnings']));
        self::assertNotSame([], $r['methods']);
        $k = $this->kernel(true);
        $m = $this->produk();
        $m['hooks'] = ['beforeSave' => 'ProdukHooks::validasiStok'];
        $h = $this->hashOf('models/produk.json');
        self::assertSame(200, $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $m, 'baseHash' => $h])->status);
    }

    public function test_BLD_access_owner_ownerExempt_requireAmr_tersimpan_dan_rowFilter_ditolak(): void
    {
        $k = $this->kernel(true);
        $m = $this->produk();
        $m['fields']['pemilik'] = ['type' => 'integer'];
        $m['access'] = ['read' => '*', 'create' => ['admin'], 'update' => ['admin'], 'delete' => ['admin'], 'owner' => 'pemilik', 'ownerExempt' => ['admin'], 'requireAmr' => ['delete' => ['otp']]];
        $h = $this->hashOf('models/produk.json');
        $r = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $m, 'baseHash' => $h]);
        self::assertSame(200, $r->status, $r->body);
        $saved = (array) json_decode((string) file_get_contents($this->defs . '/models/produk.json'), true);
        self::assertSame('pemilik', $saved['access']['owner']);
        self::assertSame(['admin'], $saved['access']['ownerExempt']);
        self::assertSame(['delete' => ['otp']], $saved['access']['requireAmr']);

        $h2 = $this->hashOf('models/produk.json');
        $bad = $m;
        $bad['access']['rowFilter'] = ['field' => 'pemilik', 'equals' => '$user.id'];
        $r = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $bad, 'baseHash' => $h2]);
        self::assertSame(422, $r->status);
        self::assertStringContainsString('rowFilter', $r->body);
        self::assertSame($h2, $this->hashOf('models/produk.json'));
    }

    public function test_HookScanner_tolak_hook_berbahaya_saat_simpan_dan_abaikan_symlink(): void
    {
        file_put_contents($this->ext . '/Jahat.php', "<?php\nfinal class Jahat {\n public static function a(array \$d): array { exec('x'); return []; }\n}\n");
        file_put_contents($this->root . '/Luar.php', "<?php\nfinal class Luar { public static function a(array \$d): array { return []; } }\n");
        symlink($this->root . '/Luar.php', $this->ext . '/Luar.php');
        $k = $this->kernel(true);
        $m = $this->produk();
        $m['hooks'] = ['beforeSave' => 'Jahat::a'];
        $h = $this->hashOf('models/produk.json');
        $r = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $m, 'baseHash' => $h]);
        self::assertSame(422, $r->status);
        $m['hooks'] = ['beforeSave' => 'Luar::a'];
        self::assertSame(422, $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $m, 'baseHash' => $h])->status);
        self::assertSame($h, $this->hashOf('models/produk.json'));
        $state = $this->body($this->req($k, 'GET', '/_builder/api/state'));
        self::assertSame('ProdukHooks', $state['hooks'][array_search('ProdukHooks', array_column($state['hooks'], 'class'), true)]['class']);
        self::assertNotContains('Luar', array_column($state['hooks'], 'class'));
    }

    public function test_BLD_tidak_ada_penulisan_php_dari_ui_hooks_hanya_dirujuk(): void
    {
        $before = glob($this->ext . '/*') ?: [];
        $k = $this->kernel(true);
        foreach (['/_builder/api/save', '/_builder/api/delete', '/_builder/api/migration'] as $p) {
            $this->req($k, 'POST', $p, ['kind' => 'model', 'name' => 'baru2', 'data' => ['model' => 'baru2', 'fields' => [], 'hooks' => ['beforeSave' => 'Baru::x']], 'baseHash' => '']);
        }
        self::assertSame($before, glob($this->ext . '/*') ?: []);
    }

    // ---------- Sampler ----------

    public function test_Sampler_hanya_dev_dan_data_dummy(): void
    {
        $schema = new \bFramework\Runtime\DefinitionSchema();
        $model = $schema->model('produk', $this->produk());
        self::assertIsArray($model);
        $rows = Sampler::seed($model, 5, true);
        self::assertCount(5, $rows);
        self::assertSame(['id', 'nama', 'harga', 'stok', 'kategori', 'aktif'], array_keys($rows[0]));
        self::assertMatchesRegularExpression('/^[A-Z][a-z]+ 1$/', $rows[0]['nama']);
        // tidak menyentuh database aplikasi
        self::assertSame(0, (int) $this->conn->pdo()->query('SELECT COUNT(*) FROM produk')->fetchColumn());
        $this->expectException(\RuntimeException::class);
        Sampler::seed($model, 5, false);
    }

    public function test_Sampler_endpoint_dev_saja(): void
    {
        $dev = $this->req($this->kernel(true), 'GET', '/_builder/api/sample?model=produk');
        self::assertSame(200, $dev->status);
        self::assertCount(8, json_decode($dev->body, true));
        self::assertSame(404, $this->req($this->kernel(true), 'GET', '/_builder/api/sample?model=..%2Fx')->status);
        $k = $this->kernel(false, $this->prodOpts());
        $this->req($k, 'POST', '/_builder/login', null, true, '203.0.113.7', ['password' => self::PW]);
        self::assertSame(404, $this->req($k, 'GET', '/_builder/api/sample?model=produk')->status);
    }

    // ---------- state / IDOR ----------

    public function test_state_memuat_definisi_hash_peran_dan_hooks(): void
    {
        $k = $this->kernel(true);
        $s = $this->body($this->req($k, 'GET', '/_builder/api/state'));
        self::assertSame(['kategori', 'produk'], array_keys($s['models']));
        self::assertSame(hash('sha256', (string) file_get_contents($this->defs . '/models/produk.json')), $s['models']['produk']['hash']);
        self::assertSame([['role' => 'admin'], ['role' => 'staf']], $s['roles']);
        self::assertSame('local', $s['auth']['data']['driver']);
        self::assertSame('', $s['auth']['hash']);
        self::assertStringNotContainsString($this->root, json_encode($s), 'path server tidak bocor');
        // auth.json: simpan lalu client_secret ditolak
        $a = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'auth', 'name' => 'auth', 'data' => ['driver' => 'bikinin_sso', 'sso' => ['issuer' => 'https://sso.contoh.test', 'client_id' => 'abc', 'client_secret' => 'RAHASIA']], 'baseHash' => '']);
        self::assertSame(422, $a->status);
        $a = $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'auth', 'name' => 'auth', 'data' => ['driver' => 'bikinin_sso', 'sso' => ['issuer' => 'https://sso.contoh.test', 'client_id' => 'abc']], 'baseHash' => '']);
        self::assertSame(200, $a->status, $a->body);
        self::assertStringNotContainsString('secret', strtolower((string) file_get_contents($this->defs . '/auth.json')));
    }

    public function test_hapus_definisi_divalidasi_dan_diaudit(): void
    {
        $k = $this->kernel(true);
        // menghapus model yang masih dirujuk halaman -> ditolak, file tetap
        $r = $this->req($k, 'POST', '/_builder/api/delete', ['kind' => 'model', 'name' => 'produk', 'baseHash' => $this->hashOf('models/produk.json')]);
        self::assertSame(422, $r->status);
        self::assertFileExists($this->defs . '/models/produk.json');
        // hapus halaman: ok
        $r = $this->req($k, 'POST', '/_builder/api/delete', ['kind' => 'page', 'name' => 'daftar-produk', 'baseHash' => $this->hashOf('pages/daftar-produk.json')]);
        self::assertSame(200, $r->status, $r->body);
        self::assertFileDoesNotExist($this->defs . '/pages/daftar-produk.json');
        self::assertSame(422, $this->req($k, 'POST', '/_builder/api/delete', ['kind' => 'auth', 'name' => 'auth', 'baseHash' => ''])->status);
        $log = $this->audit->recent();
        self::assertContains('builder.delete', array_column($log, 'action'));
        self::assertContains('pages/daftar-produk.json', array_column($log, 'target'));
    }

    public function test_audit_log_tanpa_data_sensitif(): void
    {
        $k = $this->kernel(true);
        $m = $this->produk();
        $m['fields']['nama']['label'] = 'LABEL-RAHASIA-123';
        $this->req($k, 'POST', '/_builder/api/save', ['kind' => 'model', 'name' => 'produk', 'data' => $m, 'baseHash' => $this->hashOf('models/produk.json')]);
        $rows = $this->audit->recent();
        self::assertSame('builder.save', $rows[0]['action']);
        self::assertSame('models/produk.json', $rows[0]['target']);
        self::assertSame(7, (int) $rows[0]['actor']);
        self::assertStringNotContainsString('LABEL-RAHASIA', json_encode($rows) . $this->log->all());
    }

    public function test_BLD_08_hari_normalize_kontrak_writer(): void
    {
        [$d, $err] = $this->writer->normalize('model', ['access' => ['write' => ['admin'], 'read' => '*'], 'fields' => ['a' => ['max' => 5, 'type' => 'string', 'label' => '', 'default' => null]], 'model' => 'm1'], 'm1');
        self::assertNull($err);
        self::assertSame(['model', 'fields', 'access'], array_keys($d ?? []));
        self::assertSame(['type', 'max'], array_keys($d['fields']['a']));
        self::assertSame(['read', 'write'], array_keys($d['access']));
        [$x, $e] = $this->writer->normalize('model', ['model' => 'm1', 'fields' => ['a' => ['type' => 'xx']]], 'm1');
        self::assertNull($x);
        self::assertNotNull($e);
        [$x, $e] = $this->writer->normalize('lain', [], 'm1');
        self::assertNull($x);
    }
}
