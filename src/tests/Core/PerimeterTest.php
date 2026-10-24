<?php

declare(strict_types=1);

namespace bFramework\Tests\Core;

use bFramework\Contracts\BadHost;
use bFramework\Contracts\Clock;
use bFramework\Contracts\CsrfMismatch;
use bFramework\Core\Csrf;
use bFramework\Core\CsrfMiddleware;
use bFramework\Core\HostGuard;
use bFramework\Core\Kernel;
use bFramework\Core\RateLimiter;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\RouteOpts;
use bFramework\Core\Router;
use bFramework\Core\SecurityHeaders;
use bFramework\Tests\Fixtures\ArraySessionStore;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class PerimeterTest extends TestCase
{
    private const PUB = __DIR__ . '/../../public_html';

    private function ok(): callable
    {
        return static fn(Request $r): Response => Response::html('ok');
    }

    // --- SEC-PER-01 / SEC-PER-02 (konfigurasi statis; Apache tidak tersedia di CI)

    public function test_SEC_PER_01_htaccess_memblokir_dotfile_json_sqlite_log(): void
    {
        $h = (string) file_get_contents(self::PUB . '/.htaccess');
        self::assertStringContainsString('RewriteRule (^|/)\. - [F,L]', $h);
        self::assertMatchesRegularExpression('/RewriteRule \\\\\.\(json\|sqlite\|sqlite3\|log\)\$ - \[F,L\]/', $h);
        self::assertStringContainsString('RewriteRule !^index\.php$ index.php [L]', $h);
        // blokir harus muncul sebelum aturan catch-all
        self::assertLessThan(strpos($h, 'index.php [L]'), strpos($h, '[F,L]'));
        foreach (['/.env', '/x.json', '/x.sqlite', '/a/b.log'] as $p) {
            self::assertSame(1, preg_match('#(^|/)\.|\.(json|sqlite|sqlite3|log)$#', $p), $p);
        }
    }

    public function test_SEC_PER_02_php_mati_di_assets(): void
    {
        $h = (string) file_get_contents(self::PUB . '/assets/.htaccess');
        self::assertStringContainsString('php_flag engine off', $h);
        self::assertStringContainsString('RemoveHandler .php', $h);
        self::assertStringContainsString('Require all denied', $h);
    }

    // --- SEC-PER-03

    public function test_SEC_PER_03_header_selalu_dikirim_tanpa_hsts_di_http(): void
    {
        $res = (new SecurityHeaders())->process(new Request('GET', '/'), $this->ok());
        self::assertSame('nosniff', $res->headers['X-Content-Type-Options']);
        self::assertArrayHasKey('Referrer-Policy', $res->headers);
        self::assertSame('DENY', $res->headers['X-Frame-Options']);
        self::assertArrayNotHasKey('Strict-Transport-Security', $res->headers);
    }

    public function test_SEC_PER_03_hsts_bila_https(): void
    {
        $res = (new SecurityHeaders())->process(new Request('GET', '/', isHttps: true), $this->ok());
        self::assertStringStartsWith('max-age=', $res->headers['Strict-Transport-Security']);
    }

    public function test_SEC_PER_03_header_ikut_di_respons_error_lewat_kernel(): void
    {
        $k = new Kernel(new Router(), [new SecurityHeaders()]);
        $res = $k->handle(new Request('GET', '/tidak-ada'));
        self::assertSame(404, $res->status);
        self::assertSame('nosniff', $res->headers['X-Content-Type-Options']);
    }

    public function test_INT_F2_csp_handler_dipertahankan_dan_respons_lain_dapat_csp_default(): void
    {
        $sb = "default-src 'none'; sandbox";
        $mw = new SecurityHeaders();
        $kept = $mw->process(new Request('GET', '/'), static fn(Request $r): Response => Response::html('x')->withHeader('Content-Security-Policy', $sb));
        self::assertSame($sb, $kept->headers['Content-Security-Policy']);
        self::assertSame('nosniff', $kept->headers['X-Content-Type-Options']);
        $def = $mw->process(new Request('GET', '/'), $this->ok());
        self::assertStringStartsWith("default-src 'self'", $def->headers['Content-Security-Policy']);
        self::assertStringNotContainsString('sandbox', $def->headers['Content-Security-Policy']);
    }

    public function test_SEC_OUT_02_csp_memakai_nonce_dan_menolak_nonce_berbahaya(): void
    {
        $res = (new SecurityHeaders(static fn(): string => 'abc123XYZ'))->process(new Request('GET', '/'), $this->ok());
        self::assertStringContainsString("script-src 'self' 'nonce-abc123XYZ'", $res->headers['Content-Security-Policy']);
        self::assertStringContainsString("object-src 'none'", $res->headers['Content-Security-Policy']);
        $bad = (new SecurityHeaders(static fn(): string => "x'; script-src *"))->process(new Request('GET', '/'), $this->ok());
        self::assertStringNotContainsString('nonce-', $bad->headers['Content-Security-Policy']);
    }

    // --- SEC-REQ-01

    private function csrfKernel(ArraySessionStore $s, bool $csrfOpt = true): Kernel
    {
        $router = new Router();
        $router->add('POST', '/f', static fn(): Response => Response::html('posted'), new RouteOpts($csrfOpt));
        $router->add('GET', '/f', static fn(): Response => Response::html('form'));
        return new Kernel($router, [new CsrfMiddleware($router, new Csrf($s), $s)]);
    }

    public function test_SEC_REQ_01_post_tanpa_token_419(): void
    {
        $s = new ArraySessionStore();
        self::assertSame(419, $this->csrfKernel($s)->handle(new Request('POST', '/f'))->status);
    }

    public function test_SEC_REQ_01_post_token_salah_419(): void
    {
        $s = new ArraySessionStore();
        $s->start();
        (new Csrf($s))->token();
        self::assertSame(419, $this->csrfKernel($s)->handle(new Request('POST', '/f', post: ['_csrf' => 'salah']))->status);
    }

    public function test_SEC_REQ_01_post_token_benar_lolos_via_body_dan_header(): void
    {
        $s = new ArraySessionStore();
        $s->start();
        $t = (new Csrf($s))->token();
        $k = $this->csrfKernel($s);
        self::assertSame('posted', $k->handle(new Request('POST', '/f', post: ['_csrf' => $t]))->body);
        self::assertSame('posted', $k->handle(new Request('POST', '/f', headers: ['x-csrf-token' => $t]))->body);
    }

    public function test_SEC_REQ_01_get_tidak_perlu_token_dan_token_stabil_per_sesi(): void
    {
        $s = new ArraySessionStore();
        self::assertSame('form', $this->csrfKernel($s)->handle(new Request('GET', '/f'))->body);
        $c = new Csrf($s);
        self::assertSame($c->token(), $c->token());
        self::assertSame(64, strlen($c->token()));
        self::assertFalse($c->verify(null));
        self::assertFalse($c->verify(''));
    }

    public function test_SEC_REQ_01_csrf_false_dihormati_dan_sesi_lain_ditolak(): void
    {
        $s = new ArraySessionStore();
        self::assertSame('posted', $this->csrfKernel($s, false)->handle(new Request('POST', '/f'))->body);
        $a = new ArraySessionStore();
        $b = new ArraySessionStore();
        $ta = (new Csrf($a))->token();
        (new Csrf($b))->token();
        self::assertFalse((new Csrf($b))->verify($ta));
    }

    public function test_SEC_REQ_01_method_selain_get_head_juga_diperiksa_dan_rute_tak_dikenal_404(): void
    {
        $s = new ArraySessionStore();
        $router = new Router();
        $router->add('DELETE', '/d', static fn(): Response => Response::html('x'));
        $k = new Kernel($router, [new CsrfMiddleware($router, new Csrf($s), $s)]);
        self::assertSame(419, $k->handle(new Request('DELETE', '/d'))->status);
        self::assertSame(404, $k->handle(new Request('POST', '/nope'))->status);
    }

    public function test_SEC_REQ_01_cookie_sesi_samesite_lax_dan_secure_default(): void
    {
        $c = Response::html('x')->withCookie('sid', 'abc')->cookies[0];
        self::assertSame('Lax', $c['options']['samesite']);
        self::assertTrue($c['options']['secure']);
        $dev = Response::html('x')->withCookie('sid', 'abc', ['secure' => false])->cookies[0];
        self::assertFalse($dev['options']['secure']);
    }

    // --- SEC-REQ-02

    private function limiterDir(): string
    {
        $d = sys_get_temp_dir() . '/rl_' . bin2hex(random_bytes(4));
        $this->dirs[] = $d;
        return $d;
    }

    /** @var list<string> */
    private array $dirs = [];

    protected function tearDown(): void
    {
        foreach ($this->dirs as $d) {
            foreach (glob($d . '/*') ?: [] as $f) {
                unlink($f);
            }
            @rmdir($d);
        }
    }

    private function clock(int &$t): Clock
    {
        return new class ($t) implements Clock {
            public function __construct(private int &$t)
            {
            }

            public function now(): DateTimeImmutable
            {
                return (new DateTimeImmutable())->setTimestamp($this->t);
            }
        };
    }

    public function test_SEC_REQ_02_percobaan_ke_6_dalam_15_menit_ditolak(): void
    {
        $t = 1000;
        $rl = new RateLimiter($this->limiterDir(), $this->clock($t));
        for ($i = 1; $i <= 5; $i++) {
            self::assertTrue($rl->hit('login:1.2.3.4', 5, 900), "ke-$i");
        }
        self::assertFalse($rl->hit('login:1.2.3.4', 5, 900));
        self::assertTrue($rl->hit('login:9.9.9.9', 5, 900), 'kunci lain tidak terpengaruh');
    }

    public function test_SEC_REQ_02_jendela_bergeser_dan_nama_file_tanpa_data_mentah(): void
    {
        $t = 1000;
        $dir = $this->limiterDir();
        $rl = new RateLimiter($dir, $this->clock($t));
        for ($i = 0; $i < 5; $i++) {
            $rl->hit('user@example.com', 5, 900);
        }
        self::assertFalse($rl->hit('user@example.com', 5, 900));
        $t += 901;
        self::assertTrue($rl->hit('user@example.com', 5, 900));
        foreach (glob($dir . '/*') ?: [] as $f) {
            self::assertStringNotContainsString('example', $f);
            self::assertSame('0600', substr(sprintf('%o', fileperms($f)), -4));
        }
    }

    public function test_SEC_REQ_02_argumen_tidak_valid(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new RateLimiter($this->limiterDir()))->hit('k', 0, 10);
    }

    // --- SEC-REQ-03

    public function test_SEC_REQ_03_host_di_luar_whitelist_400(): void
    {
        $g = new HostGuard(['example.com']);
        $k = new Kernel(new Router(), [$g]);
        self::assertSame(400, $k->handle(new Request('GET', '/', headers: ['host' => 'evil.com']))->status);
        self::assertSame(400, $k->handle(new Request('GET', '/'))->status, 'tanpa Host');
        self::assertSame(400, $k->handle(new Request('GET', '/', headers: ['host' => "example.com\r\nX: y"]))->status);
        self::assertSame(400, $k->handle(new Request('GET', '/', headers: ['host' => 'example.com.evil.com']))->status);
    }

    public function test_SEC_REQ_03_host_valid_lolos_dengan_atau_tanpa_port_dan_case(): void
    {
        $g = new HostGuard(['example.com', 'localhost:8080']);
        self::assertSame('ok', $g->process(new Request('GET', '/', headers: ['host' => 'EXAMPLE.com']), $this->ok())->body);
        self::assertSame('ok', $g->process(new Request('GET', '/', headers: ['host' => 'example.com:8443']), $this->ok())->body);
        self::assertSame('ok', $g->process(new Request('GET', '/', headers: ['host' => 'localhost:8080']), $this->ok())->body);
    }

    public function test_SEC_REQ_03_whitelist_kosong_menolak_semua(): void
    {
        $this->expectException(BadHost::class);
        (new HostGuard([]))->process(new Request('GET', '/', headers: ['host' => 'example.com']), $this->ok());
    }

    // --- Catatan review M1: redirect (SEC-REQ-04 internal)

    public function test_redirect_hanya_relatif_atau_host_whitelist(): void
    {
        self::assertSame('/a?b=1', Response::redirect('/a?b=1')->headers['Location']);
        foreach (['//evil.com', 'https://evil.com/x', '/\\evil.com', 'javascript:alert(1)', 'evil.com', '', 'https://u:p@example.com/'] as $bad) {
            try {
                Response::redirect($bad, 302, ['example.com']);
                self::fail("harus ditolak: $bad");
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
        self::assertSame('https://example.com/x', Response::redirect('https://example.com/x', 302, ['example.com'])->headers['Location']);
    }

    public function test_CsrfMismatch_status_419(): void
    {
        self::assertSame(419, (new CsrfMismatch())->status);
    }
}
