<?php

declare(strict_types=1);

namespace bFramework\Tests\Auth;

use bFramework\Auth\CookieJar;
use bFramework\Auth\Cookies;
use bFramework\Auth\Deferred;
use bFramework\Auth\SessionMiddleware;
use bFramework\Core\Config;
use bFramework\Core\FileSessionStore;
use bFramework\Core\Request;
use bFramework\Core\Response;
use PHPUnit\Framework\TestCase;

final class WiringTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/wire_' . bin2hex(random_bytes(6));
        mkdir($this->dir . '/storage', 0700, true);
        mkdir($this->dir . '/core', 0700, true);
        symlink(dirname(__DIR__, 2) . '/app/core/Auth', $this->dir . '/core/Auth');
        symlink(dirname(__DIR__, 2) . '/app/core/Core', $this->dir . '/core/Core');
    }

    protected function tearDown(): void
    {
        unlink($this->dir . '/core/Auth');
        unlink($this->dir . '/core/Core');
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) {
            $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
        }
        rmdir($this->dir);
        Config::set([]);
    }

    public function test_SEC_SESS_03_middleware_memasang_cookie_sesi_ke_response_dengan_atribut_aman(): void
    {
        $jar = new CookieJar();
        $store = new FileSessionStore($this->dir . '/s', true, 1800, 28800, [], $jar->add(...));
        $mw = new SessionMiddleware($store, $jar);
        $res = $mw->process(new Request('GET', '/', isHttps: true), static fn(Request $r): Response => Response::html('ok'));
        self::assertCount(1, $res->cookies);
        $c = $res->cookies[0];
        self::assertSame('__Host-bf_sid', $c['name']);
        self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $c['value']);
        self::assertTrue($c['options']['secure']);
        self::assertTrue($c['options']['httponly']);
        self::assertSame('Lax', $c['options']['samesite']);
    }

    public function test_SEC_SESS_01_gc_sesi_dipicu_probabilistik(): void
    {
        $jar = new CookieJar();
        $store = new FileSessionStore($this->dir . '/s', false, 1800, 28800, [], $jar->add(...));
        $calls = 0;
        $next = static fn(Request $r): Response => Response::html('ok');
        $never = new SessionMiddleware($store, $jar, function () use (&$calls): int {
            return ++$calls;
        }, 100, static fn(): int => 57);
        $never->process(new Request('GET', '/'), $next);
        self::assertSame(0, $calls);
        $always = new SessionMiddleware($store, $jar, function () use (&$calls): int {
            return ++$calls;
        }, 100, static fn(): int => 1);
        $always->process(new Request('GET', '/'), $next);
        self::assertSame(1, $calls);
    }

    public function test_SEC_SESS_01_gc_menghapus_sesi_kedaluwarsa_lewat_middleware(): void
    {
        $clock = new \bFramework\Tests\Fixtures\FakeClock();
        $jar = new CookieJar();
        $store = new FileSessionStore($this->dir . '/s', false, 100, 1000, [], $jar->add(...), $clock);
        $store->start();
        $store->set('x', 1);
        self::assertCount(1, glob($this->dir . '/s/sess_*') ?: []);
        $clock->advance(5000);
        (new SessionMiddleware($store, $jar, $store->gc(...), 1, static fn(): int => 1))
            ->process(new Request('GET', '/'), static fn(Request $r): Response => Response::html('ok'));
        self::assertCount(0, glob($this->dir . '/s/sess_*') ?: []);
    }

    public function test_cookie_parser_menolak_nama_aneh_dan_duplikat_pertama_menang(): void
    {
        self::assertSame(['a' => '1', 'b' => '2'], Cookies::parse('a=1; b=2; a=9; =x; bad name=3; c'));
        self::assertSame([], Cookies::parse(''));
    }

    public function test_deferred_menjalankan_setelah_dan_menelan_galat(): void
    {
        $log = new \bFramework\Tests\Fixtures\CaptureLogger();
        $d = new Deferred($log);
        $ran = [];
        $d->push(function () use (&$ran): void {
            $ran[] = 1;
        });
        $d->push(static function (): void {
            throw new \RuntimeException('rahasia-dummy');
        });
        $d->push(function () use (&$ran): void {
            $ran[] = 3;
        });
        self::assertSame([], $ran);
        $d->run();
        self::assertSame([1, 3], $ran);
        self::assertStringNotContainsString('rahasia-dummy', $log->all());
        self::assertSame(0, $d->pending());
    }

    public function test_bootstrap_buildAuth_merakit_driver_lokal_registrasi_mati_dan_urutan_middleware(): void
    {
        Config::set(['DB_DRIVER' => 'sqlite', 'DB_FILE' => 'tes.sqlite', 'APP_URL' => 'https://app.contoh.test',
            'APP_KEY' => str_repeat('k', 40), 'APP_ENV' => 'production']);
        $conn = \bFramework\connectDatabase($this->dir);
        \bFramework\Auth\AuthSchema::install($conn);
        self::assertSame([], \bFramework\Auth\AuthSchema::install($conn), 'idempoten');
        $kit = \bFramework\buildAuth($this->dir, $conn, true);
        self::assertSame('local', $kit->driver->name());
        $router = new \bFramework\Core\Router();
        $kit->driver->registerRoutes($router);
        $names = array_map(static fn($m) => $m::class, $kit->middleware($router, ['app.contoh.test']));
        self::assertSame([
            \bFramework\Core\SecurityHeaders::class, \bFramework\Core\HostGuard::class, SessionMiddleware::class,
            \bFramework\Auth\AuthMiddleware::class, \bFramework\Core\CsrfMiddleware::class,
        ], $names);
        // AUTH-08: tanpa konfigurasi, /auth/register tidak ada.
        $kernel = new \bFramework\Core\Kernel($router, $kit->middleware($router, ['app.contoh.test']));
        self::assertSame(404, $kernel->handle(new Request('GET', '/auth/register', headers: ['host' => 'app.contoh.test']))->status);
        self::assertSame(400, $kernel->handle(new Request('GET', '/login', headers: ['host' => 'jahat.test']))->status, 'Host di luar whitelist');
        $kit = \bFramework\buildAuth($this->dir, $conn, true); // satu kit = satu request
        $router = new \bFramework\Core\Router();
        $kit->driver->registerRoutes($router);
        $kernel = new \bFramework\Core\Kernel($router, $kit->middleware($router, ['app.contoh.test']));
        $ok = $kernel->handle(new Request('GET', '/login', headers: ['host' => 'app.contoh.test'], isHttps: true));
        self::assertSame(200, $ok->status);
        self::assertSame('__Host-bf_sid', $ok->cookies[0]['name']);
        self::assertSame('no-store', $ok->headers['Cache-Control']);
    }

    public function test_bootstrap_menolak_app_url_tidak_aman_di_produksi(): void
    {
        Config::set(['DB_FILE' => 'tes.sqlite', 'APP_URL' => 'http://app.contoh.test', 'APP_ENV' => 'production']);
        $conn = \bFramework\connectDatabase($this->dir);
        \bFramework\Auth\AuthSchema::install($conn);
        $this->expectException(\InvalidArgumentException::class);
        \bFramework\buildAuth($this->dir, $conn, true);
    }

    public function test_arsitektur_auth_tidak_bergantung_ke_lapisan_atas(): void
    {
        foreach (glob(dirname(__DIR__, 2) . '/app/core/Auth/*.php') ?: [] as $f) {
            self::assertDoesNotMatchRegularExpression('/use bFramework\\\\Builder\\\\/', (string) file_get_contents($f), basename($f));
        }
    }
}
