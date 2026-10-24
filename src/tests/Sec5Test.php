<?php

declare(strict_types=1);

namespace bFramework\Tests;

use bFramework\Contracts\Clock;
use bFramework\Contracts\HttpException;
use bFramework\Contracts\TooManyRequests;
use bFramework\Core\Csrf;
use bFramework\Core\FileSessionStore;
use bFramework\Core\Kernel;
use bFramework\Core\RateLimiter;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\Router;
use bFramework\Sso\BackchannelHandler;
use bFramework\Sso\ClaimsValidator;
use bFramework\Sso\JtiStore;
use bFramework\Tests\Fixtures\AuthHarness;
use bFramework\Tests\Fixtures\SsoHarness;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

/** SEC-5: S4 (secret 2FA), S20 (kuota back-channel), S7 (gc sesi anonim), Retry-After / Allow. */
final class Sec5Test extends TestCase
{
    public function test_SEC5_S4_password_salah_tidak_menampilkan_secret_tertunda(): void
    {
        $h = new AuthHarness();
        $uid = $h->user('ada@contoh.test');
        $b = $h->browser();
        $b->login('ada@contoh.test');
        $b->get('/auth/2fa');
        $ok = $b->post('/auth/2fa/begin', ['password' => AuthHarness::PASSWORD]);
        $secret = (string) $h->twofa()->pendingSecret($h->accounts->find($uid) ?? throw new \RuntimeException());
        self::assertStringContainsString($secret, $ok->body);

        $bad = $b->post('/auth/2fa/confirm', ['code' => '000000', 'password' => 'salah-salah-salah']);
        self::assertSame(401, $bad->status);
        self::assertStringNotContainsString($secret, $bad->body);
        self::assertStringNotContainsString('otpauth://', $bad->body);
        self::assertStringContainsString('Password salah', $bad->body);
    }

    public function test_SEC5_S20_kuota_backchannel_dapat_dikonfigurasi(): void
    {
        $h = new SsoHarness();
        $a = $h->a;
        $mk = static fn(int $max, int $win): BackchannelHandler => new BackchannelHandler(
            $h->oidc(), new ClaimsValidator($h->config()->issuer, $h->config()->clientId),
            new JtiStore($a->dir . '/jti' . $max, $a->clock), $h->sids(), $h->vault(), $a->clock, $a->logger,
            new RateLimiter($a->dir . '/rl' . $max, $a->clock), $max, $win,
        );
        $req = static fn(): Request => new Request('POST', '/auth/sso/backchannel', [], ['logout_token' => 'x'], [], '', [], false, '198.51.100.9');
        $small = $mk(3, 120);
        $codes = [];
        for ($i = 0; $i < 5; $i++) {
            $codes[] = $small->handle($req())->status;
        }
        self::assertSame([3, 2], [count(array_filter($codes, static fn($c) => $c !== 429)), count(array_filter($codes, static fn($c) => $c === 429))]);
        self::assertSame('120', $small->handle($req())->headers['Retry-After'] ?? null);
        $big = $mk(50, 60);
        for ($i = 0; $i < 40; $i++) {
            self::assertNotSame(429, $big->handle($req())->status);
        }
        self::assertSame(30, BackchannelHandler::RATE_MAX, 'bawaan tetap 30/menit');
    }

    private string $dir = '';
    private int $t = 1_000_000;

    private function sessions(): FileSessionStore
    {
        $this->dir = sys_get_temp_dir() . '/sec5_' . bin2hex(random_bytes(6));
        $self = $this;
        $clock = new class ($self) implements Clock {
            public function __construct(private Sec5Test $t)
            {
            }

            public function now(): DateTimeImmutable
            {
                return (new DateTimeImmutable())->setTimestamp($this->t->time());
            }
        };
        return new FileSessionStore($this->dir, false, 10000, 28800, [], static function (): void {
        }, $clock);
    }

    public function time(): int
    {
        return $this->t;
    }

    protected function tearDown(): void
    {
        if ($this->dir !== '') {
            foreach (glob($this->dir . '/*') ?: [] as $f) {
                @unlink($f);
            }
            @rmdir($this->dir);
        }
    }

    private function make(FileSessionStore $base, callable $fill): string
    {
        // Setiap sesi dibuat dengan penyimpanan baru (tanpa cookie) pada direktori yang sama.
        $s = new FileSessionStore($this->dir, false, 10000, 28800, [], static function (): void {
        }, new class ($this) implements Clock {
            public function __construct(private Sec5Test $t)
            {
            }

            public function now(): DateTimeImmutable
            {
                return (new DateTimeImmutable())->setTimestamp($this->t->time());
            }
        });
        $s->start();
        $fill($s);
        return $s->id();
    }

    public function test_SEC5_S7_gc_hapus_sesi_anonim_kosong_tapi_pertahankan_yang_berisi(): void
    {
        $gc = $this->sessions();
        $empty = $this->make($gc, static function (): void {
        });
        $csrfOnly = $this->make($gc, static fn($s) => $s->set(Csrf::KEY, 'tok'));
        $withId = $this->make($gc, static function ($s): void {
            $s->set(Csrf::KEY, 'tok');
            $s->set('identity', 7);
        });
        $flow = $this->make($gc, static function ($s): void {
            $s->set('sso.state', ['n' => 'abc', 'v' => 'pkce']);
        });
        $flash = $this->make($gc, static fn($s) => $s->flash('ok', 'halo'));
        $this->t += 200;
        self::assertSame(0, $gc->gc(), 'belum 5 menit idle');
        $this->t += 200; // 400 dtk: kosong terhapus, hanya-CSRF masih ada
        self::assertSame(1, $gc->gc());
        self::assertFileDoesNotExist($this->dir . '/sess_' . $empty);
        self::assertFileExists($this->dir . '/sess_' . $csrfOnly);
        $this->t += 2300; // 2700 dtk: belum melewati batas hanya-CSRF
        self::assertSame(0, $gc->gc());
        $this->t += 100; // 2800 dtk
        self::assertSame(1, $gc->gc());
        self::assertFileDoesNotExist($this->dir . '/sess_' . $csrfOnly);
        foreach ([$withId, $flow, $flash] as $id) {
            self::assertFileExists($this->dir . '/sess_' . $id);
        }
    }

    public function test_SEC5_S20_konfigurasi_tak_sah_pakai_bawaan_dan_catat_satu_peringatan(): void
    {
        self::assertSame([30, 60], BackchannelHandler::rateFromConfig(null));
        self::assertSame([5, 120], BackchannelHandler::rateFromConfig([5, 120]));
        foreach (['30', [0, 60], [-1, 60], [30, 0], [10001, 60], [30, 86401], ['30', 60], [30], [30, 60, 1], 30] as $bad) {
            $log = new Fixtures\CaptureLogger();
            self::assertSame([30, 60], BackchannelHandler::rateFromConfig($bad, $log), json_encode($bad));
            self::assertCount(1, $log->lines, json_encode($bad));
        }
    }

    public function test_SEC5_Retry_After_pada_429_dan_Allow_pada_405(): void
    {
        $router = new Router();
        $router->add('GET', '/x', static fn(): Response => Response::html('ok'));
        $router->add('POST', '/x', static fn(): Response => Response::html('ok'));
        $router->add('GET', '/lim', static function (): Response {
            throw new TooManyRequests('', 900);
        });
        $k = new Kernel($router);
        $r = $k->handle(new Request('PUT', '/x'));
        self::assertSame(405, $r->status);
        self::assertSame('GET, HEAD, POST', $r->headers['Allow'] ?? null);
        $r = $k->handle(new Request('GET', '/lim'));
        self::assertSame(429, $r->status);
        self::assertSame('900', $r->headers['Retry-After'] ?? null);
        self::assertSame(404, $k->handle(new Request('GET', '/nope'))->status);
        self::assertArrayNotHasKey('Allow', $k->handle(new Request('GET', '/nope'))->headers);
        self::assertInstanceOf(HttpException::class, new TooManyRequests());
    }
}
