<?php

declare(strict_types=1);

namespace bFramework\Tests\Sso;

use bFramework\Core\BlockedDestination;
use bFramework\Core\HttpClient;
use bFramework\Core\HttpResponse;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Sso\BackchannelHandler;
use bFramework\Tests\Fixtures\SsoHarness;
use PHPUnit\Framework\TestCase;

/** SEC-2: S2 (TTL clamp, rate limit, negative cache, urutan murah-dulu), S10 (redirect ber-body). */
final class SecHardeningTest extends TestCase
{
    private SsoHarness $h;

    protected function setUp(): void
    {
        $this->h = new SsoHarness();
    }

    private function bc(string $token, string $ip = '198.51.100.5'): Response
    {
        return $this->h->dispatch(new Request('POST', '/auth/sso/backchannel', [], ['logout_token' => $token], [], '', [], false, $ip), []);
    }

    public function test_S2_ttl_no_cache_di_clamp_ke_60_detik(): void
    {
        $idp = $this->h->idp;
        foreach (['no-cache', 'no-store', 'max-age=0', 'max-age=5'] as $cc) {
            $idp->hits = ['discovery' => 0, 'jwks' => 0, 'token' => 0, 'introspect' => 0];
            $idp->cacheControl = $cc;
            $h = new SsoHarness();
            $h->idp->cacheControl = $cc;
            $h->oidc()->verifyToken($h->idp->sign($h->idp->claims()));
            $h->idp->clock->advance(59);
            $h->oidc()->verifyToken($h->idp->sign($h->idp->claims(['iat' => $h->idp->clock->t, 'exp' => $h->idp->clock->t + 300])));
            self::assertSame(1, $h->idp->hits['jwks'], $cc);
            $h->idp->clock->advance(2);
            $h->oidc()->verifyToken($h->idp->sign($h->idp->claims(['iat' => $h->idp->clock->t, 'exp' => $h->idp->clock->t + 300])));
            self::assertSame(2, $h->idp->hits['jwks'], $cc);
        }
    }

    public function test_S2_ttl_dibatasi_atas_24_jam(): void
    {
        $idp = $this->h->idp;
        $idp->cacheControl = 'max-age=999999999';
        $this->h->oidc()->verifyToken($idp->sign($idp->claims()));
        $idp->clock->advance(86400 + 1);
        $this->h->oidc()->verifyToken($idp->sign($idp->claims(['iat' => $idp->clock->t, 'exp' => $idp->clock->t + 300])));
        self::assertSame(2, $idp->hits['jwks']);
    }

    public function test_S2_100_post_backchannel_anonim_fetch_maks_2_dan_429_setelah_batas(): void
    {
        $idp = $this->h->idp;
        $idp->cacheControl = 'no-cache';
        $idp->activeKid = 'kid-1';
        $tok = $idp->logoutToken(['sid' => 'sid-x']);
        $codes = [];
        for ($i = 0; $i < 100; $i++) {
            $codes[] = $this->bc($tok . '', '198.51.100.9')->status;
        }
        self::assertLessThanOrEqual(2, $idp->hits['discovery'] + $idp->hits['jwks']);
        self::assertSame(429, $codes[99]);
        self::assertSame(BackchannelHandler::RATE_MAX, count(array_filter($codes, static fn(int $c): bool => $c !== 429)));
        $r = $this->bc($tok, '198.51.100.9');
        self::assertSame(429, $r->status);
        self::assertSame('no-store', $r->headers['Cache-Control']);
        // IP lain tidak terdampak.
        self::assertNotSame(429, $this->bc($tok, '198.51.100.10')->status);
    }

    public function test_S2_kunci_ip_dinormalisasi(): void
    {
        self::assertSame(BackchannelHandler::ipKey('::ffff:203.0.113.7'), BackchannelHandler::ipKey('203.0.113.7'));
        self::assertSame(BackchannelHandler::ipKey('2001:db8:1:2::1'), BackchannelHandler::ipKey('2001:db8:1:2:ffff::9'));
        self::assertNotSame(BackchannelHandler::ipKey('2001:db8:1:2::1'), BackchannelHandler::ipKey('2001:db8:1:3::1'));
        self::assertSame('unknown', BackchannelHandler::ipKey(''));
        self::assertSame('unknown', BackchannelHandler::ipKey('bukan-ip'));
    }

    public function test_S2_jwt_cacat_ditolak_sebelum_fetch(): void
    {
        $idp = $this->h->idp;
        $b = static fn(string $x): string => rtrim(strtr(base64_encode($x), '+/', '-_'), '=');
        $sig = $b(str_repeat('s', 40));
        $bad = [
            'bukan jwt' => 'abc',
            'dua segmen' => $b('{"alg":"RS256","kid":"k"}') . '.' . $b('{}'),
            'alg none' => $b('{"alg":"none","kid":"k"}') . '.' . $b('{}') . '.' . $sig,
            'alg HS256' => $b('{"alg":"HS256","kid":"k"}') . '.' . $b('{}') . '.' . $sig,
            'tanpa kid' => $b('{"alg":"RS256"}') . '.' . $b('{}') . '.' . $sig,
            'kid bukan string' => $b('{"alg":"RS256","kid":5}') . '.' . $b('{}') . '.' . $sig,
            'header bukan json' => $b('xx') . '.' . $b('{}') . '.' . $sig,
        ];
        foreach ($bad as $name => $t) {
            self::assertSame(400, $this->bc($t, '198.51.100.30')->status, $name);
        }
        self::assertSame(0, $idp->hits['discovery'] + $idp->hits['jwks'], 'tanpa fetch keluar');
    }

    public function test_S2_negative_cache_setelah_fetch_gagal(): void
    {
        $idp = $this->h->idp;
        $idp->discoveryOverride = ['issuer' => 'https://lain.test'];
        $oidc = $this->h->oidc();
        for ($i = 0; $i < 5; $i++) {
            try {
                $oidc->authorizationUrl('s', 'n', 'c');
                self::fail('harus gagal');
            } catch (\bFramework\Sso\OidcException) {
            }
        }
        self::assertSame(1, $idp->hits['discovery'], 'gagal sekali, 4 sisanya tanpa fetch');
        $idp->clock->advance(31);
        $idp->discoveryOverride = [];
        self::assertNotSame('', $this->h->oidc()->authorizationUrl('s', 'n', 'c'));
        self::assertSame(2, $idp->hits['discovery']);
    }

    // ---- S10 ----

    private function client(SecFakeTransport $t, array $ports = [443]): HttpClient
    {
        return new HttpClient(null, $t, 1000, [], $ports, static fn(string $h): array => ['93.184.216.34']);
    }

    public function test_S10_redirect_307_lintas_origin_tidak_membawa_body(): void
    {
        foreach ([307, 308] as $st) {
            $t = new SecFakeTransport([new HttpResponse($st, ['location' => 'https://jahat.example.org/x'], ''), new HttpResponse(200, [], 'ok')]);
            try {
                $this->client($t)->request('POST', 'https://idp.example.com/tok', ['Authorization' => 'Basic x'], 'code=rahasia&code_verifier=v');
                self::fail('harus ditolak');
            } catch (BlockedDestination) {
            }
            self::assertCount(1, $t->calls, 'permintaan kedua tidak pernah dikirim');
        }
    }

    public function test_S10_port_berbeda_adalah_origin_berbeda(): void
    {
        $t = new SecFakeTransport([new HttpResponse(307, ['location' => 'https://idp.example.com:8443/x'], ''), new HttpResponse(200, [], 'ok')]);
        $this->expectException(BlockedDestination::class);
        $this->client($t, [443, 8443])->request('POST', 'https://idp.example.com/tok', [], 'code=rahasia');
    }

    public function test_S10_port_berbeda_membuang_authorization_pada_GET(): void
    {
        $t = new SecFakeTransport([new HttpResponse(302, ['location' => 'https://idp.example.com:8443/x'], ''), new HttpResponse(200, [], 'ok')]);
        $this->client($t, [443, 8443])->request('GET', 'https://idp.example.com/', ['Authorization' => 'Bearer r', 'Cookie' => 'a=b']);
        self::assertArrayNotHasKey('Authorization', $t->calls[1]['headers']);
        self::assertArrayNotHasKey('Cookie', $t->calls[1]['headers']);
    }

    public function test_S10_redirect_307_origin_sama_tetap_membawa_body(): void
    {
        $t = new SecFakeTransport([new HttpResponse(307, ['location' => '/lain'], ''), new HttpResponse(200, [], 'ok')]);
        $this->client($t)->request('POST', 'https://idp.example.com/tok', [], 'a=1');
        self::assertSame('a=1', $t->calls[1]['body']);
    }
}

final class SecFakeTransport implements \bFramework\Core\Transport
{
    /** @var list<array<string,mixed>> */
    public array $calls = [];

    /** @param list<HttpResponse> $queue */
    public function __construct(private array $queue)
    {
    }

    public function send(string $method, string $host, int $port, string $ip, string $pathAndQuery, array $headers, ?string $body, int $timeout, int $maxBytes): HttpResponse
    {
        $this->calls[] = compact('method', 'host', 'port', 'headers', 'body');
        return array_shift($this->queue) ?? new HttpResponse(200, [], 'ok');
    }
}
