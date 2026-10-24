<?php

declare(strict_types=1);

namespace bFramework\Tests\Sso;

use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Tests\Fixtures\FakeIdp;
use bFramework\Tests\Fixtures\SsoHarness;
use PHPUnit\Framework\TestCase;

final class BackchannelTest extends TestCase
{
    private SsoHarness $h;

    protected function setUp(): void
    {
        $this->h = new SsoHarness();
    }

    private function bc(string $token, ?string $csrf = null): Response
    {
        $post = ['logout_token' => $token] + ($csrf === null ? [] : ['_csrf' => $csrf]);
        return $this->h->dispatch(new Request('POST', '/auth/sso/backchannel', [], $post, [], '', [], false, '198.51.100.5'), []);
    }

    public function test_SSO_15_logout_token_valid_204_dan_sesi_dicabut_SSO_17(): void
    {
        $b = $this->h->browser();
        $b->login(['sid' => 'sid-A']);
        self::assertTrue($b->loggedIn());
        $t0 = hrtime(true);
        $res = $this->bc($this->h->idp->logoutToken(['sid' => 'sid-A']));
        $ms = (hrtime(true) - $t0) / 1e6;
        self::assertSame(204, $res->status);
        self::assertSame('', $res->body);
        self::assertLessThan(1000, $ms, 'balas < 1 detik');
        self::assertFalse($b->loggedIn(), 'request berikutnya dari sesi itu harus login ulang');
    }

    public function test_SSO_17_hanya_sesi_dengan_sid_itu_yang_dicabut(): void
    {
        $a = $this->h->browser('203.0.113.1');
        $b = $this->h->browser('203.0.113.2');
        $a->login(['sid' => 'sid-A']);
        $b->login(['sid' => 'sid-B', 'sub' => 'sub-002', 'email' => 'dua@contoh.test']);
        self::assertSame(204, $this->bc($this->h->idp->logoutToken(['sid' => 'sid-A']))->status);
        self::assertFalse($a->loggedIn());
        self::assertTrue($b->loggedIn());
    }

    public function test_SSO_17_logout_token_hanya_sub_mencabut_semua_sesi_user_itu(): void
    {
        $a = $this->h->browser('203.0.113.1');
        $b = $this->h->browser('203.0.113.2');
        $a->login(['sid' => 'sid-A']);
        $b->login(['sid' => 'sid-B']);
        self::assertSame(204, $this->bc($this->h->idp->logoutToken(['sid' => null, 'sub' => 'sub-001']))->status);
        self::assertFalse($a->loggedIn());
        self::assertFalse($b->loggedIn());
    }

    public function test_SSO_17_sesi_tetap_dicabut_meski_id_sesi_sudah_diregenerasi(): void
    {
        $b = $this->h->browser();
        $b->login(['sid' => 'sid-A']);
        $before = $b->cookies['bf_sid'];
        $store = new \bFramework\Core\FileSessionStore($this->h->a->dir . '/sessions', false, 1800, 28800, $b->cookies, static function (): void {
        }, $this->h->a->clock);
        $store->start();
        $store->regenerate(); // mis. switchRole: ID file sesi berganti, pemetaan sid tetap berlaku
        $b->cookies['bf_sid'] = $store->id();
        self::assertNotSame($before, $b->cookies['bf_sid']);
        self::assertTrue($b->loggedIn());
        self::assertSame(204, $this->bc($this->h->idp->logoutToken(['sid' => 'sid-A']))->status);
        self::assertFalse($b->loggedIn());
    }

    public function test_SSO_15_replay_jti_ditolak(): void
    {
        $b = $this->h->browser();
        $b->login(['sid' => 'sid-A']);
        $t = $this->h->idp->logoutToken(['sid' => 'sid-A', 'jti' => 'jti-tetap']);
        self::assertSame(204, $this->bc($t)->status);
        self::assertSame(400, $this->bc($t)->status);
        $this->h->a->clock->advance(100); // masih dalam 2 menit
        self::assertSame(400, $this->bc($this->h->idp->logoutToken(['sid' => 'sid-A', 'jti' => 'jti-tetap']))->status);
    }

    public function test_SSO_15_tanpa_events_atau_dengan_nonce_400_dan_sesi_utuh(): void
    {
        $b = $this->h->browser();
        $b->login(['sid' => 'sid-A']);
        $idp = $this->h->idp;
        $bad = [
            'tanpa events' => $idp->logoutToken(['events' => null]),
            'events salah' => $idp->logoutToken(['events' => ['http://lain' => new \stdClass()]]),
            'dengan nonce' => $idp->logoutToken(['nonce' => 'abc']),
            'tanpa jti' => $idp->logoutToken(['jti' => null]),
            'tanpa sub dan sid' => $idp->logoutToken(['sub' => null, 'sid' => null]),
            'iss salah' => $idp->logoutToken(['iss' => 'https://jahat.test']),
            'aud salah' => $idp->logoutToken(['aud' => 'lain']),
            'terlalu lama' => $idp->logoutToken(['iat' => $idp->clock->t - 3600]),
            'iat masa depan' => $idp->logoutToken(['iat' => $idp->clock->t + 3600]),
            'kedaluwarsa' => $idp->logoutToken(['exp' => $idp->clock->t - 600]),
        ];
        foreach ($bad as $name => $t) {
            $res = $this->bc($t);
            self::assertSame(400, $res->status, $name);
            self::assertStringNotContainsString('nonce', $res->body, $name);
        }
        self::assertTrue($b->loggedIn(), 'token ditolak tidak boleh mencabut sesi');
    }

    public function test_SSO_15_tanda_tangan_alg_dan_kunci_salah_ditolak(): void
    {
        $b = $this->h->browser();
        $b->login(['sid' => 'sid-A']);
        $idp = $this->h->idp;
        $claims = ['iss' => FakeIdp::ISSUER, 'aud' => FakeIdp::CLIENT_ID, 'sid' => 'sid-A', 'iat' => $idp->clock->t, 'jti' => 'j1',
            'events' => ['http://schemas.openid.net/event/backchannel-logout' => new \stdClass()]];
        self::assertSame(400, $this->bc($idp->forge('none', $claims))->status);
        self::assertSame(400, $this->bc($idp->forge('HS256', $claims, $idp->publicPem()))->status);
        self::assertSame(400, $this->bc($idp->forge('RS256', $claims))->status);
        self::assertSame(400, $this->bc('bukan-jwt')->status);
        self::assertSame(400, $this->bc('')->status);
        self::assertSame(400, $this->bc(str_repeat('a', 9000))->status);
        self::assertTrue($b->loggedIn());
    }

    public function test_SSO_16_backchannel_tanpa_csrf_dan_GET_tidak_ada(): void
    {
        self::assertSame(400, $this->bc('x')->status, 'tidak 419: lolos CSRF, ditolak karena token');
        $this->h->wire([]);
        $b = $this->h->browser();
        self::assertSame(405, $b->get('/auth/sso/backchannel')->status);
    }

    public function test_SSO_15_respons_tidak_membocorkan_alasan(): void
    {
        $res = $this->bc($this->h->idp->logoutToken(['nonce' => 'x']));
        self::assertSame('{"error":"invalid_request"}', $res->body);
        self::assertSame('no-store', $res->headers['Cache-Control']);
    }
}
