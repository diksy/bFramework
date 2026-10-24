<?php

declare(strict_types=1);

namespace bFramework\Tests\Sso;

use bFramework\Tests\Fixtures\AuthHarness;
use bFramework\Tests\Fixtures\SsoBrowser;
use bFramework\Tests\Fixtures\SsoHarness;
use PHPUnit\Framework\TestCase;

final class HybridTest extends TestCase
{
    private const PATH = '/auth/break-glass';

    private function setFlag(SsoHarness $h, int $uid, bool $on): void
    {
        $h->a->conn->pdo()->exec('UPDATE users SET break_glass = ' . ($on ? 1 : 0) . ' WHERE id = ' . $uid);
    }

    private function bgLogin(SsoBrowser $b, string $email, string $pw = AuthHarness::PASSWORD): \bFramework\Core\Response
    {
        $b->get(self::PATH);
        return $b->post(self::PATH, ['email' => $email, 'password' => $pw]);
    }

    public function test_SSO_01_akun_biasa_ditolak_login_lokal_di_hybrid(): void
    {
        $h = new SsoHarness('hybrid');
        $h->a->user('biasa@contoh.test');
        $b = $h->browser();
        $res = $this->bgLogin($b, 'biasa@contoh.test');
        self::assertSame(401, $res->status);
        self::assertStringContainsString('Email atau password salah', $res->body);
        self::assertFalse($b->loggedIn());
        // Pesan identik dengan akun yang tidak ada (tidak membocorkan status break_glass).
        $b2 = $h->browser('198.51.100.9');
        $res2 = $this->bgLogin($b2, 'hantu@contoh.test');
        self::assertSame(401, $res2->status);
    }

    public function test_SSO_01_akun_break_glass_bisa_login_lewat_url_terpisah(): void
    {
        $h = new SsoHarness('hybrid');
        $uid = $h->a->user('darurat@contoh.test', roles: ['admin']);
        $this->setFlag($h, $uid, true);
        $b = $h->browser();
        $res = $this->bgLogin($b, 'darurat@contoh.test');
        self::assertSame(302, $res->status);
        self::assertTrue($b->loggedIn());
        $b->refreshCsrf();
        $out = $b->post('/logout');
        self::assertSame('/login', $out->headers['Location']);
        self::assertFalse($b->loggedIn());
    }

    public function test_SSO_01_url_darurat_tidak_ditautkan_dan_form_lokal_biasa_tidak_ada(): void
    {
        $h = new SsoHarness('hybrid');
        $b = $h->browser();
        $login = $b->get('/login');
        self::assertSame(200, $login->status);
        self::assertStringNotContainsString('break-glass', $login->body);
        self::assertStringNotContainsString('type="password"', $login->body);
        self::assertStringContainsString('/auth/sso/login', $login->body);
        self::assertSame(405, $b->post('/login', ['email' => 'a@b.test', 'password' => 'x'])->status);
        foreach (['/auth/forgot', '/auth/register', '/auth/reset', '/auth/verify'] as $p) {
            self::assertSame(404, $b->get($p)->status, $p);
        }
        $bg = $b->get(self::PATH);
        self::assertSame(200, $bg->status);
        self::assertStringNotContainsString('name="remember"', $bg->body, 'login darurat tanpa ingat-saya');
        self::assertStringNotContainsString('/auth/forgot', $bg->body);
    }

    public function test_SSO_01_mode_bikinin_sso_murni_tidak_punya_login_lokal(): void
    {
        $h = new SsoHarness('bikinin_sso');
        $uid = $h->a->user('darurat@contoh.test', roles: ['admin']);
        $this->setFlag($h, $uid, true);
        $b = $h->browser();
        self::assertSame(404, $b->get(self::PATH)->status);
        self::assertSame(404, $b->post(self::PATH, ['email' => 'darurat@contoh.test', 'password' => AuthHarness::PASSWORD], false)->status);
    }

    public function test_SSO_01_flag_break_glass_lewat_UserStore_hanya_boolean(): void
    {
        $h = new SsoHarness('hybrid');
        $uid = $h->a->user('darurat@contoh.test', roles: ['admin']);
        $h->a->users()->update($uid, ['break_glass' => true]);
        self::assertTrue($h->a->users()->find($uid)?->breakGlass);
        $b = $h->browser();
        self::assertSame(302, $this->bgLogin($b, 'darurat@contoh.test')->status);
        $h->a->users()->update($uid, ['break_glass' => false]);
        self::assertFalse($h->a->users()->find($uid)?->breakGlass);
        $this->expectException(\InvalidArgumentException::class);
        $h->a->users()->update($uid, ['break_glass' => 'ya']);
    }

    public function test_SSO_01_hybrid_login_sso_tetap_berfungsi(): void
    {
        $h = new SsoHarness('hybrid');
        $b = $h->browser();
        self::assertSame(302, $b->login()['callback']->status);
        self::assertTrue($b->loggedIn());
    }

    public function test_SSO_01_sesi_lokal_biasa_dan_ingat_saya_tidak_berlaku_di_mode_sso(): void
    {
        foreach (['hybrid', 'bikinin_sso'] as $mode) {
            $h = new SsoHarness($mode);
            $uid = $h->a->user('biasa@contoh.test');
            $cookie = $h->a->remember()->issue($uid); // sisa token ingat-saya dari masa driver local
            $b = $h->browser();
            $b->cookies['bf_remember'] = $cookie;
            self::assertFalse($b->loggedIn(), $mode);
            self::assertArrayNotHasKey('bf_remember', $b->cookies, 'cookie tidak sah dibersihkan');
        }
    }

    public function test_SSO_01_flag_break_glass_dicabut_mengakhiri_sesi_darurat(): void
    {
        $h = new SsoHarness('hybrid');
        $uid = $h->a->user('darurat@contoh.test', roles: ['admin']);
        $this->setFlag($h, $uid, true);
        $b = $h->browser();
        $this->bgLogin($b, 'darurat@contoh.test');
        self::assertTrue($b->loggedIn());
        $this->setFlag($h, $uid, false);
        self::assertFalse($b->loggedIn());
    }

    public function test_SSO_14_logout_sesi_sso_di_hybrid_tetap_ke_SSO(): void
    {
        $h = new SsoHarness('hybrid');
        $b = $h->browser();
        $b->login();
        $b->refreshCsrf();
        $res = $b->post('/logout');
        self::assertStringStartsWith('0; url=https://sso.contoh.test/oauth2/bye?', $res->headers['Refresh']);
    }
}
