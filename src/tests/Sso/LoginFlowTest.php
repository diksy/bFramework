<?php

declare(strict_types=1);

namespace bFramework\Tests\Sso;

use bFramework\Tests\Fixtures\AuthHarness;
use bFramework\Tests\Fixtures\FakeIdp;
use bFramework\Tests\Fixtures\SsoHarness;
use PHPUnit\Framework\TestCase;

final class LoginFlowTest extends TestCase
{
    private SsoHarness $h;

    protected function setUp(): void
    {
        $this->h = new SsoHarness();
    }

    private function userCount(): int
    {
        return (int) $this->h->a->conn->pdo()->query('SELECT COUNT(*) FROM users')->fetchColumn();
    }

    public function test_SSO_02_dan_03_endpoint_dari_discovery_dan_client_secret_basic(): void
    {
        $b = $this->h->browser();
        $r = $b->login();
        self::assertSame(302, $r['callback']->status);
        $loc = $b->get('/login');
        self::assertSame('/', $loc->headers['Location']);
        // Endpoint non-standar dari discovery dipakai apa adanya (/oauth2/auth, /oauth2/tok).
        $first = $this->h->idp->calls;
        $paths = array_column($first, 'path');
        self::assertContains('/oauth2/tok', $paths);
        $tok = $first[array_search('/oauth2/tok', $paths, true)];
        self::assertSame('Basic ' . base64_encode(FakeIdp::CLIENT_ID . ':' . FakeIdp::SECRET), $tok['headers']['Authorization']);
        self::assertStringContainsString('grant_type=authorization_code', (string) $tok['body']);
        self::assertStringNotContainsString(FakeIdp::SECRET, (string) $tok['body']);
        self::assertStringNotContainsString(FakeIdp::SECRET, $this->h->a->logger->all(), 'client_secret tidak boleh masuk log');
        $authz = $this->h->browser()->start()['res']->headers['Location'];
        self::assertStringStartsWith(FakeIdp::ISSUER . '/oauth2/auth?', $authz);
    }

    public function test_SSO_02_client_secret_tidak_tersimpan_di_cache_atau_berkas_apa_pun(): void
    {
        $this->h->browser()->login();
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->h->a->dir, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if ($f->isFile()) {
                self::assertStringNotContainsString(FakeIdp::SECRET, (string) file_get_contents($f->getPathname()), $f->getPathname());
            }
        }
        ob_start();
        var_dump($this->h->config());
        $dump = print_r($this->h->config(), true) . ob_get_clean();
        self::assertStringNotContainsString(FakeIdp::SECRET, $dump);
    }

    public function test_SSO_08_pkce_s256_state_nonce_acak_dan_unik(): void
    {
        $b1 = $this->h->browser();
        $s1 = $b1->start()['params'];
        $s2 = $this->h->browser('203.0.113.8')->start()['params'];
        self::assertSame('S256', $s1['code_challenge_method']);
        self::assertSame('code', $s1['response_type']);
        self::assertGreaterThanOrEqual(43, strlen($s1['state']));
        self::assertGreaterThanOrEqual(43, strlen($s1['nonce']));
        self::assertNotSame($s1['state'], $s2['state']);
        self::assertNotSame($s1['nonce'], $s2['nonce']);
        self::assertNotSame($s1['code_challenge'], $s2['code_challenge']);
        // Pertukaran code mengirim code_verifier yang hash S256-nya = code_challenge.
        $idt = $this->h->idp->idToken($s1['nonce']);
        $this->h->idp->tokenQueue[] = [200, ['access_token' => 'a', 'id_token' => $idt, 'expires_in' => 60]];
        $b1->get('/auth/sso/callback?code=k&state=' . $s1['state']);
        $calls = array_values(array_filter($this->h->idp->calls, static fn(array $c): bool => $c['path'] === '/oauth2/tok'));
        parse_str((string) $calls[0]['body'], $form);
        self::assertSame(rtrim(strtr(base64_encode(hash('sha256', (string) $form['code_verifier'], true)), '+/', '-_'), '='), $s1['code_challenge']);
        self::assertSame('https://app.contoh.test/auth/sso/callback', $form['redirect_uri']);
    }

    public function test_SSO_08_state_salah_400_dan_tanpa_pertukaran_code(): void
    {
        $b = $this->h->browser();
        $b->start();
        $res = $b->get('/auth/sso/callback?code=k&state=salah');
        self::assertSame(400, $res->status);
        self::assertSame(0, $this->h->idp->hits['token']);
        self::assertFalse($b->loggedIn());
        // Tanpa flow sama sekali (mis. callback langsung) juga 400.
        self::assertSame(400, $this->h->browser('203.0.113.9')->get('/auth/sso/callback?code=k&state=x')->status);
    }

    public function test_SSO_08_nonce_salah_ditolak(): void
    {
        $b = $this->h->browser();
        $s = $b->start()['params'];
        $this->h->idp->tokenQueue[] = [200, ['access_token' => 'a', 'id_token' => $this->h->idp->idToken('nonce-lain-yang-salah')]];
        $res = $b->get('/auth/sso/callback?code=k&state=' . $s['state']);
        self::assertSame(400, $res->status);
        self::assertFalse($b->loggedIn());
    }

    public function test_SSO_08_replay_callback_dan_code_reuse_tidak_menukar_lagi(): void
    {
        $b = $this->h->browser();
        $r = $b->login();
        self::assertSame(302, $r['callback']->status);
        $state = $r['start']['state'];
        $again = $b->get('/auth/sso/callback?code=kode-1&state=' . $state);
        self::assertSame(400, $again->status);
        self::assertSame(1, $this->h->idp->hits['token'], 'code yang sama tidak dikirim ke token endpoint dua kali');
    }

    public function test_SSO_20_invalid_grant_halaman_ramah_tanpa_retry(): void
    {
        $b = $this->h->browser();
        $s = $b->start()['params'];
        $this->h->idp->tokenQueue[] = [400, ['error' => 'invalid_grant', 'error_description' => 'rahasia']];
        $res = $b->get('/auth/sso/callback?code=basi&state=' . $s['state']);
        self::assertSame(400, $res->status);
        self::assertStringContainsString('login ulang', strtolower($res->body));
        self::assertStringContainsString('/auth/sso/login', $res->body);
        self::assertStringNotContainsString('Stack', $res->body);
        self::assertStringNotContainsString('rahasia', $res->body);
        self::assertSame(1, $this->h->idp->hits['token'], 'tanpa retry otomatis');
    }

    public function test_SSO_09_akun_ditautkan_lewat_sub_bukan_email(): void
    {
        $b = $this->h->browser();
        $b->login();
        $before = $this->userCount();
        self::assertSame(1, $before);
        $b->refreshCsrf();
        $b->post('/logout');
        // Email di SSO berubah, sub sama -> akun yang sama, tidak ada akun baru.
        $b2 = $this->h->browser('203.0.113.50');
        $r = $b2->login(['email' => 'baru@contoh.test']);
        self::assertSame(302, $r['callback']->status);
        self::assertSame($before, $this->userCount());
        $u = $this->h->a->users()->findBySsoSub('sub-001');
        self::assertNotNull($u);
        self::assertSame('budi@contoh.test', $u->email, 'email lokal tidak diubah diam-diam');
    }

    public function test_SSO_09_tidak_takeover_lewat_email_akun_lokal(): void
    {
        $victim = $this->h->a->user('admin@contoh.test', roles: ['admin']);
        $b = $this->h->browser();
        $r = $b->login(['email' => 'admin@contoh.test', 'sub' => 'sub-penyerang']);
        self::assertSame(200, $r['callback']->status, 'meminta bukti kepemilikan, bukan masuk');
        self::assertStringContainsString('/auth/sso/link', $r['callback']->body);
        self::assertFalse($b->loggedIn());
        self::assertNull($this->h->a->accounts->find($victim)?->ssoSub);
        // Password salah -> ditolak, tetap tidak tertaut.
        self::assertSame(401, $b->post('/auth/sso/link', ['password' => 'salah-salah-salah'])->status);
        self::assertFalse($b->loggedIn());
        self::assertNull($this->h->a->accounts->find($victim)?->ssoSub);
    }

    public function test_AUTH_02_tautan_dengan_bukti_password_lalu_pencocokan_lewat_sub(): void
    {
        $uid = $this->h->a->user('admin@contoh.test', roles: ['admin']);
        $b = $this->h->browser();
        $b->login(['email' => 'admin@contoh.test', 'sub' => 'sub-admin']);
        $res = $b->post('/auth/sso/link', ['password' => AuthHarness::PASSWORD]);
        self::assertSame(302, $res->status);
        self::assertTrue($b->loggedIn());
        self::assertSame('sub-admin', $this->h->a->accounts->find($uid)?->ssoSub);
        // Login berikutnya langsung lewat sub, tanpa tautan lagi (dan email SSO boleh berbeda).
        $b->refreshCsrf();
        $b->post('/logout');
        $b2 = $this->h->browser('203.0.113.60');
        $r = $b2->login(['email' => 'lain@contoh.test', 'sub' => 'sub-admin']);
        self::assertSame(302, $r['callback']->status);
        self::assertTrue($b2->loggedIn());
        self::assertSame($uid, $this->h->a->users()->findBySsoSub('sub-admin')?->id);
    }

    public function test_SSO_10_jit_membuat_akun_dengan_default_role(): void
    {
        $this->h->sso['default_role'] = 'staf';
        $b = $this->h->browser();
        $r = $b->login();
        self::assertSame(302, $r['callback']->status);
        $u = $this->h->a->users()->findBySsoSub('sub-001');
        self::assertNotNull($u);
        self::assertSame(['staf'], $u->roles);
        self::assertSame('active', $u->status);
        self::assertNull($this->h->a->accounts->find($u->id)?->passwordHash, 'akun SSO tanpa password');
    }

    public function test_SSO_10_pre_registered_menolak_sub_belum_terdaftar_dan_menerima_yang_terdaftar(): void
    {
        $this->h->sso['provisioning'] = 'pre_registered';
        $b = $this->h->browser();
        $r = $b->login();
        self::assertSame(403, $r['callback']->status);
        self::assertFalse($b->loggedIn());
        self::assertSame(0, $this->userCount());
        $uid = $this->h->a->user('budi@contoh.test');
        $this->h->a->users()->update($uid, ['sso_sub' => 'sub-001']);
        $b2 = $this->h->browser('203.0.113.70');
        self::assertSame(302, $b2->login()['callback']->status);
        self::assertTrue($b2->loggedIn());
    }

    public function test_SSO_10_akun_nonaktif_ditolak(): void
    {
        $uid = $this->h->a->user('budi@contoh.test');
        $this->h->a->users()->update($uid, ['sso_sub' => 'sub-001', 'status' => 'disabled']);
        $b = $this->h->browser();
        self::assertSame(403, $b->login()['callback']->status);
        self::assertFalse($b->loggedIn());
    }

    public function test_SSO_11_scope_default_dan_offline_access_hanya_bila_diaktifkan(): void
    {
        self::assertSame('openid profile email', $this->h->browser()->start()['params']['scope']);
        $h2 = new SsoHarness();
        $h2->sso['offline_access'] = true;
        self::assertSame('openid profile email offline_access', $h2->browser()->start()['params']['scope']);
    }

    public function test_redirect_uri_ketat_dari_APP_URL_bukan_dari_request(): void
    {
        $p = $this->h->browser()->start()['params'];
        self::assertSame('https://app.contoh.test/auth/sso/callback', $p['redirect_uri']);
        self::assertSame(FakeIdp::CLIENT_ID, $p['client_id']);
    }

    public function test_open_redirect_lewat_next_ditolak(): void
    {
        foreach (['//evil.test', '/\\evil.test', 'https://evil.test/x', '/auth/sso/login', "/ok\r\nSet-Cookie: x=1", 'javascript:alert(1)'] as $i => $next) {
            $b = $this->h->browser('198.51.100.' . $i);
            $r = $b->login(['sub' => 'sub-' . $i, 'email' => "u$i@contoh.test"], [], $next);
            self::assertSame('/', $r['callback']->headers['Location'] ?? null, "next=$next");
        }
        $b = $this->h->browser('198.51.100.99');
        $r = $b->login(['sub' => 'sub-ok', 'email' => 'ok@contoh.test'], [], '/laporan?bulan=1');
        self::assertSame('/laporan?bulan=1', $r['callback']->headers['Location']);
    }

    public function test_XSS_claim_name_dan_email_di_halaman_tautan_di_escape(): void
    {
        $this->h->a->user('admin@contoh.test', roles: ['admin']);
        $b = $this->h->browser();
        $r = $b->login(['email' => 'admin@contoh.test', 'name' => '<script>alert(1)</script><img src=x onerror=alert(2)>', 'sub' => 'sub-x']);
        self::assertSame(200, $r['callback']->status);
        self::assertStringNotContainsString('<script>alert(1)', $r['callback']->body);
        self::assertStringNotContainsString('<img src=x', $r['callback']->body);
        self::assertStringContainsString('&lt;script&gt;', $r['callback']->body);
    }

    public function test_XSS_claim_name_jit_tersimpan_aman_dan_karakter_kontrol_dibuang(): void
    {
        $b = $this->h->browser();
        $b->login(['name' => "Budi\x00\x1B[31m<b>x</b>"]);
        $u = $this->h->a->users()->findBySsoSub('sub-001');
        self::assertNotNull($u);
        self::assertDoesNotMatchRegularExpression('/[\x00-\x1F]/', $u->name);
    }

    public function test_email_tidak_terverifikasi_tidak_membuat_akun(): void
    {
        $b = $this->h->browser();
        $r = $b->login(['email_verified' => false]);
        self::assertSame(403, $r['callback']->status);
        self::assertSame(0, $this->userCount());
    }

    public function test_SSO_14_logout_lokal_lalu_redirect_ke_end_session_dengan_id_token_hint(): void
    {
        $b = $this->h->browser();
        $r = $b->login();
        self::assertTrue($b->loggedIn());
        $b->refreshCsrf();
        $res = $b->post('/logout');
        // 200 + Refresh (bukan 302): CSP form-action 'self' memblokir redirect lintas-origin dari POST di Chrome.
        self::assertSame(200, $res->status);
        self::assertStringStartsWith('0; url=', $res->headers['Refresh']);
        $loc = substr($res->headers['Refresh'], 7);
        self::assertStringContainsString('href="' . htmlspecialchars($loc, ENT_QUOTES) . '"', $res->body);
        self::assertStringStartsWith(FakeIdp::ISSUER . '/oauth2/bye?', $loc);
        parse_str((string) parse_url($loc, PHP_URL_QUERY), $q);
        self::assertSame($r['idToken'], $q['id_token_hint']);
        self::assertSame('https://app.contoh.test/auth/sso/signed-out', $q['post_logout_redirect_uri']);
        self::assertFalse($b->loggedIn(), 'sesi lokal hilang');
        self::assertSame(200, $b->get('/auth/sso/signed-out')->status);
    }

    public function test_SSO_16_logout_tanpa_csrf_ditolak(): void
    {
        $b = $this->h->browser();
        $b->login();
        $b->refreshCsrf();
        self::assertSame(419, $b->post('/logout', [], false)->status);
        self::assertTrue($b->loggedIn());
    }

    public function test_SSO_16_hanya_backchannel_tanpa_csrf(): void
    {
        $this->h->browser()->start();
        $router = $this->h->router;
        self::assertNotNull($router);
        $rows = [
            ['POST', '/auth/sso/backchannel', false], ['POST', '/auth/sso/link', true], ['POST', '/logout', true],
        ];
        foreach ($rows as [$m, $p, $csrf]) {
            $opts = $router->opts(new \bFramework\Core\Request($m, $p));
            self::assertNotNull($opts, $p);
            self::assertSame($csrf, $opts->csrf, $p);
        }
        $b = $this->h->browser('203.0.113.77');
        $b->get('/login');
        self::assertSame(419, $b->post('/auth/sso/link', [], false)->status);
    }

    public function test_SSO_19_ssrf_discovery_ke_ip_privat_ditolak(): void
    {
        $this->h->idp->ip = '10.0.0.5';
        $b = $this->h->browser();
        $res = $b->get('/login');
        $res = $b->get('/auth/sso/login');
        self::assertSame(503, $res->status);
        self::assertSame([], $this->h->idp->calls, 'tidak ada request keluar ke IP privat');
    }

    public function test_SSO_04_discovery_dengan_issuer_berbeda_ditolak_saat_login(): void
    {
        $this->h->idp->discoveryOverride = ['issuer' => 'https://sso-lain.test'];
        $b = $this->h->browser();
        $b->get('/login');
        self::assertSame(503, $b->get('/auth/sso/login')->status);
    }
}
