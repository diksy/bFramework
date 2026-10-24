<?php

declare(strict_types=1);

namespace bFramework\Tests\Integration;

use bFramework\Tests\Fixtures\FakeClock;
use bFramework\Tests\Fixtures\FakeIdp;
use bFramework\Tests\Fixtures\KernelApp;
use bFramework\Tests\Fixtures\KernelBrowser;
use PHPUnit\Framework\TestCase;

/** INT-08 (F13 SSO, F12 auth, F3 sesi): OIDC lewat index.php nyata; IdP palsu menggantikan HttpClient di server tes. */
final class SsoFlowTest extends TestCase
{
    private ?KernelApp $app = null;
    private FakeIdp $idp;

    protected function setUp(): void
    {
        $this->idp = new FakeIdp(new FakeClock(time()));
    }

    protected function tearDown(): void
    {
        $this->app?->destroy();
        $this->app = null;
    }

    private function boot(string $driver): KernelApp
    {
        $a = $this->app = KernelApp::installed();
        $a->useSso($driver, $this->idp);
        return $a;
    }

    /** @return array{params:array<string,string>,res:\bFramework\Tests\Fixtures\KernelResp} */
    private function start(KernelBrowser $b): array
    {
        $b->get('/login');
        $res = $b->get('/auth/sso/login');
        $params = [];
        parse_str((string) parse_url($res->location(), PHP_URL_QUERY), $params);
        /** @var array<string,string> $params */
        return ['params' => $params, 'res' => $res];
    }

    /** @param array<string,mixed> $claims */
    private function login(KernelApp $a, KernelBrowser $b, array $claims = []): \bFramework\Tests\Fixtures\KernelResp
    {
        $s = $this->start($b);
        $a->queueToken(['access_token' => 'at-1', 'token_type' => 'Bearer', 'expires_in' => 300, 'id_token' => $this->idp->idToken($s['params']['nonce'], $claims)]);
        return $b->get('/auth/sso/callback?code=kode-1&state=' . rawurlencode($s['params']['state']));
    }

    private function backchannel(KernelApp $a, string $token): \bFramework\Tests\Fixtures\KernelResp
    {
        return $a->send('POST', '/auth/sso/backchannel', ['logout_token' => $token], [], ['X-Int-Remote' => '198.51.100.77']);
    }

    private function authed(KernelBrowser $b): bool
    {
        $r = $b->get('/produk');
        return $r->status === 200;
    }

    public function test_INT_08a_login_oidc_pkce_jit_dan_sesi_lokal(): void
    {
        $a = $this->boot('bikinin_sso');
        $b = $a->browser('198.51.100.20');
        $s = $this->start($b);
        $p = $s['params'];
        self::assertSame(302, $s['res']->status);
        self::assertStringStartsWith('https://sso.contoh.test/oauth2/auth?', $s['res']->location());
        self::assertSame('code', $p['response_type']);
        self::assertSame('S256', $p['code_challenge_method']);
        self::assertSame(FakeIdp::CLIENT_ID, $p['client_id']);
        self::assertSame('https://app.contoh.test/auth/sso/callback', $p['redirect_uri']);
        self::assertGreaterThanOrEqual(32, strlen($p['state']));
        self::assertGreaterThanOrEqual(32, strlen($p['nonce']));
        self::assertArrayNotHasKey('client_secret', $p);
        self::assertStringNotContainsString(FakeIdp::SECRET, $s['res']->location());
        self::assertFalse($this->authed($b), 'belum login sebelum callback');

        $b = $a->browser('198.51.100.20');
        $cb = $this->login($a, $b);
        self::assertSame(302, $cb->status, substr(strip_tags($cb->body), 0, 200));
        self::assertTrue($this->authed($b));
        // Akun JIT dibuat dengan peran default, tanpa password.
        $u = $a->pdo()->query("SELECT email, status, password_hash, sso_sub FROM users WHERE email = 'budi@contoh.test'")->fetch(\PDO::FETCH_ASSOC);
        self::assertIsArray($u);
        self::assertSame('active', $u['status']);
        self::assertNull($u['password_hash']);
        self::assertSame('sub-001', $u['sso_sub']);
        self::assertSame(['staf'], $a->pdo()->query("SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id JOIN users u ON u.id = ur.user_id WHERE u.email = 'budi@contoh.test'")->fetchAll(\PDO::FETCH_COLUMN));
        // Panggilan keluar hanya ke IdP palsu (discovery, jwks, token).
        foreach ($a->idpCalls() as $c) {
            self::assertSame('sso.contoh.test', $c['host']);
        }
        // Mode SSO: tidak ada login/pemulihan lokal.
        $anon = $a->browser('198.51.100.21');
        self::assertSame(405, $anon->post('/login', ['email' => KernelApp::ADMIN_EMAIL, 'password' => KernelApp::PASSWORD], false)->status);
        foreach (['/auth/forgot', '/auth/register', '/auth/break-glass'] as $path) {
            self::assertSame(404, $anon->get($path)->status, $path);
        }
    }

    public function test_INT_08b_callback_tidak_sah_ditolak_tanpa_sesi(): void
    {
        $a = $this->boot('bikinin_sso');
        // state salah
        $b = $a->browser('198.51.100.22');
        $s = $this->start($b);
        $a->queueToken(['access_token' => 'x', 'token_type' => 'Bearer', 'expires_in' => 300, 'id_token' => $this->idp->idToken($s['params']['nonce'])]);
        $r = $b->get('/auth/sso/callback?code=k&state=' . str_repeat('a', 43));
        self::assertNotSame('/', $r->location(), 'state salah tidak boleh berujung login');
        self::assertFalse($this->authed($b));
        // nonce salah, audience salah, issuer salah, token kedaluwarsa, alg none
        $cases = [
            'nonce' => static fn(FakeIdp $i, string $n): string => $i->idToken('nonce-lain'),
            'aud' => static fn(FakeIdp $i, string $n): string => $i->idToken($n, ['aud' => 'app-lain']),
            'iss' => static fn(FakeIdp $i, string $n): string => $i->idToken($n, ['iss' => 'https://jahat.example']),
            'exp' => static fn(FakeIdp $i, string $n): string => $i->idToken($n, ['exp' => time() - 3600, 'iat' => time() - 7200]),
            'none' => static fn(FakeIdp $i, string $n): string => $i->forge('none', $i->claims(['nonce' => $n])),
            'hs256' => static fn(FakeIdp $i, string $n): string => $i->forge('HS256', $i->claims(['nonce' => $n]), FakeIdp::SECRET),
        ];
        $i = 30;
        foreach ($cases as $name => $make) {
            $br = $a->browser('198.51.100.' . $i++);
            $s = $this->start($br);
            $a->queueToken(['access_token' => 'x', 'token_type' => 'Bearer', 'expires_in' => 300, 'id_token' => $make($this->idp, $s['params']['nonce'])]);
            $br->get('/auth/sso/callback?code=k&state=' . rawurlencode($s['params']['state']));
            self::assertFalse($this->authed($br), "token $name harus ditolak");
        }
        self::assertSame(0, (int) $a->pdo()->query("SELECT COUNT(*) FROM users WHERE email = 'budi@contoh.test'")->fetchColumn(), 'tidak ada akun JIT dari token tak sah');
        // state sekali pakai: callback kedua dengan state yang sama gagal.
        $br = $a->browser('198.51.100.60');
        $s = $this->start($br);
        $tok = ['access_token' => 'x', 'token_type' => 'Bearer', 'expires_in' => 300, 'id_token' => $this->idp->idToken($s['params']['nonce'])];
        $a->queueToken($tok);
        $br->get('/auth/sso/callback?code=k&state=' . rawurlencode($s['params']['state']));
        self::assertTrue($this->authed($br));
        $br2 = $a->browser('198.51.100.61');
        $br2->cookies = [];
        $a->queueToken($tok);
        $br2->get('/auth/sso/callback?code=k&state=' . rawurlencode($s['params']['state']));
        self::assertFalse($this->authed($br2), 'state yang sama dari klien lain tak berlaku');
    }

    public function test_INT_08c_backchannel_logout_mencabut_sesi_lokal(): void
    {
        $a = $this->boot('bikinin_sso');
        $x = $a->browser('198.51.100.70');
        $y = $a->browser('198.51.100.71');
        $this->login($a, $x, ['sid' => 'sid-X']);
        $this->login($a, $y, ['sid' => 'sid-Y', 'sub' => 'sub-002', 'email' => 'dua@contoh.test']);
        self::assertTrue($this->authed($x));
        self::assertTrue($this->authed($y));
        $tok = $this->idp->logoutToken(['sid' => 'sid-X']);
        $r = $this->backchannel($a, $tok);
        self::assertSame(204, $r->status, $r->body);
        self::assertFalse($this->authed($x), 'sesi X dicabut');
        self::assertTrue($this->authed($y), 'sesi Y tetap');
        // Replay jti, tanda tangan palsu, claim salah, token tanpa events: ditolak, sesi Y tetap utuh.
        self::assertSame(400, $this->backchannel($a, $tok)->status);
        self::assertSame(400, $this->backchannel($a, $this->idp->forge('none', ['iss' => FakeIdp::ISSUER, 'aud' => FakeIdp::CLIENT_ID, 'sid' => 'sid-Y']))->status);
        self::assertSame(400, $this->backchannel($a, $this->idp->logoutToken(['sid' => 'sid-Y', 'aud' => 'lain']))->status);
        self::assertSame(400, $this->backchannel($a, $this->idp->logoutToken(['sid' => 'sid-Y', 'events' => null]))->status);
        self::assertSame(400, $this->backchannel($a, 'bukan-jwt')->status);
        self::assertTrue($this->authed($y));
        // Hanya sub: semua sesi user itu dicabut.
        self::assertSame(204, $this->backchannel($a, $this->idp->logoutToken(['sid' => null, 'sub' => 'sub-002']))->status);
        self::assertFalse($this->authed($y));
        self::assertSame(1, (int) $a->pdo()->query("SELECT COUNT(*) FROM users WHERE email = 'dua@contoh.test'")->fetchColumn(), 'akun tidak dihapus');
    }

    public function test_INT_08d_logout_lokal_mengakhiri_sesi_dan_mengarahkan_ke_idp(): void
    {
        $a = $this->boot('bikinin_sso');
        $b = $a->browser('198.51.100.72');
        $this->login($a, $b);
        $b->get('/produk');
        $out = $b->post('/logout');
        self::assertSame(200, $out->status);
        self::assertStringContainsString('https://sso.contoh.test/oauth2/bye', $out->header('refresh'));
        self::assertFalse($this->authed($b));
    }

    public function test_INT_08e_hybrid_break_glass_hanya_untuk_akun_bertanda(): void
    {
        $a = $this->app = KernelApp::installed(); // pengguna lokal dibuat sebelum beralih ke hybrid
        $uid = $a->newUser('darurat@contoh.test', ['admin']);
        $a->newUser('biasa@contoh.test', ['staf']);
        $a->useSso('hybrid', $this->idp);
        // Tanpa pengguna bertanda, break_glass menolak semua (juga admin instalasi).
        $b = $a->browser('198.51.100.73');
        $login = $b->get('/login');
        self::assertStringContainsString('/auth/sso/login', $login->body);
        self::assertStringNotContainsString('break-glass', $login->body, 'URL darurat tidak ditautkan');
        $b->get('/auth/break-glass');
        self::assertSame(401, $b->post('/auth/break-glass', ['email' => 'darurat@contoh.test', 'password' => KernelApp::PASSWORD])->status);
        $a->pdo()->exec('UPDATE users SET break_glass = 1 WHERE id = ' . $uid);
        $b = $a->browser('198.51.100.74');
        $b->get('/auth/break-glass');
        $ok = $b->post('/auth/break-glass', ['email' => 'darurat@contoh.test', 'password' => KernelApp::PASSWORD]);
        self::assertSame(302, $ok->status);
        self::assertTrue($this->authed($b));
        self::assertArrayNotHasKey('bf_remember', $ok->setCookies(), 'login darurat tanpa ingat-saya');
        self::assertArrayNotHasKey('__Host-bf_remember', $ok->setCookies());
        // Akun biasa dengan password benar tetap ditolak, pesan sama dengan akun tak ada.
        $c = $a->browser('198.51.100.75');
        $c->get('/auth/break-glass');
        $r1 = $c->post('/auth/break-glass', ['email' => 'biasa@contoh.test', 'password' => KernelApp::PASSWORD]);
        $c2 = $a->browser('198.51.100.76');
        $c2->get('/auth/break-glass');
        $r2 = $c2->post('/auth/break-glass', ['email' => 'hantu@contoh.test', 'password' => KernelApp::PASSWORD]);
        self::assertSame(401, $r1->status);
        self::assertSame($r2->status, $r1->status);
        self::assertFalse($this->authed($c));
        // SSO tetap berfungsi berdampingan.
        $d = $a->browser('198.51.100.77');
        self::assertSame(302, $this->login($a, $d)->status);
        self::assertTrue($this->authed($d));
    }

    public function test_INT_08f_driver_local_tidak_membuka_rute_sso(): void
    {
        $a = $this->app = KernelApp::installed();
        $b = $a->loggedIn();
        foreach (['/auth/sso/login', '/auth/sso/callback', '/auth/sso/signed-out', '/auth/sso/link'] as $p) {
            $r = $b->get($p);
            self::assertSame(404, $r->status, $p);
            self::assertSame([], $r->securityIssues());
        }
        self::assertSame(404, $a->send('POST', '/auth/sso/backchannel', ['logout_token' => 'x'], [], ['X-Int-Remote' => '198.51.100.78'])->status);
        self::assertSame(404, $b->post('/auth/sso/link')->status);
        self::assertSame([], $a->idpCalls());
        // Konfigurasi SSO tak lengkap/driver tak dikenal -> tetap local (fail-closed), login lokal berjalan.
        $a->mergeConfig(['auth' => ['driver' => 'ngawur']]);
        self::assertSame(404, $a->browser('198.51.100.79')->get('/auth/sso/login')->status);
        self::assertSame(302, $a->browser('198.51.100.80')->login(KernelApp::ADMIN_EMAIL, KernelApp::PASSWORD)->status);
    }
}
