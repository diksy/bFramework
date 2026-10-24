<?php

declare(strict_types=1);

namespace bFramework\Tests\Auth;

use bFramework\Auth\NewUser;
use bFramework\Auth\RoleStore;
use bFramework\Auth\RuleViolation;
use bFramework\Core\FileSessionStore;
use bFramework\Runtime\CurrentIdentity;
use bFramework\Contracts\Identity;
use bFramework\Tests\Fixtures\AuthBrowser;
use bFramework\Tests\Fixtures\AuthHarness;
use PHPUnit\Framework\TestCase;

/** M11 (F16): administrasi pengguna & peran, ganti peran aktif. Hanya data dummy. */
final class AdminTest extends TestCase
{
    private AuthHarness $h;

    protected function setUp(): void
    {
        $this->h = new AuthHarness();
    }

    private function adminBrowser(string $email = 'admin@contoh.test'): AuthBrowser
    {
        $this->h->user($email, roles: ['admin']);
        $b = $this->h->browser();
        $b->login($email);
        $b->get('/admin/pengguna');
        return $b;
    }

    private function hashOf(int $id): string
    {
        $st = $this->h->conn->pdo()->prepare('SELECT password_hash FROM users WHERE id = ?');
        $st->execute([$id]);
        return (string) $st->fetchColumn();
    }

    public function test_SEC_AUTHZ_01_anonim_diarahkan_ke_login_dan_post_tanpa_csrf_419(): void
    {
        $b = $this->h->browser();
        $res = $b->get('/admin/pengguna');
        self::assertSame(302, $res->status);
        self::assertSame('/login', $res->headers['Location']);
        self::assertSame(302, $b->get('/admin/peran')->status);
        self::assertSame(419, $b->post('/admin/pengguna', ['email' => 'x@contoh.test'], false)->status);
    }

    public function test_SEC_AUTHZ_01_peran_biasa_ditolak_403_di_semua_rute_admin(): void
    {
        $id = $this->h->user('staf@contoh.test', roles: ['staf']);
        $target = $this->h->user('lain@contoh.test', roles: ['staf']);
        $b = $this->h->browser();
        $b->login('staf@contoh.test');
        $b->get('/'); // memastikan sesi ada
        $b->csrf = $this->csrfFrom($b);
        foreach (['/admin/pengguna', '/admin/pengguna/baru', '/admin/pengguna/' . $target, '/admin/peran'] as $path) {
            self::assertSame(403, $b->get($path)->status, $path);
        }
        // IDOR/eskalasi lewat POST langsung ke objek lain, tombol tersembunyi tidak relevan.
        foreach ([
            ['/admin/pengguna/' . $target, ['name' => 'X', 'roles' => ['admin']]],
            ['/admin/pengguna/' . $id, ['name' => 'X', 'roles' => ['admin']]],
            ['/admin/pengguna/' . $target . '/status', ['status' => 'disabled']],
            ['/admin/pengguna/' . $target . '/reset', []],
            ['/admin/pengguna/' . $target . '/hapus', []],
            ['/admin/pengguna', ['email' => 'baru@contoh.test', 'name' => 'B', 'roles' => ['admin']]],
            ['/admin/peran', ['name' => 'baru']],
        ] as [$path, $data]) {
            self::assertSame(403, $b->post($path, $data)->status, $path);
        }
        self::assertSame(['staf'], $this->h->users()->roles($id));
        self::assertNull($this->h->users()->findByEmail('baru@contoh.test'));
    }

    private function csrfFrom(AuthBrowser $b): string
    {
        // Token CSRF sesi tampil di halaman yang memakai layout; untuk staf pakai halaman login bila perlu.
        $res = $b->get('/auth/forgot');
        preg_match('/name="_csrf" value="([a-f0-9]{64})"/', $res->body, $m);
        return $m[1] ?? $b->csrf;
    }

    public function test_SEC_AUTHZ_01_admin_melihat_daftar_dan_id_tidak_ada_404(): void
    {
        $b = $this->adminBrowser();
        $this->h->user('budi@contoh.test', roles: ['staf']);
        $res = $b->get('/admin/pengguna');
        self::assertSame(200, $res->status);
        self::assertStringContainsString('budi@contoh.test', $res->body);
        self::assertSame(404, $b->get('/admin/pengguna/99999')->status);
        self::assertSame(404, $b->get('/admin/pengguna/abc')->status);
        self::assertSame(404, $b->get('/admin/pengguna/0')->status);
        self::assertSame(404, $b->post('/admin/pengguna/99999/hapus')->status);
    }

    public function test_AUTH_01_hash_tidak_bocor_di_toArray_dump_html_dan_log(): void
    {
        $b = $this->adminBrowser();
        $uid = $this->h->user('budi@contoh.test', roles: ['staf']);
        $hash = $this->hashOf($uid);
        self::assertNotSame('', $hash);
        $user = $this->h->users()->find($uid);
        self::assertNotNull($user);
        $flat = json_encode($user->toArray()) . var_export($user, true) . print_r($user, true);
        self::assertStringNotContainsString($hash, $flat);
        self::assertArrayNotHasKey('password_hash', $user->toArray());
        self::assertArrayNotHasKey('passwordHash', $user->toArray());
        $html = $b->get('/admin/pengguna')->body . $b->get('/admin/pengguna/' . $uid)->body;
        self::assertStringNotContainsString($hash, $html);
        self::assertStringNotContainsString('argon', $html);
        $b->post('/admin/pengguna/' . $uid, ['name' => 'Budi', 'roles' => ['staf', 'admin']]);
        self::assertStringNotContainsString($hash, $this->h->logger->all());
        self::assertStringNotContainsString('budi@contoh.test', $this->h->logger->all());
    }

    public function test_SEC_DATA_02_mass_assignment_pada_pembuatan_dan_ubah(): void
    {
        $b = $this->adminBrowser();
        $b->post('/admin/pengguna', [
            'email' => 'Baru@Contoh.test', 'name' => 'Baru', 'roles' => ['staf', 'tidak-ada'],
            'status' => 'active', 'password_hash' => 'sembarang', 'password' => 'abc', 'id' => '1', 'sso_sub' => 'x', 'break_glass' => '1',
            'email_verified_at' => '1', 'totp_enabled' => '1',
        ]);
        $u = $this->h->users()->findByEmail('baru@contoh.test');
        self::assertNotNull($u);
        self::assertSame('pending', $u->status);
        self::assertSame(['staf'], $u->roles);
        self::assertNull($u->ssoSub);
        self::assertFalse($u->breakGlass);
        self::assertNull($u->emailVerifiedAt);
        self::assertFalse($u->totpEnabled);
        self::assertSame('', $this->hashOf($u->id));
        self::assertGreaterThan(1, $u->id);

        // Ubah: hanya nama dan peran yang berlaku.
        $b->post('/admin/pengguna/' . $u->id, [
            'name' => 'Nama Baru', 'roles' => ['staf'], 'status' => 'disabled', 'email' => 'x@contoh.test',
            'password_hash' => 'sembarang', 'sso_sub' => 'x',
        ]);
        $after = $this->h->users()->find($u->id);
        self::assertNotNull($after);
        self::assertSame('Nama Baru', $after->name);
        self::assertSame('pending', $after->status);
        self::assertSame('baru@contoh.test', $after->email);
        self::assertSame('', $this->hashOf($u->id));
    }

    public function test_SEC_DATA_02_store_menolak_kolom_di_luar_whitelist(): void
    {
        $uid = $this->h->user('budi@contoh.test');
        foreach (['password_hash', 'totp_secret', 'break_glass', 'id', 'recovery_codes', 'pw_changed_at'] as $col) {
            try {
                $this->h->users()->update($uid, [$col => 'x']);
                self::fail("kolom $col lolos");
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
        $this->expectException(\InvalidArgumentException::class);
        $this->h->users()->create(new NewUser('z@contoh.test', 'Z', null, 'pending', null, ['peran-gaib']));
    }

    public function test_SEC_REQ_01_semua_aksi_admin_butuh_csrf(): void
    {
        $b = $this->adminBrowser();
        $uid = $this->h->user('budi@contoh.test', roles: ['staf']);
        $b->get('/admin/pengguna');
        foreach ([
            '/admin/pengguna', '/admin/pengguna/' . $uid, '/admin/pengguna/' . $uid . '/status', '/admin/pengguna/' . $uid . '/reset',
            '/admin/pengguna/' . $uid . '/hapus', '/admin/pengguna/bersihkan', '/admin/peran', '/admin/peran/1/hapus', '/peran-aktif',
        ] as $path) {
            self::assertSame(419, $b->post($path, ['role' => 'staf'], false)->status, $path);
            self::assertSame(419, $b->post($path, ['_csrf' => str_repeat('a', 64)], false)->status, $path . ' token salah');
        }
        self::assertNotNull($this->h->users()->find($uid));
    }

    public function test_AUTH_01_admin_terakhir_tidak_bisa_dicabut_dinonaktifkan_atau_dihapus(): void
    {
        $adminId = $this->h->user('admin@contoh.test', roles: ['admin']);
        $store = $this->h->users();
        foreach ([
            fn() => $store->setRoles($adminId, ['staf']),
            fn() => $store->update($adminId, ['status' => 'disabled']),
            fn() => $store->delete($adminId),
        ] as $op) {
            try {
                $op();
                self::fail('admin terakhir lolos');
            } catch (RuleViolation) {
                self::assertTrue(true);
            }
        }
        $u = $store->find($adminId);
        self::assertNotNull($u);
        self::assertSame(['admin'], $u->roles);
        self::assertSame('active', $u->status);

        // Admin kedua yang nonaktif tidak dihitung.
        $second = $this->h->user('dua@contoh.test', roles: ['admin'], status: 'disabled');
        try {
            $store->setRoles($adminId, ['staf']);
            self::fail('admin nonaktif tidak boleh dianggap pengganti');
        } catch (RuleViolation) {
            self::assertNotNull($store->find($second));
        }
        // Dengan admin aktif lain, pencabutan diizinkan.
        $store->update($second, ['status' => 'active']);
        $store->setRoles($adminId, ['staf']);
        self::assertSame(['staf'], $store->roles($adminId));
        // Sekarang $second adalah satu-satunya admin aktif.
        $this->expectException(RuleViolation::class);
        $store->delete($second);
    }

    public function test_AUTH_01_lewat_halaman_admin_terakhir_dan_diri_sendiri_dilindungi(): void
    {
        $b = $this->adminBrowser();
        $me = $this->h->users()->findByEmail('admin@contoh.test');
        self::assertNotNull($me);
        $b->post('/admin/pengguna/' . $me->id, ['name' => 'Admin', 'roles' => ['staf']]);
        self::assertSame(['admin'], $this->h->users()->roles($me->id));
        self::assertStringContainsString('Admin terakhir', $b->get('/admin/pengguna/' . $me->id)->body);
        $b->post('/admin/pengguna/' . $me->id . '/status', ['status' => 'disabled']);
        $b->post('/admin/pengguna/' . $me->id . '/hapus');
        $u = $this->h->users()->find($me->id);
        self::assertNotNull($u);
        self::assertSame('active', $u->status);
        // Tanpa peran sama sekali juga ditolak oleh form.
        $b->post('/admin/pengguna/' . $me->id, ['name' => 'Admin']);
        self::assertSame(['admin'], $this->h->users()->roles($me->id));
    }

    public function test_AUTH_01_peran_sistem_dan_peran_terpakai_tidak_bisa_dihapus_nama_dicek(): void
    {
        $roles = new RoleStore($this->h->conn);
        foreach (['admin', 'staf'] as $n) {
            $r = $roles->findByName($n);
            self::assertNotNull($r);
            try {
                $roles->delete($r->id);
                self::fail("peran sistem $n terhapus");
            } catch (RuleViolation) {
                self::assertNotNull($roles->findByName($n));
            }
        }
        $kasir = $roles->create('kasir', 'Kasir');
        $uid = $this->h->user('k@contoh.test', roles: ['kasir']);
        try {
            $roles->delete($kasir->id);
            self::fail('peran terpakai terhapus');
        } catch (RuleViolation) {
            self::assertNotNull($roles->findByName('kasir'));
        }
        $this->h->users()->setRoles($uid, ['staf']);
        $roles->delete($kasir->id);
        self::assertNull($roles->findByName('kasir'));
        foreach (['', 'A', 'Admin', '1abc', 'a b', "x\n", str_repeat('a', 40), 'admin'] as $bad) {
            try {
                $roles->create($bad);
                self::fail("nama '$bad' lolos");
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }

    public function test_F16_admin_membuat_dan_menghapus_peran_lewat_halaman(): void
    {
        $b = $this->adminBrowser();
        $b->post('/admin/peran', ['name' => 'kasir', 'label' => '<b>Kasir</b>']);
        $res = $b->get('/admin/peran');
        self::assertStringContainsString('kasir', $res->body);
        self::assertStringNotContainsString('<b>Kasir</b>', $res->body, 'label di-escape');
        $role = (new RoleStore($this->h->conn))->findByName('kasir');
        self::assertNotNull($role);
        $b->post('/admin/peran/' . $role->id . '/hapus');
        self::assertNull((new RoleStore($this->h->conn))->findByName('kasir'));
        $sys = (new RoleStore($this->h->conn))->findByName('admin');
        self::assertNotNull($sys);
        $b->post('/admin/peran/' . $sys->id . '/hapus');
        self::assertNotNull((new RoleStore($this->h->conn))->findByName('admin'));
    }

    public function test_SEC_SESS_02_ganti_peran_meregenerasi_sesi_dan_memutar_csrf(): void
    {
        $this->h->user('multi@contoh.test', roles: ['admin', 'staf']);
        $b = $this->h->browser();
        $b->login('multi@contoh.test');
        $b->get('/admin/pengguna');
        $sidBefore = $b->sessionCookie();
        $csrfBefore = $b->csrf;
        self::assertNotNull($sidBefore);
        $res = $b->post('/peran-aktif', ['role' => 'staf']);
        self::assertSame(302, $res->status);
        self::assertNotSame($sidBefore, $b->sessionCookie());
        $id = $this->identity($b);
        self::assertSame('staf', $id->activeRole);
        // Token CSRF lama tidak berlaku lagi.
        self::assertSame(419, $b->post('/peran-aktif', ['role' => 'admin', '_csrf' => $csrfBefore], false)->status);
        // Sebagai staf, halaman admin tertutup (hanya peran aktif dihitung).
        self::assertSame(403, $b->get('/admin/pengguna')->status);
        $b->get('/auth/forgot');
        $b->post('/peran-aktif', ['role' => 'admin']);
        self::assertSame('admin', $this->identity($b)->activeRole);
        self::assertSame(200, $b->get('/admin/pengguna')->status);
        self::assertStringContainsString('Ganti peran aktif', $b->get('/admin/pengguna')->body);
    }

    public function test_SEC_AUTHZ_01_ganti_ke_peran_tak_dimiliki_ditolak(): void
    {
        $this->h->user('staf@contoh.test', roles: ['staf']);
        $b = $this->h->browser();
        $b->login('staf@contoh.test');
        $b->get('/auth/forgot');
        $sid = $b->sessionCookie();
        foreach (['admin', 'tidak-ada', '', 'staf ', 'ADMIN'] as $role) {
            self::assertSame(403, $b->post('/peran-aktif', ['role' => $role])->status, "'$role'");
        }
        self::assertSame(403, $b->post('/peran-aktif', ['role' => ['admin']])->status);
        self::assertSame(403, $b->post('/peran-aktif', [])->status);
        self::assertSame('staf', $this->identity($b)->activeRole);
        self::assertSame($sid, $b->sessionCookie(), 'tidak ada regenerasi untuk permintaan yang ditolak');
        self::assertSame(403, $b->get('/admin/pengguna')->status);
        // Anonim
        $anon = $this->h->browser('198.51.100.9');
        $anon->get('/auth/forgot');
        self::assertSame(302, $anon->post('/peran-aktif', ['role' => 'admin'])->status);
    }

    public function test_F16_identitas_sesi_dengan_peran_aktif_di_luar_peran_ditolak(): void
    {
        $store = new FileSessionStore($this->h->dir . '/sessions', false, 1800, 28800, [], static function (): void {
        }, $this->h->clock);
        $ci = new CurrentIdentity($store);
        try {
            $ci->set(new Identity(1, ['staf'], 'admin'));
            self::fail('set lolos');
        } catch (\InvalidArgumentException) {
            self::assertNull($ci->get());
        }
        $store->start();
        $store->set('_identity', ['userId' => 1, 'roles' => ['staf'], 'activeRole' => 'admin', 'amr' => ['pwd'], 'ssoSid' => null]);
        self::assertNull($ci->get(), 'sesi hasil rekayasa tidak menjadi identitas');
    }

    public function test_F16_peran_dicabut_saat_login_menurunkan_peran_aktif_di_request_berikutnya(): void
    {
        $uid = $this->h->user('multi@contoh.test', roles: ['admin', 'staf']);
        $this->h->user('admin2@contoh.test', roles: ['admin']);
        $b = $this->h->browser();
        $b->login('multi@contoh.test');
        self::assertSame(200, $b->get('/admin/pengguna')->status);
        $this->h->users()->setRoles($uid, ['staf']);
        self::assertSame(403, $b->get('/admin/pengguna')->status);
        self::assertSame('staf', $this->identity($b)->activeRole);
    }

    public function test_AUTH_05_penonaktifan_mencabut_sesi_ingat_saya_dan_token(): void
    {
        $victim = $this->h->user('korban@contoh.test', roles: ['staf']);
        $v = $this->h->browser('192.0.2.50');
        $v->login('korban@contoh.test', remember: true);
        $rememberCookies = $v->cookies;
        self::assertSame(200, $v->get('/auth/forgot')->status);
        $this->h->tokens()->issue($victim, 'reset');

        $a = $this->adminBrowser();
        $a->post('/admin/pengguna/' . $victim . '/status', ['status' => 'disabled']);
        $u = $this->h->users()->find($victim);
        self::assertNotNull($u);
        self::assertSame('disabled', $u->status);

        // Sesi lama mati pada request berikutnya (identitas divalidasi ulang ke database).
        $v->get('/auth/forgot');
        self::assertNull($this->identity($v, false));
        self::assertSame(302, $v->get('/admin/pengguna')->status);
        // Cookie ingat-saya tidak memulihkan sesi.
        $fresh = $this->h->browser('192.0.2.51');
        $fresh->cookies = array_diff_key($rememberCookies, ['bf_sid' => 1]);
        $fresh->get('/auth/forgot');
        self::assertNull($this->identity($fresh, false));
        $cnt = $this->h->conn->pdo()->query('SELECT COUNT(*) FROM remember_tokens WHERE user_id = ' . $victim)?->fetchColumn();
        self::assertSame(0, (int) $cnt);
        $cnt = $this->h->conn->pdo()->query('SELECT COUNT(*) FROM one_time_tokens WHERE user_id = ' . $victim)?->fetchColumn();
        self::assertSame(0, (int) $cnt);
        // Login ulang ditolak; setelah diaktifkan lagi sesi lama tetap mati.
        self::assertSame(401, $this->h->browser('192.0.2.52')->login('korban@contoh.test')->status);
        $a->post('/admin/pengguna/' . $victim . '/status', ['status' => 'active']);
        $v->get('/auth/forgot');
        self::assertNull($this->identity($v, false));
    }

    public function test_AUTH_05_reset_oleh_admin_hanya_lewat_tautan_sekali_pakai(): void
    {
        $b = $this->adminBrowser();
        $uid = $this->h->user('budi@contoh.test', roles: ['staf']);
        $hash = $this->hashOf($uid);
        $res = $b->post('/admin/pengguna/' . $uid . '/reset');
        self::assertSame(302, $res->status);
        $page = $b->get('/admin/pengguna/' . $uid)->body;
        $this->h->deferred->run();
        self::assertCount(1, $this->h->mail->sent);
        self::assertSame('budi@contoh.test', $this->h->mail->sent[0]->to);
        $token = $this->h->mail->lastToken();
        self::assertStringNotContainsString($token, $page . $res->body);
        self::assertStringNotContainsString($token, $this->h->logger->all());
        self::assertSame($hash, $this->hashOf($uid), 'admin tidak mengubah password');
        self::assertSame($uid, $this->h->tokens()->consume($token, 'reset'));
        self::assertNull($this->h->tokens()->consume($token, 'reset'), 'sekali pakai');
        // Akun nonaktif tidak dapat direset.
        $b->post('/admin/pengguna/' . $uid . '/status', ['status' => 'disabled']);
        $b->post('/admin/pengguna/' . $uid . '/reset');
        $this->h->deferred->run();
        self::assertCount(1, $this->h->mail->sent);
    }

    public function test_F16_undangan_pengguna_baru_lewat_tautan_email(): void
    {
        $b = $this->adminBrowser();
        $b->post('/admin/pengguna', ['email' => 'baru@contoh.test', 'name' => 'Baru', 'roles' => ['staf']]);
        $this->h->deferred->run();
        self::assertCount(1, $this->h->mail->sent);
        self::assertSame('baru@contoh.test', $this->h->mail->sent[0]->to);
        self::assertStringStartsWith('https://app.contoh.test/auth/reset/', strstr($this->h->mail->sent[0]->body, 'https://') ?: '');
        // Email ganda ditolak tanpa membuat akun kedua.
        $b->post('/admin/pengguna', ['email' => 'BARU@contoh.test', 'name' => 'Lagi', 'roles' => ['staf']]);
        self::assertSame(2, $this->h->users()->count());
    }

    public function test_AUTH_01_audit_perubahan_peran_tanpa_data_sensitif(): void
    {
        $b = $this->adminBrowser();
        $uid = $this->h->user('budi@contoh.test', roles: ['staf']);
        $b->post('/admin/pengguna/' . $uid, ['name' => 'Budi Rahasia', 'roles' => ['staf', 'admin']]);
        $log = $this->h->logger->all();
        self::assertStringContainsString('audit: Peran pengguna diubah', $log);
        self::assertStringContainsString('"added":"admin"', $log);
        self::assertStringNotContainsString('budi@contoh.test', $log);
        self::assertStringNotContainsString('Budi Rahasia', $log);
        self::assertStringNotContainsString($this->hashOf($uid), $log);
    }

    public function test_AUTH_08_pembersihan_akun_pending_kedaluwarsa_tidak_menyentuh_akun_lain(): void
    {
        $store = $this->h->users();
        $oldPending = $this->h->user('lama@contoh.test', roles: ['staf'], status: 'pending');
        $activeOld = $this->h->user('aktif@contoh.test', roles: ['staf']);
        $disabled = $this->h->user('off@contoh.test', roles: ['staf'], status: 'disabled');
        $this->h->tokens()->issue($oldPending, 'verify_email');
        $this->h->clock->advance(5 * 86400);
        $freshPending = $this->h->user('baru@contoh.test', roles: ['staf'], status: 'pending');
        $this->h->clock->advance(3 * 86400);
        self::assertSame(1, $store->purgeExpiredPending(7 * 86400));
        self::assertNull($store->find($oldPending));
        self::assertNotNull($store->find($activeOld));
        self::assertNotNull($store->find($disabled));
        self::assertNotNull($store->find($freshPending));
        $q = $this->h->conn->pdo();
        self::assertSame(0, (int) $q->query('SELECT COUNT(*) FROM user_roles WHERE user_id = ' . $oldPending)?->fetchColumn());
        self::assertSame(0, (int) $q->query('SELECT COUNT(*) FROM one_time_tokens WHERE user_id = ' . $oldPending)?->fetchColumn());
        self::assertSame(0, $store->purgeExpiredPending(7 * 86400), 'idempoten');
    }

    public function test_AUTH_08_tombol_admin_pembersihan(): void
    {
        $b = $this->adminBrowser();
        $old = $this->h->user('lama@contoh.test', roles: ['staf'], status: 'pending');
        $this->h->conn->pdo()->exec('UPDATE users SET created_at = created_at - 864000 WHERE id = ' . $old);
        $b->post('/admin/pengguna/bersihkan');
        self::assertNull($this->h->users()->find($old));
        self::assertNotNull($this->h->users()->findByEmail('admin@contoh.test'));
    }

    public function test_SEC_OUT_01_nama_dan_email_di_halaman_admin_di_escape(): void
    {
        $b = $this->adminBrowser();
        $uid = $this->h->users()->create(new NewUser('xss@contoh.test', '<script>alert(1)</script>', null, 'active', null, ['staf']))->id;
        $body = $b->get('/admin/pengguna')->body . $b->get('/admin/pengguna/' . $uid)->body;
        self::assertStringNotContainsString('<script>alert(1)</script>', $body);
        self::assertStringContainsString('&lt;script&gt;', $body);
    }

    public function test_SEC_AUTHZ_01_hapus_pengguna_lain_dan_dependensinya(): void
    {
        $b = $this->adminBrowser();
        $uid = $this->h->user('budi@contoh.test', roles: ['staf']);
        $b->post('/admin/pengguna/' . $uid . '/hapus');
        self::assertNull($this->h->users()->find($uid));
        self::assertSame(0, (int) $this->h->conn->pdo()->query('SELECT COUNT(*) FROM user_roles WHERE user_id = ' . $uid)?->fetchColumn());
    }

    private function identity(AuthBrowser $b, bool $required = true): ?Identity
    {
        $sid = $b->sessionCookie();
        $store = new FileSessionStore($this->h->dir . '/sessions', false, 1800, 28800, $sid === null ? [] : ['bf_sid' => $sid], static function (): void {
        }, $this->h->clock);
        $id = (new CurrentIdentity($store))->get();
        if ($required) {
            self::assertNotNull($id);
            return $id;
        }
        return $id;
    }
}
