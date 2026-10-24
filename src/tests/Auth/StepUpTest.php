<?php

declare(strict_types=1);

namespace bFramework\Tests\Auth;

use bFramework\Auth\StepUp;
use bFramework\Auth\Totp;
use bFramework\Tests\Fixtures\AuthBrowser;
use bFramework\Tests\Fixtures\AuthHarness;
use PHPUnit\Framework\TestCase;

/** SEC-3: S3 (step-up admin untuk sesi ingat-saya) dan S4 (perubahan 2FA butuh password, notifikasi, pencabutan). */
final class StepUpTest extends TestCase
{
    private AuthHarness $h;

    protected function setUp(): void
    {
        $this->h = new AuthHarness();
    }

    /** Peramban baru yang hanya memegang cookie ingat-saya (sesi dipulihkan: amr=['remember']). */
    private function rememberOnly(string $email, bool $totp = false): AuthBrowser
    {
        $uid = $this->h->user($email, roles: ['admin']);
        if ($totp) {
            $tf = $this->h->twofa();
            $secret = $tf->begin($uid);
            $tf->confirm($uid, Totp::code($secret, Totp::stepAt($this->h->clock->t)));
            $this->secret = $secret;
            // Cookie ingat-saya diterbitkan langsung (login ber-TOTP dilewati di tes ini).
            $token = $this->h->remember()->issue($uid);
        } else {
            $a = $this->h->browser('192.0.2.10');
            $a->login($email, remember: true);
            $token = $a->cookies['bf_remember'];
        }
        $b = $this->h->browser('192.0.2.11');
        $b->cookies = ['bf_remember' => $token];
        return $b;
    }

    private string $secret = '';

    private function code(): string
    {
        $this->h->clock->advance(30);
        return Totp::code($this->secret, Totp::stepAt($this->h->clock->t));
    }

    public function test_SEC3_S3_semua_rute_admin_GET_dan_POST_mengalihkan_sesi_ingat_saya_ke_step_up(): void
    {
        $b = $this->rememberOnly('admin@contoh.test');
        $get = ['/admin/pengguna', '/admin/pengguna/baru', '/admin/pengguna/1', '/admin/peran'];
        $post = ['/admin/pengguna', '/admin/pengguna/bersihkan', '/admin/pengguna/1', '/admin/pengguna/1/status',
            '/admin/pengguna/1/reset', '/admin/pengguna/1/hapus', '/admin/peran', '/admin/peran/1/hapus'];
        foreach ($get as $path) {
            $r = $b->get($path);
            self::assertSame(302, $r->status, $path);
            self::assertSame('/auth/step-up', $r->headers['Location'], $path);
        }
        // CSRF diambil dari halaman step-up.
        $b->get('/auth/step-up');
        foreach ($post as $path) {
            $r = $b->post($path, ['status' => 'disabled', 'name' => 'x', 'roles' => ['admin']]);
            self::assertSame('/auth/step-up', $r->headers['Location'] ?? '', $path);
        }
        self::assertSame(1, $this->rows('users'), 'tidak ada pengguna terhapus/dibuat');
    }

    private function rows(string $t): int
    {
        return (int) $this->h->conn->pdo()->query("SELECT COUNT(*) FROM $t")->fetchColumn();
    }

    public function test_SEC3_S3_step_up_sukses_membuka_admin_dan_kembali_ke_tujuan(): void
    {
        $b = $this->rememberOnly('admin@contoh.test');
        self::assertSame('/auth/step-up', $b->get('/admin/peran')->headers['Location']);
        self::assertSame(200, $b->get('/auth/step-up')->status);
        $r = $b->post('/auth/step-up', ['password' => AuthHarness::PASSWORD]);
        self::assertSame(302, $r->status);
        self::assertSame('/admin/peran', $r->headers['Location']);
        self::assertSame(200, $b->get('/admin/peran')->status);
        self::assertSame(200, $b->get('/admin/pengguna')->status);
    }

    public function test_SEC3_S3_step_up_gagal_pesan_generik_dan_tetap_ditolak(): void
    {
        $b = $this->rememberOnly('admin@contoh.test');
        $b->get('/admin/pengguna');
        $b->get('/auth/step-up');
        $r = $b->post('/auth/step-up', ['password' => 'salah-salah-salah']);
        self::assertSame(401, $r->status);
        self::assertStringContainsString('Password atau kode salah.', $r->body);
        self::assertSame('/auth/step-up', $b->get('/admin/pengguna')->headers['Location']);
    }

    public function test_SEC3_S3_step_up_dibatasi_laju_seperti_login(): void
    {
        $b = $this->rememberOnly('admin@contoh.test');
        $b->get('/auth/step-up');
        $last = 0;
        for ($i = 0; $i < 30; $i++) {
            $last = $b->post('/auth/step-up', ['password' => 'salah-salah-salah'])->status;
            if ($last === 429) {
                break;
            }
        }
        self::assertSame(429, $last);
    }

    public function test_SEC3_S3_step_up_kedaluwarsa_setelah_15_menit(): void
    {
        $b = $this->rememberOnly('admin@contoh.test');
        $b->get('/admin/pengguna');
        $b->get('/auth/step-up');
        $b->post('/auth/step-up', ['password' => AuthHarness::PASSWORD]);
        $this->h->clock->advance(StepUp::WINDOW);
        self::assertSame(200, $b->get('/admin/pengguna')->status, 'tepat 15 menit masih berlaku');
        $this->h->clock->advance(1);
        self::assertSame('/auth/step-up', $b->get('/admin/pengguna')->headers['Location']);
        self::assertSame('/auth/step-up', $b->post('/admin/pengguna/bersihkan')->headers['Location']);
    }

    public function test_SEC3_S3_akun_ber_totp_wajib_otp(): void
    {
        $b = $this->rememberOnly('admin@contoh.test', totp: true);
        self::assertSame('/auth/step-up', $b->get('/admin/pengguna')->headers['Location']);
        $page = $b->get('/auth/step-up');
        self::assertStringContainsString('name="code"', $page->body);
        // Password benar tanpa kode: ditolak.
        self::assertSame(401, $b->post('/auth/step-up', ['password' => AuthHarness::PASSWORD])->status);
        self::assertSame('/auth/step-up', $b->get('/admin/pengguna')->headers['Location']);
        // Kode salah.
        self::assertSame(401, $b->post('/auth/step-up', ['password' => AuthHarness::PASSWORD, 'code' => '000000'])->status);
        // Password salah dengan kode benar: ditolak.
        self::assertSame(401, $b->post('/auth/step-up', ['password' => 'salah-salah-salah', 'code' => $this->code()])->status);
        $ok = $b->post('/auth/step-up', ['password' => AuthHarness::PASSWORD, 'code' => $this->code()]);
        self::assertSame(302, $ok->status);
        self::assertSame('/admin/pengguna', $ok->headers['Location']);
        self::assertSame(200, $b->get('/admin/pengguna')->status);
    }

    public function test_SEC3_S3_login_segar_pwd_langsung_diterima_dan_ganti_peran_membersihkan_step_up(): void
    {
        $this->h->user('admin@contoh.test', roles: ['admin', 'staf']);
        $a = $this->h->browser();
        $a->login('admin@contoh.test');
        self::assertSame(200, $a->get('/admin/pengguna')->status);

        $uid = $this->h->accounts->findByEmail('rm@contoh.test')?->id ?? $this->h->user('rm@contoh.test', roles: ['admin', 'staf']);
        $r = $this->h->browser('192.0.2.30');
        $r->login('rm@contoh.test', remember: true);
        $b = $this->h->browser('192.0.2.31');
        $b->cookies = ['bf_remember' => $r->cookies['bf_remember']];
        $b->get('/admin/pengguna');
        $b->get('/auth/step-up');
        $b->post('/auth/step-up', ['password' => AuthHarness::PASSWORD]);
        self::assertSame(200, $b->get('/admin/pengguna')->status);
        // Ganti peran (regenerate sesi) menghapus status step-up.
        $b->post('/peran-aktif', ['role' => 'staf']);
        $b->get('/auth/forgot');
        $b->post('/peran-aktif', ['role' => 'admin']);
        self::assertSame('/auth/step-up', $b->get('/admin/pengguna')->headers['Location']);
        self::assertGreaterThan(0, $uid);
    }

    public function test_SEC3_S3_logout_dan_login_ulang_menghapus_step_up(): void
    {
        $b = $this->rememberOnly('admin@contoh.test');
        $b->get('/admin/pengguna');
        $b->get('/auth/step-up');
        $b->post('/auth/step-up', ['password' => AuthHarness::PASSWORD]);
        self::assertSame(200, $b->get('/admin/pengguna')->status);
        $b->post('/logout');
        self::assertSame('/login', $b->get('/admin/pengguna')->headers['Location']);
    }

    public function test_SEC3_S3_redirect_aman_next_hanya_jalur_internal_ter_whitelist(): void
    {
        foreach (['https://evil.test/', '//evil.test', '/admin/../etc', '/admin/pengguna?x=1', '/auth/2fa', '/admin/pengguna/abc', 'javascript:alert(1)', ''] as $bad) {
            self::assertNull(StepUp::safeNext($bad), $bad);
        }
        foreach (['/admin/pengguna', '/admin/pengguna/baru', '/admin/pengguna/12', '/admin/peran', '/admin/pembaruan'] as $good) {
            self::assertSame($good, StepUp::safeNext($good));
        }
        // POST ke rute admin: kembali ke daftar pengguna, bukan ke jalur POST.
        $b = $this->rememberOnly('admin@contoh.test');
        $b->get('/auth/step-up');
        $b->post('/admin/peran', ['name' => 'x']);
        $r = $b->post('/auth/step-up', ['password' => AuthHarness::PASSWORD]);
        self::assertSame('/admin/pengguna', $r->headers['Location']);
    }

    public function test_SEC3_S3_step_up_butuh_login_dan_csrf(): void
    {
        $anon = $this->h->browser();
        self::assertSame('/login', $anon->get('/auth/step-up')->headers['Location']);
        $b = $this->rememberOnly('admin@contoh.test');
        $b->get('/auth/step-up');
        self::assertSame(419, $b->post('/auth/step-up', ['password' => AuthHarness::PASSWORD], false)->status);
    }

    public function test_SEC3_S3_pengguna_non_admin_tidak_terpengaruh(): void
    {
        $this->h->user('staf@contoh.test', roles: ['staf']);
        $a = $this->h->browser('192.0.2.40');
        $a->login('staf@contoh.test', remember: true);
        $b = $this->h->browser('192.0.2.41');
        $b->cookies = ['bf_remember' => $a->cookies['bf_remember']];
        self::assertSame(403, $b->get('/admin/pengguna')->status, 'non-admin tetap 403, bukan step-up');
        self::assertSame(200, $b->get('/auth/forgot')->status);
    }

    // ---------- S4 ----------

    public function test_SEC3_S4_begin_dan_confirm_tanpa_password_ditolak(): void
    {
        $uid = $this->h->user('ada@contoh.test');
        $b = $this->h->browser();
        $b->login('ada@contoh.test');
        $b->get('/auth/2fa');
        self::assertSame(401, $b->post('/auth/2fa/begin')->status);
        self::assertSame(401, $b->post('/auth/2fa/begin', ['password' => 'salah-salah-salah'])->status);
        self::assertNull($this->h->accounts->find($uid)?->totpSealed, 'tidak ada secret terdaftar');

        $begin = $b->post('/auth/2fa/begin', ['password' => AuthHarness::PASSWORD]);
        self::assertSame(200, $begin->status);
        $secret = (string) $this->h->twofa()->pendingSecret($this->h->accounts->find($uid) ?? throw new \RuntimeException());
        $this->h->clock->advance(30);
        $code = Totp::code($secret, Totp::stepAt($this->h->clock->t));
        self::assertSame(401, $b->post('/auth/2fa/confirm', ['code' => $code])->status);
        self::assertSame(401, $b->post('/auth/2fa/confirm', ['code' => $code, 'password' => 'salah-salah-salah'])->status);
        self::assertFalse($this->h->accounts->find($uid)?->totpEnabled);
        self::assertSame(200, $b->post('/auth/2fa/confirm', ['code' => $code, 'password' => AuthHarness::PASSWORD])->status);
        self::assertTrue($this->h->accounts->find($uid)?->totpEnabled);
    }

    public function test_SEC3_S4_nonaktifkan_butuh_password_dan_otp_lama(): void
    {
        $uid = $this->h->user('ada@contoh.test');
        $tf = $this->h->twofa();
        $secret = $tf->begin($uid);
        $tf->confirm($uid, Totp::code($secret, Totp::stepAt($this->h->clock->t)));
        $this->secret = $secret;
        $b = $this->h->browser();
        $b->get('/login');
        $b->post('/login', ['email' => 'ada@contoh.test', 'password' => AuthHarness::PASSWORD]);
        $b->get('/auth/otp');
        $this->h->clock->advance(30);
        $b->post('/auth/otp', ['code' => Totp::code($secret, Totp::stepAt($this->h->clock->t))]);
        $b->get('/auth/2fa');
        self::assertSame(401, $b->post('/auth/2fa/disable', ['password' => AuthHarness::PASSWORD])->status);
        self::assertSame(401, $b->post('/auth/2fa/disable', ['code' => $this->code()])->status);
        self::assertTrue($this->h->accounts->find($uid)?->totpEnabled);
    }

    public function test_SEC3_S4_perubahan_2fa_mengirim_email_dan_mencabut_ingat_saya_dan_sesi_lain(): void
    {
        $uid = $this->h->user('ada@contoh.test');
        $dev = $this->h->browser('192.0.2.60');
        $dev->login('ada@contoh.test', remember: true);
        $other = $this->h->browser('192.0.2.61');
        $other->login('ada@contoh.test');
        $this->h->clock->advance(5);
        self::assertGreaterThan(0, $this->rows('remember_tokens'));
        self::assertSame(200, $other->get('/auth/2fa')->status);

        $b = $this->h->browser('192.0.2.62');
        $b->login('ada@contoh.test');
        $b->get('/auth/2fa');
        $begin = $b->post('/auth/2fa/begin', ['password' => AuthHarness::PASSWORD]);
        self::assertSame(1, preg_match('/Kunci: ([A-Z2-7]+)/', $begin->body, $m));
        $this->secret = $m[1];
        $this->h->clock->advance(30);
        $sent = count($this->h->mail->sent);
        $ok = $b->post('/auth/2fa/confirm', ['code' => Totp::code($this->secret, Totp::stepAt($this->h->clock->t)), 'password' => AuthHarness::PASSWORD]);
        self::assertSame(200, $ok->status);
        $this->h->deferred->run();
        self::assertCount($sent + 1, $this->h->mail->sent);
        $mail = end($this->h->mail->sent);
        self::assertSame('ada@contoh.test', $mail->to);
        self::assertStringContainsString('diaktifkan', $mail->body);
        self::assertStringNotContainsString($this->secret, $mail->body);
        self::assertSame(0, $this->rows('remember_tokens'), 'token ingat-saya dicabut');
        self::assertSame(200, $b->get('/auth/2fa')->status, 'sesi saat ini tetap hidup');
        self::assertSame('/login', $other->get('/auth/2fa')->headers['Location'], 'sesi lain dicabut');

        // Nonaktifkan: email lagi + pencabutan.
        $dev2 = $this->h->browser('192.0.2.63');
        $this->h->remember()->issue($uid);
        self::assertSame(1, $this->rows('remember_tokens'));
        $this->h->clock->advance(30);
        $r = $b->post('/auth/2fa/disable', ['password' => AuthHarness::PASSWORD, 'code' => $this->code()]);
        self::assertSame(302, $r->status);
        $this->h->deferred->run();
        self::assertCount($sent + 2, $this->h->mail->sent);
        self::assertStringContainsString('dinonaktifkan', end($this->h->mail->sent)->body);
        self::assertSame(0, $this->rows('remember_tokens'));
        self::assertNotNull($dev2);
    }
}
