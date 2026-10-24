<?php

declare(strict_types=1);

namespace bFramework\Tests\Auth;

use bFramework\Auth\SecretVault;
use bFramework\Auth\Totp;
use bFramework\Tests\Fixtures\AuthHarness;
use PHPUnit\Framework\TestCase;

final class TotpTest extends TestCase
{
    private const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // "12345678901234567890"

    private AuthHarness $h;

    protected function setUp(): void
    {
        $this->h = new AuthHarness();
    }

    public function test_AUTH_07_vektor_rfc6238(): void
    {
        // RFC 6238 Appendix B (SHA-1), 6 digit terakhir dari kode 8 digit.
        foreach ([59 => '287082', 1111111109 => '081804', 1111111111 => '050471', 1234567890 => '005924', 2000000000 => '279037'] as $t => $code) {
            self::assertSame($code, Totp::code(self::RFC_SECRET, Totp::stepAt($t)));
            self::assertTrue(Totp::verify(self::RFC_SECRET, $code, $t));
        }
        self::assertFalse(Totp::verify(self::RFC_SECRET, '000000', 59));
        self::assertFalse(Totp::verify(self::RFC_SECRET, '12345', 59));
        self::assertFalse(Totp::verify(self::RFC_SECRET, 'abcdef', 59));
    }

    public function test_AUTH_07_jendela_toleransi_hanya_satu_langkah(): void
    {
        $t = 1_700_000_000;
        $step = Totp::stepAt($t);
        self::assertTrue(Totp::verify(self::RFC_SECRET, Totp::code(self::RFC_SECRET, $step - 1), $t));
        self::assertTrue(Totp::verify(self::RFC_SECRET, Totp::code(self::RFC_SECRET, $step + 1), $t));
        self::assertFalse(Totp::verify(self::RFC_SECRET, Totp::code(self::RFC_SECRET, $step - 2), $t));
        self::assertFalse(Totp::verify(self::RFC_SECRET, Totp::code(self::RFC_SECRET, $step + 2), $t));
    }

    public function test_AUTH_07_replay_langkah_yang_sama_ditolak(): void
    {
        $t = 1_700_000_000;
        $code = Totp::code(self::RFC_SECRET, Totp::stepAt($t));
        $step = Totp::matchStep(self::RFC_SECRET, $code, $t, null);
        self::assertSame(Totp::stepAt($t), $step);
        self::assertNull(Totp::matchStep(self::RFC_SECRET, $code, $t, $step));
        self::assertNull(Totp::matchStep(self::RFC_SECRET, Totp::code(self::RFC_SECRET, $step - 1), $t, $step), 'kode lebih lama dari langkah terakhir');
    }

    /** @return array{0:int,1:string,2:list<string>} */
    private function enroll(string $email = 'ada@contoh.test'): array
    {
        $uid = $this->h->user($email);
        $tf = $this->h->twofa();
        $secret = $tf->begin($uid);
        $codes = $tf->confirm($uid, Totp::code($secret, Totp::stepAt($this->h->clock->t)));
        self::assertNotNull($codes);
        return [$uid, $secret, $codes];
    }

    public function test_AUTH_07_secret_terenkripsi_di_database_dan_kode_pemulihan_di_hash(): void
    {
        [$uid, $secret, $codes] = $this->enroll();
        $row = $this->h->conn->pdo()->query("SELECT totp_secret, recovery_codes FROM users WHERE id = $uid")->fetch();
        self::assertStringNotContainsString($secret, (string) $row['totp_secret']);
        self::assertSame($secret, $this->h->vault()->open((string) $row['totp_secret'], 'totp-secret'));
        self::assertNull($this->h->vault()->open((string) $row['totp_secret'], 'konteks-lain'), 'terikat konteks');
        self::assertNull((new SecretVault(str_repeat('k', 40)))->open((string) $row['totp_secret'], 'totp-secret'), 'kunci lain gagal');
        self::assertCount(10, $codes);
        foreach ($codes as $c) {
            self::assertStringNotContainsString(str_replace('-', '', $c), (string) $row['recovery_codes']);
        }
    }

    public function test_AUTH_07_login_dengan_2fa_wajib_otp_dan_mengisi_amr(): void
    {
        [$uid, $secret] = $this->enroll();
        $b = $this->h->browser();
        $res = $b->login('ada@contoh.test');
        self::assertSame('/auth/otp', $res->headers['Location']);
        self::assertNull($this->h->wire($b->cookies)[1]->manager->current(), 'belum login sebelum OTP');
        $b->get('/auth/otp');
        self::assertSame(401, $b->post('/auth/otp', ['code' => '000000'])->status);
        $this->h->clock->advance(30);
        $code = Totp::code($secret, Totp::stepAt($this->h->clock->t));
        $ok = $b->post('/auth/otp', ['code' => $code]);
        self::assertSame(302, $ok->status);
        self::assertSame('/', $ok->headers['Location']);
        self::assertSame(['pwd', 'otp'], $this->h->wire($b->cookies)[1]->manager->current()?->amr);
        self::assertSame($uid, $this->h->wire($b->cookies)[1]->manager->current()?->userId);
    }

    public function test_AUTH_07_replay_kode_otp_pada_login_kedua_ditolak(): void
    {
        [, $secret] = $this->enroll();
        $this->h->clock->advance(30);
        $code = Totp::code($secret, Totp::stepAt($this->h->clock->t));
        $b1 = $this->h->browser('192.0.2.1');
        $b1->login('ada@contoh.test');
        $b1->get('/auth/otp');
        self::assertSame(302, $b1->post('/auth/otp', ['code' => $code])->status);
        $b2 = $this->h->browser('192.0.2.2');
        $b2->login('ada@contoh.test');
        $b2->get('/auth/otp');
        self::assertSame(401, $b2->post('/auth/otp', ['code' => $code])->status, 'kode yang sama dipakai ulang');
    }

    public function test_AUTH_07_kode_pemulihan_sekali_pakai(): void
    {
        [, , $codes] = $this->enroll();
        $b1 = $this->h->browser('192.0.2.1');
        $b1->login('ada@contoh.test');
        $b1->get('/auth/otp');
        self::assertSame(302, $b1->post('/auth/otp', ['code' => strtoupper($codes[0])])->status);
        $b2 = $this->h->browser('192.0.2.2');
        $b2->login('ada@contoh.test');
        $b2->get('/auth/otp');
        self::assertSame(401, $b2->post('/auth/otp', ['code' => $codes[0]])->status);
        self::assertSame(302, $b2->post('/auth/otp', ['code' => $codes[1]])->status, 'kode lain tetap sah');
    }

    public function test_SEC_REQ_02_otp_dibatasi_laju(): void
    {
        $this->enroll();
        $b = $this->h->browser();
        $b->login('ada@contoh.test');
        $b->get('/auth/otp');
        for ($i = 0; $i < 5; $i++) {
            self::assertSame(401, $b->post('/auth/otp', ['code' => '00000' . $i])->status);
        }
        self::assertSame(429, $b->post('/auth/otp', ['code' => '000009'])->status);
    }

    public function test_AUTH_07_state_pending_kedaluwarsa_dalam_5_menit(): void
    {
        $this->enroll();
        $b = $this->h->browser();
        $b->login('ada@contoh.test');
        $this->h->clock->advance(301);
        $res = $b->get('/auth/otp');
        self::assertSame('/login', $res->headers['Location']);
    }

    public function test_AUTH_07_konfirmasi_pendaftaran_butuh_kode_benar_dan_nonaktifkan_butuh_password(): void
    {
        $uid = $this->h->user('ada@contoh.test');
        $b = $this->h->browser();
        $b->login('ada@contoh.test');
        $b->get('/auth/2fa');
        $page = $b->post('/auth/2fa/begin', ['password' => AuthHarness::PASSWORD]);
        self::assertSame(200, $page->status);
        self::assertSame(422, $b->post('/auth/2fa/confirm', ['code' => '000000', 'password' => AuthHarness::PASSWORD])->status);
        self::assertFalse($this->h->accounts->find($uid)?->totpEnabled);
        $secret = (string) $this->h->twofa()->pendingSecret($this->h->accounts->find($uid) ?? throw new \RuntimeException());
        $this->h->clock->advance(30);
        $ok = $b->post('/auth/2fa/confirm', ['code' => Totp::code($secret, Totp::stepAt($this->h->clock->t)), 'password' => AuthHarness::PASSWORD]);
        self::assertSame(200, $ok->status);
        self::assertTrue($this->h->accounts->find($uid)?->totpEnabled);
        self::assertSame(10, preg_match_all('/<code>[a-z2-7]{5}-[a-z2-7]{5}<\/code>/', $ok->body));
        self::assertSame(401, $b->post('/auth/2fa/disable', ['password' => 'salah-salah-salah'])->status);
        self::assertTrue($this->h->accounts->find($uid)?->totpEnabled);
        // Nonaktifkan butuh password DAN kode lama (SEC-3/S4).
        self::assertSame(401, $b->post('/auth/2fa/disable', ['password' => AuthHarness::PASSWORD])->status);
        self::assertTrue($this->h->accounts->find($uid)?->totpEnabled);
        $this->h->clock->advance(30);
        $code = Totp::code($secret, Totp::stepAt($this->h->clock->t));
        self::assertSame(302, $b->post('/auth/2fa/disable', ['password' => AuthHarness::PASSWORD, 'code' => $code])->status);
        self::assertFalse($this->h->accounts->find($uid)?->totpEnabled);
    }

    public function test_AUTH_07_halaman_2fa_butuh_login(): void
    {
        $b = $this->h->browser();
        self::assertSame('/login', $b->get('/auth/2fa')->headers['Location']);
        $b->get('/auth/forgot');
        self::assertSame('/login', $b->post('/auth/2fa/begin')->headers['Location']);
    }
}
