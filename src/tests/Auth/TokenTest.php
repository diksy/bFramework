<?php

declare(strict_types=1);

namespace bFramework\Tests\Auth;

use bFramework\Auth\AuthTables;
use bFramework\Auth\OneTimeToken;
use bFramework\Tests\Fixtures\AuthHarness;
use PHPUnit\Framework\TestCase;

final class TokenTest extends TestCase
{
    private AuthHarness $h;

    protected function setUp(): void
    {
        $this->h = new AuthHarness();
    }

    private function rows(string $table): array
    {
        return $this->h->conn->pdo()->query('SELECT * FROM ' . $table)->fetchAll();
    }

    // ---------- ingat saya (AUTH-04) ----------

    public function test_AUTH_04_database_hanya_menyimpan_hash_bukan_nilai_cookie(): void
    {
        $uid = $this->h->user('ada@contoh.test');
        $token = $this->h->remember()->issue($uid);
        [$selector, $validator] = explode('.', $token);
        $row = $this->rows('remember_tokens')[0];
        self::assertNotSame($token, $row['token_hash']);
        self::assertNotSame($validator, $row['token_hash']);
        self::assertSame(hash('sha256', $validator), $row['token_hash']);
        self::assertSame($selector, $row['selector']);
        self::assertStringNotContainsString($validator, json_encode($row, JSON_THROW_ON_ERROR));
    }

    public function test_AUTH_04_rotasi_tiap_pakai_dan_token_lama_tidak_berlaku(): void
    {
        $uid = $this->h->user('ada@contoh.test');
        $rm = $this->h->remember();
        $t1 = $rm->issue($uid);
        $t2 = null;
        self::assertSame($uid, $rm->consume($t1, $t2));
        self::assertNotNull($t2);
        self::assertNotSame($t1, $t2);
        $t3 = null;
        self::assertSame($uid, $rm->consume((string) $t2, $t3));
        self::assertNotSame($t2, $t3);
    }

    public function test_AUTH_04_deteksi_pencurian_pakai_ulang_token_lama_mencabut_semua(): void
    {
        $uid = $this->h->user('ada@contoh.test');
        $rm = $this->h->remember();
        $t1 = $rm->issue($uid);
        $other = $rm->issue($uid); // perangkat lain
        $t2 = null;
        $rm->consume($t1, $t2); // pemilik sah memakai & dirotasi
        $this->h->clock->advance(60);
        $n = null;
        self::assertNull($rm->consume($t1, $n), 'penyerang memakai token lama');
        self::assertNull($n);
        self::assertSame([], $this->rows('remember_tokens'), 'semua token pengguna dicabut');
        self::assertNull($rm->consume((string) $t2));
        self::assertNull($rm->consume($other));
        self::assertStringContainsString('dicabut', $this->h->logger->all());
        self::assertStringNotContainsString(explode('.', $t1)[1], $this->h->logger->all());
    }

    public function test_AUTH_04_request_paralel_dalam_masa_tenggang_tidak_dianggap_pencurian(): void
    {
        $uid = $this->h->user('ada@contoh.test');
        $rm = $this->h->remember();
        $t1 = $rm->issue($uid);
        $t2 = null;
        $rm->consume($t1, $t2);
        $this->h->clock->advance(3);
        self::assertNull($rm->consume($t1));
        self::assertSame($uid, $rm->consume((string) $t2), 'token baru tetap sah');
    }

    public function test_AUTH_04_validator_salah_pada_selector_valid_mencabut_semua(): void
    {
        $uid = $this->h->user('ada@contoh.test');
        $rm = $this->h->remember();
        $t = $rm->issue($uid);
        $tampered = explode('.', $t)[0] . '.' . str_repeat('A', 43);
        self::assertNull($rm->consume($tampered));
        self::assertSame([], $this->rows('remember_tokens'));
    }

    public function test_AUTH_04_kedaluwarsa_dan_bentuk_salah_ditolak(): void
    {
        $uid = $this->h->user('ada@contoh.test');
        $rm = $this->h->remember();
        $t = $rm->issue($uid);
        $this->h->clock->advance($rm->ttl() + 1);
        self::assertNull($rm->consume($t));
        foreach (['', 'abc', str_repeat('a', 24) . '.' . str_repeat('b', 10), "x'; DROP TABLE users;--"] as $bad) {
            self::assertNull($rm->consume($bad));
        }
        self::assertSame(1, (int) $this->h->conn->pdo()->query('SELECT COUNT(*) FROM users')->fetchColumn());
    }

    public function test_AUTH_04_cookie_ingat_saya_memulihkan_sesi_dengan_amr_remember_dan_merotasi(): void
    {
        $this->h->user('ada@contoh.test');
        $a = $this->h->browser();
        $a->login('ada@contoh.test', remember: true);
        $cookie1 = $a->cookies['bf_remember'];
        $b = $this->h->browser();
        $b->cookies = ['bf_remember' => $cookie1];
        $b->get('/login'); // sudah terpulihkan -> redirect
        self::assertSame(['remember'], $this->h->wire($b->cookies)[1]->manager->current()?->amr);
        self::assertNotSame($cookie1, $b->cookies['bf_remember'], 'token dirotasi');
        // Token lama dibawa penyerang setelah masa tenggang -> semua dicabut, pemilik harus login ulang.
        $this->h->clock->advance(120);
        $thief = $this->h->browser('198.51.100.9');
        $thief->cookies = ['bf_remember' => $cookie1];
        $thief->get('/login');
        self::assertNull($this->h->wire($thief->cookies)[1]->manager->current());
        $this->h->clock->advance(1);
        $b2 = $this->h->browser();
        $b2->cookies = ['bf_remember' => $b->cookies['bf_remember']];
        $b2->get('/login');
        self::assertNull($this->h->wire($b2->cookies)[1]->manager->current(), 'token pemilik ikut dicabut');
    }

    // ---------- token sekali pakai (AUTH-05) ----------

    public function test_AUTH_05_token_sekali_pakai_dan_hanya_hash_di_db(): void
    {
        $uid = $this->h->user('ada@contoh.test');
        $ot = $this->h->tokens();
        $t = $ot->issue($uid, OneTimeToken::RESET, 1800);
        $row = $this->rows('one_time_tokens')[0];
        self::assertSame(hash('sha256', explode('.', $t)[1]), $row['token_hash']);
        self::assertStringNotContainsString(explode('.', $t)[1], json_encode($row, JSON_THROW_ON_ERROR));
        self::assertSame($uid, $ot->consume($t, OneTimeToken::RESET));
        self::assertNull($ot->consume($t, OneTimeToken::RESET), 'pakai ulang ditolak');
    }

    public function test_AUTH_05_kedaluwarsa_tampered_dan_tujuan_salah_ditolak(): void
    {
        $uid = $this->h->user('ada@contoh.test');
        $ot = $this->h->tokens();
        $t = $ot->issue($uid, OneTimeToken::RESET, 600);
        $this->h->clock->advance(601);
        self::assertNull($ot->consume($t, OneTimeToken::RESET), 'kedaluwarsa');
        $t = $ot->issue($uid, OneTimeToken::RESET, 600);
        $bad = explode('.', $t)[0] . '.' . strrev(explode('.', $t)[1]);
        self::assertNull($ot->consume($bad, OneTimeToken::RESET), 'validator diubah');
        self::assertNull($ot->consume($t, OneTimeToken::VERIFY_EMAIL), 'tujuan beda');
        self::assertNull($ot->consume('0000000000000000000000ff.' . str_repeat('A', 43), OneTimeToken::RESET), 'selector tak ada');
        self::assertSame($uid, $ot->consume($t, OneTimeToken::RESET), 'token asli masih sah setelah percobaan gagal');
    }

    public function test_AUTH_05_ttl_maksimum_60_menit_dan_penerbitan_baru_membatalkan_lama(): void
    {
        $uid = $this->h->user('ada@contoh.test');
        $ot = $this->h->tokens();
        $this->expectNotToPerformAssertions();
        try {
            $ot->issue($uid, OneTimeToken::RESET, 3601);
            self::fail('TTL > 3600 harus ditolak');
        } catch (\InvalidArgumentException) {
        }
    }

    public function test_AUTH_05_token_baru_membatalkan_token_lama_dan_revokeAll(): void
    {
        $uid = $this->h->user('ada@contoh.test');
        $ot = $this->h->tokens();
        $a = $ot->issue($uid, OneTimeToken::RESET, 900);
        $b = $ot->issue($uid, OneTimeToken::RESET, 900);
        self::assertNull($ot->consume($a, OneTimeToken::RESET));
        $ot->revokeAll($uid);
        self::assertNull($ot->consume($b, OneTimeToken::RESET));
    }

    public function test_AUTH_05_pembandingan_memakai_hash_equals(): void
    {
        foreach (['OneTimeToken', 'RememberMe'] as $cls) {
            $src = (string) file_get_contents(dirname(__DIR__, 2) . '/app/core/Auth/' . $cls . '.php');
            self::assertStringContainsString('hash_equals(', $src);
            self::assertDoesNotMatchRegularExpression('/token_hash\'\]\s*[!=]==\s*hash/', $src);
        }
    }

    // ---------- alur lupa/reset password ----------

    public function test_AUTH_05_alur_reset_penuh_dan_semua_kredensial_lama_gugur(): void
    {
        $uid = $this->h->user('ada@contoh.test');
        $dev = $this->h->browser();
        $dev->login('ada@contoh.test', remember: true);
        $old = $dev->cookies;

        $b = $this->h->browser('192.0.2.10');
        $b->get('/auth/forgot');
        $res = $b->post('/auth/forgot', ['email' => 'ADA@contoh.test']);
        self::assertSame(200, $res->status);
        self::assertCount(0, $this->h->mail->sent, 'email belum terkirim sebelum respons selesai');
        $this->h->deferred->run();
        self::assertCount(1, $this->h->mail->sent);
        $mail = $this->h->mail->sent[0];
        self::assertSame('ada@contoh.test', $mail->to);
        self::assertStringStartsWith('https://app.contoh.test/auth/reset/', strstr($mail->body, 'https://') ?: '', 'tautan memakai APP_URL, bukan Host request');
        $token = $this->h->mail->lastToken();

        $link = $b->get('/auth/reset/' . $token);
        self::assertSame(302, $link->status);
        self::assertSame('/auth/reset', $link->headers['Location']);
        $b->get('/auth/reset');
        $weak = $b->post('/auth/reset', ['password' => 'pendek', 'password2' => 'pendek']);
        self::assertSame(422, $weak->status);
        $mismatch = $b->post('/auth/reset', ['password' => 'kalimat-baru-yang-panjang', 'password2' => 'lain-sekali-bedanya']);
        self::assertSame(422, $mismatch->status);
        $this->h->clock->advance(2);
        $ok = $b->post('/auth/reset', ['password' => 'kalimat-baru-yang-panjang', 'password2' => 'kalimat-baru-yang-panjang']);
        self::assertSame(302, $ok->status);
        self::assertSame('/login', $ok->headers['Location']);

        // Token tidak bisa dipakai lagi.
        $b2 = $this->h->browser('192.0.2.11');
        $b2->get('/auth/reset/' . $token);
        $b2->get('/auth/reset');
        self::assertSame(400, $b2->post('/auth/reset', ['password' => 'kalimat-lain-yang-panjang', 'password2' => 'kalimat-lain-yang-panjang'])->status);

        // Password lama gagal, baru berhasil; sesi & ingat-saya perangkat lama gugur.
        self::assertSame(401, $this->h->browser('192.0.2.12')->login('ada@contoh.test')->status);
        self::assertSame(302, $this->h->browser('192.0.2.13')->login('ada@contoh.test', 'kalimat-baru-yang-panjang')->status);
        $d = $this->h->browser('192.0.2.14');
        $d->cookies = $old;
        $d->get('/login');
        self::assertNull($this->h->wire($d->cookies)[1]->manager->current());
        self::assertSame([], $this->h->conn->pdo()->query("SELECT 1 FROM remember_tokens WHERE user_id = $uid")->fetchAll());
    }

    public function test_AUTH_05_forgot_respons_seragam_dan_tidak_mengirim_untuk_akun_tak_ada(): void
    {
        $this->h->user('ada@contoh.test');
        $this->h->user('off@contoh.test', status: 'disabled');
        $out = [];
        foreach (['ada@contoh.test', 'hantu@contoh.test', 'off@contoh.test', 'bukan-email'] as $i => $e) {
            $b = $this->h->browser('192.0.2.' . (20 + $i));
            $b->get('/auth/forgot');
            $res = $b->post('/auth/forgot', ['email' => $e]);
            self::assertSame(200, $res->status);
            $out[] = preg_replace('/(value|nonce|content)="[^"]*"/', '', $res->body);
        }
        self::assertSame(1, count(array_unique($out)));
        $this->h->deferred->run();
        self::assertCount(1, $this->h->mail->sent);
    }

    public function test_SEC_REQ_02_forgot_dibatasi_laju(): void
    {
        $this->h->user('ada@contoh.test');
        $b = $this->h->browser();
        $b->get('/auth/forgot');
        for ($i = 0; $i < 3; $i++) {
            self::assertSame(200, $b->post('/auth/forgot', ['email' => 'ada@contoh.test'])->status);
        }
        self::assertSame(429, $b->post('/auth/forgot', ['email' => 'ada@contoh.test'])->status);
    }

    public function test_AUTH_05_token_di_url_dipindah_ke_sesi_dan_bentuk_salah_ditolak(): void
    {
        $b = $this->h->browser();
        self::assertSame(400, $b->get('/auth/reset/bukan-token')->status);
        self::assertSame(400, $b->get('/auth/reset')->status);
        self::assertSame(400, $b->get('/auth/verify')->status);
    }

    public function test_AUTH_05_verifikasi_email_lewat_konfirmasi_post(): void
    {
        $uid = $this->h->user('ada@contoh.test');
        $t = $this->h->tokens()->issue($uid, OneTimeToken::VERIFY_EMAIL, 1800);
        $b = $this->h->browser();
        $b->get('/auth/verify/' . $t);
        $b->get('/auth/verify');
        self::assertNull($this->h->accounts->find($uid)?->emailVerifiedAt, 'GET tidak menghanguskan token');
        self::assertSame(302, $b->post('/auth/verify')->status);
        self::assertNotNull($this->h->accounts->find($uid)?->emailVerifiedAt);
        self::assertNull($this->h->tokens()->consume($t, OneTimeToken::VERIFY_EMAIL));
    }

    public function test_SEC_LOG_02_tidak_ada_password_atau_token_di_log(): void
    {
        $uid = $this->h->user('ada@contoh.test');
        $b = $this->h->browser();
        $b->login('ada@contoh.test', 'salah-salah-salah');
        $b->login('ada@contoh.test');
        $b->get('/auth/forgot');
        $b->post('/auth/forgot', ['email' => 'ada@contoh.test']);
        $this->h->deferred->run();
        $t = $this->h->mail->lastToken();
        $rm = $this->h->remember();
        $r = $rm->issue($uid);
        $rm->consume($r);
        $rm->consume($r); // pencurian -> dicatat
        $log = $this->h->logger->all();
        foreach ([AuthHarness::PASSWORD, 'salah-salah-salah', $t, explode('.', $t)[1], explode('.', $r)[1], '/auth/reset/'] as $secret) {
            self::assertStringNotContainsString($secret, $log);
        }
    }

    public function test_tabel_core_sesuai_kontrak(): void
    {
        $names = array_map(static fn($s) => $s->name, AuthTables::specs());
        self::assertSame(['users', 'roles', 'user_roles', 'remember_tokens', 'one_time_tokens'], $names);
    }
}
