<?php

declare(strict_types=1);

namespace bFramework\Tests\Auth;

use bFramework\Auth\LocalDriver;
use bFramework\Auth\PasswordHasher;
use bFramework\Core\FileSessionStore;
use bFramework\Runtime\CurrentIdentity;
use bFramework\Tests\Fixtures\AuthHarness;
use PHPUnit\Framework\TestCase;

final class LoginTest extends TestCase
{
    private AuthHarness $h;

    protected function setUp(): void
    {
        $this->h = new AuthHarness();
    }

    private function identityOf(string $sid): ?\bFramework\Contracts\Identity
    {
        $store = new FileSessionStore($this->h->dir . '/sessions', false, 1800, 28800, ['bf_sid' => $sid], static function (): void {
        }, $this->h->clock);
        return (new CurrentIdentity($store))->get();
    }

    public function test_AUTH_01_login_berhasil_membuat_identitas_dengan_amr_pwd(): void
    {
        $this->h->user('budi@contoh.test', roles: ['staf', 'admin']);
        $b = $this->h->browser();
        $res = $b->login('Budi@Contoh.test');
        self::assertSame(302, $res->status);
        self::assertSame('/', $res->headers['Location']);
        $id = $this->identityOf((string) $b->sessionCookie());
        self::assertNotNull($id);
        self::assertSame(['pwd'], $id->amr);
        self::assertSame(['admin', 'staf'], $id->roles);
        self::assertSame('admin', $id->activeRole);
    }

    public function test_AUTH_03_hash_argon2id_atau_bcrypt_dan_rehash_otomatis(): void
    {
        $argon = new PasswordHasher(64, 1, 1, 4, true);
        $h = $argon->hash('contoh-password-panjang');
        self::assertStringStartsWith('$argon2id$', $h);
        self::assertTrue($argon->verify('contoh-password-panjang', $h));
        self::assertFalse($argon->verify('salah', $h));
        self::assertFalse($argon->needsRehash($h));
        self::assertTrue((new PasswordHasher(128, 2, 1, 4, true))->needsRehash($h), 'parameter lebih kuat -> rehash');
        $bc = new PasswordHasher(64, 1, 1, 4, false);
        $b = $bc->hash('contoh-password-panjang');
        self::assertStringStartsWith('$2y$', $b);
        self::assertTrue($argon->needsRehash($b), 'bcrypt -> argon2id saat tersedia');
        self::assertSame(72, $bc->maxBytes());
    }

    public function test_AUTH_03_login_merehash_hash_lama_dan_kolom_tidak_polos(): void
    {
        $id = $this->h->user('rehash@contoh.test');
        $old = (new PasswordHasher(64, 1, 1, 4, false))->hash(AuthHarness::PASSWORD);
        $this->h->accounts->updateHash($id, $old);
        $b = $this->h->browser();
        self::assertSame(302, $b->login('rehash@contoh.test')->status);
        $stored = (string) $this->h->accounts->find($id)?->passwordHash;
        self::assertStringStartsWith('$argon2id$', $stored);
        self::assertStringNotContainsString(AuthHarness::PASSWORD, $stored);
    }

    public function test_AUTH_enumerasi_pesan_sama_untuk_akun_ada_tidak_ada_salah_password_dan_nonaktif(): void
    {
        $this->h->user('ada@contoh.test');
        $this->h->user('off@contoh.test', status: 'disabled');
        $bodies = [];
        foreach ([['ada@contoh.test', 'password-salah-sekali'], ['tidakada@contoh.test', AuthHarness::PASSWORD],
            ['off@contoh.test', AuthHarness::PASSWORD], ['bukan-email', 'x']] as $i => [$e, $p]) {
            $b = $this->h->browser('198.51.100.' . $i);
            $res = $b->login($e, $p);
            self::assertSame(401, $res->status);
            self::assertStringContainsString(LocalDriver::GENERIC_FAIL, $res->body);
            $bodies[] = preg_replace('/(value|nonce|content)="[^"]*"/', '', $res->body);
        }
        // Setelah token/nilai input dibuang, isi halaman identik.
        self::assertSame(1, count(array_unique(array_slice($bodies, 0, 3))));
    }

    public function test_AUTH_enumerasi_waktu_verifikasi_hash_selalu_dijalankan(): void
    {
        $this->h->user('ada@contoh.test');
        $this->h->hasher->verifies = 0;
        $this->h->browser('198.51.100.1')->login('ada@contoh.test', 'salah-salah-salah');
        self::assertSame(1, $this->h->hasher->verifies);
        $this->h->hasher->verifies = 0;
        $this->h->browser('198.51.100.2')->login('hantu@contoh.test', 'salah-salah-salah');
        self::assertSame(1, $this->h->hasher->verifies, 'akun tak ada tetap memverifikasi hash palsu');
        $this->h->hasher->verifies = 0;
        $this->h->browser('198.51.100.3')->login('bukan email', 'salah-salah-salah');
        self::assertSame(1, $this->h->hasher->verifies);
    }

    public function test_AUTH_enumerasi_waktu_tidak_beda_jauh(): void
    {
        // Hasher produksi (bukan parameter tes) agar hash dominan; rasio median harus mendekati 1.
        $this->h->hasher = new \bFramework\Tests\Fixtures\SpyHasher(4096, 1, 1, 4);
        $this->h->user('ada@contoh.test', 'password-benar-panjang');
        $time = function (string $email, int $n): float {
            $t = [];
            for ($i = 0; $i < 5; $i++) {
                $b = $this->h->browser('10.' . $n . '.0.' . $i);
                $b->get('/login');
                $s = hrtime(true);
                $b->post('/login', ['email' => $email, 'password' => 'salah-salah-salah']);
                $t[] = hrtime(true) - $s;
            }
            sort($t);
            return (float) $t[2];
        };
        $known = $time('ada@contoh.test', 1);
        $unknown = $time('hantu@contoh.test', 2);
        $ratio = $unknown / $known;
        self::assertGreaterThan(0.4, $ratio);
        self::assertLessThan(2.5, $ratio);
    }

    public function test_SEC_REQ_02_brute_force_percobaan_ke_6_mendapat_429_walau_password_benar(): void
    {
        $this->h->user('ada@contoh.test');
        $b = $this->h->browser();
        for ($i = 0; $i < 5; $i++) {
            self::assertSame(401, $b->login('ada@contoh.test', 'salah-salah-salah')->status);
        }
        self::assertSame(429, $b->login('ada@contoh.test', 'salah-salah-salah')->status);
        self::assertSame(429, $b->login('ada@contoh.test', AuthHarness::PASSWORD)->status, 'terkunci walau password benar');
        // IP lain pun terkunci untuk akun yang sama (kunci per akun).
        self::assertSame(429, $this->h->browser('192.0.2.50')->login('ada@contoh.test')->status);
    }

    public function test_SEC_REQ_02_lockout_bertahap_makin_lama(): void
    {
        $this->h->user('ada@contoh.test');
        $b = $this->h->browser();
        $fail = 0;
        for ($round = 0; $round < 3; $round++) {
            for ($i = 0; $i < 5; $i++) {
                $s = $b->login('ada@contoh.test', 'salah-salah-salah')->status;
                $fail += $s === 401 ? 1 : 0;
            }
            $this->h->clock->advance(901); // jendela 15 menit lewat
        }
        self::assertSame(10, $fail, 'tangga ke-2 (10/jam) menahan ronde ketiga walau jendela 15 menit lewat');
        self::assertSame(429, $b->login('ada@contoh.test')->status);
        $this->h->clock->advance(3600);
        self::assertSame(302, $b->login('ada@contoh.test')->status, 'setelah jam berlalu bisa lagi');
    }

    public function test_SEC_REQ_01_login_tanpa_csrf_ditolak_419(): void
    {
        $this->h->user('ada@contoh.test');
        $b = $this->h->browser();
        $b->get('/login');
        self::assertSame(419, $b->post('/login', ['email' => 'ada@contoh.test', 'password' => AuthHarness::PASSWORD], false)->status);
        self::assertSame(419, $b->post('/login', ['email' => 'ada@contoh.test', 'password' => AuthHarness::PASSWORD, '_csrf' => str_repeat('a', 64)], false)->status);
    }

    public function test_SEC_SESS_02_fixation_id_sesi_dan_csrf_berubah_saat_login(): void
    {
        $this->h->user('ada@contoh.test');
        $b = $this->h->browser();
        $b->get('/login');
        $before = $b->sessionCookie();
        $csrfBefore = $b->csrf;
        self::assertNotNull($before);
        $b->post('/login', ['email' => 'ada@contoh.test', 'password' => AuthHarness::PASSWORD]);
        $after = $b->sessionCookie();
        self::assertNotNull($after);
        self::assertNotSame($before, $after);
        self::assertFileDoesNotExist($this->h->dir . '/sessions/sess_' . $before);
        self::assertNull($this->identityOf((string) $before), 'ID lama tidak bisa dipakai');
        self::assertNotNull($this->identityOf($after));
        $b->get('/login'); // sudah login -> redirect; token CSRF baru dipakai sesi baru
        self::assertNotSame($csrfBefore, (new \bFramework\Core\Csrf(new FileSessionStore($this->h->dir . '/sessions', false, 1800, 28800, ['bf_sid' => $after], static function (): void {
        }, $this->h->clock)))->token());
    }

    public function test_SEC_SESS_02_id_sesi_buatan_penyerang_tidak_diadopsi(): void
    {
        $this->h->user('ada@contoh.test');
        $b = $this->h->browser();
        $fixed = str_repeat('a', 64);
        $b->cookies['bf_sid'] = $fixed;
        $b->get('/login');
        self::assertNotSame($fixed, $b->sessionCookie());
        $b->post('/login', ['email' => 'ada@contoh.test', 'password' => AuthHarness::PASSWORD]);
        self::assertNull($this->identityOf($fixed));
    }

    public function test_AUTH_logout_mencabut_sesi_dan_ingat_saya(): void
    {
        $this->h->user('ada@contoh.test');
        $b = $this->h->browser();
        $b->login('ada@contoh.test', remember: true);
        $sid = (string) $b->sessionCookie();
        self::assertArrayHasKey('bf_remember', $b->cookies);
        $old = $b->cookies;
        $b->get('/auth/forgot'); // halaman berikutnya memuat token CSRF sesi baru
        $res = $b->post('/logout');
        self::assertSame('/login', $res->headers['Location']);
        self::assertNull($this->identityOf($sid));
        self::assertArrayNotHasKey('bf_remember', $b->cookies);
        // Cookie ingat-saya lama tidak lagi memulihkan sesi.
        $thief = $this->h->browser();
        $thief->cookies = ['bf_remember' => $old['bf_remember']];
        $thief->get('/login');
        self::assertNull($this->identityOf((string) $thief->sessionCookie()));
    }

    public function test_AUTH_sesi_dicabut_bila_akun_dinonaktifkan_atau_password_berubah(): void
    {
        $id = $this->h->user('ada@contoh.test');
        $b = $this->h->browser();
        $b->login('ada@contoh.test');
        $mgr = $this->h->wire($b->cookies)[1]->manager;
        self::assertNotNull($mgr->current());
        $this->h->clock->advance(5);
        $this->h->accounts->setPassword($id, $this->h->hasher->hash('password-baru-panjang'));
        self::assertNull($this->h->wire($b->cookies)[1]->manager->current(), 'sesi lama gugur setelah ganti password');
    }

    public function test_SEC_SESS_02_ganti_peran_regenerate_dan_validasi_kepemilikan(): void
    {
        $this->h->user('dua@contoh.test', roles: ['staf', 'admin']);
        $this->h->user('satu@contoh.test', roles: ['staf']);
        $b = $this->h->browser();
        $b->login('dua@contoh.test');
        $sid = $b->sessionCookie();
        [, $kit, $jar] = $this->h->wire($b->cookies);
        $id = $kit->manager->switchRole('staf');
        self::assertSame('staf', $id->activeRole);
        $jar->applyTo(\bFramework\Core\Response::html(''));
        $b2 = $this->h->browser('203.0.113.99');
        $b2->login('satu@contoh.test');
        [, $kit2] = $this->h->wire($b2->cookies);
        $this->expectException(\bFramework\Contracts\Forbidden::class);
        $kit2->manager->switchRole('admin');
        self::assertNotNull($sid);
    }

    public function test_AUTH_08_registrasi_publik_mati_secara_default(): void
    {
        $b = $this->h->browser();
        self::assertSame(404, $b->get('/auth/register')->status);
        self::assertSame(404, $b->post('/auth/register', ['email' => 'x@contoh.test'], false)->status);
        self::assertStringNotContainsString('/auth/register', $b->get('/login')->body);
    }

    public function test_AUTH_08_registrasi_bila_diaktifkan_membuat_akun_pending_dan_respons_seragam(): void
    {
        $this->h->registration = true;
        $this->h->user('lama@contoh.test');
        $b = $this->h->browser();
        $b->get('/auth/register');
        $r1 = $b->post('/auth/register', ['name' => 'Baru', 'email' => 'baru@contoh.test', 'password' => 'sandi-rahasia-panjang-sekali']);
        $r2 = $b->post('/auth/register', ['name' => 'Lama', 'email' => 'lama@contoh.test', 'password' => 'sandi-rahasia-panjang-sekali']);
        self::assertSame(200, $r1->status);
        self::assertSame(preg_replace('/(value|nonce|content)="[^"]*"/', '', $r1->body), preg_replace('/(value|nonce|content)="[^"]*"/', '', $r2->body));
        $this->h->deferred->run();
        self::assertCount(1, $this->h->mail->sent, 'email verifikasi hanya untuk akun baru');
        self::assertSame('pending', $this->h->accounts->findByEmail('baru@contoh.test')?->status);
        self::assertSame(401, $this->h->browser('1.1.1.1')->login('baru@contoh.test', 'sandi-rahasia-panjang-sekali')->status, 'belum verifikasi = belum bisa login');
    }

    public function test_AUTH_08_pra_registrasi_tidak_bisa_membajak_akun_korban(): void
    {
        $this->h->registration = true;
        $atk = $this->h->browser('198.51.100.1');
        $atk->get('/auth/register');
        $atk->post('/auth/register', ['name' => 'Penyerang', 'email' => 'korban@contoh.test', 'password' => 'sandi-penyerang-panjang-1']);
        $this->h->deferred->run();
        self::assertNull($this->h->accounts->findByEmail('korban@contoh.test')?->passwordHash, 'password pendaftar tidak disimpan');
        self::assertCount(1, $this->h->mail->sent);
        $token = $this->h->mail->lastToken();

        // Korban membuka tautan dan menetapkan password sendiri.
        $v = $this->h->browser('203.0.113.50');
        $v->get('/auth/reset/' . $token);
        $v->get('/auth/reset');
        self::assertSame(302, $v->post('/auth/reset', ['password' => 'kalimat-pemilik-asli-yang-panjang', 'password2' => 'kalimat-pemilik-asli-yang-panjang'])->status);
        self::assertSame('active', $this->h->accounts->findByEmail('korban@contoh.test')?->status);
        self::assertSame(401, $this->h->browser('198.51.100.2')->login('korban@contoh.test', 'sandi-penyerang-panjang-1')->status);
        self::assertSame(302, $this->h->browser('203.0.113.51')->login('korban@contoh.test', 'kalimat-pemilik-asli-yang-panjang')->status);
    }

    public function test_AUTH_08_register_ulang_email_pending_tidak_menimpa_dan_respons_seragam(): void
    {
        $this->h->registration = true;
        $b = $this->h->browser('198.51.100.3');
        $b->get('/auth/register');
        $r1 = $b->post('/auth/register', ['name' => 'Satu', 'email' => 'p@contoh.test', 'password' => 'x']);
        $this->h->deferred->run();
        $id = $this->h->accounts->findByEmail('p@contoh.test')?->id;
        $r2 = $b->post('/auth/register', ['name' => 'Dua', 'email' => 'p@contoh.test', 'password' => 'x']);
        $this->h->deferred->run();
        $strip = static fn(string $x): string => (string) preg_replace('/(value|nonce|content)="[^"]*"/', '', $x);
        self::assertSame($strip($r1->body), $strip($r2->body));
        $acc = $this->h->accounts->findByEmail('p@contoh.test');
        self::assertSame($id, $acc?->id);
        self::assertSame('Satu', $acc?->name);
        self::assertNull($acc?->passwordHash);
        self::assertCount(2, $this->h->mail->sent, 'tautan dikirim ulang ke pemilik email saja');
    }

    public function test_AUTH_08_tautan_registrasi_kedaluwarsa_dan_sekali_pakai(): void
    {
        $this->h->registration = true;
        $b = $this->h->browser('198.51.100.4');
        $b->get('/auth/register');
        $b->post('/auth/register', ['name' => 'Satu', 'email' => 'q@contoh.test']);
        $this->h->deferred->run();
        $token = $this->h->mail->lastToken();
        $this->h->clock->advance(4000);
        $e = $this->h->browser('203.0.113.60');
        $e->get('/auth/reset/' . $token);
        $e->get('/auth/reset');
        self::assertSame(400, $e->post('/auth/reset', ['password' => 'kalimat-pemilik-asli-yang-panjang', 'password2' => 'kalimat-pemilik-asli-yang-panjang'])->status);
        self::assertSame('pending', $this->h->accounts->findByEmail('q@contoh.test')?->status);
    }

    public function test_SEC_REQ_03_host_fail_closed_tanpa_allowed_hosts(): void
    {
        $this->h->user('a@contoh.test');
        [, $kit] = $this->h->wire([]);
        $router = new \bFramework\Core\Router();
        $kit->driver->registerRoutes($router);
        $req = new \bFramework\Core\Request('GET', '/login', headers: ['host' => 'apa-saja.test']);
        $prod = new \bFramework\Core\Kernel($router, $kit->middleware($router, [], false));
        self::assertSame(400, $prod->handle($req)->status, 'produksi + daftar kosong ditolak');
        [, $kit] = $this->h->wire([]);
        $dev = new \bFramework\Core\Kernel($router, $kit->middleware($router, [], true));
        self::assertSame(200, $dev->handle($req)->status, 'dev + daftar kosong lolos');
        [, $kit] = $this->h->wire([]);
        $set = new \bFramework\Core\Kernel($router, $kit->middleware($router, ['app.contoh.test'], false));
        self::assertSame(400, $set->handle($req)->status);
    }

    public function test_AUTH_05_pekerjaan_khusus_akun_tidak_jalan_di_jalur_respons_dan_respons_dikirim_sebelum_deferred(): void
    {
        $this->h->user('ada@contoh.test');
        $b = $this->h->browser();
        $b->get('/auth/forgot');
        $tokens = static fn(AuthHarness $h): int => (int) $h->conn->pdo()->query('SELECT COUNT(*) FROM one_time_tokens')->fetchColumn();
        $before = $tokens($this->h);
        $b->post('/auth/forgot', ['email' => 'ada@contoh.test']);
        self::assertSame($before, $tokens($this->h), 'tidak ada token diterbitkan sebelum Deferred');
        self::assertSame(1, $this->h->deferred->pending());
        $b->post('/auth/forgot', ['email' => 'hantu@contoh.test']);
        self::assertSame(2, $this->h->deferred->pending(), 'jalur ada dan tidak ada sama di sisi respons');

        $log = [];
        $d = new \bFramework\Auth\Deferred();
        $d->push(function () use (&$log): void {
            $log[] = 'job';
        });
        $d->respondThenRun(
            \bFramework\Core\Response::html('halo'),
            function () use (&$log): void {
                $log[] = 'kirim';
            },
            function () use (&$log): void {
                $log[] = 'tutup';
            },
        );
        self::assertSame(['kirim', 'tutup', 'job'], $log);
    }

    public function test_AUTH_akun_tanpa_peran_tidak_bisa_login(): void
    {
        $this->h->user('kosong@contoh.test', roles: []);
        $res = $this->h->browser()->login('kosong@contoh.test');
        self::assertSame(403, $res->status);
    }

    public function test_AUTH_password_policy(): void
    {
        $p = \bFramework\Auth\PasswordPolicy::class;
        self::assertSame([], $p::check('kalimat sandi yang cukup panjang'));
        self::assertNotSame([], $p::check('pendek'));
        self::assertNotSame([], $p::check('Password123'));
        self::assertNotSame([], $p::check('aaaaaaaaaaaa'));
        self::assertNotSame([], $p::check('budisantoso2024', 'budisantoso@x.test'));
        self::assertNotSame([], $p::check(str_repeat('x1', 200)));
        self::assertNotSame([], $p::check("abc\0defghijklmnop"));
        self::assertSame([], $p::check('sederhana tapi PANJANG'), 'tanpa aturan komposisi');
    }
}
