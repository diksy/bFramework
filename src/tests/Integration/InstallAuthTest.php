<?php

declare(strict_types=1);

namespace bFramework\Tests\Integration;

use bFramework\Auth\Totp;
use bFramework\Tests\Fixtures\KernelApp;
use PHPUnit\Framework\TestCase;

/**
 * INT-01..03 (F14 installer, F12 auth lokal, F16 user & peran, F3 sesi, F2 CSRF). Semua lewat public_html/index.php
 * nyata di server PHP bawaan dengan SQLite sementara di tmp; email ditangkap (transport palsu).
 */
final class InstallAuthTest extends TestCase
{
    private function installPost(KernelApp $a, string $token): \bFramework\Tests\Fixtures\KernelResp
    {
        $b = $a->browser();
        $b->get('/install');
        return $b->post('/install', [
            'app_url' => 'https://' . KernelApp::HOST, 'admin_email' => KernelApp::ADMIN_EMAIL, 'admin_name' => 'Admin Dummy',
            'db_driver' => 'sqlite', 'db_file' => 'app.sqlite', 'mail_from' => 'noreply@contoh.test', 'install_token' => $token,
        ]);
    }

    // ---------- INT-01 ----------

    public function test_INT_01_instal_dari_nol_lewat_install_token(): void
    {
        $a = KernelApp::fresh();
        $root = $a->root . '/app';
        // Belum terpasang: rute lain dialihkan ke /install, POST lain 503.
        $r = $a->browser()->get('/produk');
        self::assertSame(302, $r->status);
        self::assertSame('/install', $r->location());
        self::assertSame(503, $a->browser()->post('/login', [], false)->status);

        $b = $a->browser();
        $form = $b->get('/install');
        self::assertSame(200, $form->status);
        self::assertSame([], $form->securityIssues());
        $token = KernelApp::tokenOf($root . '/storage');
        self::assertGreaterThanOrEqual(32, strlen($token));
        self::assertMatchesRegularExpression('#/install_token_[a-f0-9]{16}$#', (glob($root . '/storage/install_token_*') ?: [''])[0], 'nama token acak (S1)');
        self::assertFalse(is_file($root . '/storage/install_token'), 'nama tetap lama tidak dipakai');
        self::assertFalse(is_file($root . '/config/config.php'));

        // Token salah ditolak, tidak ada yang ditulis.
        $bad = $this->installPost($a, str_repeat('a', 40));
        self::assertSame(403, $bad->status);
        self::assertFalse(is_file($root . '/config/config.php'));
        self::assertFalse(is_file($root . '/storage/installed.lock'));

        $ok = $this->installPost($a, $token);
        clearstatcache();
        self::assertSame(200, $ok->status);
        self::assertSame('no-store', $ok->header('cache-control'));
        self::assertMatchesRegularExpression('#https://app\.contoh\.test/auth/reset/[A-Za-z0-9._-]+#', $ok->body);

        $cfgFile = $root . '/config/config.php';
        self::assertTrue(is_file($cfgFile));
        self::assertSame('0600', substr(sprintf('%o', fileperms($cfgFile)), -4));
        $cfg = (static function (string $f): array {
            /** @var array<string,mixed> */
            return require $f;
        })($cfgFile);
        self::assertSame('https://app.contoh.test', $cfg['APP_URL']);
        self::assertIsString($cfg['APP_KEY']);
        self::assertGreaterThanOrEqual(32, strlen($cfg['APP_KEY']));
        self::assertTrue(is_file($root . '/storage/installed.lock'));
        self::assertSame([], glob($root . '/storage/install_token*') ?: [], 'token instal harus dihapus');
        self::assertSame([], glob($root . '/storage/canary*') ?: [], 'layout normal: tanpa kanari');

        $u = $a->pdo()->query('SELECT email, status, password_hash FROM users')->fetchAll(\PDO::FETCH_ASSOC);
        self::assertCount(1, $u);
        self::assertSame(KernelApp::ADMIN_EMAIL, $u[0]['email']);
        self::assertSame('pending', $u[0]['status']);
        self::assertNull($u[0]['password_hash'], 'admin pertama tanpa password sampai tautan reset dibuka');
        $roles = $a->pdo()->query('SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id')->fetchAll(\PDO::FETCH_COLUMN);
        self::assertSame(['admin'], $roles);

        $a->deploy(); // 500 tanpa compile adalah bug terpisah (INT-01b)
        // Setelah terpasang /install = 404 (GET dan POST) dan instal ulang tidak menimpa apa pun.
        self::assertSame(404, $a->browser()->get('/install')->status);
        clearstatcache();
        $again = $this->installPost($a, $token);
        self::assertSame(404, $again->status);
        self::assertSame($cfg['APP_KEY'], ((static fn(string $f): array => require $f)($cfgFile))['APP_KEY']);

        // Login admin pending selalu gagal generik.
        $l = $a->browser()->login(KernelApp::ADMIN_EMAIL, 'apa saja yang panjang 123');
        self::assertSame(401, $l->status);
        self::assertStringNotContainsString('pending', strtolower($l->body));
    }

    /**
     * Bug: rilis yang baru diinstal belum punya cache compile, dan index.php memanggil Definitions::allowlist()
     * (via buildUploads) sebelum rute dilayani -> setiap request (termasuk tautan reset admin) 500.
     */
    public function test_INT_01b_tautan_reset_admin_berfungsi_tepat_setelah_instal_tanpa_compile(): void
    {
        $a = KernelApp::fresh();
        $b = $a->browser();
        $b->get('/install');
        $ok = $this->installPost($a, KernelApp::tokenOf($a->root . '/app/storage'));
        self::assertSame(200, $ok->status);
        if (preg_match('#(/auth/reset/[A-Za-z0-9._-]+)#', $ok->body, $m) !== 1) {
            self::fail('tautan reset tidak ada di halaman instal');
        }
        $r = $a->browser('198.51.100.50')->get($m[1]);
        self::assertSame(302, $r->status, 'tautan reset harus dapat dibuka pada instalasi baru: ' . $r->status);
    }

    /** INT-F4: GET / anonim -> /login; admin -> halaman pertama; peran tanpa halaman -> 404; tidak pernah di-cache. */
    public function test_INT_F4_rute_root_mengalihkan_sesuai_akses(): void
    {
        $a = KernelApp::installed(deploy: true);
        $anon = $a->browser('198.51.100.71')->get('/');
        self::assertSame(302, $anon->status);
        self::assertSame('/login', $anon->location());
        $adm = $a->loggedIn();
        $r = $adm->get('/');
        self::assertSame(302, $r->status);
        self::assertSame('/produk', $r->location());
        self::assertFileDoesNotExist($a->root . '/public_html/_pc/index.html');
        $a->newUser('staf@example.test');
        $k = $a->loggedIn('staf@example.test', '198.51.100.72');
        $kr = $k->get('/');
        self::assertSame(302, $kr->status);
        self::assertSame('/produk', $kr->location());
        $adm->get('/admin/peran');
        self::assertSame(302, $adm->post('/admin/peran', ['name' => 'tamu', 'label' => 'Tamu'])->status);
        $a->newUser('tamu@example.test', ['tamu']);
        $t = $a->browser('198.51.100.73');
        $t->login('tamu@example.test', KernelApp::PASSWORD);
        self::assertSame(404, $t->get('/')->status);
    }

    /** Build otomatis NYATA: tanpa deploy manual, request pertama setelah instal sudah punya rute, menu, dan tabel model. */
    public function test_INT_01c_build_otomatis_membuat_rute_dan_tabel_pada_request_pertama(): void
    {
        $a = KernelApp::installed(deploy: false);
        $adm = $a->loggedIn();
        self::assertSame(302, $adm->get('/')->status);
        $page = $adm->get('/produk');
        self::assertSame(200, $page->status);
        self::assertStringContainsString('href="/produk"', $page->body);
        $adm->get('/produk/baru');
        $r = $adm->post('/produk', ['nama' => 'Barang Otomatis', 'stok' => '3']);
        self::assertSame(302, $r->status);
        self::assertSame(1, (int) $a->pdo()->query("SELECT COUNT(*) FROM produk WHERE nama = 'Barang Otomatis'")->fetchColumn());
        self::assertSame(0, (int) $a->pdo()->query('SELECT COUNT(*) FROM kategori')->fetchColumn(), 'tabel kosong, tanpa data dummy');
    }

    // ---------- INT-02 ----------

    public function test_INT_02_reset_password_sekali_pakai_login_totp_csrf_dan_logout(): void
    {
        $a = KernelApp::installed(deploy: true);
        $pdo = $a->pdo();
        self::assertSame('active', $pdo->query('SELECT status FROM users WHERE id = 1')->fetchColumn());
        self::assertStringStartsWith('$argon2id$', (string) $pdo->query('SELECT password_hash FROM users WHERE id = 1')->fetchColumn());

        // Tautan reset sekali pakai: pemakaian kedua gagal.
        $b = $a->browser();
        $b->get('/auth/forgot');
        $b->post('/auth/forgot', ['email' => KernelApp::ADMIN_EMAIL]);
        $tok = $a->lastMailToken(KernelApp::ADMIN_EMAIL);
        $b2 = $a->browser('198.51.100.60');
        $b2->follow($b2->get('/auth/reset/' . $tok));
        $pw2 = 'password kedua yang panjang 77';
        self::assertSame(302, $b2->post('/auth/reset', ['password' => $pw2, 'password2' => $pw2])->status);
        $b3 = $a->browser('198.51.100.61');
        $b3->get('/auth/reset/' . $tok);
        $pw3 = 'password ketiga yang panjang 88';
        $reuse = $b3->post('/auth/reset', ['password' => $pw3, 'password2' => $pw3]);
        self::assertGreaterThanOrEqual(400, $reuse->status, 'token bekas harus tidak valid');
        self::assertSame(401, $a->browser('198.51.100.66')->login(KernelApp::ADMIN_EMAIL, $pw3)->status);
        // Password lama tidak lagi berlaku, yang baru berlaku.
        self::assertSame(401, $a->browser('198.51.100.62')->login(KernelApp::ADMIN_EMAIL, KernelApp::PASSWORD)->status);

        // Login -> sesi; id sesi dan token CSRF berganti saat login.
        $u = $a->browser('198.51.100.63');
        $u->get('/login');
        $sidBefore = $u->sessionId();
        $csrfBefore = $u->csrf;
        self::assertNotSame('', $csrfBefore);
        $r = $u->post('/login', ['email' => KernelApp::ADMIN_EMAIL, 'password' => $pw2]);
        self::assertSame(302, $r->status);
        self::assertSame('/', $r->location());
        self::assertNotSame($sidBefore, $u->sessionId(), 'id sesi wajib diregenerasi saat login');
        $page = $u->get('/produk');
        self::assertSame(200, $page->status);
        self::assertNotSame($csrfBefore, $u->csrf, 'token CSRF wajib dirotasi setelah login');
        // Token CSRF lama tidak lagi berlaku.
        self::assertSame(419, $u->post('/peran-aktif', ['role' => 'admin', '_csrf' => $csrfBefore], false)->status);
        // Tanpa token sama sekali: 419 dan header keamanan tetap ada.
        $no = $u->post('/logout', [], false);
        self::assertSame(419, $no->status);
        self::assertSame([], $no->securityIssues());

        // TOTP: aktifkan, logout, login butuh kode; kode salah ditolak; kode dipakai ulang ditolak.
        $u->get('/auth/2fa');
        $begin = $u->post('/auth/2fa/begin');
        self::assertSame(200, $begin->status);
        if (preg_match('/Kunci: ([A-Z2-7]+)/', $begin->body, $m) !== 1) {
            self::fail('kunci TOTP tidak tampil');
        }
        $secret = $m[1];
        $codeNow = Totp::code($secret, Totp::stepAt(time()));
        $conf = $u->post('/auth/2fa/confirm', ['code' => $codeNow]);
        self::assertSame(200, $conf->status);
        self::assertStringContainsString('Simpan kode pemulihan', $conf->body);
        $u->post('/logout');

        $v = $a->browser('198.51.100.64');
        $v->get('/login');
        $r = $v->post('/login', ['email' => KernelApp::ADMIN_EMAIL, 'password' => $pw2]);
        self::assertSame('/auth/otp', $r->location());
        self::assertSame(302, $r->status);
        self::assertSame(302, $v->get('/produk')->status, 'sebelum OTP belum ada sesi penuh');
        $v->get('/auth/otp');
        self::assertSame(401, $v->post('/auth/otp', ['code' => '000000'])->status);
        $step = Totp::stepAt(time());
        $code = Totp::code($secret, $step);
        $ok = $v->post('/auth/otp', ['code' => $code]);
        if ($ok->status === 401) { // kode awal konfirmasi sudah memakai langkah ini (anti-replay); pakai langkah berikut
            $code = Totp::code($secret, $step + 1);
            $ok = $v->post('/auth/otp', ['code' => $code]);
        }
        self::assertSame(302, $ok->status);
        self::assertSame('/', $ok->location());
        self::assertSame(200, $v->get('/produk')->status);
        $v->get('/produk');
        $v->post('/logout');
        // Pemakaian ulang kode yang sama pada login berikutnya ditolak.
        $w = $a->browser('198.51.100.65');
        $w->get('/login');
        $w->post('/login', ['email' => KernelApp::ADMIN_EMAIL, 'password' => $pw2]);
        $w->get('/auth/otp');
        self::assertSame(401, $w->post('/auth/otp', ['code' => $code])->status, 'replay kode TOTP harus ditolak');
    }

    public function test_INT_02b_logout_mencabut_sesi_di_server(): void
    {
        $a = KernelApp::installed();
        $u = $a->loggedIn();
        $sid = $u->sessionId();
        self::assertNotNull($sid);
        self::assertSame(200, $u->get('/produk')->status);
        $u->get('/produk');
        $out = $u->post('/logout');
        self::assertSame(302, $out->status);
        self::assertSame('/login', $out->location());
        // Memutar ulang cookie sesi lama tidak memulihkan akses.
        $replay = $a->browser('198.51.100.70');
        $replay->cookies = ['bf_sid' => $sid];
        $replay->cookies += ['__Host-bf_sid' => $sid];
        $r = $replay->get('/produk');
        self::assertSame(302, $r->status);
        self::assertSame('/login', $r->location());
        self::assertSame(302, $replay->get('/admin/pengguna')->status);
    }

    // ---------- INT-03 ----------

    public function test_INT_03_admin_kelola_pengguna_peran_ganti_peran_dan_nonaktif_mencabut_sesi(): void
    {
        $a = KernelApp::installed();
        $adm = $a->loggedIn();
        $adm->get('/admin/peran');
        $r = $adm->post('/admin/peran', ['name' => 'kasir', 'label' => 'Kasir']);
        self::assertSame(302, $r->status);
        self::assertStringContainsString('kasir', $adm->get('/admin/peran')->body);
        // Peran sistem tidak dapat dihapus.
        $adminRoleId = (int) $a->pdo()->query("SELECT id FROM roles WHERE name = 'admin'")->fetchColumn();
        $adm->post('/admin/peran/' . $adminRoleId . '/hapus');
        self::assertSame(1, (int) $a->pdo()->query("SELECT COUNT(*) FROM roles WHERE name = 'admin'")->fetchColumn());

        $uid = $a->newUser('kasir1@contoh.test', ['staf', 'kasir']);
        $roles = $a->pdo()->query('SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ' . $uid . ' ORDER BY r.name')->fetchAll(\PDO::FETCH_COLUMN);
        self::assertSame(['kasir', 'staf'], $roles);

        $u = $a->loggedIn('kasir1@contoh.test', '198.51.100.81');
        $u->get('/produk');
        // Pengguna biasa tidak boleh ke /admin/*.
        $f = $u->get('/admin/pengguna');
        self::assertSame(403, $f->status);
        self::assertSame([], $f->securityIssues());
        self::assertSame(403, $u->post('/admin/peran', ['name' => 'x', 'label' => 'x'])->status);

        // Ganti peran aktif: hanya peran yang dimiliki; sid + CSRF dirotasi.
        $sid = $u->sessionId();
        $csrf = $u->csrf;
        self::assertSame(403, $u->post('/peran-aktif', ['role' => 'admin'])->status);
        $sw = $u->post('/peran-aktif', ['role' => 'kasir']);
        self::assertSame(302, $sw->status);
        self::assertNotSame($sid, $u->sessionId(), 'sesi diregenerasi saat ganti peran');
        $u->get('/produk');
        self::assertNotSame($csrf, $u->csrf, 'CSRF dirotasi saat ganti peran');
        self::assertSame(403, $u->get('/admin/pengguna')->status);

        // Menonaktifkan: sesi aktif langsung tidak berlaku, login baru gagal; diaktifkan lagi bisa login.
        $adm->get('/admin/pengguna/' . $uid);
        $d = $adm->post('/admin/pengguna/' . $uid . '/status', ['status' => 'disabled']);
        self::assertSame(302, $d->status);
        $after = $u->get('/produk');
        self::assertSame(302, $after->status);
        self::assertSame('/login', $after->location(), 'sesi pengguna nonaktif harus dicabut');
        self::assertSame(401, $a->browser('198.51.100.82')->login('kasir1@contoh.test', KernelApp::PASSWORD)->status);
        self::assertSame(0, (int) $a->pdo()->query('SELECT COUNT(*) FROM remember_tokens WHERE user_id = ' . $uid)->fetchColumn());
        // Admin tidak bisa menonaktifkan/menghapus dirinya sendiri atau menghapus admin terakhir.
        $adm->post('/admin/pengguna/1/status', ['status' => 'disabled']);
        self::assertSame('active', $a->pdo()->query('SELECT status FROM users WHERE id = 1')->fetchColumn());
        $adm->post('/admin/pengguna/1/hapus');
        self::assertSame(1, (int) $a->pdo()->query('SELECT COUNT(*) FROM users WHERE id = 1')->fetchColumn());
        $adm->post('/admin/pengguna/' . $uid . '/status', ['status' => 'active']);
        self::assertSame(302, $a->browser('198.51.100.83')->login('kasir1@contoh.test', KernelApp::PASSWORD)->status);
    }
}
