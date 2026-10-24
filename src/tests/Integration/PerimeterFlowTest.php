<?php

declare(strict_types=1);

namespace bFramework\Tests\Integration;

use bFramework\Tests\Fixtures\KernelApp;
use PHPUnit\Framework\TestCase;

/** INT-10 (F2 perimeter, F12 lockout, F1 mode dev/produksi, F10 error): rate limit, HostGuard fail-closed, dev vs produksi. */
final class PerimeterFlowTest extends TestCase
{
    private ?KernelApp $app = null;

    protected function tearDown(): void
    {
        $this->app?->destroy();
        $this->app = null;
    }

    public function test_INT_10a_lockout_login_per_akun_lintas_ip_dan_tanpa_membedakan_akun_nyata_atau_palsu(): void
    {
        $a = $this->app = KernelApp::installed();
        $a->newUser('korban@contoh.test');
        $statuses = ['nyata' => [], 'palsu' => []];
        foreach (['nyata' => 'korban@contoh.test', 'palsu' => 'hantu@contoh.test'] as $k => $email) {
            for ($i = 1; $i <= 7; $i++) { // IP berbeda tiap percobaan: kunci per akun, bukan hanya per IP
                $b = $a->browser('198.51.100.' . ($k === 'nyata' ? 100 + $i : 120 + $i));
                $statuses[$k][] = $b->login($email, 'salah-salah-salah-' . $i)->status;
            }
        }
        self::assertSame([401, 401, 401, 401, 401, 429, 429], $statuses['nyata']);
        self::assertSame($statuses['nyata'], $statuses['palsu'], 'perilaku identik untuk akun nyata dan palsu');
        // Saat terkunci, password BENAR pun ditolak (429), tanpa sesi.
        $b = $a->browser('198.51.100.150');
        $r = $b->login('korban@contoh.test', KernelApp::PASSWORD);
        self::assertSame(429, $r->status);
        self::assertSame([], $r->securityIssues());
        foreach (array_keys($r->setCookies()) as $name) {
            self::assertStringNotContainsString('remember', $name, 'tidak ada cookie ingat-saya saat terkunci');
        }
        self::assertSame(302, $b->get('/produk')->status);
        // Akun lain tidak ikut terkunci.
        self::assertSame(302, $a->browser('198.51.100.151')->login(KernelApp::ADMIN_EMAIL, KernelApp::PASSWORD)->status);
        self::assertStringNotContainsString(KernelApp::PASSWORD, $a->appLog(), 'password tak masuk log');
        self::assertStringNotContainsString('salah-salah', $a->appLog());
    }

    public function test_INT_10b_lockout_per_ip_dan_throttle_email_lupa_password(): void
    {
        $a = $this->app = KernelApp::installed();
        $codes = [];
        for ($i = 1; $i <= 33; $i++) {
            $codes[] = $a->browser('198.51.100.190')->login("orang$i@contoh.test", 'salah-salah-salah')->status;
        }
        self::assertSame(array_fill(0, 30, 401), array_slice($codes, 0, 30));
        self::assertSame([429, 429, 429], array_slice($codes, 30));
        // IP lain tetap boleh.
        self::assertSame(302, $a->browser('198.51.100.201')->login(KernelApp::ADMIN_EMAIL, KernelApp::PASSWORD)->status);

        // Lupa password: respons selalu generik; email dibatasi 3/jam per akun.
        $texts = [];
        for ($i = 1; $i <= 5; $i++) {
            $b = $a->browser('198.51.100.' . (210 + $i));
            $b->get('/auth/forgot');
            $r = $b->post('/auth/forgot', ['email' => KernelApp::ADMIN_EMAIL]);
            $texts[] = $r->status;
        }
        $a->mails();
        $resets = array_filter($a->mails(), static fn(array $m): bool => $m['to'] === KernelApp::ADMIN_EMAIL && str_contains($m['body'], '/auth/reset/'));
        self::assertCount(3, $resets, 'maks 3 email reset per jam per akun');
        $a->newUser('segar@contoh.test');
        $b = $a->browser('198.51.100.230');
        $b->get('/auth/forgot');
        $real = $b->post('/auth/forgot', ['email' => 'segar@contoh.test']);
        $b2 = $a->browser('198.51.100.231');
        $b2->get('/auth/forgot');
        $fake = $b2->post('/auth/forgot', ['email' => 'tidak-ada@contoh.test']);
        self::assertSame($fake->status, $real->status);
        self::assertSame(strip_tags(preg_replace('/name="_csrf" value="[a-f0-9]+"|nonce="[a-f0-9]+"/', '', $fake->body) ?? ''), strip_tags(preg_replace('/name="_csrf" value="[a-f0-9]+"|nonce="[a-f0-9]+"/', '', $real->body) ?? ''), 'tidak membocorkan keberadaan akun');
        // Tautan di email memakai APP_URL, bukan Host/X-Forwarded-Host dari request.
        $c = $a->browser('198.51.100.232');
        $c->get('/auth/forgot');
        $a->send('POST', '/auth/forgot', ['email' => 'korban2@contoh.test', '_csrf' => $c->csrf], [], ['Cookie' => 'bf_sid=' . ($c->sessionId() ?? ''), 'X-Forwarded-Host' => 'evil.example', 'X-Int-Remote' => '198.51.100.232']);
        foreach ($a->mails() as $m) {
            self::assertStringNotContainsString('evil.example', $m['body']);
            if (str_contains($m['body'], '/auth/reset/')) {
                self::assertStringContainsString('https://app.contoh.test/auth/reset/', $m['body']);
            }
        }
    }

    public function test_INT_10c_hostguard_fail_closed(): void
    {
        $a = $this->app = KernelApp::installed();
        $get = static fn(string $host): \bFramework\Tests\Fixtures\KernelResp => $a->send('GET', '/login', [], [], ['Host' => $host, 'X-Int-Remote' => '198.51.100.240'], true);
        self::assertSame(200, $get('app.contoh.test')->status);
        self::assertSame(200, $get('APP.Contoh.TEST')->status, 'host tak peka huruf besar-kecil');
        foreach (['evil.example', 'app.contoh.test.evil.example', 'evil.example/app.contoh.test', 'app.contoh.test@evil.example', "app.contoh.test\tx", ''] as $h) {
            $r = $get($h);
            self::assertGreaterThanOrEqual(400, $r->status, "Host '$h'");
            self::assertLessThan(500, $r->status, "Host '$h'");
            self::assertSame([], $r->securityIssues(), "Host '$h' tetap membawa header keamanan");
            self::assertStringNotContainsString('evil.example', $r->body);
        }
        // Pencantuman X-Forwarded-Host tidak mengubah keputusan.
        self::assertSame(400, $a->send('GET', '/login', [], [], ['Host' => 'evil.example', 'X-Forwarded-Host' => 'app.contoh.test'], true)->status);
        self::assertSame(200, $a->send('GET', '/login', [], [], ['Host' => 'app.contoh.test', 'X-Forwarded-Host' => 'evil.example'], true)->status);
        // Host tambahan harus eksplisit di ALLOWED_HOSTS; entri tak valid diabaikan, bukan "izinkan semua".
        $a->mergeConfig(['ALLOWED_HOSTS' => ['app.contoh.test', 'alias.contoh.test', '*', 'bukan host!']]);
        self::assertSame(200, $get('alias.contoh.test')->status);
        self::assertSame(400, $get('lain.contoh.test')->status);
        self::assertSame(400, $get('evil.example')->status);
        // ALLOWED_HOSTS kosong -> host dari APP_URL saja.
        $a->mergeConfig(['ALLOWED_HOSTS' => ['!!!']]);
        self::assertSame(200, $get('app.contoh.test')->status);
        self::assertSame(400, $get('alias.contoh.test')->status);
        // POST ke host asing juga ditolak sebelum menyentuh logika login.
        $r = $a->send('POST', '/login', ['email' => KernelApp::ADMIN_EMAIL, 'password' => KernelApp::PASSWORD], [], ['Host' => 'evil.example', 'X-Int-Remote' => '198.51.100.241'], true);
        self::assertSame(400, $r->status);
        self::assertSame([], $r->setCookies());
        // APP_URL hilang pada instalasi terpasang -> 503 (tidak melayani tanpa HostGuard).
        $f = $a->root . '/app/config/config.php';
        $cfg = (string) file_get_contents($f);
        file_put_contents($f, str_replace("'APP_URL' => 'https://app.contoh.test'", "'APP_URL' => ''", $cfg));
        $r = $get('app.contoh.test');
        self::assertSame(503, $r->status);
        self::assertStringNotContainsString('/login', $r->body);
    }

    public function test_INT_10d_mode_dev_vs_produksi_src_detail_dan_fail_closed_env(): void
    {
        $a = $this->app = KernelApp::installed();
        $a->defineProdukOwner();
        $adm = $a->loggedIn();
        $adm->get('/produk/baru');
        $invalid = static fn(): \bFramework\Tests\Fixtures\KernelResp => $adm->post('/produk', ['nama' => '', 'stok' => '-1']);

        $prod = $invalid();
        self::assertSame(422, $prod->status);
        self::assertStringNotContainsString('models/produk.json', $prod->body, 'produksi: _src tidak tampil');
        self::assertStringNotContainsString('#/fields', $prod->body);
        $nf = $adm->get('/tidak-ada');
        self::assertStringNotContainsString('storage/logs', $nf->body);

        $a->mergeConfig(['APP_ENV' => 'dev']);
        $adm->get('/produk/baru');
        $dev = $invalid();
        self::assertSame(422, $dev->status);
        self::assertStringContainsString('models/produk.json', $dev->body, 'dev: _src tampil untuk debugging');
        self::assertStringContainsString('storage/logs', $adm->get('/tidak-ada')->body);
        self::assertSame(200, $adm->get('/_builder')->status, 'builder hanya hidup di dev');

        // Nilai APP_ENV selain allowlist = produksi (fail-closed); tidak ada _src, builder 404.
        foreach (['production', 'prod', 'Staging', 'devx', ' ', '0', 'false'] as $env) {
            $a->mergeConfig(['APP_ENV' => $env]);
            $adm->get('/produk/baru');
            $r = $invalid();
            self::assertStringNotContainsString('models/produk.json', $r->body, "APP_ENV='$env'");
            self::assertSame(404, $adm->get('/_builder')->status, "APP_ENV='$env'");
        }
        // Alias dev yang sah (allowlist) tetap dev, termasuk dengan huruf besar dan spasi.
        $a->mergeConfig(['APP_ENV' => ' LOCAL ']);
        $adm->get('/produk/baru');
        self::assertStringContainsString('models/produk.json', $invalid()->body);

        // Produksi: 500 tidak membocorkan detail (jalur, SQL) dan masuk log; dev pun tidak menampilkan trace ke klien.
        $a->mergeConfig(['APP_ENV' => 'production']);
        $pdo = $a->pdo();
        $pdo->exec('ALTER TABLE produk RENAME TO produk_x');
        try {
            $r = $adm->get('/produk');
        } finally {
            $pdo->exec('ALTER TABLE produk_x RENAME TO produk');
        }
        self::assertSame(500, $r->status);
        foreach (['SQLSTATE', 'produk_x', 'Stack trace', '/tmp/', 'Query.php'] as $leak) {
            self::assertStringNotContainsString($leak, $r->body);
        }
        self::assertStringContainsString('"lvl":"error"', $a->appLog());
    }
}
