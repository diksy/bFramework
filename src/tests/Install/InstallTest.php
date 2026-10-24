<?php

declare(strict_types=1);

namespace bFramework\Tests\Install;

use bFramework\Auth\AccountStore;
use bFramework\Auth\AuthSchema;
use bFramework\Auth\OneTimeToken;
use bFramework\Core\Csrf;
use bFramework\Core\CsrfMiddleware;
use bFramework\Core\Kernel;
use bFramework\Core\RateLimiter;
use bFramework\Core\Request;
use bFramework\Core\Router;
use bFramework\Core\Template;
use bFramework\Install\HostPolicy;
use bFramework\Install\InstallController;
use bFramework\Install\InstallGate;
use bFramework\Install\InstallInput;
use bFramework\Install\InstallRejected;
use bFramework\Install\Installer;
use bFramework\Runtime\Connection;
use bFramework\Tests\Fixtures\ArraySessionStore;
use bFramework\Tests\Fixtures\CaptureLogger;
use bFramework\Tests\Fixtures\FakeClock;
use PHPUnit\Framework\TestCase;

/** Hanya data dummy; semua berkas di bawah sys_get_temp_dir(). */
final class InstallTest extends TestCase
{
    private string $root;
    private string $app;
    private string $docroot;
    private FakeClock $clock;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/inst_' . bin2hex(random_bytes(6));
        $this->app = $this->root . '/app';
        $this->docroot = $this->root . '/public_html';
        mkdir($this->app . '/storage', 0750, true);
        mkdir($this->app . '/config', 0750, true);
        mkdir($this->docroot, 0750, true);
        $this->clock = new FakeClock();
    }

    protected function tearDown(): void
    {
        self::rm($this->root);
    }

    private static function rm(string $d): void
    {
        foreach (glob($d . '/{,.}*', GLOB_BRACE) ?: [] as $f) {
            if (basename($f) === '.' || basename($f) === '..') {
                continue;
            }
            is_dir($f) && !is_link($f) ? self::rm($f) : @unlink($f);
        }
        @rmdir($d);
    }

    private function installer(?string $app = null, ?CaptureLogger $log = null): Installer
    {
        return new Installer($app ?? $this->app, $this->docroot, $this->clock, $log);
    }

    private function token(Installer $i): string
    {
        $i->ensureToken();
        return trim((string) file_get_contents($i->tokenPath()));
    }

    /** Lulus uji kanari (browser melaporkan terblokir) pada mode cadangan. */
    private function prove(Installer $i): void
    {
        self::assertNotNull($i->ensureCanary());
        self::assertTrue($i->reportCanary(true));
    }

    /** @param array<string,mixed> $o */
    private function input(string $token, array $o = []): InstallInput
    {
        $o += [
            'appUrl' => 'http://localhost:8080', 'adminEmail' => 'Admin@Contoh.test', 'adminName' => 'Admin Dummy',
            'installToken' => $token,
        ];
        return new InstallInput(...$o);
    }

    public function test_SEC_CONF_tanpa_token_atau_token_salah_ditolak_dan_tidak_ada_efek(): void
    {
        $i = $this->installer();
        $good = $this->token($i);
        foreach (['', 'salah', substr($good, 0, -1)] as $bad) {
            try {
                $i->install($this->input($bad));
                self::fail('Harus ditolak');
            } catch (InstallRejected $e) {
                self::assertSame(403, $e->status);
            }
        }
        self::assertFalse($i->isInstalled());
        self::assertFileDoesNotExist($this->app . '/config/config.php');
        self::assertFileDoesNotExist($this->app . '/storage/app.sqlite');
    }

    public function test_SEC_CONF_tanpa_file_token_installer_menolak(): void
    {
        $this->expectException(InstallRejected::class);
        $this->installer()->install($this->input('x'));
    }

    public function test_SEC_CONF_token_acak_izin_0600_dan_berbeda_antar_instalasi(): void
    {
        $a = $this->installer();
        $t1 = $this->token($a);
        self::assertSame(0600, fileperms($a->tokenPath()) & 0777);
        self::assertGreaterThanOrEqual(32, strlen($t1));
        $other = $this->root . '/app2';
        mkdir($other . '/storage', 0750, true);
        mkdir($other . '/config', 0750, true);
        self::assertNotSame($t1, $this->token($this->installer($other)));
    }

    public function test_SEC_CONF_01_instal_sukses_config_0600_app_key_unik_dan_lock(): void
    {
        $log = new CaptureLogger();
        $i = $this->installer(null, $log);
        $tok = $this->token($i);
        $res = $i->install($this->input($tok, ['mailFrom' => 'noreply@contoh.test']));
        self::assertTrue($i->isInstalled());
        self::assertFileDoesNotExist($i->tokenPath(), 'token dihapus sesudah instal');
        $cfgFile = $this->app . '/config/config.php';
        self::assertSame(0600, fileperms($cfgFile) & 0777);
        $cfg = $this->loadConfig($cfgFile);
        self::assertGreaterThanOrEqual(32, strlen(base64_decode($cfg['APP_KEY'], true) ?: ''));
        self::assertSame('http://localhost:8080', $cfg['APP_URL']);
        self::assertSame(['localhost:8080'], $cfg['ALLOWED_HOSTS']);
        self::assertSame(['registration' => false], $cfg['auth']);
        self::assertSame('production', $cfg['APP_ENV']);
        self::assertStringStartsWith('http://localhost:8080/auth/reset/', $res->resetUrl);
        self::assertStringNotContainsString($cfg['APP_KEY'], $log->all());
        self::assertStringNotContainsString($tok, $log->all());
        self::assertStringNotContainsString($cfg['APP_KEY'], $res->resetUrl);

        // Instalasi kedua di direktori lain: APP_KEY berbeda.
        $other = $this->root . '/app2';
        mkdir($other . '/storage', 0750, true);
        mkdir($other . '/config', 0750, true);
        $j = $this->installer($other);
        $j->install($this->input($this->token($j)));
        self::assertNotSame($cfg['APP_KEY'], $this->loadConfig($other . '/config/config.php')['APP_KEY']);
    }

    /** @return array<string,mixed> */
    private function loadConfig(string $file): array
    {
        $d = (static fn(string $f): mixed => require $f)($file);
        self::assertIsArray($d);
        return $d;
    }

    public function test_SEC_CONF_instal_ulang_ditolak_404(): void
    {
        $i = $this->installer();
        $tok = $this->token($i);
        $i->install($this->input($tok));
        $before = (string) file_get_contents($this->app . '/config/config.php');
        try {
            $i->install($this->input($tok, ['adminEmail' => 'lain@contoh.test']));
            self::fail('Harus ditolak');
        } catch (InstallRejected $e) {
            self::assertSame(404, $e->status);
        }
        self::assertSame($before, (string) file_get_contents($this->app . '/config/config.php'));
        $i->ensureToken();
        self::assertFileDoesNotExist($i->tokenPath(), 'tidak ada token baru setelah terpasang');
    }

    public function test_SEC_CONF_race_dua_instal_bersamaan_hanya_satu(): void
    {
        $i = $this->installer();
        $tok = $this->token($i);
        // Instal lain sedang memegang kunci eksklusif.
        $held = fopen($this->app . '/storage/install.busy', 'c');
        self::assertNotFalse($held);
        self::assertTrue(flock($held, LOCK_EX | LOCK_NB));
        try {
            $i->install($this->input($tok));
            self::fail('Harus ditolak');
        } catch (InstallRejected $e) {
            self::assertSame(409, $e->status);
        }
        self::assertFalse($i->isInstalled());
        flock($held, LOCK_UN);
        fclose($held);
        // Balapan pada installed.lock sendiri: mode "x" menjamin satu pemenang.
        $i->install($this->input($tok));
        $a = @fopen($this->app . '/storage/' . Installer::LOCK_FILE, 'x');
        self::assertFalse($a);
    }

    public function test_SEC_CONF_injeksi_di_input_config_tidak_dieksekusi(): void
    {
        $i = $this->installer();
        $tok = $this->token($i);
        $evil = "x'.system('id').'\\";
        $marker = $this->root . '/pwned';
        $pass = "p'; file_put_contents('$marker','1'); //";
        $i->install($this->input($tok, [
            'mailFrom' => "o'brien@contoh.test", 'smtpHost' => 'smtp.contoh.test', 'smtpUser' => $evil, 'smtpPassword' => $pass,
        ]));
        $cfg = $this->loadConfig($this->app . '/config/config.php');
        self::assertFileDoesNotExist($marker);
        self::assertSame($evil, $cfg['SMTP_USER']);
        self::assertSame($pass, $cfg['SMTP_PASSWORD']);
        self::assertSame("o'brien@contoh.test", $cfg['MAIL_FROM']);
        exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($this->app . '/config/config.php') . ' 2>&1', $out, $rc);
        self::assertSame(0, $rc);
    }

    public function test_SEC_CONF_input_tidak_valid_ditolak_tanpa_efek(): void
    {
        $i = $this->installer();
        $tok = $this->token($i);
        $bad = [
            ['appUrl' => 'https://contoh.test/path'], ['appUrl' => 'javascript:alert(1)'], ['appUrl' => 'http://contoh.test'],
            ['appUrl' => 'https://a b.test'], ['adminEmail' => 'bukan-email'], ['adminName' => "A\nB"], ['adminName' => ''],
            ['dbFile' => '../x.sqlite'], ['dbFile' => 'x.php'], ['dbDriver' => 'pgsql'],
            ['dbDriver' => 'mysql', 'dbName' => 'a;drop', 'dbUser' => 'u'], ['dbDriver' => 'mysql', 'dbName' => 'd', 'dbHost' => 'h/../x'],
            ['mailFrom' => 'x'], ['smtpHost' => 'a b', 'smtpPort' => 587], ['allowedHosts' => ['*.contoh.test']],
            ['smtpHost' => 'smtp.contoh.test', 'smtpSecure' => 'none'],
        ];
        foreach ($bad as $o) {
            try {
                $i->install($this->input($tok, $o));
                self::fail('Harus ditolak: ' . json_encode($o));
            } catch (InstallRejected $e) {
                self::assertSame(422, $e->status, json_encode($o));
            }
        }
        self::assertFalse($i->isInstalled());
        self::assertFileDoesNotExist($this->app . '/config/config.php');
        self::assertFileDoesNotExist($this->app . '/storage/app.sqlite');
    }

    public function test_SEC_CONF_galat_koneksi_db_generik_tanpa_kredensial(): void
    {
        $i = $this->installer();
        $tok = $this->token($i);
        try {
            $i->install($this->input($tok, [
                'dbDriver' => 'mysql', 'dbHost' => '127.0.0.1', 'dbPort' => 1, 'dbName' => 'dbdummy', 'dbUser' => 'userdummy',
                'dbPassword' => 'RahasiaDummy123',
            ]));
            self::fail('Harus gagal');
        } catch (InstallRejected $e) {
            $all = $e->getMessage() . json_encode($e->errors) . $e->getTraceAsString();
            foreach (['RahasiaDummy123', 'userdummy', 'dbdummy', '127.0.0.1'] as $leak) {
                self::assertStringNotContainsString($leak, $all);
            }
        }
        self::assertFalse($i->isInstalled());
        self::assertFileDoesNotExist($this->app . '/config/config.php');
    }

    public function test_SEC_CONF_admin_pending_tanpa_password_peran_admin_dan_tautan_sekali_pakai(): void
    {
        $i = $this->installer();
        $res = $i->install($this->input($this->token($i)));
        $conn = Connection::sqlite($this->app . '/storage/app.sqlite');
        self::assertSame(0600, fileperms($this->app . '/storage/app.sqlite') & 0777);
        $acc = (new AccountStore($conn, $this->clock))->findByEmail('admin@contoh.test');
        self::assertNotNull($acc);
        self::assertSame('pending', $acc->status);
        self::assertNull($acc->passwordHash);
        self::assertSame(['admin'], (new AccountStore($conn, $this->clock))->roles($acc->id));
        self::assertSame(1, (int) $conn->pdo()->query('SELECT COUNT(*) FROM users')->fetchColumn());
        self::assertSame(1, (int) $conn->pdo()->query("SELECT COUNT(*) FROM sqlite_master WHERE name = 'files'")->fetchColumn());

        $token = substr($res->resetUrl, strlen('http://localhost:8080/auth/reset/'));
        $stored = $conn->pdo()->query('SELECT selector, token_hash FROM one_time_tokens')->fetchAll();
        self::assertCount(1, $stored);
        self::assertStringNotContainsString(explode('.', $token)[1], json_encode($stored) ?: '');
        $tokens = new OneTimeToken($conn, $this->clock);
        self::assertSame($acc->id, $tokens->consume($token, OneTimeToken::RESET));
        self::assertNull($tokens->consume($token, OneTimeToken::RESET), 'sekali pakai');
        // Tidak ada password/tautan di config.
        self::assertStringNotContainsString('auth/reset', (string) file_get_contents($this->app . '/config/config.php'));
    }

    public function test_AuthSchema_install_idempoten(): void
    {
        $conn = Connection::sqlite(':memory:');
        self::assertNotSame([], AuthSchema::install($conn));
        self::assertSame([], AuthSchema::install($conn));
    }

    public function test_instal_terputus_bisa_diulang_dengan_admin_yang_sama(): void
    {
        $i = $this->installer();
        $tok = $this->token($i);
        $conn = Connection::sqlite($this->app . '/storage/app.sqlite');
        AuthSchema::install($conn);
        (new AccountStore($conn, $this->clock))->create('admin@contoh.test', 'Sisa', null, 'pending');
        $i->install($this->input($tok));
        self::assertSame(1, (int) $conn->pdo()->query('SELECT COUNT(*) FROM users')->fetchColumn());
    }

    public function test_config_sudah_ada_instal_ditolak_dan_tidak_ditimpa(): void
    {
        file_put_contents($this->app . '/config/config.php', "<?php return ['APP_URL' => 'https://lama.test'];");
        $i = $this->installer();
        try {
            $i->install($this->input($this->token($i)));
            self::fail('Harus ditolak');
        } catch (InstallRejected) {
        }
        self::assertStringContainsString('lama.test', (string) file_get_contents($this->app . '/config/config.php'));
    }

    public function test_ARCH_02_mode_cadangan_app_dalam_docroot_peringatan_dan_penjaga(): void
    {
        $app = $this->docroot . '/app';
        mkdir($app . '/storage', 0750, true);
        mkdir($app . '/config', 0750, true);
        $i = $this->installer($app);
        $this->prove($i);
        $byId = [];
        foreach ($i->checks() as $c) {
            $byId[$c->id] = $c;
        }
        self::assertFalse($byId['app_outside_docroot']->ok);
        self::assertFalse($byId['app_outside_docroot']->fatal);
        self::assertStringContainsString('PERINGATAN', $byId['app_outside_docroot']->msg);
        self::assertTrue($byId['guard']->ok);
        self::assertFileExists($app . '/.htaccess');
        $i->install($this->input($this->token($i)));
        $h = (string) file_get_contents($app . '/.htaccess');
        self::assertStringContainsString('Require all denied', $h);
        self::assertStringContainsString('Deny from all', $h);
        self::assertStringStartsWith('<?php', (string) file_get_contents($app . '/config/config.php'));
        self::assertStringContainsString("defined('APP_BOOTED') || exit;", (string) file_get_contents($app . '/config/config.php'));
    }

    public function test_ARCH_02_penjaga_ada_sebelum_token_dibuat_mode_cadangan(): void
    {
        $app = $this->docroot . '/app';
        mkdir($app . '/storage', 0750, true);
        mkdir($app . '/config', 0750, true);
        $i = $this->installer($app);
        self::assertFileDoesNotExist($app . '/.htaccess');
        $this->prove($i);
        $i->ensureToken();
        self::assertFileExists($app . '/.htaccess');
        self::assertStringContainsString('Require all denied', (string) file_get_contents($app . '/.htaccess'));
        self::assertFileExists($i->tokenPath());
    }

    public function test_ARCH_02_token_tidak_dibuat_bila_penjaga_gagal_ditulis(): void
    {
        $app = $this->docroot . '/app';
        mkdir($app . '/storage', 0750, true);
        mkdir($app . '/config', 0750, true);
        mkdir($app . '/.htaccess'); // penghalang: penjaga tidak bisa ditulis
        $i = $this->installer($app);
        $this->prove($i);
        $i->ensureToken();
        self::assertFileDoesNotExist($i->tokenPath());
        $byId = [];
        foreach ($i->checks() as $c) {
            $byId[$c->id] = $c;
        }
        self::assertFalse($byId['guard']->ok);
        self::assertTrue($byId['guard']->fatal);
        $this->expectException(InstallRejected::class);
        $i->install($this->input('x'));
    }

    public function test_ARCH_02_penjaga_lemah_tidak_dianggap_siap(): void
    {
        $app = $this->docroot . '/app';
        mkdir($app . '/storage', 0750, true);
        mkdir($app . '/config', 0750, true);
        file_put_contents($app . '/.htaccess', "# kosong\n");
        $i = $this->installer($app);
        $this->prove($i);
        $i->ensureToken();
        self::assertStringContainsString('Deny from all', (string) file_get_contents($app . '/.htaccess'));
    }

    public function test_S1_logika_keputusan_kanari_js(): void
    {
        exec('command -v node 2>/dev/null', $o, $rc);
        if ($rc !== 0) {
            self::markTestSkipped('node tidak tersedia');
        }
        $out = [];
        exec('node ' . escapeshellarg(__DIR__ . '/canary.test.js') . ' 2>&1', $out, $rc);
        self::assertSame(0, $rc, implode("\n", $out));
    }

    private function fallbackApp(): string
    {
        $app = $this->docroot . '/app';
        mkdir($app . '/storage', 0750, true);
        mkdir($app . '/config', 0750, true);
        return $app;
    }

    public function test_S1_mode_cadangan_tanpa_bukti_kanari_token_tidak_dibuat_dan_instal_ditolak(): void
    {
        $i = $this->installer($this->fallbackApp());
        $i->ensureToken();
        self::assertSame([], glob($this->docroot . '/app/storage/install_token*') ?: []);
        $c = $i->ensureCanary();
        self::assertNotNull($c);
        self::assertMatchesRegularExpression('#^/app/storage/canary_[a-f0-9]{32}\.txt$#', $c['url']);
        self::assertStringStartsWith('bfcanary:', $c['content']);
        self::assertSame($c['content'], file_get_contents($this->docroot . $c['url']), 'URL kanari dipetakan ke berkas kanari');
        try {
            $i->install($this->input('x'));
            self::fail('Harus ditolak');
        } catch (InstallRejected $e) {
            self::assertSame(422, $e->status);
            self::assertStringContainsString('kanari', $e->getMessage());
        }
        $byId = [];
        foreach ($i->checks() as $ch) {
            $byId[$ch->id] = $ch;
        }
        self::assertFalse($byId['canary']->ok);
        self::assertTrue($byId['canary']->fatal);
    }

    public function test_S1_kanari_terbaca_instal_ditolak_kanari_dihapus_dan_tanpa_token(): void
    {
        $app = $this->fallbackApp();
        $i = $this->installer($app);
        self::assertNotNull($i->ensureCanary());
        self::assertFalse($i->reportCanary(false), 'browser membaca isi kanari');
        self::assertSame([], glob($app . '/storage/canary*') ?: [], 'kanari tidak tertinggal');
        self::assertFalse($i->canaryProven());
        $i->ensureToken();
        self::assertSame([], glob($app . '/storage/install_token*') ?: []);
        self::assertNotNull($i->ensureCanary(), 'kanari baru untuk percobaan ulang');
        self::assertNotSame('', basename((string) (glob($app . '/storage/canary*')[0] ?? '')));
    }

    public function test_S1_kanari_403_404_lanjut_token_acak_dan_kanari_tidak_tertinggal(): void
    {
        $app = $this->fallbackApp();
        $i = $this->installer($app);
        self::assertNotNull($i->ensureCanary());
        self::assertTrue($i->reportCanary(true));
        self::assertSame([], glob($app . '/storage/canary_*') ?: [], 'kanari dihapus setelah verifikasi');
        self::assertTrue($i->canaryProven());
        self::assertNull($i->ensureCanary(), 'terbukti: tidak perlu kanari lagi');
        $tok = $this->token($i);
        self::assertMatchesRegularExpression('#/install_token_[a-f0-9]{16}$#', $i->tokenPath());
        $i->install($this->input($tok));
        self::assertTrue($i->isInstalled());
        self::assertSame([], glob($app . '/storage/install_token*') ?: []);
        self::assertSame([], glob($app . '/storage/canary*') ?: [], 'penanda bukti dan kanari bersih');
    }

    public function test_S1_laporan_tanpa_kanari_tertunda_tidak_membuktikan_apa_pun(): void
    {
        $i = $this->installer($this->fallbackApp());
        self::assertFalse($i->reportCanary(true));
        self::assertFalse($i->canaryProven());
    }

    public function test_S1_layout_normal_tanpa_kanari(): void
    {
        $i = $this->installer();
        self::assertFalse($i->canaryRequired());
        self::assertNull($i->ensureCanary());
        self::assertFalse($i->reportCanary(true));
        $tok = $this->token($i);
        self::assertSame([], glob($this->app . '/storage/canary*') ?: []);
        $i->install($this->input($tok));
        self::assertTrue($i->isInstalled());
        foreach ($i->checks() as $c) {
            self::assertNotSame('canary', $c->id);
        }
    }

    public function test_S1_nama_token_acak_antar_instalasi_dan_tidak_di_halaman(): void
    {
        $a = $this->installer();
        $this->token($a);
        $other = $this->root . '/app2';
        mkdir($other . '/storage', 0750, true);
        mkdir($other . '/config', 0750, true);
        $b = $this->installer($other);
        $this->token($b);
        self::assertNotSame(basename($a->tokenPath()), basename($b->tokenPath()));
        self::assertMatchesRegularExpression('/^install_token_[a-f0-9]{16}$/', basename($a->tokenPath()));
        [$k] = $this->web();
        $get = $k->handle(new Request('GET', '/install', headers: ['host' => 'localhost:8080']));
        self::assertStringNotContainsString(basename($a->tokenPath()), $get->body);
    }

    /** @return array<string,array{0:string,1:bool}> */
    public static function guardProvider(): array
    {
        $ok = "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order allow,deny\n    Deny from all\n</IfModule>\n";
        return [
            'sah' => [$ok, true],
            'komentar saja' => ["# Require all denied\n# Deny from all\n", false],
            'komentar + longgar' => ["# Require all denied Deny from all\nRequire all granted\n", false],
            'allow from all' => [$ok . "Allow from all\n", false],
            'require all granted tambahan' => [$ok . "Require all granted\n", false],
            'satisfy any' => [$ok . "Satisfy any\n", false],
            'deny di konteks salah' => ["Require all denied\nDeny from all\n", false],
            'blok tak dikenal' => [$ok . "<Files x>\nRequire all granted\n</Files>\n", false],
            'ifmodule tak tertutup' => [substr($ok, 0, -12), false],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('guardProvider')]
    public function test_S1_guardPresent_memeriksa_direktif_efektif(string $htaccess, bool $valid): void
    {
        $app = $this->fallbackApp();
        file_put_contents($app . '/.htaccess', $htaccess);
        $i = $this->installer($app);
        $byId = [];
        foreach ($i->checks() as $c) {
            $byId[$c->id] = $c;
        }
        // checks() menulis ulang penjaga yang tidak sah; berkas sah dibiarkan apa adanya
        self::assertTrue($byId['guard']->ok);
        $now = file_get_contents($app . '/.htaccess');
        $valid ? self::assertSame($htaccess, $now) : self::assertNotSame($htaccess, $now, 'penjaga lemah diganti');
    }

    public function test_S1_controller_mode_cadangan_menampilkan_uji_kanari_dan_route_laporan(): void
    {
        $app = $this->fallbackApp();
        $i = $this->installer($app);
        $session = new ArraySessionStore();
        $csrf = new Csrf($session);
        $src = __DIR__ . '/../../app/core';
        $router = new Router();
        (new InstallController(
            $i,
            $csrf,
            new Template($src . '/Install/views', $this->root . '/cache'),
            new Template($src . '/Core/views', $this->root . '/cache'),
            new RateLimiter($this->root . '/rl'),
        ))->registerRoutes($router);
        $k = new Kernel($router, [new CsrfMiddleware($router, $csrf, $session)]);
        $h = ['host' => 'localhost:8080'];
        $get = $k->handle(new Request('GET', '/install', headers: $h));
        self::assertSame(200, $get->status);
        self::assertStringContainsString('canary-box', $get->body);
        self::assertStringContainsString('/app/storage/canary_', $get->body);
        self::assertStringContainsString('install-canary.js', $get->body);
        self::assertStringNotContainsString('name="install_token"', $get->body, 'formulir tersembunyi sebelum terbukti');
        self::assertSame([], glob($app . '/storage/install_token*') ?: []);
        $t = (string) $csrf->token();
        $bad = $k->handle(new Request('POST', '/install/canary', post: ['blocked' => '1']));
        self::assertSame(419, $bad->status, 'CSRF wajib');
        $exposed = $k->handle(new Request('POST', '/install/canary', post: ['_csrf' => $t, 'blocked' => '0']));
        self::assertSame(422, $exposed->status);
        self::assertSame([], glob($app . '/storage/install_token*') ?: []);
        $k->handle(new Request('GET', '/install', headers: $h));
        $ok = $k->handle(new Request('POST', '/install/canary', post: ['_csrf' => $t, 'blocked' => '1']));
        self::assertSame(200, $ok->status);
        self::assertCount(1, glob($app . '/storage/install_token_*') ?: []);
        self::assertSame([], glob($app . '/storage/canary_*') ?: []);
        $again = $k->handle(new Request('GET', '/install', headers: $h));
        self::assertStringContainsString('name="install_token"', $again->body);
        self::assertStringNotContainsString('canary-box', $again->body);
    }

    public function test_ARCH_02_mode_normal_app_di_luar_docroot_dan_prasyarat(): void
    {
        $byId = [];
        foreach ($this->installer()->checks() as $c) {
            $byId[$c->id] = $c;
        }
        self::assertTrue($byId['app_outside_docroot']->ok);
        foreach (['php', 'ext', 'pdo_driver', 'storage', 'config_absent'] as $id) {
            self::assertTrue($byId[$id]->ok, $id);
        }
        self::assertArrayNotHasKey('guard', $byId);
    }

    public function test_SEC_CONF_02_storage_dapat_ditulis_semua_orang_diperingatkan(): void
    {
        chmod($this->app . '/storage', 0777);
        $byId = [];
        foreach ($this->installer()->checks() as $c) {
            $byId[$c->id] = $c;
        }
        self::assertFalse($byId['perm']->ok);
        self::assertFalse($byId['perm']->fatal);
    }

    public function test_input_tidak_membocorkan_rahasia_lewat_dump(): void
    {
        $in = $this->input('TOKENDUMMY', ['dbPassword' => 'PWDUMMY', 'smtpPassword' => 'SMTPDUMMY']);
        ob_start();
        var_dump($in);
        print_r($in);
        $dump = (string) ob_get_clean();
        foreach (['TOKENDUMMY', 'PWDUMMY', 'SMTPDUMMY'] as $s) {
            self::assertStringNotContainsString($s, $dump);
        }
        self::assertSame(['localhost:8080'], $in->allowedHosts);
        self::assertFalse($in->registration);
    }

    public function test_SEC_REQ_03_host_diizinkan_default_dari_app_url_fail_closed(): void
    {
        self::assertSame(['app.contoh.test'], HostPolicy::allowed([], 'https://app.contoh.test'));
        self::assertSame(['app.contoh.test'], HostPolicy::allowed(['', 5, '*.x'], 'https://App.Contoh.test/'));
        self::assertSame(['a.test', 'b.test'], HostPolicy::allowed(['a.test', 'B.test'], 'https://app.contoh.test'));
        self::assertSame([], HostPolicy::allowed([], ''), 'tanpa APP_URL tetap kosong (HostGuard menolak semua)');
    }

    public function test_gate_sebelum_terpasang_hanya_install_dilayani(): void
    {
        $router = new Router();
        $router->add('GET', '/install', static fn(Request $r, array $p = []): \bFramework\Core\Response => \bFramework\Core\Response::html('i'));
        $k = new Kernel($router, [new InstallGate()]);
        $h = ['host' => 'localhost:8080'];
        self::assertSame(200, $k->handle(new Request('GET', '/install', headers: $h))->status);
        $r = $k->handle(new Request('GET', '/login', headers: $h));
        self::assertSame(302, $r->status);
        self::assertSame('/install', $r->headers['Location'] ?? null);
        self::assertSame(503, $k->handle(new Request('POST', '/login', headers: $h))->status);
        self::assertSame(400, $k->handle(new Request('GET', '/install', headers: ['host' => 'x y']))->status);
    }

    /** @return array{0:Kernel,1:ArraySessionStore,2:Installer} */
    private function web(int $rateMax = 10): array
    {
        $i = $this->installer();
        $session = new ArraySessionStore();
        $csrf = new Csrf($session);
        $src = __DIR__ . '/../../app/core';
        $router = new Router();
        (new InstallController(
            $i,
            $csrf,
            new Template($src . '/Install/views', $this->root . '/cache'),
            new Template($src . '/Core/views', $this->root . '/cache'),
            new RateLimiter($this->root . '/rl'),
            null,
            $rateMax,
        ))->registerRoutes($router);
        return [new Kernel($router, [new CsrfMiddleware($router, $csrf, $session)]), $session, $i];
    }

    /** @return array<string,string> */
    private function form(string $token, string $csrf): array
    {
        return ['_csrf' => $csrf, 'install_token' => $token, 'app_url' => 'http://localhost:8080', 'admin_email' => 'admin@contoh.test',
            'admin_name' => 'Admin Dummy', 'db_driver' => 'sqlite', 'db_file' => 'app.sqlite', 'smtp_port' => '587', 'smtp_secure' => 'starttls'];
    }

    public function test_controller_get_form_post_csrf_dan_tautan_tampil_sekali(): void
    {
        [$k, $session, $i] = $this->web();
        $h = ['host' => 'localhost:8080'];
        $get = $k->handle(new Request('GET', '/install', headers: $h));
        self::assertSame(200, $get->status);
        self::assertStringContainsString('Instalasi', $get->body);
        self::assertStringNotContainsString($this->token($i), $get->body, 'token tidak pernah ditampilkan');
        $csrf = (string) (new Csrf($session))->token();

        $noCsrf = $this->form($this->token($i), $csrf);
        $noCsrf['_csrf'] = 'salah';
        self::assertSame(419, $k->handle(new Request('POST', '/install', post: $noCsrf, headers: $h))->status);
        self::assertFalse($i->isInstalled());

        $wrongTok = $k->handle(new Request('POST', '/install', post: $this->form('salah', $csrf), headers: $h));
        self::assertSame(403, $wrongTok->status);
        self::assertStringNotContainsString('value="salah"', $wrongTok->body);

        $hostMismatch = $k->handle(new Request('POST', '/install', post: $this->form($this->token($i), $csrf), headers: ['host' => 'jahat.test']));
        self::assertSame(422, $hostMismatch->status);
        self::assertFalse($i->isInstalled());

        $ok = $k->handle(new Request('POST', '/install', post: $this->form($this->token($i), $csrf), headers: $h));
        self::assertSame(200, $ok->status);
        self::assertStringContainsString('/auth/reset/', $ok->body);
        self::assertSame('no-store', $ok->headers['Cache-Control'] ?? null);

        // Sesudah terpasang: GET dan POST = 404.
        self::assertSame(404, $k->handle(new Request('GET', '/install', headers: $h))->status);
        self::assertSame(404, $k->handle(new Request('POST', '/install', post: $this->form('x', $csrf), headers: $h))->status);
    }

    public function test_controller_form_tidak_menampilkan_ulang_password(): void
    {
        [$k, $session] = $this->web();
        $csrf = (new Csrf($session))->token();
        $post = $this->form('salah', $csrf) + ['db_password' => 'PwDummyRahasia', 'smtp_password' => 'SmtpDummyRahasia'];
        $res = $k->handle(new Request('POST', '/install', post: $post, headers: ['host' => 'localhost:8080']));
        self::assertStringNotContainsString('PwDummyRahasia', $res->body);
        self::assertStringNotContainsString('SmtpDummyRahasia', $res->body);
    }

    public function test_controller_rate_limit_429(): void
    {
        [$k, $session] = $this->web(2);
        $csrf = (new Csrf($session))->token();
        $h = ['host' => 'localhost:8080'];
        $codes = [];
        for ($n = 0; $n < 3; $n++) {
            $codes[] = $k->handle(new Request('POST', '/install', post: $this->form('salah', $csrf), headers: $h, remoteAddr: '203.0.113.9'))->status;
        }
        self::assertSame([403, 403, 429], $codes);
    }
}
