<?php

declare(strict_types=1);

namespace bFramework\Tests\Core;

use bFramework\Auth\AuthMiddleware;
use bFramework\Contracts\HttpException;
use bFramework\Core\ErrorHandler;
use bFramework\Core\Kernel;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\RotatingFileLogger;
use bFramework\Core\Router;
use bFramework\Core\SecurityHeaders;
use bFramework\Core\Template;
use bFramework\Core\TransportPolicy;
use PHPUnit\Framework\TestCase;

/** SEC-4: S5 (header jalur awal), S8 (log/audit), S9 (HTTPS di balik proxy). Cache-Control S6 ada di Integration/HardeningFlowTest. */
final class HardeningTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/hard_' . bin2hex(random_bytes(4));
        mkdir($this->dir . '/c', 0700, true);
        TransportPolicy::reset();
    }

    protected function tearDown(): void
    {
        TransportPolicy::reset();
        $this->rm($this->dir);
    }

    private function rm(string $d): void
    {
        foreach (glob($d . '/{,.}*', GLOB_BRACE) ?: [] as $f) {
            if (basename($f) === '.' || basename($f) === '..') {
                continue;
            }
            is_dir($f) && !is_link($f) ? $this->rm($f) : @unlink($f);
        }
        @rmdir($d);
    }

    /** @param list<string> $names */
    private function assertSecure(Response $r, array $names = ['X-Content-Type-Options', 'Referrer-Policy', 'X-Frame-Options', 'Content-Security-Policy']): void
    {
        $h = array_change_key_case($r->headers, CASE_LOWER);
        foreach ($names as $n) {
            self::assertArrayHasKey(strtolower($n), $h, $n);
        }
        self::assertSame('nosniff', $h['x-content-type-options']);
    }

    private function errors(): ErrorHandler
    {
        return new ErrorHandler(true, new RotatingFileLogger($this->dir . '/l', 65536, 2), new Template(__DIR__ . '/../../app/core/Core/views', $this->dir . '/c'));
    }

    // --- S5

    public function test_SEC_4_S5_400_path_rusak_sebelum_middleware_membawa_header(): void
    {
        $k = new Kernel(new Router(), [], null, $this->errors()->page(...));
        $res = $k->handleGlobals(static fn(): Request => throw new HttpException(400, 'Path tidak valid'));
        self::assertSame(400, $res->status);
        $this->assertSecure($res);
        $res = (new Kernel(new Router()))->handleGlobals(static fn(): Request => throw new \RuntimeException('x'));
        self::assertSame(400, $res->status);
        $this->assertSecure($res);
    }

    public function test_SEC_4_S5_500_fatal_global_membawa_header_dan_csp_tanpa_nonce(): void
    {
        $res = $this->errors()->fatalResponse();
        self::assertSame(500, $res->status);
        $this->assertSecure($res);
        self::assertStringNotContainsString('nonce-', $res->headers['Content-Security-Policy']);
    }

    public function test_SEC_4_S5_apply_tidak_menimpa_csp_handler_dan_hsts_hanya_https(): void
    {
        $r = Response::html('x')->withHeader('Content-Security-Policy', "default-src 'none'; sandbox");
        $out = SecurityHeaders::apply($r, false);
        self::assertSame("default-src 'none'; sandbox", $out->headers['Content-Security-Policy']);
        self::assertArrayNotHasKey('Strict-Transport-Security', $out->headers);
        self::assertArrayHasKey('Strict-Transport-Security', SecurityHeaders::apply(Response::html('x'), true)->headers);
    }

    public function test_SEC_4_S5_503_index_php_memanggil_header_keamanan_sebelum_keluaran(): void
    {
        $src = (string) file_get_contents(__DIR__ . '/../../public_html/index.php');
        self::assertSame(2, substr_count($src, 'SecurityHeaders::sendRaw($https);'));
        foreach (["echo 'Sedang dalam pemeliharaan", "echo 'Konfigurasi tidak lengkap"] as $echo) {
            self::assertLessThan(strpos($src, $echo), strrpos(substr($src, 0, strpos($src, $echo)), 'sendRaw'));
        }
    }

    public function test_SEC_4_S5_assets_htaccess_header_kompatibel_apache_22_24(): void
    {
        $h = (string) file_get_contents(__DIR__ . '/../../public_html/assets/.htaccess');
        self::assertStringContainsString('<IfModule mod_headers.c>', $h);
        foreach (['X-Content-Type-Options "nosniff"', 'Referrer-Policy "strict-origin-when-cross-origin"', 'X-Frame-Options "DENY"'] as $x) {
            self::assertStringContainsString('Header always set ' . $x, $h);
        }
        self::assertStringNotContainsString('expr=', $h);
        self::assertStringNotContainsString('[END]', $h);
    }

    // --- S8

    public function test_SEC_4_S8a_audit_admin_tidak_hilang_saat_banjir_log_anonim(): void
    {
        $logs = $this->dir . '/logs';
        $app = new RotatingFileLogger($logs, 4096, 2, 'app.log', 5);
        $audit = new RotatingFileLogger($logs, 65536, 3, 'audit.log');
        $audit->info('audit: user.create', ['actor_id' => 1]);
        for ($i = 0; $i < 2000; $i++) {
            $app->warning('Back-channel logout ditolak', ['alasan' => 'x' . ($i % 7)]);
            $app->warning('beda ' . $i);
        }
        self::assertStringContainsString('audit: user.create', (string) file_get_contents($logs . '/audit.log'));
        $lines = 0;
        foreach (glob($logs . '/app.log*') ?: [] as $f) {
            $lines += count(file($f) ?: []);
        }
        self::assertLessThan(150, $lines, 'laju log anonim dibatasi');
    }

    public function test_SEC_4_S8a_batas_laju_per_pesan_dan_reset_jendela(): void
    {
        $l = new RotatingFileLogger($this->dir . '/r', 65536, 2, 'app.log', 3);
        for ($i = 0; $i < 10; $i++) {
            $l->warning('sama');
        }
        $l->warning('lain');
        self::assertCount(4, file($this->dir . '/r/app.log') ?: []);
        // jendela berikutnya: ringkasan penekanan tercatat
        $st = json_decode((string) file_get_contents($this->dir . '/r/.rate'), true);
        $st['w'] -= 120;
        file_put_contents($this->dir . '/r/.rate', json_encode($st));
        $l->warning('sama');
        $raw = (string) file_get_contents($this->dir . '/r/app.log');
        self::assertStringContainsString('"ditekan":7', $raw);
    }

    public function test_SEC_4_S8b_rotasi_gagal_tanpa_deadlock_atau_reentrancy(): void
    {
        $logs = $this->dir . '/rot';
        mkdir($logs . '/app.log.1', 0700, true); // rename(app.log -> app.log.1) gagal: tujuan direktori tak kosong
        touch($logs . '/app.log.1/x');
        file_put_contents($logs . '/app.log', str_repeat('a', 4000) . "\n");
        $script = $this->dir . '/run.php';
        file_put_contents($script, '<?php require ' . var_export(realpath(__DIR__ . '/../bootstrap.php'), true) . ';'
            . '$l = new bFramework\Core\RotatingFileLogger(' . var_export($logs, true) . ', 4096, 2);'
            // Handler tanpa filter error_reporting (mensimulasikan ErrorHandler::onError yang mencatat ke logger yang sama).
            . 'set_error_handler(static function (int $no, string $m) use ($l): bool { $l->warning("PHP error", ["pesan" => $m]); return true; });'
            . 'for ($i = 0; $i < 3; $i++) { $l->error("baris $i", ["pad" => str_repeat("y", 200)]); }'
            . 'echo "SELESAI";');
        $proc = proc_open([PHP_BINARY, $script], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($proc);
        stream_set_blocking($pipes[1], false);
        $out = '';
        $deadline = microtime(true) + 15;
        do {
            $out .= (string) stream_get_contents($pipes[1]);
            $st = proc_get_status($proc);
            if (!$st['running']) {
                break;
            }
            usleep(50000);
        } while (microtime(true) < $deadline);
        $running = proc_get_status($proc)['running'];
        if ($running) {
            proc_terminate($proc, 9);
        }
        proc_close($proc);
        self::assertFalse($running, 'proses menggantung (deadlock flock)');
        self::assertStringContainsString('SELESAI', $out);
        self::assertLessThanOrEqual(4096, filesize($logs . '/app.log'), 'ukuran tetap terbatas walau rename gagal');
    }

    public function test_SEC_4_S8b_dua_instance_berbagi_lock_tanpa_deadlock_dan_audit_tidak_dipotong(): void
    {
        $logs = $this->dir . '/dua';
        mkdir($logs . '/audit.log.1', 0700, true); // rotasi audit.log gagal
        touch($logs . '/audit.log.1/x');
        $audit0 = str_repeat('a', 4000) . "\n";
        file_put_contents($logs . '/audit.log', $audit0);
        $script = $this->dir . '/run2.php';
        file_put_contents($script, '<?php require ' . var_export(realpath(__DIR__ . '/../bootstrap.php'), true) . ';'
            . '$app = new bFramework\Core\RotatingFileLogger(' . var_export($logs, true) . ', 65536, 2);'
            . '$audit = new bFramework\Core\RotatingFileLogger(' . var_export($logs, true) . ', 4096, 2, "audit.log", null, false);'
            . 'set_error_handler(static function (int $no, string $m) use ($app): bool { $app->warning("PHP error", ["pesan" => $m]); return true; });'
            . 'for ($i = 0; $i < 3; $i++) { $audit->info("audit $i", ["pad" => str_repeat("y", 200)]); }'
            . 'echo "SELESAI";');
        [$running, $out] = $this->runLimited($script);
        self::assertFalse($running, 'proses menggantung (deadlock lintas instance)');
        self::assertStringContainsString('SELESAI', $out);
        self::assertSame($audit0, file_get_contents($logs . '/audit.log'), 'audit tidak boleh dipotong/ditimpa');
    }

    public function test_SEC_4_S8b_rotasi_audit_gagal_dicatat_ke_app_log_tanpa_isi_terbatas_dan_terlewat_dihitung(): void
    {
        $logs = $this->dir . '/skip';
        mkdir($logs . '/audit.log.1', 0700, true); // rename(audit.log -> audit.log.1) gagal
        touch($logs . '/audit.log.1/x');
        $audit0 = str_repeat('a', 4000) . "\n";
        file_put_contents($logs . '/audit.log', $audit0);
        $script = $this->dir . '/run3.php';
        $boot = var_export(realpath(__DIR__ . '/../bootstrap.php'), true);
        $mk = 'new bFramework\Core\RotatingFileLogger(' . var_export($logs, true) . ', ';
        file_put_contents($script, '<?php require ' . $boot . ';'
            . '$app = ' . $mk . '65536, 2);'
            // path berbeda (trailing slash + "/.") ke direktori yang sama: tetap terdeteksi re-entrant lewat realpath
            . '$audit = new bFramework\Core\RotatingFileLogger(' . var_export($logs . '/./', true) . ', 4096, 2, "audit.log", null, false);'
            . 'set_error_handler(static function (int $no, string $m) use ($app): bool { $app->warning("PHP error", ["pesan" => $m]); return true; });'
            . 'for ($i = 0; $i < 50; $i++) { $audit->info("ISI-ENTRI-$i", ["pad" => str_repeat("y", 200)]); }'
            . '$f = ' . var_export($logs . '/.audit.log.skip', true) . '; $st = json_decode(file_get_contents($f), true); $st["w"] -= 120; file_put_contents($f, json_encode($st));'
            . '$audit->info("ISI-ENTRI-akhir");'
            . 'echo "SELESAI";');
        [$running, $out] = $this->runLimited($script);
        self::assertFalse($running, 'proses menggantung (deadlock)');
        self::assertStringContainsString('SELESAI', $out);
        self::assertSame($audit0, file_get_contents($logs . '/audit.log'), 'audit.log utuh');

        $app = (string) file_get_contents($logs . '/app.log');
        $fails = array_values(array_filter(explode("\n", $app), static fn (string $l): bool => str_contains($l, 'Rotasi log gagal')));
        self::assertCount(2, $fails, 'satu baris per jendela, tidak membanjiri (50 entri -> 1 baris, jendela baru -> 1 baris)');
        self::assertStringContainsString('"kanal":"audit.log"', $fails[0]);
        self::assertStringContainsString('"terlewat":1', $fails[0]);
        self::assertStringContainsString('"terlewat":51', $fails[1]);
        self::assertStringNotContainsString('ISI-ENTRI', $app, 'isi entri tidak bocor ke app.log');
        self::assertStringNotContainsString($logs, $app, 'tanpa path absolut');

        // Pulih: catatan berikutnya yang berhasil menyertakan penghitung terlewat, lalu penghitung direset.
        $this->rm($logs . '/audit.log.1');
        $audit = new RotatingFileLogger($logs, 4096, 2, 'audit.log', null, false);
        $audit->info('pulih');
        $now = (string) file_get_contents($logs . '/audit.log');
        self::assertStringContainsString('"terlewat":51', $now);
        self::assertStringContainsString('pulih', $now);
        self::assertSame($audit0, file_get_contents($logs . '/audit.log.1'));
        self::assertFileDoesNotExist($logs . '/.audit.log.skip');
        $audit->info('lagi');
        self::assertSame(1, substr_count((string) file_get_contents($logs . '/audit.log'), '"terlewat":'));
    }

    public function test_SEC_4_S8b_fatal_di_dalam_write_tetap_dicatat_shutdown_tanpa_deadlock(): void
    {
        $logs = $this->dir . '/fatal';
        mkdir($logs . '/app.log.1', 0700, true); // rename gagal -> warning dipicu selagi .lock dipegang
        touch($logs . '/app.log.1/x');
        file_put_contents($logs . '/app.log', str_repeat('a', 4000) . "\n");
        $script = $this->dir . '/run4.php';
        file_put_contents($script, '<?php require ' . var_export(realpath(__DIR__ . '/../bootstrap.php'), true) . ';'
            . 'ini_set("memory_limit", "32M");'
            . '$l = new bFramework\Core\RotatingFileLogger(' . var_export($logs, true) . ', 4096, 2);'
            . '$eh = new bFramework\Core\ErrorHandler(true, $l, new bFramework\Core\Template(' . var_export(realpath(__DIR__ . '/../../app/core/Core/views'), true) . ', ' . var_export($this->dir . '/c', true) . '));'
            . 'register_shutdown_function(static function () use ($eh): void { $eh->onShutdown(); echo "SHUTDOWN"; });'
            // Fatal (memori habis) di dalam write(): dari warning rename() selagi flock dipegang; hanya sekali.
            . 'set_error_handler(static function (): bool { static $n = 0; if ($n++ === 0) { $x = str_repeat("z", 256 * 1024 * 1024); } return true; });'
            . '$l->error("pemicu", ["pad" => str_repeat("y", 200)]);'
            . 'echo "TIDAK-TERCAPAI";');
        [$running, $out] = $this->runLimited($script);
        self::assertFalse($running, 'shutdown menggantung (deadlock flock basi)');
        self::assertStringContainsString('SHUTDOWN', $out);
        self::assertStringNotContainsString('TIDAK-TERCAPAI', $out);
        self::assertStringContainsString('Fatal error', (string) file_get_contents($logs . '/app.log'), 'fatal tercatat oleh handler shutdown');
    }

    /** @return array{0:bool,1:string} */
    private function runLimited(string $script): array
    {
        $proc = proc_open([PHP_BINARY, $script], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($proc);
        stream_set_blocking($pipes[1], false);
        $out = '';
        $deadline = microtime(true) + 15;
        do {
            $out .= (string) stream_get_contents($pipes[1]);
            if (!proc_get_status($proc)['running']) {
                break;
            }
            usleep(50000);
        } while (microtime(true) < $deadline);
        $running = proc_get_status($proc)['running'];
        if ($running) {
            proc_terminate($proc, 9);
        }
        proc_close($proc);
        return [$running, $out];
    }

    // --- S9

    public function test_SEC_4_S9_app_url_https_memaksa_cookie_secure_host_dan_hsts_tanpa_flag_https(): void
    {
        TransportPolicy::configure('https://contoh.example');
        $r = Request::fromServer(['REQUEST_URI' => '/', 'REQUEST_METHOD' => 'GET', 'REMOTE_ADDR' => '10.0.0.5'], [], [], [], '');
        self::assertTrue($r->isHttps);
        self::assertSame('__Host-bf_remember', AuthMiddleware::cookieName($r->isHttps));
        self::assertTrue(AuthMiddleware::cookieOptions($r->isHttps, 1)['secure']);
        self::assertArrayHasKey('Strict-Transport-Security', SecurityHeaders::apply(Response::html('x'), $r->isHttps)->headers);
        $store = new \bFramework\Core\FileSessionStore($this->dir . '/s', $r->isHttps);
        self::assertStringStartsWith('__Host-', $store->cookieName());
    }

    public function test_SEC_4_S9_app_url_http_tidak_memaksa(): void
    {
        TransportPolicy::configure('http://localhost:8080');
        $r = Request::fromServer(['REQUEST_URI' => '/', 'REQUEST_METHOD' => 'GET'], [], [], [], '');
        self::assertFalse($r->isHttps);
    }

    public function test_SEC_4_S9_trusted_proxies_default_kosong_tidak_percaya_x_forwarded_proto(): void
    {
        $server = ['REQUEST_URI' => '/', 'REQUEST_METHOD' => 'GET', 'REMOTE_ADDR' => '10.0.0.5', 'HTTP_X_FORWARDED_PROTO' => 'https'];
        TransportPolicy::configure('http://localhost');
        self::assertFalse(Request::fromServer($server, [], [], [], '')->isHttps);
        TransportPolicy::configure('http://localhost', []);
        self::assertFalse(Request::fromServer($server, [], [], [], '')->isHttps);
    }

    public function test_SEC_4_S9_trusted_proxies_hanya_dari_ip_cidr_terdaftar(): void
    {
        TransportPolicy::configure('http://localhost', ['10.0.0.0/24', '2001:db8::/32', 'bukan-ip']);
        $mk = static fn(string $ip, string $proto = 'https'): Request => Request::fromServer(
            ['REQUEST_URI' => '/', 'REQUEST_METHOD' => 'GET', 'REMOTE_ADDR' => $ip, 'HTTP_X_FORWARDED_PROTO' => $proto],
            [],
            [],
            [],
            '',
        );
        self::assertTrue($mk('10.0.0.77')->isHttps);
        self::assertTrue($mk('2001:db8::1')->isHttps);
        self::assertFalse($mk('10.0.1.1')->isHttps, 'di luar CIDR');
        self::assertFalse($mk('203.0.113.9')->isHttps, 'klien biasa memalsukan header');
        self::assertFalse($mk('10.0.0.77', 'http')->isHttps);
    }

    public function test_SEC_4_S9_x_forwarded_proto_pakai_nilai_terakhir_dan_tolak_aneh(): void
    {
        TransportPolicy::configure('http://localhost', ['10.0.0.0/8']);
        $cases = ['https, http' => false, 'http, https' => true, 'https' => true, 'http' => false, 'HTTPS' => true,
            '' => false, 'ftp' => false, 'https, ' => false, 'https,wss' => false, ' https ' => true];
        foreach ($cases as $proto => $want) {
            $r = Request::fromServer(['REQUEST_URI' => '/', 'REQUEST_METHOD' => 'GET', 'REMOTE_ADDR' => '10.1.2.3', 'HTTP_X_FORWARDED_PROTO' => (string) $proto], [], [], [], '');
            self::assertSame($want, $r->isHttps, "'$proto'");
        }
        TransportPolicy::reset();
        foreach (['https', 'http, https'] as $proto) {
            $r = Request::fromServer(['REQUEST_URI' => '/', 'REQUEST_METHOD' => 'GET', 'REMOTE_ADDR' => '10.1.2.3', 'HTTP_X_FORWARDED_PROTO' => $proto], [], [], [], '');
            self::assertFalse($r->isHttps, 'tanpa TRUSTED_PROXIES header diabaikan');
        }
    }
}
