<?php

declare(strict_types=1);

namespace bFramework\Tests\Core;

use bFramework\Core\ErrorHandler;
use bFramework\Core\Kernel;
use bFramework\Core\Nonce;
use bFramework\Core\Redactor;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\RotatingFileLogger;
use bFramework\Core\Router;
use bFramework\Core\Template;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class ErrorLogTest extends TestCase
{
    private const VIEWS = __DIR__ . '/../../app/core/Core/views';

    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/errlog_' . bin2hex(random_bytes(4));
        mkdir($this->dir . '/c', 0700, true);
        Nonce::reset();
    }

    protected function tearDown(): void
    {
        $this->rmTree($this->dir);
    }

    private function template(): Template
    {
        return new Template(self::VIEWS, $this->dir . '/c');
    }

    /** ID: SEC-LOG-02-REDAKSI-KUNCI — nilai pada kunci sensitif (termasuk bersarang) disamarkan. */
    public function test_SEC_LOG_02_kunci_sensitif_disamarkan(): void
    {
        $out = Redactor::clean([
            'password' => 'hunter2',
            'csrf_token' => 'abc',
            'app_key' => 'base64:xyz',
            'auth_code' => '123456',
            'cookie' => 'sid=1',
            'Authorization' => 'Bearer t0ken',
            'nested' => ['client_secret' => 's3cr3t', 'ok' => 'biasa'],
            'user' => 'budi',
            'status' => 404,
        ]);
        self::assertSame(Redactor::MASK, $out['password']);
        self::assertSame(Redactor::MASK, $out['csrf_token']);
        self::assertSame(Redactor::MASK, $out['app_key']);
        self::assertSame(Redactor::MASK, $out['auth_code']);
        self::assertSame(Redactor::MASK, $out['cookie']);
        self::assertSame(Redactor::MASK, $out['Authorization']);
        self::assertSame(Redactor::MASK, $out['nested']['client_secret']);
        self::assertSame('biasa', $out['nested']['ok']);
        self::assertSame('budi', $out['user']);
        self::assertSame(404, $out['status']);
    }

    /** ID: SEC-LOG-02-REDAKSI-POLA — token dan kredensial di dalam teks pesan disamarkan. */
    public function test_SEC_LOG_02_pola_token_di_pesan_disamarkan(): void
    {
        $jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl';
        $hex = str_repeat('ab', 20);
        $inputs = [
            'login gagal password=hunter2 untuk budi',
            'refresh access_token=XYZ123&lang=id',
            'kode otorisasi code=ZZ9 ditolak',
            "Authorization: Bearer abc.def.ghi",
            "jwt $jwt terkirim",
            "digest $hex",
        ];
        foreach ($inputs as $in) {
            $out = Redactor::message($in);
            self::assertStringNotContainsString('hunter2', $out);
            self::assertStringNotContainsString('XYZ123', $out);
            self::assertStringNotContainsString('ZZ9', $out);
            self::assertStringNotContainsString('abc.def.ghi', $out);
            self::assertStringNotContainsString($jwt, $out);
            self::assertStringNotContainsString($hex, $out);
        }
        self::assertStringContainsString('budi', Redactor::message('login gagal password=hunter2 untuk budi'));
    }

    /** ID: SEC-LOG-02-FILE — rahasia tidak pernah tertulis ke berkas log. */
    public function test_SEC_LOG_02_rahasia_tidak_masuk_berkas_log(): void
    {
        $logger = new RotatingFileLogger($this->dir . '/logs', 65536, 3);
        $logger->error('Login gagal password=hunter2', [
            'password' => 'hunter2',
            'token' => 'TOK-123',
            'Cookie' => 'sid=SESS-9',
            'pesan' => 'Bearer SECRET-BEARER',
            'user' => 'budi',
        ]);
        $raw = (string) file_get_contents($this->dir . '/logs/app.log');
        foreach (['hunter2', 'TOK-123', 'SESS-9', 'SECRET-BEARER'] as $secret) {
            self::assertStringNotContainsString($secret, $raw);
        }
        self::assertStringContainsString('budi', $raw);
        $line = json_decode(trim($raw), true);
        self::assertIsArray($line);
        self::assertSame('error', $line['lvl']);
    }

    /** ID: SEC-LOG-01-ROTASI — berkas tidak melebihi batas dan jumlah berkas dibatasi `keep`. */
    public function test_SEC_LOG_01_rotasi_ukuran_dan_jumlah_berkas(): void
    {
        $max = 4096;
        $logger = new RotatingFileLogger($this->dir . '/logs', $max, 2);
        for ($i = 0; $i < 300; $i++) {
            $logger->info('baris ' . $i, ['n' => $i, 'pad' => str_repeat('x', 100)]);
            clearstatcache();
            self::assertLessThanOrEqual($max, filesize($this->dir . '/logs/app.log'));
        }
        self::assertFileExists($this->dir . '/logs/app.log.1');
        self::assertFileExists($this->dir . '/logs/app.log.2');
        self::assertFileDoesNotExist($this->dir . '/logs/app.log.3');
        $names = array_map('basename', glob($this->dir . '/logs/app.log*') ?: []);
        self::assertCount(3, $names);
    }

    /** ID: SEC-LOG-01-IZIN — berkas log dibuat dengan izin 0640. */
    public function test_SEC_LOG_01_izin_berkas_log(): void
    {
        $logger = new RotatingFileLogger($this->dir . '/logs', 65536, 2);
        $logger->warning('uji');
        self::assertSame('640', substr(sprintf('%o', fileperms($this->dir . '/logs/app.log')), -3));
    }

    /** ID: SEC-LOG-01-KONFIG — parameter rotasi tidak masuk akal ditolak. */
    public function test_SEC_LOG_01_parameter_rotasi_divalidasi(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new RotatingFileLogger($this->dir, 100, 1);
    }

    /** ID: SEC-LOG-01-GENERIK — exception di produksi tidak membocorkan pesan, path, atau trace. */
    public function test_SEC_LOG_01_halaman_produksi_generik_tanpa_detail(): void
    {
        $logger = new RotatingFileLogger($this->dir . '/logs', 65536, 2);
        $handler = new ErrorHandler(true, $logger, $this->template());
        $router = new Router();
        $router->add('GET', '/', static function (): Response {
            throw new RuntimeException('rahasia-db di /var/www/app.php');
        });
        $kernel = new Kernel($router, [], $logger, $handler->page(...));

        $res = $kernel->handle(new Request('GET', '/'));
        self::assertSame(500, $res->status);
        self::assertStringContainsString('Terjadi kesalahan pada server', $res->body);
        self::assertStringNotContainsString('rahasia-db', $res->body);
        self::assertStringNotContainsString('.php', $res->body);
        self::assertStringNotContainsString('Stack', $res->body);
        self::assertStringNotContainsString('storage/logs', $res->body);
        self::assertStringNotContainsString('Detail teknis', $res->body);

        // Detail hanya di log (dengan pesan yang sudah disamarkan bila perlu).
        $raw = (string) file_get_contents($this->dir . '/logs/app.log');
        self::assertStringContainsString('RuntimeException', $raw);
    }

    /** ID: SEC-LOG-01-DEV — mode non-produksi menambah petunjuk ke log, tanpa trace. */
    public function test_SEC_LOG_01_mode_dev_hanya_menambah_petunjuk(): void
    {
        $logger = new RotatingFileLogger($this->dir . '/logs', 65536, 2);
        $body = (new ErrorHandler(false, $logger, $this->template()))->page(404)->body;
        self::assertStringContainsString('Halaman tidak ditemukan', $body);
        self::assertStringContainsString('storage/logs', $body);
        self::assertStringNotContainsString('Trace', $body);
    }

    /** ID: SEC-LOG-01-HTML — halaman error tidak memuat skrip inline dan tetap di-escape. */
    public function test_SEC_LOG_01_halaman_error_tanpa_skrip_inline(): void
    {
        $logger = new RotatingFileLogger($this->dir . '/logs', 65536, 2);
        $body = (new ErrorHandler(true, $logger, $this->template()))->page(999)->body;
        self::assertStringContainsString('<h1>500</h1>', $body);
        self::assertStringNotContainsString('<script', $body);
    }

    /** ID: SEC-LOG-01-FALLBACK — kegagalan template tidak membuat exception keluar dari handler. */
    public function test_SEC_LOG_01_kegagalan_template_ditangani(): void
    {
        $logger = new RotatingFileLogger($this->dir . '/logs', 65536, 2);
        mkdir($this->dir . '/kosong', 0700);
        $handler = new ErrorHandler(true, $logger, new Template($this->dir . '/kosong', $this->dir . '/c'));
        $res = $handler->page(503);
        self::assertSame(503, $res->status);
        self::assertStringContainsString('Terjadi kesalahan', $res->body);
    }

    /** ID: SEC-LOG-01-DOCROOT — folder log default berada di luar docroot (public_html). */
    public function test_SEC_LOG_01_log_di_luar_docroot(): void
    {
        $storage = realpath(__DIR__ . '/../../app/storage');
        self::assertNotFalse($storage);
        $public = realpath(__DIR__ . '/../../public_html');
        self::assertNotFalse($public);
        self::assertFalse(str_starts_with($storage . DIRECTORY_SEPARATOR, $public . DIRECTORY_SEPARATOR));
    }

    /** ID: SEC-LOG-01-DIR — logger membuat folder log bila belum ada. */
    public function test_SEC_LOG_01_logger_membuat_direktori_log(): void
    {
        $logger = new RotatingFileLogger($this->dir . '/baru/logs', 4096, 1);
        $logger->error('uji');
        self::assertFileExists($this->dir . '/baru/logs/app.log');
    }

    private function handler(bool $production = true): ErrorHandler
    {
        return new ErrorHandler($production, new RotatingFileLogger($this->dir . '/logs', 65536, 2), $this->template());
    }

    private function rawLog(): string
    {
        clearstatcache();
        return is_file($this->dir . '/logs/app.log') ? (string) file_get_contents($this->dir . '/logs/app.log') : '';
    }

    /** ID: SEC-LOG-01-ONERROR — warning PHP dicatat tanpa path lengkap dan pesan rahasia disamarkan. */
    public function test_SEC_LOG_01_onError_mencatat_warning_tersamar(): void
    {
        $old = error_reporting();
        error_reporting(E_ALL);
        try {
            $h = $this->handler();
            self::assertTrue($h->onError(E_USER_WARNING, 'gagal password=hunter2', '/var/www/app/a.php', 12));
        } finally {
            error_reporting($old);
        }
        $raw = $this->rawLog();
        self::assertStringContainsString('PHP error', $raw);
        self::assertStringContainsString('a.php', $raw);
        self::assertStringNotContainsString('/var/www', $raw);
        self::assertStringNotContainsString('hunter2', $raw);
    }

    /** ID: SEC-LOG-01-ONERROR-MASKA — error yang tidak ada di error_reporting tidak dicatat. */
    public function test_SEC_LOG_01_onError_menghormati_error_reporting(): void
    {
        $old = error_reporting();
        error_reporting(E_ALL & ~E_USER_NOTICE);
        try {
            self::assertFalse($this->handler()->onError(E_USER_NOTICE, 'diabaikan', __FILE__, 1));
        } finally {
            error_reporting($old);
        }
        self::assertSame('', $this->rawLog());
    }

    /** ID: SEC-LOG-01-ONEXCEPTION — exception dicatat dengan kelas, berkas, baris, dan pesan tersamar; tidak tampil di respons. */
    public function test_SEC_LOG_01_onException_mencatat_detail_tanpa_bocor_ke_respons(): void
    {
        $h = $this->handler();
        ob_start();
        try {
            $h->onException(new RuntimeException('gagal token=TOK-77 di proses'));
        } finally {
            $out = (string) ob_get_clean();
        }
        $raw = $this->rawLog();
        self::assertStringContainsString('RuntimeException', $raw);
        self::assertStringContainsString('ErrorLogTest.php', $raw);
        self::assertStringContainsString('"line"', $raw);
        self::assertStringNotContainsString('TOK-77', $raw);
        self::assertStringNotContainsString('gagal token', $out);
        self::assertStringNotContainsString('ErrorLogTest', $out);
        self::assertStringNotContainsString('TOK-77', $out);
    }

    /** ID: SEC-LOG-01-PREVIOUS — rantai previous ikut tercatat dan rahasia di tiap tingkat disamarkan. */
    public function test_SEC_LOG_01_rantai_previous_ikut_tercatat(): void
    {
        $inner = new \LogicException('akar password=hunter2');
        $outer = new RuntimeException('luar sesi', 0, $inner);
        $ctx = ErrorHandler::context($outer);
        self::assertSame(\LogicException::class, $ctx['prev1_class']);
        self::assertSame('akar password=[REDAKSI]', $ctx['prev1_pesan']);
        self::assertArrayNotHasKey('prev2_class', $ctx);

        ob_start();
        try {
            $this->handler()->onException($outer);
        } finally {
            ob_end_clean();
        }
        $raw = $this->rawLog();
        self::assertStringContainsString(\LogicException::class, $raw);
        self::assertStringNotContainsString('hunter2', $raw);
    }

    /** ID: SEC-LOG-01-KERNEL — exception di Kernel dicatat lengkap (termasuk previous) dan respons tetap generik. */
    public function test_SEC_LOG_01_kernel_mencatat_previous_tanpa_respons_detail(): void
    {
        $logger = new RotatingFileLogger($this->dir . '/logs', 65536, 2);
        $router = new Router();
        $router->add('GET', '/', static function (): Response {
            throw new RuntimeException('luar', 0, new \LogicException('dalam secret=S3CR3T'));
        });
        $res = (new Kernel($router, [], $logger))->handle(new Request('GET', '/'));
        self::assertSame(500, $res->status);
        self::assertStringNotContainsString('LogicException', $res->body);
        self::assertStringNotContainsString('S3CR3T', $res->body);
        $raw = $this->rawLog();
        self::assertStringContainsString('prev1_class', $raw);
        self::assertStringContainsString(\LogicException::class, $raw);
        self::assertStringNotContainsString('S3CR3T', $raw);
    }

    /** ID: SEC-LOG-01-INSTALL — install() mematikan display_errors dan memasang handler yang berfungsi. */
    public function test_SEC_LOG_01_install_mematikan_display_errors(): void
    {
        $origDisplay = ini_get('display_errors');
        $origLog = ini_get('log_errors');
        $origReporting = error_reporting();
        $h = $this->handler(true);
        $h->install();
        try {
            self::assertSame('0', ini_get('display_errors'));
            self::assertSame('0', ini_get('log_errors'));
            trigger_error('uji install password=hunter2', E_USER_WARNING);
        } finally {
            restore_error_handler();
            restore_exception_handler();
            ini_set('display_errors', (string) $origDisplay);
            ini_set('log_errors', (string) $origLog);
            error_reporting($origReporting);
        }
        $raw = $this->rawLog();
        self::assertStringContainsString('uji install', $raw);
        self::assertStringNotContainsString('hunter2', $raw);
    }

    /** ID: SEC-LOG-01-SHUTDOWN — shutdown tanpa error fatal tidak mencatat apa pun. */
    public function test_SEC_LOG_01_onShutdown_tanpa_fatal_diam(): void
    {
        ob_start();
        try {
            $this->handler()->onShutdown();
        } finally {
            ob_end_clean();
        }
        self::assertSame('', $this->rawLog());
    }

    /** ID: SEC-LOG-01-FATAL — error fatal sungguhan (memori habis) dicatat oleh onShutdown di proses terpisah. */
    public function test_SEC_LOG_01_fatal_error_dicatat_saat_shutdown(): void
    {
        $boot = realpath(__DIR__ . '/../../app/bootstrap.php');
        self::assertNotFalse($boot);
        $code = sprintf(
            'require %s; $l = new \bFramework\Core\RotatingFileLogger(%s, 65536, 2);'
            . ' (new \bFramework\Core\ErrorHandler(true, $l, new \bFramework\Core\Template(%s, %s)))->install();'
            . ' $s = str_repeat("x", 64 * 1024 * 1024);',
            var_export((string) $boot, true),
            var_export($this->dir . '/fatal/logs', true),
            var_export(self::VIEWS, true),
            var_export($this->dir . '/c', true),
        );
        $cmd = escapeshellarg(PHP_BINARY) . ' -d memory_limit=8M -r ' . escapeshellarg($code) . ' 2>/dev/null';
        exec($cmd, $out);
        $raw = (string) file_get_contents($this->dir . '/fatal/logs/app.log');
        self::assertStringContainsString('Fatal error', $raw);
        self::assertStringContainsString('"lvl":"error"', $raw);
        self::assertStringNotContainsString('str_repeat', implode("\n", $out));
    }

    /** ID: SEC-LOG-02-CRLF — CRLF/baris baru di pesan tidak memecah berkas log menjadi baris palsu. */
    public function test_SEC_LOG_02_injeksi_crlf_di_pesan_log(): void
    {
        $logger = new RotatingFileLogger($this->dir . '/logs', 65536, 2);
        $msg = "baris1\r\n{\"lvl\":\"info\",\"msg\":\"palsu\"}\nbaris3";
        $logger->error($msg, ['x' => "a\r\nb"]);
        $logger->info('kedua');
        $raw = $this->rawLog();
        self::assertSame(2, substr_count($raw, "\n"));
        $lines = explode("\n", rtrim($raw, "\n"));
        $first = json_decode($lines[0], true);
        self::assertIsArray($first);
        self::assertSame('error', $first['lvl']);
        self::assertSame($msg, $first['msg']);
        self::assertSame("a\r\nb", $first['ctx']['x']);
        self::assertSame('kedua', json_decode($lines[1], true)['msg']);
    }

    /** ID: SEC-LOG-02-QUERY — kunci rahasia di query string disamarkan, parameter lain tetap. */
    public function test_SEC_LOG_02_redaksi_kunci_query_string(): void
    {
        $out = Redactor::message('GET /cari?q=kopi&access_token=XYZ-9&password=hunter2&key=KK1&lang=id 200');
        self::assertStringNotContainsString('XYZ-9', $out);
        self::assertStringNotContainsString('hunter2', $out);
        self::assertStringNotContainsString('KK1', $out);
        self::assertStringContainsString('q=kopi', $out);
        self::assertStringContainsString('lang=id', $out);
    }

    private function rmTree(string $path): void
    {
        if (!is_dir($path)) {
            return;
        }
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $f) {
            $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
        }
        rmdir($path);
    }
}
