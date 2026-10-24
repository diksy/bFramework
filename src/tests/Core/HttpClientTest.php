<?php

declare(strict_types=1);

namespace bFramework\Tests\Core;

use bFramework\Contracts\Logger;
use bFramework\Core\BlockedDestination;
use bFramework\Core\CurlTransport;
use bFramework\Core\HttpClient;
use bFramework\Core\HttpError;
use bFramework\Core\HttpResponse;
use bFramework\Core\IpPolicy;
use bFramework\Core\StreamTransport;
use bFramework\Core\TlsError;
use bFramework\Core\Transport;
use PHPUnit\Framework\TestCase;

final class FakeTransport implements Transport
{
    /** @var list<array<string,mixed>> */
    public array $calls = [];

    /** @param list<HttpResponse|\Throwable> $queue */
    public function __construct(public array $queue = [])
    {
    }

    public function send(string $method, string $host, int $port, string $ip, string $pathAndQuery, array $headers, ?string $body, int $timeout, int $maxBytes): HttpResponse
    {
        $this->calls[] = compact('method', 'host', 'port', 'ip', 'pathAndQuery', 'headers', 'body', 'timeout', 'maxBytes');
        $next = array_shift($this->queue) ?? new HttpResponse(200, [], 'ok');
        if ($next instanceof \Throwable) {
            throw $next;
        }
        return $next;
    }
}

final class MemLogger implements Logger
{
    /** @var list<string> */
    public array $lines = [];

    public function error(string $msg, array $ctx = []): void
    {
        $this->lines[] = $msg . json_encode($ctx);
    }

    public function warning(string $msg, array $ctx = []): void
    {
        $this->error($msg, $ctx);
    }

    public function info(string $msg, array $ctx = []): void
    {
        $this->error($msg, $ctx);
    }
}

final class HttpClientTest extends TestCase
{
    /** @param array<string,list<string>> $dns */
    private function client(FakeTransport $t, array $dns = [], ?Logger $log = null, int $max = 1000, array $hosts = []): HttpClient
    {
        return new HttpClient(
            $log,
            $t,
            $max,
            $hosts,
            [443],
            static fn (string $h): array => $dns[$h] ?? ['93.184.216.34']
        );
    }

    public function test_ARCH_06_request_https_sukses_dan_koneksi_dikunci_ke_ip(): void
    {
        $t = new FakeTransport([new HttpResponse(200, [], 'halo')]);
        $r = $this->client($t)->request('get', 'https://api.example.com/x?a=1', ['Accept' => 'a/b']);
        self::assertSame('halo', $r->body);
        self::assertSame('93.184.216.34', $t->calls[0]['ip']);
        self::assertSame('/x?a=1', $t->calls[0]['pathAndQuery']);
        self::assertSame('GET', $t->calls[0]['method']);
    }

    public function test_ARCH_06_tolak_skema_non_https_dan_userinfo(): void
    {
        foreach (['http://example.com/', 'ftp://example.com/', 'file:///etc/passwd', 'https://u:p@example.com/', 'example.com', 'https://exa mple.com/'] as $u) {
            try {
                $this->client(new FakeTransport())->request('GET', $u);
                self::fail($u);
            } catch (BlockedDestination) {
                self::assertTrue(true);
            }
        }
    }

    public function test_ARCH_06_tidak_ada_opsi_mematikan_verifikasi_tls(): void
    {
        $rc = new \ReflectionClass(HttpClient::class);
        $names = array_map(static fn ($p) => strtolower($p->getName()), $rc->getMethod('__construct')->getParameters());
        $names = array_merge($names, array_map(static fn ($p) => strtolower($p->getName()), $rc->getMethod('request')->getParameters()));
        foreach ($names as $n) {
            self::assertDoesNotMatchRegularExpression('/verify|insecure|ssl|tls|unsafe/', $n);
        }
        $opts = StreamTransport::contextOptions('GET', 'example.com', '93.184.216.34', [], null, 5);
        self::assertTrue($opts['ssl']['verify_peer']);
        self::assertTrue($opts['ssl']['verify_peer_name']);
        self::assertFalse($opts['ssl']['allow_self_signed']);
        self::assertSame('example.com', $opts['ssl']['peer_name']);
        self::assertSame(0, $opts['http']['follow_location']);
    }

    public function test_ARCH_06_sertifikat_tidak_valid_ditolak_TlsError_diteruskan(): void
    {
        $t = new FakeTransport([new TlsError('Verifikasi TLS gagal')]);
        $this->expectException(TlsError::class);
        $this->client($t)->request('GET', 'https://bad.example.com/');
    }

    public function test_ARCH_06_fallback_stream_bila_curl_tidak_ada(): void
    {
        self::assertInstanceOf(StreamTransport::class, HttpClient::defaultTransport(false));
        self::assertInstanceOf(CurlTransport::class, HttpClient::defaultTransport(true));
    }

    public function test_ARCH_06_ssrf_ip_literal_dan_dns_privat_ditolak(): void
    {
        $urls = [
            'https://127.0.0.1/', 'https://10.0.0.5/', 'https://192.168.1.1/', 'https://172.16.0.1/',
            'https://169.254.169.254/latest/meta-data', 'https://[::1]/', 'https://[fd00:ec2::254]/',
            'https://[::ffff:127.0.0.1]/', 'https://[fe80::1]/', 'https://0.0.0.0/', 'https://100.64.0.1/',
        ];
        foreach ($urls as $u) {
            $t = new FakeTransport();
            try {
                $this->client($t)->request('GET', $u);
                self::fail($u);
            } catch (BlockedDestination) {
                self::assertSame([], $t->calls, $u);
            }
        }
        $t = new FakeTransport();
        try {
            $this->client($t, ['evil.example.com' => ['93.184.216.34', '127.0.0.1']])->request('GET', 'https://evil.example.com/');
            self::fail('dns rebinding');
        } catch (BlockedDestination) {
            self::assertSame([], $t->calls);
        }
    }

    public function test_ARCH_06_ip_policy_publik_dan_non_publik(): void
    {
        self::assertTrue(IpPolicy::isPublic('93.184.216.34'));
        self::assertTrue(IpPolicy::isPublic('2606:2800:220:1:248:1893:25c8:1946'));
        self::assertFalse(IpPolicy::isPublic('not-an-ip'));
        self::assertFalse(IpPolicy::isPublic('::'));
        self::assertFalse(IpPolicy::isPublic('64:ff9b::7f00:1'));
        self::assertFalse(IpPolicy::isPublic('2002:7f00:1::'));
    }

    public function test_ARCH_06_redirect_ke_ip_privat_atau_http_ditolak(): void
    {
        foreach (['https://169.254.169.254/', 'http://example.com/', 'https://internal.local/'] as $loc) {
            $t = new FakeTransport([new HttpResponse(302, ['location' => $loc], '')]);
            try {
                $this->client($t, ['internal.local' => ['10.1.1.1']])->request('GET', 'https://api.example.com/');
                self::fail($loc);
            } catch (BlockedDestination) {
                self::assertCount(1, $t->calls, $loc);
            }
        }
    }

    public function test_ARCH_06_redirect_dibatasi_dan_relatif_diikuti(): void
    {
        $t = new FakeTransport([new HttpResponse(301, ['location' => '/baru'], ''), new HttpResponse(200, [], 'akhir')]);
        $r = $this->client($t)->request('POST', 'https://api.example.com/lama', [], 'data');
        self::assertSame('akhir', $r->body);
        self::assertSame('/baru', $t->calls[1]['pathAndQuery']);
        self::assertSame('GET', $t->calls[1]['method']);
        self::assertNull($t->calls[1]['body']);

        $loop = new FakeTransport(array_fill(0, 10, new HttpResponse(302, ['location' => '/lagi'], '')));
        $this->expectException(HttpError::class);
        $this->client($loop)->request('GET', 'https://api.example.com/');
    }

    public function test_ARCH_06_authorization_dibuang_pada_redirect_lintas_host(): void
    {
        $t = new FakeTransport([new HttpResponse(302, ['location' => 'https://other.example.org/'], ''), new HttpResponse(200, [], '')]);
        $this->client($t)->request('GET', 'https://api.example.com/', ['Authorization' => 'Bearer rahasia']);
        self::assertArrayHasKey('Authorization', $t->calls[0]['headers']);
        self::assertArrayNotHasKey('Authorization', $t->calls[1]['headers']);
    }

    public function test_ARCH_06_allowlist_host_berlaku_juga_pada_redirect(): void
    {
        $t = new FakeTransport([new HttpResponse(302, ['location' => 'https://other.example.org/'], '')]);
        $this->expectException(BlockedDestination::class);
        $this->client($t, [], null, 1000, ['api.example.com'])->request('GET', 'https://api.example.com/');
    }

    public function test_ARCH_06_port_header_dan_metode_divalidasi(): void
    {
        $cases = [
            ['GET', 'https://example.com:8443/', []],
            ['TRACE', 'https://example.com/', []],
            ['GET', 'https://example.com/', ["X-A" => "a\r\nX-B: b"]],
        ];
        foreach ($cases as [$m, $u, $h]) {
            try {
                $this->client(new FakeTransport())->request($m, $u, $h);
                self::fail($u);
            } catch (BlockedDestination) {
                self::assertTrue(true);
            }
        }
    }

    public function test_ARCH_06_timeout_dan_batas_ukuran_diteruskan_ke_transport(): void
    {
        $t = new FakeTransport();
        $this->client($t, [], null, 500)->request('GET', 'https://example.com/', [], null, 9999);
        self::assertSame(500, $t->calls[0]['maxBytes']);
        self::assertSame(60, $t->calls[0]['timeout']);

        $big = new FakeTransport([new HttpError('Respons melebihi batas ukuran')]);
        $this->expectException(HttpError::class);
        $this->client($big)->request('GET', 'https://example.com/');
    }

    public function test_ARCH_06_log_tanpa_authorization_query_atau_body(): void
    {
        $log = new MemLogger();
        $t = new FakeTransport();
        $this->client($t, [], $log)->request('POST', 'https://example.com/p?code=XYZSECRET', ['Authorization' => 'Bearer tok123abc'], 'password=hunter2');
        try {
            $this->client(new FakeTransport(), [], $log)->request('GET', 'https://127.0.0.1/?token=abc');
        } catch (BlockedDestination) {
        }
        $all = implode("\n", $log->lines);
        self::assertNotSame('', $all);
        foreach (['tok123abc', 'XYZSECRET', 'hunter2', 'Bearer', 'abc'] as $s) {
            self::assertStringNotContainsString($s, $all);
        }
    }

    public function test_ARCH_06_head_curl_memakai_nobody(): void
    {
        if (!CurlTransport::available()) {
            self::markTestSkipped('cURL tidak tersedia');
        }
        $o = CurlTransport::methodOptions('HEAD');
        self::assertTrue($o[CURLOPT_NOBODY]);
        self::assertArrayNotHasKey(CURLOPT_CUSTOMREQUEST, $o);
        self::assertSame('DELETE', CurlTransport::methodOptions('DELETE')[CURLOPT_CUSTOMREQUEST]);
    }

    public function test_ARCH_06_stream_deadline_total_melempar_httperror(): void
    {
        $fp = fopen('php://memory', 'w+b');
        self::assertIsResource($fp);
        fwrite($fp, str_repeat('a', 100000));
        rewind($fp);
        $t = 0.0;
        $clock = static function () use (&$t): float {
            $t += 1.0;
            return $t;
        };
        $this->expectException(HttpError::class);
        $this->expectExceptionMessage('batas waktu');
        try {
            StreamTransport::readBody($fp, 3.0, 1000000, $clock);
        } finally {
            fclose($fp);
        }
    }

    public function test_ARCH_06_stream_readbody_membaca_sebelum_deadline(): void
    {
        $fp = fopen('php://memory', 'w+b');
        self::assertIsResource($fp);
        fwrite($fp, 'halo');
        rewind($fp);
        self::assertSame('halo', StreamTransport::readBody($fp, microtime(true) + 5, 100));
        fclose($fp);
    }

    /** @return list<array{string}> */
    public static function bodylessMethods(): array
    {
        return [['GET'], ['HEAD'], ['get']];
    }

    /** @dataProvider bodylessMethods */
    public function test_ARCH_06_get_head_dengan_body_ditolak_sebelum_transport(string $m): void
    {
        $t = new FakeTransport();
        try {
            $this->client($t)->request($m, 'https://example.com/', [], 'x=1');
            self::fail('Harus melempar HttpError');
        } catch (HttpError $e) {
            self::assertStringContainsString('tidak boleh membawa body', $e->getMessage());
        }
        self::assertSame([], $t->calls);
        // String kosong tetap dianggap body (cURL POSTFIELDS '' juga mengubah ke POST).
        $this->expectException(HttpError::class);
        $this->client($t)->request($m, 'https://example.com/', [], '');
    }

    /** @dataProvider bodylessMethods */
    public function test_ARCH_06_kedua_transport_menolak_get_head_dengan_body(string $m): void
    {
        $m = strtoupper($m);
        try {
            StreamTransport::contextOptions($m, 'example.com', '93.184.216.34', [], 'x', 5);
            self::fail('Stream harus menolak');
        } catch (HttpError) {
        }
        $o = StreamTransport::contextOptions($m, 'example.com', '93.184.216.34', [], null, 5);
        self::assertSame($m, $o['http']['method']);
        self::assertArrayNotHasKey('content', $o['http']);
        if (!CurlTransport::available()) {
            return;
        }
        try {
            CurlTransport::methodOptions($m, 'x');
            self::fail('cURL harus menolak');
        } catch (HttpError) {
        }
        $c = CurlTransport::methodOptions($m, null);
        self::assertArrayNotHasKey(CURLOPT_POSTFIELDS, $c);
        self::assertArrayNotHasKey(CURLOPT_CUSTOMREQUEST, $c);
        self::assertTrue($c[$m === 'HEAD' ? CURLOPT_NOBODY : CURLOPT_HTTPGET]);
    }

    /** @return list<array{string}> */
    public static function bodyMethods(): array
    {
        return [['POST'], ['PUT'], ['PATCH'], ['DELETE']];
    }

    /** @dataProvider bodyMethods */
    public function test_ARCH_06_metode_dengan_body_tetap_metode_asli_di_kedua_transport(string $m): void
    {
        $t = new FakeTransport();
        $this->client($t)->request($m, 'https://example.com/', [], '{"a":1}');
        self::assertSame($m, $t->calls[0]['method']);
        self::assertSame('{"a":1}', $t->calls[0]['body']);

        $o = StreamTransport::contextOptions($m, 'example.com', '93.184.216.34', [], '{"a":1}', 5);
        self::assertSame($m, $o['http']['method']);
        self::assertSame('{"a":1}', $o['http']['content']);

        if (!CurlTransport::available()) {
            return;
        }
        $c = CurlTransport::methodOptions($m, '{"a":1}');
        // CUSTOMREQUEST menjaga baris permintaan = metode asli meski POSTFIELDS membuat cURL masuk mode POST.
        self::assertSame($m, $c[CURLOPT_CUSTOMREQUEST]);
        self::assertSame('{"a":1}', $c[CURLOPT_POSTFIELDS]);
        self::assertArrayNotHasKey(CURLOPT_NOBODY, $c);
        self::assertArrayNotHasKey(CURLOPT_HTTPGET, $c);
        $n = CurlTransport::methodOptions($m, null);
        self::assertSame($m, $n[CURLOPT_CUSTOMREQUEST]);
        self::assertArrayNotHasKey(CURLOPT_POSTFIELDS, $n);
    }

    public function test_ARCH_06_redirect_303_dari_post_menjadi_get_tanpa_body(): void
    {
        $t = new FakeTransport([new HttpResponse(303, ['location' => '/lain'], ''), new HttpResponse(200, [], 'ok')]);
        $this->client($t)->request('POST', 'https://example.com/', [], 'x=1');
        self::assertSame('GET', $t->calls[1]['method']);
        self::assertNull($t->calls[1]['body']);
    }
}
