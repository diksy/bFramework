<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Logger;
use Closure;

/**
 * HTTP client keluar (F11, ARCH-06). Hanya HTTPS, verifikasi TLS selalu aktif (tidak ada opsi untuk
 * mematikannya), batas waktu/ukuran, redirect dibatasi dan divalidasi ulang tiap lompatan, tujuan
 * privat/loopback/link-local/metadata ditolak setelah resolusi DNS (SSRF), koneksi dikunci ke IP tervalidasi.
 */
final class HttpClient
{
    private const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'];
    private const MAX_REDIRECTS = 3;
    private const MAX_TIMEOUT = 60;

    private Transport $transport;

    /** @var Closure(string):list<string> */
    private Closure $resolver;

    /**
     * @param list<string> $allowedHosts bila tidak kosong, hanya host ini (dan target redirect-nya) diizinkan
     * @param list<int> $allowedPorts
     * @param (callable(string):list<string>)|null $resolver pemetaan host => daftar IP (untuk tes)
     */
    public function __construct(
        private readonly ?Logger $logger = null,
        ?Transport $transport = null,
        private readonly int $maxBytes = 1048576,
        private readonly array $allowedHosts = [],
        private readonly array $allowedPorts = [443],
        ?callable $resolver = null
    ) {
        $this->transport = $transport ?? self::defaultTransport(CurlTransport::available());
        $this->resolver = $resolver !== null ? Closure::fromCallable($resolver) : self::dnsResolver(...);
    }

    public static function defaultTransport(bool $curlAvailable): Transport
    {
        return $curlAvailable ? new CurlTransport() : new StreamTransport();
    }

    /**
     * @param array<string,string> $headers
     * @throws HttpError
     */
    public function request(
        string $method,
        string $url,
        array $headers = [],
        ?string $body = null,
        int $timeout = 10
    ): HttpResponse {
        $method = strtoupper($method);
        if (!in_array($method, self::METHODS, true)) {
            throw new BlockedDestination('Metode HTTP tidak diizinkan');
        }
        if ($body !== null && ($method === 'GET' || $method === 'HEAD')) {
            // cURL akan mengubahnya menjadi POST, stream tidak: tolak agar perilaku konsisten.
            throw new HttpError('Metode ' . $method . ' tidak boleh membawa body');
        }
        $timeout = max(1, min($timeout, self::MAX_TIMEOUT));
        $headers = $this->cleanHeaders($headers);
        $origOrigin = null;
        for ($hop = 0; $hop <= self::MAX_REDIRECTS; $hop++) {
            [$host, $port, $path, $ip] = $this->validate($url);
            $origin = $host . ':' . $port; // skema selalu https; origin = host + port
            $origOrigin ??= $origin;
            $send = $headers;
            if ($origin !== $origOrigin) {
                // Jangan bocorkan kredensial lintas host.
                foreach (array_keys($send) as $k) {
                    if (in_array(strtolower($k), ['authorization', 'cookie', 'proxy-authorization'], true)) {
                        unset($send[$k]);
                    }
                }
            }
            $send['Host'] = $port === 443 ? $host : $host . ':' . $port;
            $send['Connection'] = 'close';
            try {
                $res = $this->transport->send($method, $host, $port, $ip, $path, $send, $body, $timeout, $this->maxBytes);
            } catch (HttpError $e) {
                $this->log('HTTP keluar gagal', ['host' => $host, 'error' => $e->getMessage()]);
                throw $e;
            }
            $this->log('HTTP keluar', ['method' => $method, 'host' => $host, 'path' => strtok($path, '?') ?: '/', 'status' => $res->status]);
            if ($res->status >= 300 && $res->status < 400 && isset($res->headers['location'])) {
                $url = $this->resolveLocation($url, $res->headers['location']);
                if (in_array($res->status, [301, 302, 303], true)) {
                    $method = ($method === 'HEAD') ? 'HEAD' : 'GET';
                    $body = null;
                }
                if ($body !== null && self::originOf($url) !== $origin) {
                    // 307/308 akan mengulang body (code, code_verifier, refresh_token) ke origin lain: tolak.
                    throw new BlockedDestination('Redirect ber-body ke origin lain ditolak');
                }
                continue;
            }
            return $res;
        }
        throw new HttpError('Terlalu banyak redirect');
    }

    /**
     * @return array{0:string,1:int,2:string,3:string} host, port, path+query, IP tervalidasi
     */
    private function validate(string $url): array
    {
        $p = parse_url($url);
        if ($p === false || !isset($p['scheme'], $p['host'])) {
            throw new BlockedDestination('URL tidak valid');
        }
        if (strtolower($p['scheme']) !== 'https') {
            throw new BlockedDestination('Hanya HTTPS yang diizinkan');
        }
        if (isset($p['user']) || isset($p['pass']) || preg_match('/[\x00-\x20\x7f]/', $url) === 1) {
            throw new BlockedDestination('URL tidak valid');
        }
        $host = strtolower(trim($p['host'], '[]'));
        $port = $p['port'] ?? 443;
        if (!in_array($port, $this->allowedPorts, true)) {
            throw new BlockedDestination('Port tidak diizinkan');
        }
        if ($this->allowedHosts !== [] && !in_array($host, array_map('strtolower', $this->allowedHosts), true)) {
            throw new BlockedDestination('Host tidak diizinkan');
        }
        $ips = filter_var($host, FILTER_VALIDATE_IP) !== false ? [$host] : ($this->resolver)($host);
        if ($ips === []) {
            throw new HttpError('Host tidak dapat di-resolve');
        }
        foreach ($ips as $ip) {
            if (!IpPolicy::isPublic($ip)) {
                $this->log('HTTP keluar ditolak (SSRF)', ['host' => $host]);
                throw new BlockedDestination('Tujuan menunjuk alamat non-publik');
            }
        }
        $path = ($p['path'] ?? '') === '' ? '/' : $p['path'];
        if (isset($p['query'])) {
            $path .= '?' . $p['query'];
        }
        return [$host, $port, $path, $ips[0]];
    }

    /** Origin (host:port) dari URL https; null bila tak dapat diurai (validate() menolaknya kemudian). */
    private static function originOf(string $url): ?string
    {
        $p = parse_url($url);
        if ($p === false || !isset($p['host'])) {
            return null;
        }
        return strtolower(trim($p['host'], '[]')) . ':' . ($p['port'] ?? 443);
    }

    private function resolveLocation(string $base, string $loc): string
    {
        if (preg_match('/[\x00-\x20\x7f]/', $loc) === 1) {
            throw new BlockedDestination('Redirect tidak valid');
        }
        if (preg_match('#^[A-Za-z][A-Za-z0-9+.-]*:#', $loc) === 1) {
            return $loc; // absolut: skema/host divalidasi di validate()
        }
        $b = parse_url($base);
        if ($b === false || !isset($b['host'])) {
            throw new BlockedDestination('Redirect tidak valid');
        }
        $origin = 'https://' . $b['host'] . (isset($b['port']) ? ':' . $b['port'] : '');
        if (str_starts_with($loc, '//')) {
            return 'https:' . $loc;
        }
        if (str_starts_with($loc, '/')) {
            return $origin . $loc;
        }
        $dir = preg_replace('#[^/]*$#', '', $b['path'] ?? '/') ?? '/';
        return $origin . $dir . $loc;
    }

    /**
     * @param array<string,string> $headers
     * @return array<string,string>
     */
    private function cleanHeaders(array $headers): array
    {
        $out = [];
        foreach ($headers as $k => $v) {
            if (preg_match('/^[A-Za-z0-9-]+$/', (string) $k) !== 1 || preg_match('/[\r\n\0]/', $v) === 1) {
                throw new BlockedDestination('Header tidak valid');
            }
            if (in_array(strtolower((string) $k), ['host', 'connection', 'content-length', 'transfer-encoding'], true)) {
                continue;
            }
            $out[(string) $k] = $v;
        }
        return $out;
    }

    /** @return list<string> */
    private static function dnsResolver(string $host): array
    {
        $ips = [];
        foreach ([DNS_A => 'ip', DNS_AAAA => 'ipv6'] as $type => $key) {
            $rec = @dns_get_record($host, $type);
            foreach (is_array($rec) ? $rec : [] as $r) {
                if (isset($r[$key]) && is_string($r[$key])) {
                    $ips[] = $r[$key];
                }
            }
        }
        if ($ips === []) {
            $v4 = @gethostbynamel($host);
            $ips = $v4 === false ? [] : $v4;
        }
        return $ips;
    }

    /** @param array<string,scalar> $ctx */
    private function log(string $msg, array $ctx): void
    {
        if ($this->logger === null) {
            return;
        }
        // Hanya host/path/status; tidak pernah header atau query. Redactor sebagai lapis kedua.
        /** @var array<string,scalar> $clean */
        $clean = Redactor::clean($ctx);
        $this->logger->info(Redactor::message($msg), $clean);
    }
}
