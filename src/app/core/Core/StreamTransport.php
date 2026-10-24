<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

/** Fallback tanpa cURL: stream wrapper https dengan verify_peer dan verify_peer_name selalu aktif. */
final class StreamTransport implements Transport
{
    /**
     * Konteks stream. Koneksi ke IP tervalidasi, nama sertifikat diverifikasi terhadap $host.
     *
     * GET/HEAD dengan body ditolak agar perilaku sama dengan CurlTransport.
     *
     * @param array<string,string> $headers
     * @return array<string,array<string,mixed>>
     * @throws HttpError
     */
    public static function contextOptions(
        string $method,
        string $host,
        string $ip,
        array $headers,
        ?string $body,
        int $timeout
    ): array {
        if ($body !== null && ($method === 'GET' || $method === 'HEAD')) {
            throw new HttpError('Metode ' . $method . ' tidak boleh membawa body');
        }
        $lines = [];
        foreach ($headers as $k => $v) {
            $lines[] = $k . ': ' . $v;
        }
        $http = [
            'method' => $method,
            'header' => implode("\r\n", $lines),
            'timeout' => (float) $timeout,
            'follow_location' => 0,
            'max_redirects' => 0,
            'ignore_errors' => true,
            'protocol_version' => 1.1,
        ];
        if ($body !== null) {
            $http['content'] = $body;
        }
        return [
            'http' => $http,
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'allow_self_signed' => false,
                'peer_name' => $host,
                'SNI_enabled' => true,
                'SNI_server_name' => $host,
                'disable_compression' => true,
                'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
            ],
        ];
    }

    /**
     * Baca body dengan batas waktu total (deadline) dan batas ukuran.
     *
     * @param resource $fp
     * @param (callable(): float)|null $clock
     */
    public static function readBody($fp, float $deadline, int $maxBytes, ?callable $clock = null): string
    {
        $now = $clock ?? static fn (): float => microtime(true);
        $buf = '';
        while (!feof($fp)) {
            $remaining = $deadline - $now();
            if ($remaining <= 0) {
                throw new HttpError('Permintaan melewati batas waktu');
            }
            $sec = (int) $remaining;
            $usec = (int) (fmod($remaining, 1.0) * 1000000);
            if ($sec === 0 && $usec < 1) {
                $usec = 1; // batas bawah 1 µs: hindari stream_set_timeout(0, 0)
            }
            stream_set_timeout($fp, $sec, $usec);
            $chunk = fread($fp, 8192);
            if ($chunk === false) {
                break;
            }
            $buf .= $chunk;
            if (strlen($buf) > $maxBytes) {
                throw new HttpError('Respons melebihi batas ukuran');
            }
            if (stream_get_meta_data($fp)['timed_out'] || $now() > $deadline) {
                throw new HttpError('Permintaan melewati batas waktu');
            }
        }
        return $buf;
    }

    public function send(
        string $method,
        string $host,
        int $port,
        string $ip,
        string $pathAndQuery,
        array $headers,
        ?string $body,
        int $timeout,
        int $maxBytes
    ): HttpResponse {
        $deadline = microtime(true) + $timeout;
        $ipPart = str_contains($ip, ':') ? '[' . $ip . ']' : $ip;
        $ctx = stream_context_create(self::contextOptions($method, $host, $ip, $headers, $body, $timeout));
        $err = '';
        set_error_handler(static function (int $no, string $msg) use (&$err): bool {
            $err .= $msg . ' ';
            return true;
        });
        try {
            $fp = fopen('https://' . $ipPart . ':' . $port . $pathAndQuery, 'rb', false, $ctx);
        } finally {
            restore_error_handler();
        }
        if ($fp !== false && microtime(true) > $deadline) {
            fclose($fp);
            throw new HttpError('Permintaan melewati batas waktu');
        }
        if ($fp === false) {
            if (microtime(true) > $deadline) {
                throw new HttpError('Permintaan melewati batas waktu');
            }
            if (preg_match('/certificate|ssl|tls|crypto|peer/i', $err) === 1) {
                throw new TlsError('Verifikasi TLS gagal');
            }
            throw new HttpError('Permintaan gagal');
        }
        try {
            $buf = self::readBody($fp, $deadline, $maxBytes);
        } catch (HttpError $e) {
            fclose($fp);
            throw $e;
        }
        $meta = stream_get_meta_data($fp);
        fclose($fp);
        $status = 0;
        $respHeaders = [];
        $wrapper = $meta['wrapper_data'] ?? [];
        foreach (is_array($wrapper) ? $wrapper : [] as $line) {
            if (!is_string($line)) {
                continue;
            }
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) === 1) {
                $status = (int) $m[1];
                $respHeaders = [];
            } elseif (($p = strpos($line, ':')) !== false) {
                $respHeaders[strtolower(trim(substr($line, 0, $p)))] = trim(substr($line, $p + 1));
            }
        }
        return new HttpResponse($status, $respHeaders, $buf);
    }
}
