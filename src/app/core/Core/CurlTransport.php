<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

/** Transport cURL. Verifikasi peer/host selalu aktif; hanya HTTPS; tanpa redirect otomatis. */
final class CurlTransport implements Transport
{
    /** Kode cURL terkait TLS/sertifikat. */
    private const TLS_ERRORS = [35, 51, 53, 54, 58, 59, 60, 64, 66, 77, 80, 82, 83, 90, 91];

    public static function available(): bool
    {
        return extension_loaded('curl') && function_exists('curl_init');
    }

    /**
     * Opsi cURL per metode dan body. HEAD wajib CURLOPT_NOBODY agar cURL tidak menunggu body.
     * GET/HEAD dengan body ditolak: CURLOPT_POSTFIELDS akan diam-diam mengubahnya menjadi POST.
     * Metode lain memakai CUSTOMREQUEST agar baris permintaan tetap metode asli walau POSTFIELDS dipasang.
     *
     * @return array<int,mixed>
     * @throws HttpError
     */
    public static function methodOptions(string $method, ?string $body = null): array
    {
        if ($body !== null && ($method === 'GET' || $method === 'HEAD')) {
            throw new HttpError('Metode ' . $method . ' tidak boleh membawa body');
        }
        $opts = match ($method) {
            'HEAD' => [CURLOPT_NOBODY => true],
            'GET' => [CURLOPT_HTTPGET => true],
            default => [CURLOPT_CUSTOMREQUEST => $method],
        };
        if ($body !== null) {
            $opts[CURLOPT_POSTFIELDS] = $body;
        }
        return $opts;
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
        $methodOpts = self::methodOptions($method, $body);
        $ch = curl_init();
        if ($ch === false) {
            throw new HttpError('cURL tidak dapat diinisialisasi');
        }
        $lines = [];
        foreach ($headers as $k => $v) {
            $lines[] = $k . ': ' . $v;
        }
        $hostPart = str_contains($host, ':') ? '[' . $host . ']' : $host;
        $resolveIp = str_contains($ip, ':') ? '[' . $ip . ']' : $ip;
        $respHeaders = [];
        $buf = '';
        $tooBig = false;
        curl_setopt_array($ch, [
            CURLOPT_URL => 'https://' . $hostPart . ':' . $port . $pathAndQuery,
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_RESOLVE => [$host . ':' . $port . ':' . $resolveIp],
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_SSLVERSION => CURL_SSLVERSION_TLSv1_2,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROXY => '',
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_HEADERFUNCTION => static function ($c, string $line) use (&$respHeaders): int {
                $p = strpos($line, ':');
                if ($p !== false) {
                    $respHeaders[strtolower(trim(substr($line, 0, $p)))] = trim(substr($line, $p + 1));
                }
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => static function ($c, string $chunk) use (&$buf, &$tooBig, $maxBytes): int {
                if (strlen($buf) + strlen($chunk) > $maxBytes) {
                    $tooBig = true;
                    return 0;
                }
                $buf .= $chunk;
                return strlen($chunk);
            },
        ]);
        curl_setopt_array($ch, $methodOpts);
        $ok = curl_exec($ch);
        $errno = curl_errno($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        if ($tooBig) {
            throw new HttpError('Respons melebihi batas ukuran');
        }
        if ($ok === false) {
            if (in_array($errno, self::TLS_ERRORS, true)) {
                throw new TlsError('Verifikasi TLS gagal');
            }
            throw new HttpError('Permintaan gagal (cURL ' . $errno . ')');
        }
        return new HttpResponse($status, $respHeaders, $buf);
    }
}
