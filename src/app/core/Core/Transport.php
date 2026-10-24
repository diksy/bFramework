<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

interface Transport
{
    /**
     * Satu permintaan tanpa mengikuti redirect. Koneksi wajib ke $ip (hasil validasi SSRF)
     * dengan verifikasi sertifikat terhadap $host. Respons melebihi $maxBytes => HttpError.
     *
     * @param array<string,string> $headers
     * @throws TlsError|HttpError
     */
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
    ): HttpResponse;
}
