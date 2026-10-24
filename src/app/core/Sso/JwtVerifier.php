<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

/**
 * Antarmuka verifikasi JWT (SSO-05/06). Implementasi produksi (FirebaseJwtVerifier) membungkus library
 * yang di-vendor; tidak ada kriptografi buatan sendiri di kode proyek. Hanya RS256.
 */
interface JwtVerifier
{
    /**
     * Verifikasi tanda tangan + exp/nbf/iat terhadap JWKS, lalu kembalikan claims.
     *
     * @param array<string,mixed> $jwks dokumen JWKS ({"keys":[...]})
     * @param int $now detik epoch (dari Clock, bukan time())
     * @param int $leeway toleransi selisih jam, detik
     * @return array<string,mixed>
     * @throws UnknownKid bila kid tidak ada di JWKS
     * @throws JwtInvalid untuk semua kegagalan lain
     */
    public function verify(string $jwt, array $jwks, int $now, int $leeway): array;
}
