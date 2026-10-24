<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Throwable;

/**
 * Adaptor ke firebase/php-jwt. Pra-pemeriksaan header (alg harus persis RS256, kid wajib) dilakukan SEBELUM
 * library dipanggil sehingga none/HS256/algorithm confusion ditolak tanpa menyentuh kunci (SSO-06). Kunci diambil
 * dari JWKS menurut kid; JWK ber-alg selain RS256 atau use selain sig tidak pernah dipakai.
 */
final class FirebaseJwtVerifier implements JwtVerifier
{
    public function verify(string $jwt, array $jwks, int $now, int $leeway): array
    {
        if (strlen($jwt) > 16384) {
            throw new JwtInvalid('Token terlalu besar');
        }
        $kid = self::kidOf($jwt);
        $jwk = null;
        $keys = $jwks['keys'] ?? null;
        foreach (is_array($keys) ? $keys : [] as $k) {
            if (is_array($k) && ($k['kid'] ?? null) === $kid) {
                $jwk = $k;
                break;
            }
        }
        if ($jwk === null) {
            throw new UnknownKid('kid tidak dikenal');
        }
        if (($jwk['kty'] ?? null) !== 'RSA' || (isset($jwk['alg']) && $jwk['alg'] !== 'RS256')
            || (isset($jwk['use']) && $jwk['use'] !== 'sig')) {
            throw new JwtInvalid('Kunci tidak sesuai untuk RS256');
        }
        JwtLibrary::load();
        $prevTs = JWT::$timestamp;
        $prevLeeway = JWT::$leeway;
        try {
            $jwk['alg'] = 'RS256';
            $key = JWK::parseKey($jwk);
            if ($key === null) {
                throw new JwtInvalid('Kunci tidak dapat dibaca');
            }
            JWT::$timestamp = $now;
            JWT::$leeway = max(0, min($leeway, 300));
            $obj = JWT::decode($jwt, [$kid => $key]);
            $claims = json_decode((string) json_encode($obj), true);
            if (!is_array($claims)) {
                throw new JwtInvalid('Claims tidak valid');
            }
            /** @var array<string,mixed> $claims */
            return $claims;
        } catch (JwtInvalid $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new JwtInvalid('Verifikasi gagal: ' . $e::class);
        } finally {
            JWT::$timestamp = $prevTs;
            JWT::$leeway = $prevLeeway;
        }
    }

    /** Header harus JSON dengan alg === "RS256" dan kid string non-kosong. */
    private static function kidOf(string $jwt): string
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3 || preg_match('/^[A-Za-z0-9_-]+$/D', $parts[0]) !== 1) {
            throw new JwtInvalid('Format token salah');
        }
        $raw = base64_decode(strtr($parts[0], '-_', '+/'), true);
        $h = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($h) || ($h['alg'] ?? null) !== 'RS256') {
            throw new JwtInvalid('Algoritma ditolak (hanya RS256)');
        }
        $kid = $h['kid'] ?? null;
        if (!is_string($kid) || $kid === '' || strlen($kid) > 200) {
            throw new JwtInvalid('kid tidak ada');
        }
        return $kid;
    }
}
