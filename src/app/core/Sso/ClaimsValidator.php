<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

/**
 * Validasi claims setelah tanda tangan terverifikasi (SSO-04/06/08/15). Murni logika, tanpa kripto:
 * iss persis, aud/azp, sub, exp/iat/nbf dengan skew kecil, nonce dengan hash_equals.
 */
final class ClaimsValidator
{
    public const LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';
    /** Logout token lebih tua dari ini ditolak, sehingga penyimpanan jti 2 menit (+skew) menutup seluruh jendela replay. */
    public const LOGOUT_MAX_AGE = 120;

    public function __construct(private readonly string $issuer, private readonly string $clientId, private readonly int $skew = SsoConfig::SKEW)
    {
    }

    /**
     * @param array<string,mixed> $c
     * @return array{sub:string,sid:?string,email:?string,emailVerified:?bool,name:?string}
     * @throws ClaimsInvalid
     */
    public function idToken(array $c, #[\SensitiveParameter] string $expectedNonce, int $now): array
    {
        $this->common($c, $now, true);
        $nonce = $c['nonce'] ?? null;
        if ($expectedNonce === '' || !is_string($nonce) || !hash_equals($expectedNonce, $nonce)) {
            throw new ClaimsInvalid('nonce tidak cocok');
        }
        $sub = $this->str($c['sub'] ?? null, 255, 'sub');
        $sid = isset($c['sid']) ? $this->str($c['sid'], 255, 'sid') : null;
        $email = isset($c['email']) && is_string($c['email']) ? $c['email'] : null;
        $ev = $c['email_verified'] ?? null;
        $name = isset($c['name']) && is_string($c['name']) ? $c['name'] : (isset($c['preferred_username']) && is_string($c['preferred_username']) ? $c['preferred_username'] : null);
        return ['sub' => $sub, 'sid' => $sid, 'email' => $email, 'emailVerified' => is_bool($ev) ? $ev : null, 'name' => $name];
    }

    /**
     * @param array<string,mixed> $c
     * @return array{jti:string,sub:?string,sid:?string}
     * @throws ClaimsInvalid
     */
    public function logoutToken(array $c, int $now): array
    {
        $this->common($c, $now, false);
        if (array_key_exists('nonce', $c)) {
            throw new ClaimsInvalid('logout token tidak boleh memuat nonce');
        }
        $ev = $c['events'] ?? null;
        if (!is_array($ev) || !array_key_exists(self::LOGOUT_EVENT, $ev) || !is_array($ev[self::LOGOUT_EVENT])) {
            throw new ClaimsInvalid('claim events backchannel-logout tidak ada');
        }
        $iat = $c['iat'] ?? null;
        if (!is_int($iat) && !is_float($iat) || $now - $iat > self::LOGOUT_MAX_AGE + $this->skew) {
            throw new ClaimsInvalid('logout token terlalu lama');
        }
        $jti = $this->str($c['jti'] ?? null, 255, 'jti');
        $sub = isset($c['sub']) ? $this->str($c['sub'], 255, 'sub') : null;
        $sid = isset($c['sid']) ? $this->str($c['sid'], 255, 'sid') : null;
        if ($sub === null && $sid === null) {
            throw new ClaimsInvalid('logout token harus memuat sub atau sid');
        }
        return ['jti' => $jti, 'sub' => $sub, 'sid' => $sid];
    }

    /** @param array<string,mixed> $c */
    private function common(array $c, int $now, bool $expRequired): void
    {
        if (!is_string($c['iss'] ?? null) || $c['iss'] !== $this->issuer) {
            throw new ClaimsInvalid('iss tidak cocok');
        }
        $aud = $c['aud'] ?? null;
        $auds = is_string($aud) ? [$aud] : (is_array($aud) ? array_values($aud) : []);
        if (!in_array($this->clientId, $auds, true)) {
            throw new ClaimsInvalid('aud tidak memuat client_id');
        }
        $azp = $c['azp'] ?? null;
        if ($azp !== null && $azp !== $this->clientId) {
            throw new ClaimsInvalid('azp tidak cocok');
        }
        if (count($auds) > 1 && $azp !== $this->clientId) {
            throw new ClaimsInvalid('aud ganda tanpa azp yang cocok');
        }
        $exp = $c['exp'] ?? null;
        $iat = $c['iat'] ?? null;
        if (!is_int($iat) && !is_float($iat) || $iat > $now + $this->skew) {
            throw new ClaimsInvalid('iat tidak sah');
        }
        // ID token wajib punya exp; logout token (OIDC BCL) boleh tanpa exp karena dibatasi umur iat + jti.
        if ($exp === null ? $expRequired : (!is_int($exp) && !is_float($exp) || $exp <= $now - $this->skew)) {
            throw new ClaimsInvalid('exp tidak sah atau kedaluwarsa');
        }
        $nbf = $c['nbf'] ?? null;
        if ($nbf !== null && (!is_int($nbf) && !is_float($nbf) || $nbf > $now + $this->skew)) {
            throw new ClaimsInvalid('nbf belum berlaku');
        }
    }

    private function str(mixed $v, int $max, string $name): string
    {
        if (!is_string($v) || $v === '' || strlen($v) > $max || preg_match('/[\x00-\x1F\x7F]/', $v) === 1) {
            throw new ClaimsInvalid($name . ' tidak sah');
        }
        return $v;
    }
}
