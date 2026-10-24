<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

/**
 * Konfigurasi SSO tervalidasi. client_secret hanya hidup di objek ini (dari config/env), tidak masuk
 * log, cache, definisi, maupun dump (__debugInfo).
 */
final readonly class SsoConfig
{
    public const SKEW = 60;

    /** @param list<string> $scopes */
    private function __construct(
        public string $issuer,
        public string $clientId,
        #[\SensitiveParameter] private string $clientSecret,
        public string $provisioning,
        public string $defaultRole,
        public bool $offlineAccess,
        public int $sessionCheckMinutes,
        public string $callbackUri,
        public string $postLogoutUri,
        public array $scopes,
    ) {
    }

    /**
     * @param array<string,mixed> $sso blok sso gabungan (auth.json + config.php)
     * @return self|null null bila tidak lengkap/tidak sah (SSO dianggap belum dikonfigurasi, fail-closed)
     */
    public static function from(array $sso, string $appUrl): ?self
    {
        $issuer = $sso['issuer'] ?? null;
        $cid = $sso['client_id'] ?? null;
        $secret = $sso['client_secret'] ?? null;
        $prov = $sso['provisioning'] ?? 'jit';
        $role = $sso['default_role'] ?? 'staf';
        $min = $sso['session_check_minutes'] ?? 5;
        $app = rtrim($appUrl, '/');
        if (!is_string($issuer) || preg_match('#^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$#D', $issuer) !== 1
            || !is_string($cid) || preg_match('/^[A-Za-z0-9._-]{1,100}$/D', $cid) !== 1
            || !is_string($secret) || $secret === '' || strlen($secret) > 512
            || !in_array($prov, ['jit', 'pre_registered'], true)
            || !is_string($role) || preg_match('/^[a-z][a-z0-9_-]{0,63}$/D', $role) !== 1
            || !is_int($min) || $min < 1 || $min > 1440
            || preg_match('#^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$#D', $app) !== 1) {
            return null;
        }
        $offline = ($sso['offline_access'] ?? false) === true;
        // SSO-11: offline_access hanya bila diaktifkan.
        $scopes = $offline ? ['openid', 'profile', 'email', 'offline_access'] : ['openid', 'profile', 'email'];
        return new self($issuer, $cid, $secret, $prov, $role, $offline, $min, $app . '/auth/sso/callback', $app . '/auth/sso/signed-out', $scopes);
    }

    /** Header Authorization untuk client_secret_basic (SSO-02; RFC 6749 2.3.1: nilai di-urlencode lalu base64). */
    public function basicAuth(): string
    {
        return 'Basic ' . base64_encode(rawurlencode($this->clientId) . ':' . rawurlencode($this->clientSecret));
    }

    /** @return array<string,mixed> */
    public function __debugInfo(): array
    {
        return ['issuer' => $this->issuer, 'clientId' => $this->clientId, 'provisioning' => $this->provisioning];
    }
}
