<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Clock;
use bFramework\Contracts\Logger;
use bFramework\Core\RateLimiter;
use bFramework\Core\Request;
use bFramework\Core\Response;
use Throwable;

/**
 * Back-channel logout (SSO-15/17): satu-satunya endpoint tanpa CSRF (didaftarkan eksplisit oleh SsoDriver).
 * Keamanan bertumpu pada tanda tangan RS256 + iss + aud + events + tanpa nonce + jti sekali pakai, bukan cookie.
 * Balasan: 204 bila berhasil, 400 generik untuk semua kegagalan (tidak membocorkan alasan ke pemanggil).
 */
final class BackchannelHandler
{
    public function __construct(
        private readonly OidcClient $oidc,
        private readonly ClaimsValidator $claims,
        private readonly JtiStore $jti,
        private readonly SidMap $sids,
        private readonly ?RefreshVault $refresh,
        private readonly Clock $clock,
        private readonly ?Logger $logger = null,
        private readonly ?RateLimiter $limiter = null,
        /** S20: batas per IP per jendela (config sso.backchannel_rate = [maks, detik]). */
        private readonly int $rateMax = self::RATE_MAX,
        private readonly int $rateWindow = self::RATE_WINDOW,
    ) {
    }

    /** S2: batas per IP; endpoint ini anonim dan verifikasi bisa memicu fetch keluar. */
    public const RATE_MAX = 30;
    public const RATE_WINDOW = 60;

    /**
     * S20: baca sso.backchannel_rate = [maks, detik]. Tidak ada -> bawaan tanpa log; ada tapi tidak sah -> bawaan + satu peringatan.
     * @return array{0:int,1:int}
     */
    public static function rateFromConfig(mixed $cfg, ?Logger $logger = null): array
    {
        if ($cfg === null) {
            return [self::RATE_MAX, self::RATE_WINDOW];
        }
        if (is_array($cfg) && count($cfg) === 2 && is_int($cfg[0] ?? null) && is_int($cfg[1] ?? null)
            && $cfg[0] >= 1 && $cfg[0] <= 10000 && $cfg[1] >= 1 && $cfg[1] <= 86400) {
            return [$cfg[0], $cfg[1]];
        }
        $logger?->warning('sso.backchannel_rate tidak sah; memakai bawaan 30/60');
        return [self::RATE_MAX, self::RATE_WINDOW];
    }

    public function handle(Request $r): Response
    {
        // Paling murah dulu: rate limit per IP (tanpa fetch), lalu ukuran, format JWT, header (alg/kid), baru verifikasi.
        if ($this->limiter !== null && !$this->limiter->hit('sso-bc:' . self::ipKey($r->remoteAddr), $this->rateMax, $this->rateWindow)) {
            $this->logger?->warning('Back-channel logout dibatasi (rate limit)');
            return Response::json(['error' => 'too_many_requests'], 429)
                ->withHeader('Cache-Control', 'no-store')->withHeader('Retry-After', (string) $this->rateWindow);
        }
        $token = $r->post['logout_token'] ?? null;
        if (!is_string($token) || $token === '' || strlen($token) > 8192) {
            return $this->reject('logout_token tidak ada');
        }
        if (!self::wellFormed($token)) {
            return $this->reject('logout_token cacat');
        }
        try {
            $claims = $this->oidc->verifyToken($token);
            $v = $this->claims->logoutToken($claims, $this->clock->now()->getTimestamp());
        } catch (JwtInvalid | ClaimsInvalid $e) {
            return $this->reject($e->getMessage());
        } catch (Throwable $e) {
            return $this->reject('kesalahan verifikasi: ' . $e::class);
        }
        // Setelah verifikasi sukses: jti sekali pakai (replay dalam jendela ditolak).
        if (!$this->jti->firstUse($v['jti'])) {
            return $this->reject('jti dipakai ulang');
        }
        $users = $this->sids->revoke($v['sid'], $v['sub']);
        foreach ($users as $uid) {
            $this->refresh?->delete($uid);
        }
        $this->logger?->info('Back-channel logout diterima', ['sesi' => count($users)]);
        return Response::html('', 204)->withHeader('Cache-Control', 'no-store');
    }

    /** Bentuk JWT 3 segmen base64url, header JSON dengan alg RS256 dan kid string wajar. Tanpa kriptografi, tanpa jaringan. */
    private static function wellFormed(string $t): bool
    {
        if (preg_match('/^([A-Za-z0-9_-]{4,2048})\.([A-Za-z0-9_-]{2,6144})\.([A-Za-z0-9_-]{16,2048})$/D', $t, $m) !== 1) {
            return false;
        }
        $raw = base64_decode(strtr($m[1], '-_', '+/'), true);
        $h = is_string($raw) ? json_decode($raw, true) : null;
        return is_array($h) && ($h['alg'] ?? null) === 'RS256'
            && is_string($h['kid'] ?? null) && $h['kid'] !== '' && strlen($h['kid']) <= 256;
    }

    /** IPv4 apa adanya; IPv4-mapped dilipat ke IPv4; IPv6 dikelompokkan per /64; selain itu 'unknown'. */
    public static function ipKey(string $ip): string
    {
        $bin = filter_var($ip, FILTER_VALIDATE_IP) !== false ? inet_pton($ip) : false;
        if ($bin === false) {
            return 'unknown';
        }
        if (strlen($bin) === 16) {
            if (str_starts_with($bin, str_repeat("\0", 10) . "\xff\xff")) {
                return (string) inet_ntop(substr($bin, 12));
            }
            return bin2hex(substr($bin, 0, 8)) . '/64';
        }
        return (string) inet_ntop($bin);
    }

    private function reject(string $why): Response
    {
        $this->logger?->warning('Back-channel logout ditolak', ['alasan' => $why]);
        return Response::json(['error' => 'invalid_request'], 400)->withHeader('Cache-Control', 'no-store');
    }
}
