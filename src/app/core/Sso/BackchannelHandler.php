<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Clock;
use bFramework\Contracts\Logger;
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
    ) {
    }

    public function handle(Request $r): Response
    {
        $token = $r->post['logout_token'] ?? null;
        if (!is_string($token) || $token === '' || strlen($token) > 8192) {
            return $this->reject('logout_token tidak ada');
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

    private function reject(string $why): Response
    {
        $this->logger?->warning('Back-channel logout ditolak', ['alasan' => $why]);
        return Response::json(['error' => 'invalid_request'], 400)->withHeader('Cache-Control', 'no-store');
    }
}
