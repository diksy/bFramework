<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Logger;
use bFramework\Core\Middleware;
use bFramework\Core\Request;
use bFramework\Core\Response;

/**
 * Setiap request: validasi ulang identitas sesi (AuthManager::current) dan, bila anonim dan ada cookie
 * "ingat saya", pulihkan sesi dengan rotasi token. amr hasil pemulihan hanya ['remember'] sehingga
 * aturan requireAmr (pwd/otp) tidak terpenuhi tanpa login ulang. Cookie tidak sah dihapus.
 */
final class AuthMiddleware implements Middleware
{
    public function __construct(
        private readonly AuthManager $auth,
        private readonly RememberMe $remember,
        private readonly ?Logger $logger = null,
    ) {
    }

    public static function cookieName(bool $https): string
    {
        return ($https ? '__Host-' : '') . 'bf_remember';
    }

    /** @return array<string,mixed> */
    public static function cookieOptions(bool $https, int $expires): array
    {
        return ['expires' => $expires, 'path' => '/', 'secure' => $https, 'httponly' => true, 'samesite' => 'Lax'];
    }

    public function process(Request $r, callable $next): Response
    {
        $name = self::cookieName($r->isHttps);
        $token = Cookies::parse($r->header('cookie') ?? '')[$name] ?? null;
        $set = null;
        $clear = false;
        if ($this->auth->current() === null && $token !== null) {
            $new = null;
            $uid = $this->remember->consume($token, $new);
            if ($uid !== null && $new !== null) {
                try {
                    $this->auth->login($uid, ['remember']);
                    $set = $new;
                } catch (\Throwable) {
                    $this->remember->revoke($new);
                    $clear = true;
                    $this->logger?->warning('Pemulihan sesi dari ingat-saya gagal');
                }
            } else {
                $clear = true;
            }
        }
        $res = $next($r);
        if ($set !== null) {
            $res = $res->withCookie($name, $set, self::cookieOptions($r->isHttps, time() + $this->remember->ttl()));
        } elseif ($clear) {
            $res = $res->withCookie($name, '', self::cookieOptions($r->isHttps, 1));
        }
        return $res;
    }
}
