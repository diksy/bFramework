<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Action;
use bFramework\Contracts\Clock;
use bFramework\Contracts\Identity;
use bFramework\Contracts\SessionStore;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Runtime\Authorizer;

/**
 * Gerbang re-autentikasi untuk area admin (SEC-3/S3). Sesi yang dipulihkan dari cookie "ingat saya"
 * (amr=['remember']) tidak boleh membuka /admin/* tanpa password (dan OTP bila akun ber-TOTP).
 * Terpenuhi bila: (a) amr memuat 'sso' (autentikasi dipegang IdP), atau (b) amr memuat 'pwd'
 * (+ 'otp' bila akun ber-TOTP) lewat requireAmr Authorizer, atau (c) ada step-up di sesi ini
 * yang umurnya <= WINDOW detik. Selainnya diarahkan ke /auth/step-up. `next` hanya jalur
 * internal ter-whitelist dan disimpan di sesi.
 */
final class StepUp
{
    public const WINDOW = 900;
    public const NEXT_KEY = '_stepup_next';
    public const PATH = '/auth/step-up';
    private const NEXT_RE = '#^/admin/(pengguna(/baru|/[1-9][0-9]{0,17})?|peran|pembaruan)$#D';

    public function __construct(
        private readonly AuthManager $auth,
        private readonly AccountStore $accounts,
        private readonly Authorizer $authz,
        private readonly SessionStore $session,
        private readonly Clock $clock,
    ) {
    }

    public function satisfied(Identity $who): bool
    {
        if (in_array('sso', $who->amr, true)) {
            return true;
        }
        $acc = $this->accounts->find($who->userId);
        if ($acc === null) {
            return false;
        }
        $req = $acc->totpEnabled ? ['pwd', 'otp'] : ['pwd'];
        $def = ['access' => ['read' => [$who->activeRole], 'write' => [$who->activeRole], 'requireAmr' => $req]];
        if ($this->authz->can($def, Action::Read, $who)) {
            return true;
        }
        $at = $this->auth->stepUpAt();
        $now = $this->clock->now()->getTimestamp();
        return $at !== null && $at <= $now && $now - $at <= self::WINDOW;
    }

    /** Arahkan ke step-up; tujuan kembali hanya untuk GET ter-whitelist, selain itu daftar pengguna. */
    public function redirect(Request $r): Response
    {
        $next = $r->method === 'GET' ? self::safeNext($r->path) : null;
        $this->session->set(self::NEXT_KEY, $next ?? '/admin/pengguna');
        return Response::redirect(self::PATH);
    }

    public static function safeNext(mixed $v): ?string
    {
        return is_string($v) && preg_match(self::NEXT_RE, $v) === 1 ? $v : null;
    }
}
