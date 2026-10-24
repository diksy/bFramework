<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Clock;
use bFramework\Contracts\Identity;
use bFramework\Contracts\SessionStore;
use bFramework\Core\Csrf;
use bFramework\Runtime\CurrentIdentity;
use InvalidArgumentException;

/**
 * Siklus hidup identitas di sesi. SEC-SESS-02: sesi diregenerasi + token CSRF diputar saat login
 * dan saat ganti peran. current() memvalidasi ulang ke database (akun nonaktif/dihapus, peran dicabut,
 * password berubah setelah sesi dibuat) sehingga pencabutan hak berlaku di request berikutnya.
 */
final class AuthManager
{
    private const AUTH_AT = '_auth_at';
    private const STEPUP_AT = '_stepup_at';

    /** @var (\Closure(Identity):bool)|null guard sesi tambahan dari driver (SSO-01/17): false = sesi tidak sah */
    private ?\Closure $guard = null;

    public function __construct(
        private readonly SessionStore $session,
        private readonly CurrentIdentity $identity,
        private readonly Csrf $csrf,
        private readonly AccountStore $accounts,
        private readonly Clock $clock,
    ) {
    }

    /**
     * Pasang guard sesi (dipanggil sekali saat perakitan). Guard dievaluasi saat login() dan tiap current():
     * mode SSO memakainya untuk menolak sesi lokal biasa (SSO-01) dan sesi yang dicabut back-channel (SSO-17).
     *
     * @param \Closure(Identity):bool $guard
     */
    public function useGuard(\Closure $guard): void
    {
        $this->guard = $guard;
    }

    /**
     * @param list<string> $amr
     * @throws NoRoles bila akun belum punya peran
     * @throws InvalidArgumentException bila akun tidak aktif atau guard driver menolak
     */
    public function login(int $userId, array $amr, ?string $ssoSid = null): Identity
    {
        $account = $this->accounts->find($userId);
        if ($account === null || !$account->isActive()) {
            throw new InvalidArgumentException('Akun tidak dapat login');
        }
        $roles = $this->accounts->roles($userId);
        if ($roles === []) {
            throw new NoRoles('Akun belum memiliki peran');
        }
        $amr = array_values(array_unique(array_filter($amr, static fn($a): bool => preg_match('/^[a-z]{2,16}$/D', $a) === 1)));
        $id = new Identity($userId, $roles, $roles[0], $amr, $ssoSid);
        if ($this->guard !== null && !($this->guard)($id)) {
            throw new InvalidArgumentException('Akun tidak dapat login');
        }
        $this->session->start();
        $this->session->regenerate();
        $this->csrf->rotate();
        $this->identity->set($id);
        $this->session->forget(self::STEPUP_AT);
        $this->session->set(self::AUTH_AT, $this->clock->now()->getTimestamp());
        return $id;
    }

    /**
     * Catat re-auth (step-up) segar di sesi ini. Sesi diregenerasi + CSRF diputar (kenaikan hak).
     * Waktu hanya berlaku untuk sesi ini; dibersihkan saat login/ganti peran/logout.
     */
    public function markStepUp(): void
    {
        $this->session->regenerate();
        $this->csrf->rotate();
        $this->session->set(self::STEPUP_AT, $this->clock->now()->getTimestamp());
    }

    public function stepUpAt(): ?int
    {
        $t = $this->session->get(self::STEPUP_AT);
        return is_int($t) ? $t : null;
    }

    /**
     * Perubahan 2FA: cabut sesi lain milik akun (pw_changed_at dinaikkan) dan pertahankan sesi ini
     * dengan memperbarui waktu autentikasinya.
     */
    public function revokeOtherSessions(int $userId): void
    {
        $this->accounts->touchCredentials($userId);
        $this->session->set(self::AUTH_AT, $this->clock->now()->getTimestamp());
    }

    public function current(): ?Identity
    {
        $id = $this->identity->get();
        if ($id === null) {
            return null;
        }
        $account = $this->accounts->find($id->userId);
        $authAt = $this->session->get(self::AUTH_AT);
        if ($account === null || !$account->isActive() || !is_int($authAt) || $account->pwChangedAt > $authAt) {
            $this->logout();
            return null;
        }
        $roles = $this->accounts->roles($id->userId);
        if ($roles === []) {
            $this->logout();
            return null;
        }
        if ($this->guard !== null && !($this->guard)($id)) {
            $this->logout();
            return null;
        }
        if ($roles !== $id->roles || !in_array($id->activeRole, $roles, true)) {
            $active = in_array($id->activeRole, $roles, true) ? $id->activeRole : $roles[0];
            $id = new Identity($id->userId, $roles, $active, $id->amr, $id->ssoSid);
            $this->identity->set($id);
        }
        return $id;
    }

    /** Ganti peran aktif ke peran yang memang dimiliki (diperiksa ulang ke database). */
    public function switchRole(string $role): Identity
    {
        $id = $this->current() ?? throw new InvalidArgumentException('Belum login');
        if (!in_array($role, $this->accounts->roles($id->userId), true)) {
            throw new \bFramework\Contracts\Forbidden('Peran tidak dimiliki');
        }
        $this->session->regenerate();
        $this->csrf->rotate();
        $this->session->forget(self::STEPUP_AT);
        $new = new Identity($id->userId, $id->roles, $role, $id->amr, $id->ssoSid);
        $this->identity->set($new);
        return $new;
    }

    public function logout(): void
    {
        $this->identity->clear();
        $this->session->destroy();
    }
}
