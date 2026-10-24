<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Identity;
use bFramework\Contracts\SessionStore;

/** Identitas aktif disimpan di sesi sebagai array biasa (tanpa objek). Penulisnya AuthManager (M10). */
final class CurrentIdentity
{
    private const KEY = '_identity';

    public function __construct(private readonly SessionStore $session)
    {
    }

    public function get(): ?Identity
    {
        $d = $this->session->get(self::KEY);
        if (!is_array($d) || !is_int($d['userId'] ?? null) || !is_string($d['activeRole'] ?? null)
            || !is_array($d['roles'] ?? null) || !is_array($d['amr'] ?? null)) {
            return null;
        }
        $sid = $d['ssoSid'] ?? null;
        $roles = array_values(array_filter($d['roles'], 'is_string'));
        if (!in_array($d['activeRole'], $roles, true)) {
            return null; // peran aktif harus salah satu peran yang dimiliki (F16)
        }
        return new Identity(
            $d['userId'],
            $roles,
            $d['activeRole'],
            array_values(array_filter($d['amr'], 'is_string')),
            is_string($sid) ? $sid : null,
        );
    }

    public function set(Identity $i): void
    {
        if (!in_array($i->activeRole, $i->roles, true)) {
            throw new \InvalidArgumentException('Peran aktif harus salah satu peran yang dimiliki');
        }
        $this->session->set(self::KEY, [
            'userId' => $i->userId,
            'roles' => $i->roles,
            'activeRole' => $i->activeRole,
            'amr' => $i->amr,
            'ssoSid' => $i->ssoSid,
        ]);
    }

    public function clear(): void
    {
        $this->session->forget(self::KEY);
    }
}
