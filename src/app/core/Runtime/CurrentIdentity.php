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
        return new Identity(
            $d['userId'],
            array_values(array_filter($d['roles'], 'is_string')),
            $d['activeRole'],
            array_values(array_filter($d['amr'], 'is_string')),
            is_string($sid) ? $sid : null,
        );
    }

    public function set(Identity $i): void
    {
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
