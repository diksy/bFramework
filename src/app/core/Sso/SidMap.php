<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Clock;
use bFramework\Contracts\Logger;
use bFramework\Runtime\Connection;
use bFramework\Runtime\Query;
use bFramework\Runtime\Where;

/**
 * SSO-17: pemetaan `sid` (sesi di IdP) -> sesi lokal. Pencabutan ditandai di tabel dan diperiksa setiap request
 * oleh guard AuthManager, sehingga berlaku untuk semua sesi lokal meskipun ID file sesi sudah diregenerasi.
 */
final class SidMap
{
    private readonly Query $q;

    public function __construct(Connection $conn, private readonly Clock $clock, ?Logger $logger = null)
    {
        $this->q = new Query($conn, $conn->grammar(), SsoTables::allowlist(), $logger);
    }

    public function record(string $sid, int $userId, string $sub): void
    {
        $this->q->insert(SsoTables::SESSIONS, [
            'user_id' => $userId, 'sid' => $sid, 'sub' => $sub, 'created_at' => $this->now(), 'revoked_at' => null,
        ]);
    }

    public function isActive(string $sid, int $userId): bool
    {
        return $this->q->count(SsoTables::SESSIONS, new Where([['sid', '=', $sid], ['user_id', '=', $userId], ['revoked_at', 'null']])) > 0;
    }

    /**
     * Cabut sesi menurut sid (dan sub bila ada), atau semua sesi sub bila sid tidak ada.
     *
     * @return list<int> user_id yang terdampak
     */
    public function revoke(?string $sid, ?string $sub): array
    {
        $conds = [['revoked_at', 'null']];
        if ($sid !== null) {
            $conds[] = ['sid', '=', $sid];
        }
        if ($sub !== null) {
            $conds[] = ['sub', '=', $sub];
        }
        if ($sid === null && $sub === null) {
            return [];
        }
        $w = new Where($conds);
        $rows = $this->q->select(SsoTables::SESSIONS, ['user_id'], $w, null, 1000, 0);
        $this->q->update(SsoTables::SESSIONS, ['revoked_at' => $this->now()], $w);
        return array_values(array_unique(array_map(static fn(array $r): int => (int) $r['user_id'], $rows)));
    }

    /** Hapus baris yang lebih tua dari $maxAge (lewat umur absolut sesi, jadi tak mungkin dipakai lagi). */
    public function purge(int $maxAge): int
    {
        return $this->q->delete(SsoTables::SESSIONS, new Where([['created_at', '<', $this->now() - $maxAge]]));
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }
}
