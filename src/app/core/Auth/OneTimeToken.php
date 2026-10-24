<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Clock;
use bFramework\Runtime\Connection;
use bFramework\Runtime\Query;
use bFramework\Runtime\Where;
use InvalidArgumentException;

/**
 * AUTH-05: token reset/verifikasi sekali pakai, umur maksimal 3600 detik. Hanya hash yang disimpan;
 * validator dibandingkan dengan hash_equals; pemakaian diklaim secara atomik (UPDATE ... used_at IS NULL).
 */
final class OneTimeToken
{
    public const RESET = 'reset';
    public const VERIFY_EMAIL = 'verify_email';
    public const MAX_TTL = 3600;
    private const TOKEN_RE = '/^([a-f0-9]{24})\.([A-Za-z0-9_-]{43})$/D';

    private readonly Query $q;

    public function __construct(Connection $conn, private readonly Clock $clock)
    {
        $this->q = new Query($conn, $conn->grammar(), AuthTables::allowlist());
    }

    public static function wellFormed(string $token): bool
    {
        return preg_match(self::TOKEN_RE, $token) === 1;
    }

    /** Menerbitkan token baru dan membatalkan token lama (belum terpakai) untuk tujuan yang sama. */
    public function issue(int $userId, string $purpose, int $ttl = self::MAX_TTL): string
    {
        if (!in_array($purpose, [self::RESET, self::VERIFY_EMAIL], true) || $ttl < 1 || $ttl > self::MAX_TTL) {
            throw new InvalidArgumentException('Tujuan atau TTL token tidak valid');
        }
        $now = $this->now();
        $this->q->delete(AuthTables::ONE_TIME, new Where([['expires_at', '<', $now]]));
        $this->revokeAll($userId, $purpose);
        $selector = bin2hex(random_bytes(12));
        $validator = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $this->q->insert(AuthTables::ONE_TIME, [
            'user_id' => $userId,
            'purpose' => $purpose,
            'selector' => $selector,
            'token_hash' => hash('sha256', $validator),
            'expires_at' => $now + $ttl,
            'used_at' => null,
            'created_at' => $now,
        ]);
        return $selector . '.' . $validator;
    }

    /** @return int|null user id bila token sah (dan langsung hangus), selain itu null */
    public function consume(string $token, string $purpose): ?int
    {
        if (preg_match(self::TOKEN_RE, $token, $m) !== 1) {
            return null;
        }
        $rows = $this->q->select(AuthTables::ONE_TIME, ['id', 'user_id', 'purpose', 'token_hash', 'expires_at', 'used_at'],
            new Where([['selector', '=', $m[1]]]), null, 1, 0);
        $row = $rows[0] ?? null;
        $stored = $row === null ? str_repeat('0', 64) : (string) $row['token_hash'];
        $hashOk = hash_equals($stored, hash('sha256', $m[2]));
        $now = $this->now();
        if ($row === null || !$hashOk || $row['purpose'] !== $purpose || $row['used_at'] !== null || (int) $row['expires_at'] <= $now) {
            return null;
        }
        $won = $this->q->update(AuthTables::ONE_TIME, ['used_at' => $now],
            new Where([['id', '=', (int) $row['id']], ['used_at', 'null'], ['expires_at', '>', $now]])) === 1;
        return $won ? (int) $row['user_id'] : null;
    }

    /** Batalkan semua token pengguna (ganti password, email berubah). $purpose null = semua tujuan. */
    public function revokeAll(int $userId, ?string $purpose = null): void
    {
        $conds = [['user_id', '=', $userId]];
        if ($purpose !== null) {
            $conds[] = ['purpose', '=', $purpose];
        }
        $this->q->delete(AuthTables::ONE_TIME, new Where($conds));
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }
}
