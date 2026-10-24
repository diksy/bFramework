<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Clock;
use bFramework\Contracts\Logger;
use bFramework\Runtime\Connection;
use bFramework\Runtime\Query;
use bFramework\Runtime\Where;
use InvalidArgumentException;

/**
 * AUTH-04: token "ingat saya" = selector.validator. Database hanya menyimpan SHA-256(validator);
 * validator dibandingkan dengan hash_equals. Setiap pemakaian dirotasi (baris lama ditandai terpakai,
 * dicabut secara atomik). Pemakaian ulang token yang sudah dirotasi (di luar masa tenggang) atau
 * validator salah pada selector valid dianggap pencurian: semua token pengguna itu dicabut.
 */
final class RememberMe
{
    private const TOKEN_RE = '/^([a-f0-9]{24})\.([A-Za-z0-9_-]{43})$/D';
    /** Detik toleransi untuk request paralel yang membawa token yang baru dirotasi. */
    private const GRACE = 10;

    private readonly Query $q;

    public function __construct(
        Connection $conn,
        private readonly Clock $clock,
        private readonly ?Logger $logger = null,
        private readonly int $ttlSeconds = 2_592_000,
    ) {
        if ($ttlSeconds < 60) {
            throw new InvalidArgumentException('TTL terlalu pendek');
        }
        $this->q = new Query($conn, $conn->grammar(), AuthTables::allowlist(), $logger);
    }

    public function ttl(): int
    {
        return $this->ttlSeconds;
    }

    /** Terbitkan token baru (nilai asli hanya dikembalikan di sini, tidak pernah disimpan). */
    public function issue(int $userId, ?string $family = null): string
    {
        $now = $this->now();
        $this->q->delete(AuthTables::REMEMBER, new Where([['expires_at', '<', $now]]));
        $selector = bin2hex(random_bytes(12));
        $validator = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $this->q->insert(AuthTables::REMEMBER, [
            'user_id' => $userId,
            'selector' => $selector,
            'token_hash' => hash('sha256', $validator),
            'family' => $family ?? bin2hex(random_bytes(16)),
            'expires_at' => $now + $this->ttlSeconds,
            'used_at' => null,
            'created_at' => $now,
        ]);
        return $selector . '.' . $validator;
    }

    /**
     * Pakai token: bila sah mengembalikan user id dan menerbitkan token pengganti di $newToken.
     */
    public function consume(string $token, ?string &$newToken = null): ?int
    {
        $newToken = null;
        if (preg_match(self::TOKEN_RE, $token, $m) !== 1) {
            return null;
        }
        [, $selector, $validator] = $m;
        $rows = $this->q->select(AuthTables::REMEMBER, ['id', 'user_id', 'token_hash', 'family', 'expires_at', 'used_at'],
            new Where([['selector', '=', $selector]]), null, 1, 0);
        if ($rows === []) {
            $this->dummyHashCompare($validator); // samakan jalur waktu dengan cabang selector valid
            return null;
        }
        $row = $rows[0];
        $uid = (int) $row['user_id'];
        $now = $this->now();
        if (!hash_equals((string) $row['token_hash'], hash('sha256', $validator))) {
            $this->theft($uid);
            return null;
        }
        if ((int) $row['expires_at'] <= $now) {
            $this->q->delete(AuthTables::REMEMBER, new Where([['id', '=', (int) $row['id']]]));
            return null;
        }
        // Klaim atomik: hanya satu request yang berhasil menandai terpakai.
        $won = $this->q->update(AuthTables::REMEMBER, ['used_at' => $now],
            new Where([['id', '=', (int) $row['id']], ['used_at', 'null']])) === 1;
        if (!$won) {
            $usedAt = $row['used_at'] === null ? $now : (int) $row['used_at'];
            if ($now - $usedAt > self::GRACE) {
                $this->theft($uid);
            }
            return null;
        }
        $newToken = $this->issue($uid, (string) $row['family']);
        return $uid;
    }

    /** Cabut satu token (logout): seluruh keluarga rotasinya ikut dihapus. */
    public function revoke(string $token): void
    {
        if (preg_match(self::TOKEN_RE, $token, $m) !== 1) {
            return;
        }
        $rows = $this->q->select(AuthTables::REMEMBER, ['family'], new Where([['selector', '=', $m[1]]]), null, 1, 0);
        if ($rows !== []) {
            $this->q->delete(AuthTables::REMEMBER, new Where([['family', '=', (string) $rows[0]['family']]]));
        }
    }

    /** Cabut semua token pengguna (ganti password, deteksi pencurian). */
    public function revokeAll(int $userId): void
    {
        $this->q->delete(AuthTables::REMEMBER, new Where([['user_id', '=', $userId]]));
    }

    private function dummyHashCompare(string $validator): bool
    {
        return hash_equals(str_repeat('0', 64), hash('sha256', $validator));
    }

    private function theft(int $userId): void
    {
        $this->revokeAll($userId);
        $this->logger?->warning('Token ingat-saya dipakai ulang atau tidak cocok; semua token pengguna dicabut', ['user_id' => $userId]);
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }
}
