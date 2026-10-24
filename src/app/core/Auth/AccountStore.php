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
 * Akses data autentikasi ke tabel core (users, roles, user_roles). Semua query lewat Query (prepared,
 * allowlist AuthTables). M11 menambah UserStore penuh; kelas ini hanya yang dibutuhkan login.
 */
final class AccountStore
{
    private const COLS = ['id', 'email', 'name', 'password_hash', 'status', 'email_verified_at', 'totp_enabled',
        'totp_secret', 'totp_last_step', 'recovery_codes', 'pw_changed_at', 'break_glass', 'sso_sub'];

    private readonly Query $q;

    public function __construct(Connection $conn, private readonly Clock $clock, ?Logger $logger = null)
    {
        $this->q = new Query($conn, $conn->grammar(), AuthTables::allowlist(), $logger);
    }

    /** Normalisasi email: trim + huruf kecil; null bila bentuknya tidak sah. */
    public static function normalizeEmail(string $email): ?string
    {
        $e = mb_strtolower(trim($email));
        if ($e === '' || strlen($e) > 254 || preg_match('/[\x00-\x20\x7F<>,;"\\\\]/', $e) === 1
            || filter_var($e, FILTER_VALIDATE_EMAIL) === false) {
            return null;
        }
        return $e;
    }

    public function findByEmail(string $email): ?Account
    {
        $e = self::normalizeEmail($email);
        return $e === null ? null : $this->one(new Where([['email', '=', $e]]));
    }

    public function find(int $id): ?Account
    {
        return $this->one(new Where([['id', '=', $id]]));
    }

    /** @return list<string> nama peran, urut abjad */
    public function roles(int $userId): array
    {
        $links = $this->q->select(AuthTables::USER_ROLES, ['role_id'], new Where([['user_id', '=', $userId]]), null, 200, 0);
        $ids = array_map(static fn(array $r): int => (int) $r['role_id'], $links);
        if ($ids === []) {
            return [];
        }
        $rows = $this->q->select(AuthTables::ROLES, ['name'], new Where([['id', 'in', $ids]]), null, 200, 0);
        $names = array_map(static fn(array $r): string => (string) $r['name'], $rows);
        sort($names);
        return $names;
    }

    /** Membuat akun; email harus sah dan belum dipakai (UNIQUE). @return int|null id baru, null bila email sudah ada */
    public function create(string $email, string $name, ?string $passwordHash, string $status = 'active'): ?int
    {
        $e = self::normalizeEmail($email);
        if ($e === null || !in_array($status, ['active', 'pending', 'disabled'], true)) {
            throw new InvalidArgumentException('Data akun tidak valid');
        }
        $n = trim(preg_replace('/[\x00-\x1F\x7F]/u', '', $name) ?? '');
        if ($n === '' || mb_strlen($n) > 120) {
            throw new InvalidArgumentException('Nama tidak valid');
        }
        if ($this->findByEmail($e) !== null) {
            return null;
        }
        try {
            return $this->q->insert(AuthTables::USERS, [
                'email' => $e, 'name' => $n, 'password_hash' => $passwordHash, 'status' => $status,
                'pw_changed_at' => 0, 'created_at' => $this->now(),
            ]);
        } catch (\bFramework\Runtime\DatabaseError) {
            return null; // balapan UNIQUE
        }
    }

    public function assignRole(int $userId, string $role): void
    {
        $rows = $this->q->select(AuthTables::ROLES, ['id'], new Where([['name', '=', $role]]), null, 1, 0);
        if ($rows === []) {
            throw new InvalidArgumentException('Peran tidak ada');
        }
        $this->q->insert(AuthTables::USER_ROLES, ['user_id' => $userId, 'role_id' => (int) $rows[0]['id']]);
    }

    /** Ganti hash; menandai waktu perubahan kredensial (mencabut sesi lama, lihat AuthManager::current). */
    public function setPassword(int $userId, string $hash): void
    {
        $this->q->update(AuthTables::USERS, ['password_hash' => $hash, 'pw_changed_at' => $this->now()], new Where([['id', '=', $userId]]));
    }

    /** Rehash transparan setelah login; tidak mengubah pw_changed_at. */
    public function updateHash(int $userId, string $hash): void
    {
        $this->q->update(AuthTables::USERS, ['password_hash' => $hash], new Where([['id', '=', $userId]]));
    }

    /** Email terbukti milik pengguna; akun berstatus pending menjadi active (disabled tidak disentuh). */
    public function markVerified(int $userId): void
    {
        $this->q->update(AuthTables::USERS, ['email_verified_at' => $this->now()], new Where([['id', '=', $userId]]));
        $this->q->update(AuthTables::USERS, ['status' => 'active'], new Where([['id', '=', $userId], ['status', '=', 'pending']]));
    }

    /** Pembaruan kolom TOTP (hanya totp_* / recovery_codes).
     *
     * @param array<string,mixed> $values
     */
    public function updateTotp(int $userId, array $values): void
    {
        foreach (array_keys($values) as $k) {
            if (!in_array($k, ['totp_secret', 'totp_enabled', 'totp_last_step', 'recovery_codes'], true)) {
                throw new InvalidArgumentException('Kolom tidak diizinkan');
            }
        }
        $this->q->update(AuthTables::USERS, $values, new Where([['id', '=', $userId]]));
    }

    /** Naikkan totp_last_step secara atomik (anti replay); true bila langkah ini baru dipakai. */
    public function advanceTotpStep(int $userId, int $step): bool
    {
        return $this->q->update(
            AuthTables::USERS,
            ['totp_last_step' => $step],
            new Where([['id', '=', $userId], ['totp_last_step', '<', $step]]),
        ) === 1;
    }

    /** Ganti daftar kode pemulihan hanya bila belum berubah sejak dibaca (cegah pakai ganda). */
    public function swapRecovery(int $userId, string $oldJson, string $newJson): bool
    {
        return $this->q->update(
            AuthTables::USERS,
            ['recovery_codes' => $newJson],
            new Where([['id', '=', $userId], ['recovery_codes', '=', $oldJson]]),
        ) === 1;
    }

    private function one(Where $w): ?Account
    {
        $rows = $this->q->select(AuthTables::USERS, self::COLS, $w, null, 1, 0);
        if ($rows === []) {
            return null;
        }
        $r = $rows[0];
        $codes = [];
        if (is_string($r['recovery_codes'] ?? null) && $r['recovery_codes'] !== '') {
            $d = json_decode($r['recovery_codes'], true);
            $codes = is_array($d) ? array_values(array_filter($d, 'is_string')) : [];
        }
        return new Account(
            (int) $r['id'],
            (string) $r['email'],
            (string) $r['name'],
            is_string($r['password_hash']) && $r['password_hash'] !== '' ? $r['password_hash'] : null,
            (string) $r['status'],
            $r['email_verified_at'] === null ? null : (int) $r['email_verified_at'],
            (int) $r['totp_enabled'] === 1,
            is_string($r['totp_secret']) && $r['totp_secret'] !== '' ? $r['totp_secret'] : null,
            $r['totp_last_step'] === null ? null : (int) $r['totp_last_step'],
            $codes,
            (int) $r['pw_changed_at'],
            (int) $r['break_glass'] === 1,
            is_string($r['sso_sub'] ?? null) && $r['sso_sub'] !== '' ? $r['sso_sub'] : null,
        );
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }
}
