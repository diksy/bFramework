<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Clock;
use bFramework\Contracts\Logger;
use bFramework\Runtime\Connection;
use bFramework\Runtime\DatabaseError;
use bFramework\Runtime\Query;
use bFramework\Runtime\Sort;
use bFramework\Runtime\Where;
use InvalidArgumentException;

/**
 * UserStore berbasis SQL (prepared lewat Query + allowlist AuthTables). Kolom rahasia (password_hash,
 * totp_*, recovery_codes) tidak pernah dibaca di sini. Aturan "admin aktif terakhir" ditegakkan di store
 * (bukan hanya UI) di dalam transaksi. Menonaktifkan akun mencabut token ingat-saya dan token sekali pakai,
 * serta menaikkan pw_changed_at sehingga sesi lama mati (AuthManager::current).
 */
final class DbUserStore implements UserStore
{
    private const COLS = ['id', 'email', 'name', 'status', 'email_verified_at', 'totp_enabled', 'sso_sub', 'break_glass', 'created_at'];
    private const UPDATABLE = ['name', 'email', 'status', 'sso_sub'];
    private const STATUSES = ['active', 'pending', 'disabled'];

    private readonly Query $q;

    public function __construct(
        private readonly Connection $conn,
        private readonly Clock $clock,
        private readonly AccountStore $accounts,
        private readonly ?Logger $logger = null,
    ) {
        $this->q = new Query($conn, $conn->grammar(), AuthTables::allowlist(), $logger);
    }

    public function find(int $id): ?User
    {
        return $this->one(new Where([['id', '=', $id]]));
    }

    public function findByEmail(string $email): ?User
    {
        $e = AccountStore::normalizeEmail($email);
        return $e === null ? null : $this->one(new Where([['email', '=', $e]]));
    }

    public function findBySsoSub(string $sub): ?User
    {
        return $sub === '' || strlen($sub) > 255 ? null : $this->one(new Where([['sso_sub', '=', $sub]]));
    }

    public function create(NewUser $new): User
    {
        if (!in_array($new->status, self::STATUSES, true)) {
            throw new InvalidArgumentException('Status tidak valid');
        }
        $roles = $this->validRoles($new->roles);
        $id = $this->tx(function () use ($new, $roles): int {
            $id = $this->accounts->create($new->email, $new->name, $new->passwordHash, $new->status);
            if ($id === null) {
                throw new InvalidArgumentException('Email sudah dipakai');
            }
            if ($new->ssoSub !== null) {
                $this->q->update(AuthTables::USERS, ['sso_sub' => $new->ssoSub], new Where([['id', '=', $id]]));
            }
            $this->writeRoles($id, $roles);
            return $id;
        });
        return $this->find($id) ?? throw new \LogicException('Pengguna baru tidak ditemukan');
    }

    public function update(int $id, array $values): void
    {
        $set = [];
        foreach ($values as $k => $v) {
            if (!in_array($k, self::UPDATABLE, true)) {
                throw new InvalidArgumentException('Kolom tidak boleh diubah');
            }
            $set[$k] = $v;
        }
        $user = $this->find($id) ?? throw new InvalidArgumentException('Pengguna tidak ada');
        if (isset($set['name'])) {
            $n = is_string($set['name']) ? trim(preg_replace('/[\x00-\x1F\x7F]/u', '', $set['name']) ?? '') : '';
            if ($n === '' || mb_strlen($n) > 120) {
                throw new InvalidArgumentException('Nama tidak valid');
            }
            $set['name'] = $n;
        }
        if (array_key_exists('email', $set)) {
            $e = is_string($set['email']) ? AccountStore::normalizeEmail($set['email']) : null;
            if ($e === null) {
                throw new InvalidArgumentException('Email tidak valid');
            }
            $other = $this->findByEmail($e);
            if ($other !== null && $other->id !== $id) {
                throw new InvalidArgumentException('Email sudah dipakai');
            }
            if ($e !== $user->email) {
                $set['email'] = $e;
                $set['email_verified_at'] = null; // email baru belum terbukti milik pengguna
            } else {
                unset($set['email']);
            }
        }
        if (array_key_exists('sso_sub', $set) && $set['sso_sub'] !== null
            && (!is_string($set['sso_sub']) || $set['sso_sub'] === '' || strlen($set['sso_sub']) > 255)) {
            throw new InvalidArgumentException('sso_sub tidak valid');
        }
        $deactivate = false;
        if (array_key_exists('status', $set)) {
            if (!is_string($set['status']) || !in_array($set['status'], self::STATUSES, true)) {
                throw new InvalidArgumentException('Status tidak valid');
            }
            $deactivate = $user->isActive() && $set['status'] !== 'active';
        }
        if ($set === []) {
            return;
        }
        $this->tx(function () use ($id, $set, $deactivate, $user): void {
            if ($deactivate && in_array(RoleStore::ADMIN, $user->roles, true)) {
                $this->assertOtherAdmin($id);
            }
            try {
                $this->q->update(AuthTables::USERS, $set, new Where([['id', '=', $id]]));
            } catch (DatabaseError) {
                throw new InvalidArgumentException('Email atau sso_sub sudah dipakai');
            }
            if ($deactivate) {
                $this->revokeCredentials($id);
            }
        });
    }

    public function roles(int $id): array
    {
        return $this->accounts->roles($id);
    }

    public function setRoles(int $id, array $roles): void
    {
        $roles = $this->validRoles($roles);
        $user = $this->find($id) ?? throw new InvalidArgumentException('Pengguna tidak ada');
        $this->tx(function () use ($id, $roles, $user): void {
            if ($user->isActive() && in_array(RoleStore::ADMIN, $user->roles, true) && !in_array(RoleStore::ADMIN, $roles, true)) {
                $this->assertOtherAdmin($id);
            }
            $this->q->delete(AuthTables::USER_ROLES, new Where([['user_id', '=', $id]]));
            $this->writeRoles($id, $roles);
        });
    }

    public function delete(int $id): void
    {
        $user = $this->find($id) ?? throw new InvalidArgumentException('Pengguna tidak ada');
        $this->tx(function () use ($id, $user): void {
            if ($user->isActive() && in_array(RoleStore::ADMIN, $user->roles, true)) {
                $this->assertOtherAdmin($id);
            }
            $this->purge($id);
        });
    }

    public function list(int $limit, int $offset): array
    {
        $rows = $this->q->select(AuthTables::USERS, self::COLS, Where::none(), new Sort('id'), max(1, min($limit, 200)), max(0, $offset));
        return array_map(fn(array $r): User => $this->hydrate($r), $rows);
    }

    public function count(): int
    {
        return $this->q->count(AuthTables::USERS, Where::none());
    }

    /**
     * Hapus akun pending yang tidak pernah terverifikasi dan lebih tua dari $maxAge detik. Akun aktif,
     * nonaktif, atau yang emailnya sudah terverifikasi tidak disentuh.
     */
    public function purgeExpiredPending(int $maxAge): int
    {
        $cut = $this->clock->now()->getTimestamp() - max(3600, $maxAge);
        $rows = $this->q->select(AuthTables::USERS, ['id'], new Where([
            ['status', '=', 'pending'], ['email_verified_at', 'null'], ['created_at', '<', $cut],
        ]), null, 500, 0);
        $n = 0;
        foreach ($rows as $r) {
            $id = (int) $r['id'];
            $n += $this->tx(function () use ($id): int {
                // Periksa ulang di dalam transaksi: akun yang baru saja aktif/terverifikasi tidak dihapus.
                $now = $this->q->count(AuthTables::USERS, new Where([
                    ['id', '=', $id], ['status', '=', 'pending'], ['email_verified_at', 'null'],
                ]));
                if ($now === 0) {
                    return 0;
                }
                $this->purge($id);
                return 1;
            });
        }
        if ($n > 0) {
            $this->logger?->info('Akun pending kedaluwarsa dibersihkan', ['count' => $n]);
        }
        return $n;
    }

    // ---------- internal ----------

    private function purge(int $id): void
    {
        $this->q->delete(AuthTables::USER_ROLES, new Where([['user_id', '=', $id]]));
        $this->q->delete(AuthTables::REMEMBER, new Where([['user_id', '=', $id]]));
        $this->q->delete(AuthTables::ONE_TIME, new Where([['user_id', '=', $id]]));
        $this->q->delete(AuthTables::USERS, new Where([['id', '=', $id]]));
    }

    /** Cabut kredensial hidup; pw_changed_at dinaikkan agar sesi lama tidak hidup lagi walau akun diaktifkan kembali. */
    private function revokeCredentials(int $id): void
    {
        $this->q->delete(AuthTables::REMEMBER, new Where([['user_id', '=', $id]]));
        $this->q->delete(AuthTables::ONE_TIME, new Where([['user_id', '=', $id]]));
        $this->q->update(AuthTables::USERS, ['pw_changed_at' => $this->clock->now()->getTimestamp()], new Where([['id', '=', $id]]));
    }

    /** @throws RuleViolation bila tidak ada admin aktif lain selain $exceptId */
    private function assertOtherAdmin(int $exceptId): void
    {
        $role = $this->q->select(AuthTables::ROLES, ['id'], new Where([['name', '=', RoleStore::ADMIN]]), null, 1, 0);
        if ($role === []) {
            throw new RuleViolation('Admin terakhir tidak boleh dicabut, dinonaktifkan, atau dihapus.');
        }
        $links = $this->q->select(AuthTables::USER_ROLES, ['user_id'], new Where([['role_id', '=', (int) $role[0]['id']]]), null, 10000, 0);
        $ids = [];
        foreach ($links as $l) {
            $uid = (int) $l['user_id'];
            if ($uid !== $exceptId) {
                $ids[] = $uid;
            }
        }
        if ($ids === [] || $this->q->count(AuthTables::USERS, new Where([['id', 'in', $ids], ['status', '=', 'active']])) === 0) {
            throw new RuleViolation('Admin terakhir tidak boleh dicabut, dinonaktifkan, atau dihapus.');
        }
    }

    /**
     * @param list<string> $roles
     * @return list<string>
     */
    private function validRoles(array $roles): array
    {
        $roles = array_values(array_unique($roles));
        if ($roles === []) {
            return [];
        }
        $rows = $this->q->select(AuthTables::ROLES, ['name'], new Where([['name', 'in', $roles]]), null, 500, 0);
        if (count($rows) !== count($roles)) {
            throw new InvalidArgumentException('Peran tidak dikenal');
        }
        return $roles;
    }

    /** @param list<string> $roles sudah divalidasi */
    private function writeRoles(int $id, array $roles): void
    {
        foreach ($roles as $r) {
            $this->accounts->assignRole($id, $r);
        }
    }

    /**
     * @template T
     * @param \Closure():T $fn
     * @return T
     */
    private function tx(\Closure $fn): mixed
    {
        $pdo = $this->conn->pdo();
        if ($pdo->inTransaction()) {
            return $fn();
        }
        $pdo->beginTransaction();
        try {
            $r = $fn();
            $pdo->commit();
            return $r;
        } catch (\Throwable $e) {
            try {
                $pdo->rollBack();
            } catch (\PDOException) {
                // transaksi sudah berakhir
            }
            throw $e;
        }
    }

    private function one(Where $w): ?User
    {
        $rows = $this->q->select(AuthTables::USERS, self::COLS, $w, null, 1, 0);
        return $rows === [] ? null : $this->hydrate($rows[0]);
    }

    /** @param array<string,mixed> $r */
    private function hydrate(array $r): User
    {
        $id = (int) $r['id'];
        return new User(
            $id,
            (string) $r['email'],
            (string) $r['name'],
            (string) $r['status'],
            $r['email_verified_at'] === null ? null : (int) $r['email_verified_at'],
            (int) $r['totp_enabled'] === 1,
            is_string($r['sso_sub'] ?? null) && $r['sso_sub'] !== '' ? $r['sso_sub'] : null,
            (int) $r['break_glass'] === 1,
            (int) $r['created_at'],
            $this->accounts->roles($id),
        );
    }
}
