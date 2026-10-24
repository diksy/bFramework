<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use bFramework\Runtime\Connection;
use bFramework\Runtime\Query;
use bFramework\Runtime\Sort;
use bFramework\Runtime\Where;
use InvalidArgumentException;

/** Peran (tabel core roles). Peran sistem tidak bisa dihapus; peran yang masih dipakai juga tidak. */
final class RoleStore
{
    public const ADMIN = 'admin';
    /** Peran sistem: admin (administrasi) dan staf (peran bawaan pendaftaran). */
    public const SYSTEM = ['admin', 'staf'];
    public const NAME_RE = '/^[a-z][a-z0-9_-]{1,31}$/D';

    private readonly Query $q;

    public function __construct(Connection $conn)
    {
        $this->q = new Query($conn, $conn->grammar(), AuthTables::allowlist());
    }

    /** @return list<Role> urut nama */
    public function all(): array
    {
        $rows = $this->q->select(AuthTables::ROLES, ['id', 'name', 'label'], Where::none(), new Sort('name'), 500, 0);
        $out = [];
        foreach ($rows as $r) {
            $out[] = $this->hydrate($r, $this->q->count(AuthTables::USER_ROLES, new Where([['role_id', '=', (int) $r['id']]])));
        }
        return $out;
    }

    /** @return list<string> */
    public function names(): array
    {
        return array_map(static fn(Role $r): string => $r->name, $this->all());
    }

    public function find(int $id): ?Role
    {
        $rows = $this->q->select(AuthTables::ROLES, ['id', 'name', 'label'], new Where([['id', '=', $id]]), null, 1, 0);
        return $rows === [] ? null : $this->hydrate($rows[0], 0);
    }

    public function findByName(string $name): ?Role
    {
        $rows = $this->q->select(AuthTables::ROLES, ['id', 'name', 'label'], new Where([['name', '=', $name]]), null, 1, 0);
        return $rows === [] ? null : $this->hydrate($rows[0], 0);
    }

    /** @throws InvalidArgumentException nama/label tidak sah atau nama sudah ada */
    public function create(string $name, ?string $label = null): Role
    {
        if (preg_match(self::NAME_RE, $name) !== 1) {
            throw new InvalidArgumentException('Nama peran: huruf kecil, angka, - atau _ (2-32 karakter, diawali huruf)');
        }
        $label = $label === null ? null : trim(preg_replace('/[\x00-\x1F\x7F]/u', '', $label) ?? '');
        if ($label !== null && mb_strlen($label) > 120) {
            throw new InvalidArgumentException('Label peran terlalu panjang');
        }
        if ($this->findByName($name) !== null) {
            throw new InvalidArgumentException('Nama peran sudah dipakai');
        }
        try {
            $id = $this->q->insert(AuthTables::ROLES, ['name' => $name, 'label' => $label === '' ? null : $label]);
        } catch (\bFramework\Runtime\DatabaseError) {
            throw new InvalidArgumentException('Nama peran sudah dipakai');
        }
        return new Role($id, $name, $label === '' ? null : $label, in_array($name, self::SYSTEM, true));
    }

    /** @throws RuleViolation peran sistem atau masih dipakai pengguna */
    public function delete(int $id): void
    {
        $role = $this->find($id) ?? throw new InvalidArgumentException('Peran tidak ada');
        if ($role->system) {
            throw new RuleViolation('Peran sistem tidak dapat dihapus.');
        }
        if ($this->q->count(AuthTables::USER_ROLES, new Where([['role_id', '=', $id]])) > 0) {
            throw new RuleViolation('Peran masih dipakai pengguna; cabut dulu dari pengguna.');
        }
        $this->q->delete(AuthTables::ROLES, new Where([['id', '=', $id]]));
    }

    /** @param array<string,mixed> $r */
    private function hydrate(array $r, int $count): Role
    {
        $name = (string) $r['name'];
        $label = is_string($r['label'] ?? null) && $r['label'] !== '' ? $r['label'] : null;
        return new Role((int) $r['id'], $name, $label, in_array($name, self::SYSTEM, true), $count);
    }
}
