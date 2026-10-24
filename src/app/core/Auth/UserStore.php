<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

/** Kontrak M11. Tambahan atas arsitektur: delete() dan list() untuk halaman admin. */
interface UserStore
{
    public function find(int $id): ?User;

    public function findByEmail(string $email): ?User;

    public function findBySsoSub(string $sub): ?User;

    /** @throws \InvalidArgumentException data/peran tidak sah atau email sudah dipakai */
    public function create(NewUser $new): User;

    /**
     * Hanya kolom whitelist (name, email, status, sso_sub); kolom lain melempar InvalidArgumentException.
     *
     * @param array<string,mixed> $values
     * @throws RuleViolation menonaktifkan admin aktif terakhir
     */
    public function update(int $id, array $values): void;

    /** @return list<string> */
    public function roles(int $id): array;

    /**
     * @param list<string> $roles
     * @throws RuleViolation mencabut admin aktif terakhir
     */
    public function setRoles(int $id, array $roles): void;

    /** @throws RuleViolation menghapus admin aktif terakhir */
    public function delete(int $id): void;

    /** @return list<User> urut id */
    public function list(int $limit, int $offset): array;

    public function count(): int;
}
