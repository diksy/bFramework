<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

/**
 * Pengguna untuk administrasi (F16). Sengaja tidak memuat hash password, rahasia TOTP, maupun kode pemulihan
 * sehingga tidak mungkin bocor lewat toArray(), var_dump, template, atau log.
 */
final readonly class User
{
    /** @param list<string> $roles */
    public function __construct(
        public int $id,
        public string $email,
        public string $name,
        public string $status,
        public ?int $emailVerifiedAt,
        public bool $totpEnabled,
        public ?string $ssoSub,
        public bool $breakGlass,
        public int $createdAt,
        public array $roles = [],
    ) {
    }

    public function isActive(): bool
    {
        return $this->status === 'active';
    }

    /** @return array<string,scalar|list<string>|null> */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'email' => $this->email,
            'name' => $this->name,
            'status' => $this->status,
            'emailVerified' => $this->emailVerifiedAt !== null,
            'totpEnabled' => $this->totpEnabled,
            'ssoSub' => $this->ssoSub,
            'breakGlass' => $this->breakGlass,
            'createdAt' => $this->createdAt,
            'roles' => $this->roles,
        ];
    }

    /** @return array<string,mixed> */
    public function __debugInfo(): array
    {
        return ['id' => $this->id, 'status' => $this->status];
    }
}
