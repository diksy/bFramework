<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

/** Baris users untuk keperluan autentikasi. Hash/secret tidak ikut var_dump/log. */
final readonly class Account
{
    /** @param list<string> $recoveryHashes */
    public function __construct(
        public int $id,
        public string $email,
        public string $name,
        public ?string $passwordHash,
        public string $status,
        public ?int $emailVerifiedAt,
        public bool $totpEnabled,
        public ?string $totpSealed,
        public ?int $totpLastStep,
        public array $recoveryHashes,
        public int $pwChangedAt,
    ) {
    }

    public function isActive(): bool
    {
        return $this->status === 'active';
    }

    /** @return array<string,mixed> */
    public function __debugInfo(): array
    {
        return ['id' => $this->id, 'status' => $this->status];
    }
}
