<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

/** Data pembuatan pengguna. Hash (bila ada) hanya masuk, tidak pernah keluar lewat User. */
final readonly class NewUser
{
    /** @param list<string> $roles */
    public function __construct(
        public string $email,
        public string $name,
        public ?string $passwordHash = null,
        public string $status = 'pending',
        public ?string $ssoSub = null,
        public array $roles = [],
    ) {
    }

    /** @return array<string,mixed> */
    public function __debugInfo(): array
    {
        return ['status' => $this->status];
    }
}
