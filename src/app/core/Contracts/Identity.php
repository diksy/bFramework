<?php

declare(strict_types=1);

namespace bFramework\Contracts;

defined('APP_BOOTED') || exit;

final readonly class Identity
{
    /**
     * @param list<string> $roles
     * @param list<string> $amr
     */
    public function __construct(
        public int $userId,
        public array $roles,
        public string $activeRole,
        public array $amr = [],
        public ?string $ssoSid = null,
    ) {
    }
}
