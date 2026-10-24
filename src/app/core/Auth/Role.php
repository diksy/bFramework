<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

final readonly class Role
{
    public function __construct(
        public int $id,
        public string $name,
        public ?string $label,
        public bool $system,
        public int $userCount = 0,
    ) {
    }
}
