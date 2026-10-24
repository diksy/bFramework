<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

final readonly class RouteOpts
{
    public function __construct(public bool $csrf = true, public ?string $name = null)
    {
    }
}
