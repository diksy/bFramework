<?php

declare(strict_types=1);

namespace bFramework\Contracts;

defined('APP_BOOTED') || exit;

use DateTimeImmutable;

interface Clock
{
    public function now(): DateTimeImmutable;
}
