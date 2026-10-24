<?php

declare(strict_types=1);

namespace bFramework\Contracts;

defined('APP_BOOTED') || exit;

interface Logger
{
    /** @param array<string,scalar> $ctx */
    public function error(string $msg, array $ctx = []): void;

    /** @param array<string,scalar> $ctx */
    public function warning(string $msg, array $ctx = []): void;

    /** @param array<string,scalar> $ctx */
    public function info(string $msg, array $ctx = []): void;
}
