<?php

declare(strict_types=1);

namespace bFramework\Contracts;

defined('APP_BOOTED') || exit;

final class TooManyRequests extends HttpException
{
    public function __construct(string $message = '')
    {
        parent::__construct(429, $message);
    }
}
