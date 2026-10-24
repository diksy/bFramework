<?php

declare(strict_types=1);

namespace bFramework\Contracts;

defined('APP_BOOTED') || exit;

use RuntimeException;

class HttpException extends RuntimeException
{
    /** @param array<string,string> $headers header tambahan untuk respons galat (mis. Retry-After, Allow) */
    public function __construct(public readonly int $status, string $message = '', public readonly array $headers = [])
    {
        parent::__construct($message, $status);
    }
}
