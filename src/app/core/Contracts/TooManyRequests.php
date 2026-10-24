<?php

declare(strict_types=1);

namespace bFramework\Contracts;

defined('APP_BOOTED') || exit;

final class TooManyRequests extends HttpException
{
    /** @param int $retryAfter detik; >0 memasang header Retry-After */
    public function __construct(string $message = '', int $retryAfter = 0)
    {
        parent::__construct(429, $message, $retryAfter > 0 ? ['Retry-After' => (string) $retryAfter] : []);
    }
}
