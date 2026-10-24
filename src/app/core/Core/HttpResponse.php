<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

final readonly class HttpResponse
{
    /** @param array<string,string> $headers kunci huruf kecil */
    public function __construct(public int $status, public array $headers, public string $body)
    {
    }
}
