<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\NotImplemented;

/** Stub kontrak; diisi M1. */
final readonly class Request
{
    /**
     * @param array<string,mixed> $query
     * @param array<string,mixed> $post
     * @param array<string,string> $headers
     * @param array<string,mixed> $files
     */
    public function __construct(
        public string $method,
        public string $path,
        public array $query = [],
        public array $post = [],
        public array $headers = [],
        public string $body = '',
        public array $files = [],
        public bool $isHttps = false,
        public string $remoteAddr = '',
    ) {
    }

    public function input(string $key, mixed $default = null): mixed
    {
        throw NotImplemented::in(__METHOD__);
    }

    public function header(string $name): ?string
    {
        throw NotImplemented::in(__METHOD__);
    }

    /** @return array<string,mixed> */
    public function json(): array
    {
        throw NotImplemented::in(__METHOD__);
    }
}
