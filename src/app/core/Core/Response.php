<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\NotImplemented;

/** Stub kontrak; diisi M1. */
final class Response
{
    public static function html(string $body, int $status = 200): self
    {
        throw NotImplemented::in(__METHOD__);
    }

    /** @param array<mixed> $data */
    public static function json(array $data, int $status = 200): self
    {
        throw NotImplemented::in(__METHOD__);
    }

    public static function redirect(string $url, int $status = 302): self
    {
        throw NotImplemented::in(__METHOD__);
    }

    public function withHeader(string $name, string $value): self
    {
        throw NotImplemented::in(__METHOD__);
    }

    /** @param array<string,mixed> $options */
    public function withCookie(string $name, string $value, array $options = []): self
    {
        throw NotImplemented::in(__METHOD__);
    }

    public function send(): void
    {
        throw NotImplemented::in(__METHOD__);
    }
}
