<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

/** Penanda HTML tepercaya (SEC-OUT-01). Satu-satunya tipe yang diterima `{!! !!}`. */
final class SafeHtml implements \Stringable
{
    private function __construct(private readonly string $html)
    {
    }

    /** Internal: hanya untuk string yang dibangun framework (hasil render/escape), bukan input pengguna. */
    public static function fromTrusted(string $html): self
    {
        return new self($html);
    }

    public function toString(): string
    {
        return $this->html;
    }

    public function __toString(): string
    {
        return $this->html;
    }
}
