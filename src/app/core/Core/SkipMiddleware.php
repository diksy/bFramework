<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

/** Membungkus middleware: bila $skip(request) true, middleware dilewati (mis. sesi tidak dimulai untuk halaman cache, F8). */
final class SkipMiddleware implements Middleware
{
    /** @param \Closure(Request):bool $skip */
    public function __construct(private readonly Middleware $inner, private readonly \Closure $skip)
    {
    }

    public function process(Request $r, callable $next): Response
    {
        return ($this->skip)($r) ? $next($r) : $this->inner->process($r, $next);
    }
}
