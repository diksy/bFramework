<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

interface Middleware
{
    /** @param callable(Request):Response $next */
    public function process(Request $r, callable $next): Response;
}
