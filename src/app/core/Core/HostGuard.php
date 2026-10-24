<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\BadHost;

/** SEC-REQ-03: Host harus ada di whitelist (tanpa wildcard); whitelist kosong menolak semua. */
final class HostGuard implements Middleware
{
    /** @var list<string> */
    private array $allowed;

    /** @param list<string> $allowed entri "host" atau "host:port" */
    public function __construct(array $allowed)
    {
        $this->allowed = array_values(array_map('strtolower', $allowed));
    }

    public function process(Request $r, callable $next): Response
    {
        $host = strtolower($r->header('host') ?? '');
        if (preg_match('/^[a-z0-9.\-]+(:\d{1,5})?$/', $host) !== 1) {
            throw new BadHost('Host tidak valid');
        }
        $bare = explode(':', $host)[0];
        if (!in_array($host, $this->allowed, true) && !in_array($bare, $this->allowed, true)) {
            throw new BadHost('Host tidak diizinkan');
        }
        return $next($r);
    }
}
