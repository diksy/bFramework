<?php

declare(strict_types=1);

namespace bFramework\Install;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\BadHost;
use bFramework\Core\Middleware;
use bFramework\Core\Request;
use bFramework\Core\Response;

/**
 * Sebelum terpasang hanya /install yang dilayani; rute lain dialihkan (GET/HEAD) atau 503. Host harus
 * sintaks valid (daftar host baru ada setelah instal; installer mewajibkan APP_URL = Host permintaan).
 */
final class InstallGate implements Middleware
{
    public function process(Request $r, callable $next): Response
    {
        $host = strtolower($r->header('host') ?? '');
        if (!HostPolicy::validHost($host)) {
            throw new BadHost('Host tidak valid');
        }
        if ($r->path === '/install') {
            return $next($r);
        }
        if ($r->method === 'GET' || $r->method === 'HEAD') {
            return Response::redirect('/install');
        }
        return Response::html('<!doctype html><meta charset="utf-8"><title>503</title><h1>503</h1><p>Aplikasi belum terpasang.</p>', 503);
    }
}
