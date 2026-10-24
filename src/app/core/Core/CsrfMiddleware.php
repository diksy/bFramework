<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\CsrfMismatch;
use bFramework\Contracts\SessionStore;

/**
 * SEC-REQ-01: semua method selain GET/HEAD wajib token ("_csrf" di body, atau header X-CSRF-Token).
 * Hormati RouteOpts::csrf; rute tak dikenal diteruskan agar Router menghasilkan 404/405.
 * start() pada SessionStore harus idempoten.
 */
final class CsrfMiddleware implements Middleware
{
    public function __construct(
        private readonly Router $router,
        private readonly Csrf $csrf,
        private readonly SessionStore $session,
    ) {
    }

    public function process(Request $r, callable $next): Response
    {
        $this->session->start();
        if ($r->method === 'GET' || $r->method === 'HEAD') {
            return $next($r);
        }
        $opts = $this->router->opts($r);
        if ($opts === null || !$opts->csrf) {
            return $next($r);
        }
        $given = $r->post['_csrf'] ?? $r->header('x-csrf-token');
        if (!is_string($given) || !$this->csrf->verify($given)) {
            throw new CsrfMismatch('Token CSRF tidak valid');
        }
        return $next($r);
    }
}
