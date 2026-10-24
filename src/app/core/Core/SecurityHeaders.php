<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

/** SEC-PER-03: header keamanan di setiap respons; HSTS hanya bila request HTTPS. */
final class SecurityHeaders implements Middleware
{
    /** @param (callable():string)|null $nonce penyedia nonce CSP per request (Nonce::current dari M4) */
    public function __construct(private $nonce = null, private readonly int $hstsMaxAge = 31536000)
    {
    }

    public function process(Request $r, callable $next): Response
    {
        $res = $next($r);
        $script = "'self'";
        if ($this->nonce !== null) {
            $n = ($this->nonce)();
            if (preg_match('/^[A-Za-z0-9+\/=_-]+$/', $n) === 1) {
                $script .= " 'nonce-" . $n . "'";
            }
        }
        $headers = [
            'X-Content-Type-Options' => 'nosniff',
            'Referrer-Policy' => 'strict-origin-when-cross-origin',
            'X-Frame-Options' => 'DENY',
            'Content-Security-Policy' => "default-src 'self'; script-src $script; style-src 'self'; img-src 'self' data:; "
                . "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
        ];
        if ($r->isHttps) {
            $headers['Strict-Transport-Security'] = 'max-age=' . $this->hstsMaxAge . '; includeSubDomains';
        }
        foreach ($headers as $k => $v) {
            // CSP yang ditetapkan handler (mis. berkas unggahan: default-src 'none'; sandbox) tidak ditimpa.
            if ($k === 'Content-Security-Policy' && self::hasHeader($res, $k)) {
                continue;
            }
            $res = $res->withHeader($k, $v);
        }
        return $res;
    }

    private static function hasHeader(Response $res, string $name): bool
    {
        foreach (array_keys($res->headers) as $h) {
            if (strcasecmp($h, $name) === 0) {
                return true;
            }
        }
        return false;
    }
}
