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
        return self::apply($next($r), $r->isHttps, $this->nonce, $this->hstsMaxAge);
    }

    /**
     * Header keamanan untuk sebuah Response, tanpa middleware (jalur awal/fatal, S5). CSP yang sudah diset
     * handler tidak ditimpa. Tanpa penyedia nonce: CSP tanpa nonce (aman untuk halaman error statis).
     *
     * @param (callable():string)|null $nonce
     */
    public static function apply(Response $res, bool $https, $nonce = null, int $hstsMaxAge = 31536000): Response
    {
        foreach (self::headers($https, $nonce, $hstsMaxAge) as $k => $v) {
            if ($k === 'Content-Security-Policy' && self::hasHeader($res, $k)) {
                continue;
            }
            $res = $res->withHeader($k, $v);
        }
        return $res;
    }

    /**
     * Untuk keluaran mentah (echo) sebelum Response ada: 503 pemeliharaan/konfigurasi. Tidak menimpa CSP yang sudah terkirim.
     */
    public static function sendRaw(bool $https): void
    {
        if (headers_sent()) {
            return;
        }
        $hasCsp = false;
        foreach (headers_list() as $h) {
            if (stripos($h, 'Content-Security-Policy:') === 0) {
                $hasCsp = true;
            }
        }
        foreach (self::headers($https, null, 31536000) as $k => $v) {
            if ($k === 'Content-Security-Policy' && $hasCsp) {
                continue;
            }
            header($k . ': ' . $v);
        }
    }

    /**
     * @param (callable():string)|null $nonce
     * @return array<string,string>
     */
    private static function headers(bool $https, $nonce, int $hstsMaxAge): array
    {
        $script = "'self'";
        if ($nonce !== null) {
            $n = $nonce();
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
        if ($https) {
            $headers['Strict-Transport-Security'] = 'max-age=' . $hstsMaxAge . '; includeSubDomains';
        }
        return $headers;
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
