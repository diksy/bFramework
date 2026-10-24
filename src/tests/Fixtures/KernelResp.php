<?php

declare(strict_types=1);

namespace bFramework\Tests\Fixtures;

/** Respons HTTP dari server tes (index.php nyata). */
final class KernelResp
{
    /** @param array<string,list<string>> $headers kunci huruf kecil */
    public function __construct(public int $status, public array $headers, public string $body, public bool $fromStatic = false)
    {
    }

    public function header(string $name): string
    {
        return $this->headers[strtolower($name)][0] ?? '';
    }

    public function location(): string
    {
        return $this->header('location');
    }

    /** @return array<string,string> nama => nilai ('' bila dihapus) */
    public function setCookies(): array
    {
        $out = [];
        foreach ($this->headers['set-cookie'] ?? [] as $c) {
            $parts = explode(';', $c);
            [$n, $v] = array_pad(explode('=', trim($parts[0]), 2), 2, '');
            $deleted = $v === '' || preg_match('/expires=Thu, 01[ -]Jan[ -]1970/i', $c) === 1 || preg_match('/max-age=0/i', $c) === 1;
            $out[$n] = $deleted ? '' : $v;
        }
        return $out;
    }

    public function csrf(): string
    {
        return preg_match('/name="_csrf" value="([a-f0-9]{64})"|name="csrf-token" content="([a-f0-9]{64})"/', $this->body, $m) === 1
            ? ($m[1] !== '' ? $m[1] : $m[2]) : '';
    }

    /**
     * Pelanggaran header keamanan (kosong = lengkap).
     *
     * @return list<string>
     */
    public function securityIssues(): array
    {
        $out = [];
        $csp = $this->header('content-security-policy');
        if (preg_match("/script-src 'self' 'nonce-([a-f0-9]{32})'/", $csp, $m) !== 1) {
            $out[] = 'CSP tanpa nonce';
        } elseif (preg_match_all('/nonce="([^"]*)"/', $this->body, $mm) > 0) {
            foreach ($mm[1] as $n) {
                if ($n !== $m[1]) {
                    $out[] = 'nonce di body tidak sama dengan header';
                }
            }
        }
        foreach (["default-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "base-uri 'self'"] as $d) {
            if (!str_contains($csp, $d)) {
                $out[] = 'CSP tanpa ' . $d;
            }
        }
        if (strtolower($this->header('x-content-type-options')) !== 'nosniff') {
            $out[] = 'nosniff';
        }
        if (strtoupper($this->header('x-frame-options')) !== 'DENY') {
            $out[] = 'X-Frame-Options';
        }
        if ($this->header('referrer-policy') === '') {
            $out[] = 'Referrer-Policy';
        }
        if (!str_contains($this->header('strict-transport-security'), 'max-age=')) {
            $out[] = 'HSTS';
        }
        return $out;
    }
}
