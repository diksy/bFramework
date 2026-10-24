<?php

declare(strict_types=1);

namespace bFramework\Core;

/**
 * Pengganti HttpClient (tes integrasi): melayani IdP palsu dari $INT_SANDBOX/idp.json (discovery, jwks, token,
 * introspect); host lain ditolak. Panggilan dicatat di idp_calls.jsonl. Tidak ada koneksi jaringan.
 */
final class HttpClient
{
    /** @param array<string,string> $headers */
    public function request(string $method, string $url, array $headers = [], ?string $body = null, int $timeout = 10): HttpResponse
    {
        $file = (string) getenv('INT_SANDBOX') . '/idp.json';
        $state = is_file($file) ? json_decode((string) file_get_contents($file), true) : null;
        if (!is_array($state)) {
            throw new HttpError('IdP palsu tidak dikonfigurasi');
        }
        $host = (string) parse_url($url, PHP_URL_HOST);
        $path = (string) parse_url($url, PHP_URL_PATH);
        file_put_contents((string) getenv('INT_SANDBOX') . '/idp_calls.jsonl', json_encode(['m' => $method, 'host' => $host, 'path' => $path, 'body' => $body]) . "\n", FILE_APPEND | LOCK_EX);
        if ($host !== 'sso.contoh.test') {
            throw new BlockedDestination('Tujuan tidak diizinkan');
        }
        $h = ['content-type' => 'application/json', 'cache-control' => 'max-age=3600'];
        $j = static fn(mixed $v): string => json_encode($v, JSON_THROW_ON_ERROR);
        switch ($path) {
            case '/.well-known/openid-configuration':
                return new HttpResponse(200, $h, $j($state['discovery']));
            case '/keys/set.json':
                return new HttpResponse(200, $h, $j($state['jwks']));
            case '/oauth2/tok':
                $q = $state['tokens'] ?? [];
                $next = array_shift($q) ?? [400, ['error' => 'invalid_grant']];
                $state['tokens'] = $q;
                file_put_contents($file, json_encode($state));
                return new HttpResponse((int) $next[0], $h, $j($next[1]));
            case '/oauth2/check':
                return new HttpResponse(200, $h, $j(['active' => $state['introspect'] ?? true]));
        }
        return new HttpResponse(404, $h, '{}');
    }
}
