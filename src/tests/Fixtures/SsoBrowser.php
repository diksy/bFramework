<?php

declare(strict_types=1);

namespace bFramework\Tests\Fixtures;

use bFramework\Core\Request;
use bFramework\Core\Response;

/** Peramban tiruan untuk alur SSO: cookie dari Set-Cookie, token CSRF dari halaman, dan alur login lengkap dengan IdP palsu. */
final class SsoBrowser
{
    /** @var array<string,string> */
    public array $cookies = [];
    public string $csrf = '';

    public function __construct(private readonly SsoHarness $h, public string $ip)
    {
    }

    /** @param array<string,mixed> $post */
    public function request(string $method, string $uri, array $post = [], bool $withCsrf = true): Response
    {
        $query = [];
        $path = (string) strtok($uri, '?');
        $qs = parse_url($uri, PHP_URL_QUERY);
        if (is_string($qs)) {
            parse_str($qs, $query);
        }
        if ($method === 'POST' && $withCsrf && !array_key_exists('_csrf', $post)) {
            $post['_csrf'] = $this->csrf;
        }
        $cookie = implode('; ', array_map(static fn($k, $v) => $k . '=' . $v, array_keys($this->cookies), $this->cookies));
        $req = new Request($method, $path, $query, $post, $cookie === '' ? [] : ['cookie' => $cookie], '', [], false, $this->ip);
        $res = $this->h->dispatch($req, $this->cookies);
        foreach ($res->cookies as $c) {
            if ($c['value'] === '' || (($c['options']['expires'] ?? 1) > 0 && ($c['options']['expires'] ?? 1) < 100)) {
                unset($this->cookies[$c['name']]);
            } else {
                $this->cookies[$c['name']] = $c['value'];
            }
        }
        if (preg_match('/name="_csrf" value="([a-f0-9]{64})"|name="csrf-token" content="([a-f0-9]{64})"/', $res->body, $m) === 1) {
            $m[1] = $m[1] !== '' ? $m[1] : $m[2];
            $this->csrf = $m[1];
        }
        return $res;
    }

    public function get(string $uri): Response
    {
        return $this->request('GET', $uri);
    }

    /** @param array<string,mixed> $post */
    public function post(string $uri, array $post = [], bool $withCsrf = true): Response
    {
        return $this->request('POST', $uri, $post, $withCsrf);
    }

    /** Halaman publik ber-layout memuat meta csrf-token milik sesi saat ini. */
    public function refreshCsrf(): void
    {
        $this->get('/auth/sso/signed-out');
    }

    public function loggedIn(): bool
    {
        $r = $this->get('/login');
        return $r->status === 302 && ($r->headers['Location'] ?? '') === '/';
    }

    /**
     * Mulai login: GET /auth/sso/login. Mengembalikan parameter yang dikirim ke IdP.
     *
     * @return array{res:Response,params:array<string,string>}
     */
    public function start(string $next = ''): array
    {
        $this->get('/login'); // sesi + token CSRF
        $res = $this->get('/auth/sso/login' . ($next === '' ? '' : '?next=' . rawurlencode($next)));
        $loc = $res->headers['Location'] ?? '';
        $params = [];
        parse_str((string) parse_url($loc, PHP_URL_QUERY), $params);
        /** @var array<string,string> $params */
        return ['res' => $res, 'params' => $params];
    }

    /**
     * Alur lengkap sampai callback.
     *
     * @param array<string,mixed> $claims claim tambahan untuk ID token
     * @param array<string,mixed> $tokenExtra isi tambahan respons token (mis. refresh_token)
     * @return array{start:array<string,string>,callback:Response,idToken:string}
     */
    public function login(array $claims = [], array $tokenExtra = [], string $next = ''): array
    {
        $s = $this->start($next);
        $p = $s['params'];
        $idt = $this->h->idp->idToken($p['nonce'] ?? '', $claims);
        $this->h->idp->tokenQueue[] = [200, array_replace(['access_token' => 'at-1', 'token_type' => 'Bearer', 'expires_in' => 300, 'id_token' => $idt], $tokenExtra)];
        $cb = $this->get('/auth/sso/callback?code=kode-1&state=' . rawurlencode($p['state'] ?? ''));
        return ['start' => $p, 'callback' => $cb, 'idToken' => $idt];
    }
}
