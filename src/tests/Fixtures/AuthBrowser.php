<?php

declare(strict_types=1);

namespace bFramework\Tests\Fixtures;

use bFramework\Core\Request;
use bFramework\Core\Response;

/** Peramban tiruan: menyimpan cookie dari Set-Cookie dan token CSRF terakhir yang tampil di halaman. */
final class AuthBrowser
{
    /** @var array<string,string> */
    public array $cookies = [];
    public string $csrf = '';
    public ?Response $last = null;

    public function __construct(private readonly AuthHarness $h, public string $ip)
    {
    }

    /** @param array<string,mixed> $post */
    public function request(string $method, string $path, array $post = [], bool $withCsrf = true): Response
    {
        if ($method === 'POST' && $withCsrf && !array_key_exists('_csrf', $post)) {
            $post['_csrf'] = $this->csrf;
        }
        $cookie = implode('; ', array_map(static fn($k, $v) => $k . '=' . $v, array_keys($this->cookies), $this->cookies));
        $headers = $cookie === '' ? [] : ['cookie' => $cookie];
        $req = new Request($method, $path, [], $post, $headers, '', [], false, $this->ip);
        $res = $this->h->dispatch($req, $this->cookies);
        foreach ($res->cookies as $c) {
            if ($c['value'] === '' || (($c['options']['expires'] ?? 1) > 0 && ($c['options']['expires'] ?? 1) < 100)) {
                unset($this->cookies[$c['name']]);
            } else {
                $this->cookies[$c['name']] = $c['value'];
            }
        }
        if (preg_match('/name="_csrf" value="([a-f0-9]{64})"/', $res->body, $m) === 1) {
            $this->csrf = $m[1];
        }
        return $this->last = $res;
    }

    public function get(string $path): Response
    {
        return $this->request('GET', $path);
    }

    /** @param array<string,mixed> $post */
    public function post(string $path, array $post = [], bool $withCsrf = true): Response
    {
        return $this->request('POST', $path, $post, $withCsrf);
    }

    public function sessionCookie(): ?string
    {
        return $this->cookies['bf_sid'] ?? null;
    }

    /** Login lengkap (GET form agar token CSRF ada, lalu POST). */
    public function login(string $email, string $password = AuthHarness::PASSWORD, bool $remember = false): Response
    {
        $this->get('/login');
        $data = ['email' => $email, 'password' => $password];
        if ($remember) {
            $data['remember'] = '1';
        }
        return $this->post('/login', $data);
    }
}
