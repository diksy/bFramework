<?php

declare(strict_types=1);

namespace bFramework\Tests\Fixtures;

/** Peramban tiruan di atas KernelApp: cookie, CSRF terakhir yang terlihat, pengikut redirect. */
final class KernelBrowser
{
    /** @var array<string,string> */
    public array $cookies = [];
    public string $csrf = '';

    public function __construct(private readonly KernelApp $app, public string $ip = '198.51.100.10')
    {
    }

    /**
     * @param array<string,mixed> $post
     * @param array<string,string> $files nama field => path berkas
     * @param array<string,string> $headers
     */
    public function request(string $method, string $path, array $post = [], bool $withCsrf = true, array $files = [], array $headers = []): KernelResp
    {
        if ($method === 'POST' && $withCsrf && !array_key_exists('_csrf', $post)) {
            $post['_csrf'] = $this->csrf;
        }
        $cookie = implode('; ', array_map(static fn($k, $v) => $k . '=' . $v, array_keys($this->cookies), $this->cookies));
        if ($cookie !== '') {
            $headers['Cookie'] = $cookie;
        }
        $headers['X-Int-Remote'] = $this->ip;
        $res = $this->app->send($method, $path, $post, $files, $headers);
        foreach ($res->setCookies() as $n => $v) {
            if ($v === '') {
                unset($this->cookies[$n]);
            } else {
                $this->cookies[$n] = $v;
            }
        }
        $t = $res->csrf();
        if ($t !== '') {
            $this->csrf = $t;
        }
        return $res;
    }

    /** @param array<string,mixed> $data */
    public function json(string $method, string $path, array $data): KernelResp
    {
        $headers = ['X-CSRF-Token' => $this->csrf, 'X-Int-Remote' => $this->ip];
        $cookie = implode('; ', array_map(static fn($k, $v) => $k . '=' . $v, array_keys($this->cookies), $this->cookies));
        if ($cookie !== '') {
            $headers['Cookie'] = $cookie;
        }
        $res = $this->app->send($method, $path, [], [], $headers, false, json_encode($data, JSON_THROW_ON_ERROR));
        foreach ($res->setCookies() as $n => $v) {
            $v === '' ? $this->cookies = array_diff_key($this->cookies, [$n => 1]) : $this->cookies[$n] = $v;
        }
        return $res;
    }

    public function get(string $path): KernelResp
    {
        return $this->request('GET', $path);
    }

    /** @param array<string,mixed> $post */
    public function post(string $path, array $post = [], bool $withCsrf = true): KernelResp
    {
        return $this->request('POST', $path, $post, $withCsrf);
    }

    public function follow(KernelResp $r, int $max = 3): KernelResp
    {
        while ($r->status >= 300 && $r->status < 400 && $r->location() !== '' && $max-- > 0) {
            $loc = $r->location();
            $loc = (string) preg_replace('#^https?://[^/]+#', '', $loc);
            $r = $this->get($loc);
        }
        return $r;
    }

    public function sessionId(): ?string
    {
        foreach (['__Host-bf_sid', 'bf_sid'] as $n) {
            if (isset($this->cookies[$n])) {
                return $this->cookies[$n];
            }
        }
        return null;
    }

    /** Login lengkap lewat form. */
    public function login(string $email, string $password): KernelResp
    {
        $this->get('/login');
        return $this->post('/login', ['email' => $email, 'password' => $password]);
    }

    public function loggedIn(): bool
    {
        $r = $this->get('/login');
        return $r->status === 302;
    }
}
