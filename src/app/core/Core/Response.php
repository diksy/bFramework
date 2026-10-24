<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

use InvalidArgumentException;
use JsonException;

final class Response
{
    /**
     * @param array<string,string> $headers
     * @param list<array{name:string,value:string,options:array<string,mixed>}> $cookies
     */
    private function __construct(
        public readonly string $body,
        public readonly int $status,
        public readonly array $headers,
        public readonly array $cookies = [],
    ) {
    }

    public static function html(string $body, int $status = 200): self
    {
        return new self($body, $status, ['Content-Type' => 'text/html; charset=utf-8']);
    }

    /** @param array<mixed> $data */
    public static function json(array $data, int $status = 200): self
    {
        try {
            $body = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidArgumentException('Data tidak dapat di-encode ke JSON', 0, $e);
        }
        return new self($body, $status, ['Content-Type' => 'application/json; charset=utf-8']);
    }

    /**
     * Cegah open redirect (SEC-REQ-04): tujuan harus path relatif ("/..." bukan "//" atau "/\\"),
     * atau URL http(s) absolut yang host-nya ada di $allowedHosts (huruf kecil, tanpa port).
     *
     * @param list<string> $allowedHosts
     */
    public static function redirect(string $url, int $status = 302, array $allowedHosts = []): self
    {
        self::assertHeaderSafe($url);
        if (!self::isSafeRedirect($url, $allowedHosts)) {
            throw new InvalidArgumentException('Tujuan redirect tidak diizinkan');
        }
        if ($status < 300 || $status > 399) {
            throw new InvalidArgumentException('Status redirect harus 3xx');
        }
        return new self('', $status, ['Location' => $url]);
    }

    public function withHeader(string $name, string $value): self
    {
        if (preg_match('/^[A-Za-z0-9\-]+$/', $name) !== 1) {
            throw new InvalidArgumentException('Nama header tidak valid');
        }
        self::assertHeaderSafe($value);
        $headers = array_filter($this->headers, static fn(string $k): bool => strcasecmp($k, $name) !== 0, ARRAY_FILTER_USE_KEY);
        $headers[$name] = $value;
        return new self($this->body, $this->status, $headers, $this->cookies);
    }

    /**
     * Default aman: path "/", secure, httponly, samesite Lax (HTTP polos harus eksplisit secure=false). Opsi: expires(int), path, domain, secure(bool), httponly(bool), samesite.
     *
     * @param array<string,mixed> $options
     */
    public function withCookie(string $name, string $value, array $options = []): self
    {
        if (preg_match('/^[A-Za-z0-9!#$%&\'*+\-.^_`|~]+$/', $name) !== 1) {
            throw new InvalidArgumentException('Nama cookie tidak valid');
        }
        self::assertHeaderSafe($value);
        if (preg_match('/[;,\s]/', $value) === 1) {
            throw new InvalidArgumentException('Nilai cookie tidak valid');
        }
        $options += ['path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax'];
        $same = $options['samesite'];
        if (!is_string($same) || !in_array($same, ['Lax', 'Strict', 'None'], true)) {
            throw new InvalidArgumentException('samesite tidak valid');
        }
        foreach (['path', 'domain'] as $k) {
            if (isset($options[$k])) {
                if (!is_string($options[$k])) {
                    throw new InvalidArgumentException("Opsi $k tidak valid");
                }
                self::assertHeaderSafe($options[$k]);
                if (str_contains($options[$k], ';')) {
                    throw new InvalidArgumentException("Opsi $k tidak valid");
                }
            }
        }
        $cookies = $this->cookies;
        $cookies[] = ['name' => $name, 'value' => $value, 'options' => $options];
        return new self($this->body, $this->status, $this->headers, $cookies);
    }

    public function send(): void
    {
        http_response_code($this->status);
        foreach ($this->headers as $k => $v) {
            header($k . ': ' . $v);
        }
        foreach ($this->cookies as $c) {
            setcookie($c['name'], $c['value'], $c['options']);
        }
        echo $this->body;
    }

    /** Dipakai Kernel untuk HEAD: status dan header sama, tanpa body. */
    public function withoutBody(): self
    {
        return new self('', $this->status, $this->headers, $this->cookies);
    }

    /** @param list<string> $allowedHosts */
    private static function isSafeRedirect(string $url, array $allowedHosts): bool
    {
        if ($url === '' || preg_match('/[\\\\\s]/', $url) === 1) {
            return false;
        }
        if ($url[0] === '/') {
            return !str_starts_with($url, '//');
        }
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'], $parts['host']) || isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }
        return in_array(strtolower($parts['scheme']), ['http', 'https'], true)
            && in_array(strtolower($parts['host']), $allowedHosts, true);
    }

    private static function assertHeaderSafe(string $v): void
    {
        if (preg_match('/[\x00-\x08\x0A-\x1F\x7F]/', $v) === 1) {
            throw new InvalidArgumentException('Karakter kontrol tidak diizinkan di header');
        }
    }
}
