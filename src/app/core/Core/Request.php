<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\HttpException;
use JsonException;

final readonly class Request
{
    /**
     * @param array<string,mixed> $query
     * @param array<string,mixed> $post
     * @param array<string,string> $headers kunci huruf kecil
     * @param array<string,mixed> $files
     */
    public function __construct(
        public string $method,
        public string $path,
        public array $query = [],
        public array $post = [],
        public array $headers = [],
        public string $body = '',
        public array $files = [],
        public bool $isHttps = false,
        public string $remoteAddr = '',
    ) {
    }

    public static function fromGlobals(): self
    {
        return self::fromServer($_SERVER, $_GET, $_POST, $_FILES, (string) file_get_contents('php://input'));
    }

    /**
     * Header proxy (X-Forwarded-*) tidak dipercaya kecuali dari TRUSTED_PROXIES (TransportPolicy, S9); remoteAddr hanya dari SAPI.
     *
     * @param array<string,mixed> $server
     * @param array<string,mixed> $get
     * @param array<string,mixed> $post
     * @param array<string,mixed> $files
     */
    public static function fromServer(array $server, array $get, array $post, array $files, string $body): self
    {
        $uri = is_string($server['REQUEST_URI'] ?? null) ? $server['REQUEST_URI'] : '/';
        $path = parse_url($uri, PHP_URL_PATH);
        $path = is_string($path) ? rawurldecode($path) : '/';
        if (preg_match('/[\x00-\x1F\x7F]/', $path) === 1 || preg_match('//u', $path) !== 1) {
            throw new HttpException(400, 'Path tidak valid');
        }
        $path = '/' . ltrim($path, '/');
        if ($path !== '/') {
            $path = rtrim($path, '/');
        }

        $headers = [];
        foreach ($server as $k => $v) {
            if (!is_string($v)) {
                continue;
            }
            if (str_starts_with($k, 'HTTP_')) {
                $headers[strtolower(str_replace('_', '-', substr($k, 5)))] = $v;
            } elseif ($k === 'CONTENT_TYPE' || $k === 'CONTENT_LENGTH') {
                $headers[strtolower(str_replace('_', '-', $k))] = $v;
            }
        }

        $isHttps = TransportPolicy::isHttps($server);
        $addr = $server['REMOTE_ADDR'] ?? '';
        $method = is_string($server['REQUEST_METHOD'] ?? null) ? strtoupper($server['REQUEST_METHOD']) : 'GET';

        return new self($method, $path, $get, $post, $headers, $body, $files, $isHttps, is_string($addr) ? $addr : '');
    }

    public function input(string $key, mixed $default = null): mixed
    {
        return $this->post[$key] ?? $this->query[$key] ?? $default;
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    /** @return array<string,mixed> body kosong menghasilkan []; JSON rusak atau bukan objek/array melempar 400 */
    public function json(): array
    {
        if (trim($this->body) === '') {
            return [];
        }
        try {
            $d = json_decode($this->body, true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new HttpException(400, 'JSON tidak valid');
        }
        if (!is_array($d)) {
            throw new HttpException(400, 'JSON harus berupa objek atau array');
        }
        return $d;
    }
}
