<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\HttpException;
use bFramework\Contracts\NotFound;
use InvalidArgumentException;

/**
 * Handler: callable(Request, array<string,string> $params): Response.
 * CSRF tidak diperiksa di sini; M2 membaca RouteOpts lewat opts().
 */
final class Router
{
    private const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];

    /** @var list<array{method:string,regex:string,handler:callable,opts:RouteOpts}> */
    private array $routes = [];

    public function add(string $method, string $pattern, callable $handler, RouteOpts $opts = new RouteOpts()): void
    {
        $method = strtoupper($method);
        if (!in_array($method, self::METHODS, true)) {
            throw new InvalidArgumentException('Metode HTTP tidak didukung: ' . $method);
        }
        if ($pattern === '' || $pattern[0] !== '/') {
            throw new InvalidArgumentException('Pola route harus diawali "/"');
        }
        $parts = preg_split('#(\{[A-Za-z_]\w*\})#', $pattern, -1, PREG_SPLIT_DELIM_CAPTURE | PREG_SPLIT_NO_EMPTY);
        if ($parts === false) {
            throw new InvalidArgumentException('Pola route tidak valid');
        }
        $re = '';
        foreach ($parts as $p) {
            $re .= preg_match('#^\{(\w+)\}$#', $p, $m) === 1
                ? '(?P<' . $m[1] . '>[^/]+)'
                : preg_quote($p, '#');
        }
        $this->routes[] = ['method' => $method, 'regex' => '#^' . $re . '$#D', 'handler' => $handler, 'opts' => $opts];
    }

    /**
     * Tabel hasil compile (hanya array/skalar, CACHE-08): list dari
     * ['method'=>string,'pattern'=>string,'handler'=>"Kelas::metodeStatis",'csrf'=>bool,'name'=>?string,'page'=>?string].
     * Bila `page` ada, handler dipanggil (Request, array $params, string $page).
     *
     * @param list<array<string,mixed>> $table
     */
    public static function fromCompiled(array $table): self
    {
        $r = new self();
        foreach ($table as $row) {
            $method = $row['method'] ?? null;
            $pattern = $row['pattern'] ?? null;
            $handler = $row['handler'] ?? null;
            if (!is_string($method) || !is_string($pattern) || !is_string($handler)
                || preg_match('/^[A-Za-z_][\w\\\\]*::[A-Za-z_]\w*$/', $handler) !== 1) {
                throw new InvalidArgumentException('Baris route compiled tidak valid');
            }
            $name = $row['name'] ?? null;
            $page = $row['page'] ?? null;
            if ($page !== null && (!is_string($page) || preg_match('/^[a-z][a-z0-9_-]{0,40}$/D', $page) !== 1)) {
                throw new InvalidArgumentException('Kunci page pada baris route tidak valid');
            }
            $opts = new RouteOpts(($row['csrf'] ?? true) !== false, is_string($name) ? $name : null);
            $r->add($method, $pattern, static function (Request $req, array $params) use ($handler, $page): Response {
                if (!is_callable($handler)) {
                    throw new NotFound('Handler tidak ditemukan');
                }
                // Kunci `page` diteruskan sebagai argumen ke-3 (nama halaman tepercaya dari tabel compile).
                $res = $page === null ? $handler($req, $params) : $handler($req, $params, $page);
                if (!$res instanceof Response) {
                    throw new \UnexpectedValueException('Handler harus mengembalikan Response');
                }
                return $res;
            }, $opts);
        }
        return $r;
    }

    /** Opsi route yang cocok dengan request (HEAD dianggap GET); null bila tidak ada. */
    public function opts(Request $req): ?RouteOpts
    {
        $hit = $this->match($req);
        return $hit === null ? null : $hit[0]['opts'];
    }

    public function dispatch(Request $req): Response
    {
        $hit = $this->match($req);
        if ($hit === null) {
            $allow = $this->allowedMethods($req->path);
            throw $allow !== [] ? new HttpException(405, 'Metode tidak diizinkan', ['Allow' => implode(', ', $allow)]) : new NotFound();
        }
        [$route, $params] = $hit;
        $res = ($route['handler'])($req, $params);
        if (!$res instanceof Response) {
            throw new \UnexpectedValueException('Handler harus mengembalikan Response');
        }
        return $res;
    }

    /** @return array{0:array{method:string,regex:string,handler:callable,opts:RouteOpts},1:array<string,string>}|null */
    private function match(Request $req): ?array
    {
        $method = $req->method === 'HEAD' ? 'GET' : $req->method;
        foreach ($this->routes as $route) {
            if ($route['method'] === $method && preg_match($route['regex'], $req->path, $m) === 1) {
                /** @var array<string,string> $params */
                $params = array_filter($m, 'is_string', ARRAY_FILTER_USE_KEY);
                return [$route, $params];
            }
        }
        return null;
    }

    /** @return list<string> metode (urut) yang punya route untuk path ini; HEAD ikut bila GET ada. */
    private function allowedMethods(string $path): array
    {
        $m = [];
        foreach ($this->routes as $route) {
            if (preg_match($route['regex'], $path) === 1) {
                $m[$route['method']] = true;
            }
        }
        if (isset($m['GET'])) {
            $m['HEAD'] = true;
        }
        $out = array_keys($m);
        sort($out);
        return $out;
    }
}
