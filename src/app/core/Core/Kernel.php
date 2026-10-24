<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\HttpException;
use bFramework\Contracts\Logger;
use Throwable;

/** Menjalankan rantai Middleware (yang pertama terluar) lalu Router. Error tidak membocorkan detail. */
final class Kernel
{
    /** @param list<Middleware> $middleware */
    public function __construct(
        private readonly Router $router,
        private readonly array $middleware = [],
        private readonly ?Logger $logger = null,
        /** Halaman error (M5, ErrorHandler::page); null = halaman minimal bawaan. */
        private readonly ?\Closure $errorPage = null,
    ) {
    }

    /** Membuat Request dari global di dalam jaring pengaman; path rusak menjadi 400 generik. */
    public function handleGlobals(?callable $factory = null): Response
    {
        try {
            $request = $factory !== null ? $factory() : Request::fromGlobals();
        } catch (HttpException $e) {
            return $this->early($this->errorResponse($e->status));
        } catch (Throwable $e) {
            $this->logger?->error('Request gagal dibentuk', ErrorHandler::context($e));
            return $this->early($this->errorResponse(400));
        }
        return $this->handle($request);
    }

    /** Respons sebelum rantai middleware ada (S5): header keamanan dipasang langsung. */
    private function early(Response $res): Response
    {
        return SecurityHeaders::apply($res, TransportPolicy::isHttps($_SERVER));
    }

    public function handle(Request $request): Response
    {
        $res = $this->run($request);
        return $request->method === 'HEAD' ? $res->withoutBody() : $res;
    }

    /**
     * Setiap lapisan dibungkus penjaga error sehingga respons error (404, 419, 400 HostGuard, 500)
     * tetap melewati middleware di luarnya (mis. SecurityHeaders, SEC-PER-03).
     */
    private function run(Request $request): Response
    {
        $next = fn(Request $r): Response => $this->guard(fn(): Response => $this->router->dispatch($r));
        foreach (array_reverse($this->middleware) as $mw) {
            $inner = $next;
            $next = fn(Request $r): Response => $this->guard(static fn(): Response => $mw->process($r, $inner));
        }
        return $next($request);
    }

    /** @param callable():Response $fn */
    private function guard(callable $fn): Response
    {
        try {
            return $fn();
        } catch (HttpException $e) {
            return $this->errorResponse($e->status);
        } catch (Throwable $e) {
            $this->logger?->error('Unhandled exception', ErrorHandler::context($e));
            return $this->errorResponse(500);
        }
    }

    private function errorResponse(int $status): Response
    {
        if ($this->errorPage !== null) {
            try {
                return ($this->errorPage)($status);
            } catch (Throwable) {
                $this->logger?->error('Halaman error gagal dibuat');
            }
        }
        return self::fallbackResponse($status);
    }

    /** Halaman error minimal dan generik, dipakai bila ErrorHandler tidak terpasang. */
    private static function fallbackResponse(int $status): Response
    {
        $msg = match ($status) {
            400 => 'Permintaan tidak valid',
            403 => 'Akses ditolak',
            404 => 'Halaman tidak ditemukan',
            405 => 'Metode tidak diizinkan',
            419 => 'Sesi kedaluwarsa',
            429 => 'Terlalu banyak permintaan',
            default => $status >= 500 ? 'Terjadi kesalahan pada server' : 'Permintaan gagal',
        };
        return Response::html('<!doctype html><meta charset="utf-8"><title>' . $status . '</title><h1>' . $status . '</h1><p>' . $msg . '</p>', $status >= 400 && $status < 600 ? $status : 500);
    }
}
