<?php

declare(strict_types=1);

namespace bFramework\Tests\Core;

use bFramework\Contracts\Logger;
use bFramework\Core\Kernel;
use bFramework\Core\Middleware;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\Router;
use PHPUnit\Framework\TestCase;

final class KernelTest extends TestCase
{
    public function test_rantai_middleware_urut_luar_ke_dalam(): void
    {
        $log = [];
        $mk = static function (string $n) use (&$log): Middleware {
            return new class ($n, $log) implements Middleware {
                /** @param array<int,string> $log */
                public function __construct(private string $n, private array &$log)
                {
                }

                public function process(Request $r, callable $next): Response
                {
                    $this->log[] = $this->n;
                    return $next($r);
                }
            };
        };
        $router = new Router();
        $router->add('GET', '/', static fn(): Response => Response::html('ok'));
        $res = (new Kernel($router, [$mk('A'), $mk('B')]))->handle(new Request('GET', '/'));
        self::assertSame(['A', 'B'], $log);
        self::assertSame('ok', $res->body);
    }

    public function test_middleware_bisa_memotong(): void
    {
        $mw = new class implements Middleware {
            public function process(Request $r, callable $next): Response
            {
                return Response::html('stop', 403);
            }
        };
        $res = (new Kernel(new Router(), [$mw]))->handle(new Request('GET', '/x'));
        self::assertSame(403, $res->status);
    }

    public function test_404_dan_405(): void
    {
        $router = new Router();
        $router->add('GET', '/x', static fn(): Response => Response::html('ok'));
        $k = new Kernel($router);
        self::assertSame(404, $k->handle(new Request('GET', '/y'))->status);
        self::assertSame(405, $k->handle(new Request('POST', '/x'))->status);
    }

    public function test_exception_tak_terduga_500_tanpa_bocor_dan_dilog(): void
    {
        $router = new Router();
        $router->add('GET', '/', static function (): Response {
            throw new \RuntimeException('rahasia-db');
        });
        $logger = new class implements Logger {
            /** @var list<string> */
            public array $lines = [];
            public function error(string $msg, array $ctx = []): void
            {
                $this->lines[] = $msg . json_encode($ctx);
            }
            public function warning(string $msg, array $ctx = []): void
            {
            }
            public function info(string $msg, array $ctx = []): void
            {
            }
        };
        $res = (new Kernel($router, [], $logger))->handle(new Request('GET', '/'));
        self::assertSame(500, $res->status);
        self::assertStringNotContainsString('rahasia-db', $res->body);
        self::assertStringContainsString('RuntimeException', implode('', $logger->lines));
    }

    public function test_HEAD_tanpa_body(): void
    {
        $router = new Router();
        $router->add('GET', '/', static fn(): Response => Response::html('isi'));
        $res = (new Kernel($router))->handle(new Request('HEAD', '/'));
        self::assertSame('', $res->body);
        self::assertSame(200, $res->status);
    }

    /** ID: CORE-KERNEL-400-PATH */
    public function test_path_tidak_valid_dari_globals_jadi_400_generik(): void
    {
        foreach (['/a%00b', "/\xC3\x28", '/x%C3%28'] as $uri) {
            $res = (new Kernel(new Router()))->handleGlobals(
                static fn(): Request => Request::fromServer(['REQUEST_URI' => $uri, 'REQUEST_METHOD' => 'GET'], [], [], [], ''),
            );
            self::assertSame(400, $res->status, $uri);
            self::assertStringNotContainsString('Path tidak valid', $res->body);
            self::assertStringNotContainsString('HttpException', $res->body);
        }
    }
}
