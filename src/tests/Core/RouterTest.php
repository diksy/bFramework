<?php

declare(strict_types=1);

namespace bFramework\Tests\Core;

use bFramework\Contracts\HttpException;
use bFramework\Contracts\NotFound;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\RouteOpts;
use bFramework\Core\Router;
use PHPUnit\Framework\TestCase;

final class RouterTest extends TestCase
{
    public static function handle(Request $r, array $p): Response
    {
        return Response::html('id=' . ($p['id'] ?? ''));
    }

    public function test_param_dinamis_dan_regex_di_literal_di_escape(): void
    {
        $r = new Router();
        $r->add('GET', '/a.b/{id}', static fn(Request $q, array $p): Response => Response::html($p['id']));
        self::assertSame('7', $r->dispatch(new Request('GET', '/a.b/7'))->body);
        $this->expectException(NotFound::class);
        $r->dispatch(new Request('GET', '/aXb/7'));
    }

    public function test_404_dan_405_lewat_HttpException(): void
    {
        $r = new Router();
        $r->add('GET', '/x', static fn(): Response => Response::html('ok'));
        try {
            $r->dispatch(new Request('POST', '/x'));
            self::fail();
        } catch (HttpException $e) {
            self::assertSame(405, $e->status);
        }
        try {
            $r->dispatch(new Request('GET', '/nope'));
            self::fail();
        } catch (HttpException $e) {
            self::assertSame(404, $e->status);
        }
    }

    public function test_HEAD_memakai_route_GET(): void
    {
        $r = new Router();
        $r->add('GET', '/x', static fn(): Response => Response::html('ok'));
        self::assertSame(200, $r->dispatch(new Request('HEAD', '/x'))->status);
    }

    public function test_opts_csrf_dan_name(): void
    {
        $r = new Router();
        $r->add('POST', '/hook', static fn(): Response => Response::html('ok'), new RouteOpts(csrf: false, name: 'hook'));
        $r->add('POST', '/form', static fn(): Response => Response::html('ok'));
        self::assertFalse($r->opts(new Request('POST', '/hook'))?->csrf);
        self::assertTrue($r->opts(new Request('POST', '/form'))?->csrf);
        self::assertNull($r->opts(new Request('POST', '/none')));
    }

    public function test_fromCompiled(): void
    {
        $r = Router::fromCompiled([
            ['method' => 'GET', 'pattern' => '/p/{id}', 'handler' => self::class . '::handle', 'csrf' => false, 'name' => 'p'],
        ]);
        self::assertSame('id=5', $r->dispatch(new Request('GET', '/p/5'))->body);
        self::assertFalse($r->opts(new Request('GET', '/p/5'))?->csrf);
    }

    public function test_fromCompiled_menolak_baris_tidak_valid(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Router::fromCompiled([['method' => 'GET', 'pattern' => '/x', 'handler' => 'system']]);
    }
}
