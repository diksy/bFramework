<?php

declare(strict_types=1);

namespace bFramework\Tests\Core;

use bFramework\Contracts\HttpException;
use bFramework\Core\Request;
use bFramework\Core\Response;
use PHPUnit\Framework\TestCase;

final class RequestResponseTest extends TestCase
{
    public function test_fromServer_header_remote_dan_https(): void
    {
        $r = Request::fromServer([
            'REQUEST_METHOD' => 'post', 'REQUEST_URI' => '/a/b/?x=1', 'HTTP_X_CSRF_TOKEN' => 't',
            'CONTENT_TYPE' => 'application/json', 'REMOTE_ADDR' => '10.0.0.1', 'HTTPS' => 'on',
        ], ['x' => '1'], [], [], '');
        self::assertSame('POST', $r->method);
        self::assertSame('/a/b', $r->path);
        self::assertSame('t', $r->header('X-CSRF-Token'));
        self::assertSame('application/json', $r->header('content-type'));
        self::assertTrue($r->isHttps);
        self::assertSame('10.0.0.1', $r->remoteAddr);
    }

    public function test_header_proxy_tidak_dipercaya(): void
    {
        $r = Request::fromServer([
            'REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4', 'HTTP_X_FORWARDED_PROTO' => 'https',
        ], [], [], [], '');
        self::assertSame('10.0.0.1', $r->remoteAddr);
        self::assertFalse($r->isHttps);
    }

    public function test_path_dengan_karakter_kontrol_ditolak(): void
    {
        $this->expectException(HttpException::class);
        Request::fromServer(['REQUEST_URI' => '/a%00b'], [], [], [], '');
    }

    public function test_input_dan_json(): void
    {
        $r = new Request('POST', '/', ['a' => 'q'], ['a' => 'p'], [], '{"k":1}');
        self::assertSame('p', $r->input('a'));
        self::assertSame('d', $r->input('z', 'd'));
        self::assertSame(['k' => 1], $r->json());
        self::assertSame([], (new Request('POST', '/'))->json());
    }

    public function test_json_rusak_400(): void
    {
        try {
            (new Request('POST', '/', body: '{bad'))->json();
            self::fail();
        } catch (HttpException $e) {
            self::assertSame(400, $e->status);
        }
    }

    public function test_response_factory(): void
    {
        self::assertSame(201, Response::html('x', 201)->status);
        $j = Response::json(['a' => '/é']);
        self::assertSame('{"a":"/é"}', $j->body);
        self::assertSame(303, Response::redirect('/x', 303)->status);
        self::assertSame('/x', Response::redirect('/x')->headers['Location']);
    }

    public function test_withHeader_immutable_dan_tolak_crlf(): void
    {
        $a = Response::html('x');
        $b = $a->withHeader('X-A', '1');
        self::assertArrayNotHasKey('X-A', $a->headers);
        self::assertSame('1', $b->headers['X-A']);
        $this->expectException(\InvalidArgumentException::class);
        $a->withHeader('X-A', "1\r\nSet-Cookie: x=y");
    }

    public function test_redirect_tolak_crlf(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Response::redirect("/x\r\nX: y");
    }

    public function test_cookie_default_aman(): void
    {
        $c = Response::html('x')->withCookie('sid', 'abc')->cookies[0];
        self::assertTrue($c['options']['httponly']);
        self::assertSame('Lax', $c['options']['samesite']);
        self::assertSame('/', $c['options']['path']);
    }

    public function test_cookie_tolak_nilai_berbahaya(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Response::html('x')->withCookie('sid', 'a; Domain=evil');
    }
}
