<?php

declare(strict_types=1);

namespace bFramework\Tests\Arch;

use bFramework\Contracts\Action;
use bFramework\Contracts\BadHost;
use bFramework\Contracts\CsrfMismatch;
use bFramework\Contracts\Dialect;
use bFramework\Contracts\FieldType;
use bFramework\Contracts\Forbidden;
use bFramework\Contracts\HttpException;
use bFramework\Contracts\Identity;
use bFramework\Contracts\NotFound;
use bFramework\Contracts\TooManyRequests;
use PHPUnit\Framework\TestCase;

final class ContractsTest extends TestCase
{
    public function test_ARCH_04_enum_tipe_field(): void
    {
        self::assertCount(9, FieldType::cases());
        self::assertCount(2, Dialect::cases());
        self::assertCount(4, Action::cases());
    }

    public function test_status_exception_http(): void
    {
        self::assertSame(403, (new Forbidden())->status);
        self::assertSame(404, (new NotFound())->status);
        self::assertSame(419, (new CsrfMismatch())->status);
        self::assertSame(429, (new TooManyRequests())->status);
        self::assertSame(400, (new BadHost())->status);
        self::assertInstanceOf(HttpException::class, new Forbidden());
    }

    public function test_identity(): void
    {
        $i = new Identity(1, ['a'], 'a', ['pwd']);
        self::assertSame('a', $i->activeRole);
        self::assertNull($i->ssoSid);
    }
}
