<?php

declare(strict_types=1);

namespace bFramework\Tests\Fixtures;

use bFramework\Contracts\Clock;
use DateTimeImmutable;

final class FakeClock implements Clock
{
    public function __construct(public int $t = 1_800_000_000)
    {
    }

    public function now(): DateTimeImmutable
    {
        return (new DateTimeImmutable())->setTimestamp($this->t);
    }

    public function advance(int $seconds): void
    {
        $this->t += $seconds;
    }
}
