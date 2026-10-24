<?php

declare(strict_types=1);

namespace bFramework\Tests\Fixtures;

use bFramework\Contracts\Logger;

final class CaptureLogger implements Logger
{
    /** @var list<string> */
    public array $lines = [];

    public function error(string $msg, array $ctx = []): void
    {
        $this->lines[] = 'E ' . $msg . json_encode($ctx);
    }

    public function warning(string $msg, array $ctx = []): void
    {
        $this->lines[] = 'W ' . $msg . json_encode($ctx);
    }

    public function info(string $msg, array $ctx = []): void
    {
        $this->lines[] = 'I ' . $msg . json_encode($ctx);
    }

    public function all(): string
    {
        return implode("\n", $this->lines);
    }
}
