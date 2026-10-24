<?php

declare(strict_types=1);

namespace bFramework\Tests\Fixtures;

use bFramework\Auth\MailTransport;
use bFramework\Auth\Message;

final class CaptureTransport implements MailTransport
{
    /** @var list<Message> */
    public array $sent = [];

    public function send(Message $m): void
    {
        $this->sent[] = $m;
    }

    /** Token dari tautan terakhir di email terakhir. */
    public function lastToken(): string
    {
        $m = end($this->sent);
        if ($m === false || preg_match('#/auth/(?:reset|verify)/([a-f0-9]{24}\.[A-Za-z0-9_-]{43})#', $m->body, $mm) !== 1) {
            throw new \RuntimeException('Tidak ada token di email');
        }
        return $mm[1];
    }
}
