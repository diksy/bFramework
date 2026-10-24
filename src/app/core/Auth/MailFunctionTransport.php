<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

/** AUTH-06: fallback mail() PHP bila SMTP tidak dikonfigurasi. */
final class MailFunctionTransport implements MailTransport
{
    /** @var (callable(string,string,string,string):bool)|null */
    private $mailFn;

    /** @param (callable(string,string,string,string):bool)|null $mailFn disuntik untuk tes */
    public function __construct(private readonly string $host = 'localhost', ?callable $mailFn = null)
    {
        $this->mailFn = $mailFn;
    }

    public function send(Message $m): void
    {
        $headers = implode("\r\n", $m->headers($this->host, time()));
        $fn = $this->mailFn ?? static fn(string $to, string $s, string $b, string $h): bool => mail($to, $s, $b, $h);
        if (!$fn($m->to, $m->encodedSubject(), $m->encodedBody(), $headers)) {
            throw new MailException('Pengiriman email gagal');
        }
    }
}
