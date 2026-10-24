<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Logger;

/**
 * AUTH-06. Bila SMTP dikonfigurasi, HANYA SMTP (TLS wajib) yang dipakai; kegagalannya tidak diturunkan
 * ke mail() (mencegah downgrade). Tanpa SMTP, memakai mail(). Log hanya mencatat kegagalan generik.
 */
final class Mailer
{
    public function __construct(private readonly MailTransport $transport, private readonly ?Logger $logger = null)
    {
    }

    /** @param array<string,mixed> $cfg kunci: SMTP_HOST, SMTP_PORT, SMTP_SECURE, SMTP_USER, SMTP_PASSWORD, APP_HOST */
    public static function fromConfig(array $cfg, ?Logger $logger = null): self
    {
        $host = $cfg['SMTP_HOST'] ?? '';
        $ehlo = is_string($cfg['APP_HOST'] ?? null) ? $cfg['APP_HOST'] : 'localhost';
        if (is_string($host) && $host !== '') {
            $port = is_int($cfg['SMTP_PORT'] ?? null) ? $cfg['SMTP_PORT'] : 587;
            $secure = is_string($cfg['SMTP_SECURE'] ?? null) ? $cfg['SMTP_SECURE'] : 'starttls';
            $user = is_string($cfg['SMTP_USER'] ?? null) ? $cfg['SMTP_USER'] : null;
            $pass = is_string($cfg['SMTP_PASSWORD'] ?? null) ? $cfg['SMTP_PASSWORD'] : null;
            return new self(new SmtpTransport($host, $port, $secure, $user, $pass, $ehlo), $logger);
        }
        return new self(new MailFunctionTransport($ehlo), $logger);
    }

    /** @throws MailException */
    public function send(Message $m): void
    {
        try {
            $this->transport->send($m);
        } catch (MailException $e) {
            $this->logger?->error('Pengiriman email gagal');
            throw new MailException('Pengiriman email gagal', 0, $e);
        }
    }
}
