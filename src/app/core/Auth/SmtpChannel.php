<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

/** Saluran byte ke server SMTP (dipisah agar protokol bisa diuji tanpa jaringan). */
interface SmtpChannel
{
    /** Satu baris balasan tanpa CRLF; MailException bila koneksi putus. */
    public function readLine(): string;

    public function write(string $data): void;

    /** Upgrade ke TLS dengan verifikasi sertifikat; false bila gagal. */
    public function enableTls(): bool;

    public function close(): void;
}
