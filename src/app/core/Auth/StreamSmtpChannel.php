<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

/** Saluran nyata via stream; verifikasi sertifikat dan nama host selalu aktif (tidak ada opsi mematikan). */
final class StreamSmtpChannel implements SmtpChannel
{
    /** @var resource|null */
    private $fp = null;

    public function __construct(string $host, int $port, bool $implicitTls, int $timeout = 10)
    {
        if (preg_match('/^[A-Za-z0-9.-]{1,253}$/D', $host) !== 1 || $port < 1 || $port > 65535) {
            throw new MailException('Konfigurasi SMTP tidak valid');
        }
        $ctx = stream_context_create(['ssl' => [
            'verify_peer' => true, 'verify_peer_name' => true, 'allow_self_signed' => false, 'peer_name' => $host,
            'SNI_enabled' => true, 'disable_compression' => true,
        ]]);
        $scheme = $implicitTls ? 'ssl' : 'tcp';
        $fp = @stream_socket_client("$scheme://$host:$port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
        if ($fp === false) {
            throw new MailException('Koneksi SMTP gagal');
        }
        stream_set_timeout($fp, $timeout);
        $this->fp = $fp;
    }

    public function readLine(): string
    {
        $line = $this->fp === null ? false : fgets($this->fp, 1024);
        if ($line === false) {
            throw new MailException('Koneksi SMTP terputus');
        }
        return rtrim($line, "\r\n");
    }

    public function write(string $data): void
    {
        if ($this->fp === null || @fwrite($this->fp, $data) === false) {
            throw new MailException('Koneksi SMTP terputus');
        }
    }

    public function enableTls(): bool
    {
        if ($this->fp === null) {
            return false;
        }
        $m = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT') ? STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT : 0);
        return @stream_socket_enable_crypto($this->fp, true, $m) === true;
    }

    public function close(): void
    {
        if ($this->fp !== null) {
            @fclose($this->fp);
            $this->fp = null;
        }
    }
}
