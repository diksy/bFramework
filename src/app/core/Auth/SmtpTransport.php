<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

/**
 * SMTP dengan TLS WAJIB: 'tls' = TLS implisit (port 465), 'starttls' = STARTTLS (port 587) dan
 * pengiriman dibatalkan bila server tidak menawarkannya. Kredensial tidak dikirim sebelum TLS aktif.
 * Tidak ada fallback ke plaintext. Isi pesan/tautan tidak pernah dicatat.
 */
final class SmtpTransport implements MailTransport
{
    /** @var callable(): SmtpChannel */
    private $connect;

    /**
     * @param (callable(): SmtpChannel)|null $connect disuntik untuk tes
     */
    public function __construct(
        string $host,
        int $port,
        private readonly string $secure = 'starttls',
        private readonly ?string $user = null,
        #[\SensitiveParameter] private readonly ?string $pass = null,
        private readonly string $ehloName = 'localhost',
        ?callable $connect = null,
    ) {
        if (!in_array($secure, ['tls', 'starttls'], true)) {
            throw new MailException('Mode TLS SMTP harus tls atau starttls');
        }
        if (preg_match('/^[A-Za-z0-9.-]{1,253}$/D', $ehloName) !== 1) {
            throw new MailException('Nama EHLO tidak valid');
        }
        $this->connect = $connect ?? fn(): SmtpChannel => new StreamSmtpChannel($host, $port, $secure === 'tls');
    }

    public function send(Message $m): void
    {
        $ch = ($this->connect)();
        try {
            $this->expect($ch, [220]);
            $caps = $this->ehlo($ch);
            if ($this->secure === 'starttls') {
                if (!in_array('STARTTLS', $caps, true)) {
                    throw new MailException('Server SMTP tidak mendukung STARTTLS');
                }
                $this->cmd($ch, 'STARTTLS', [220]);
                if (!$ch->enableTls()) {
                    throw new MailException('Negosiasi TLS SMTP gagal');
                }
                $caps = $this->ehlo($ch);
            }
            if ($this->user !== null && $this->user !== '') {
                $this->auth($ch, $caps);
            }
            $this->cmd($ch, 'MAIL FROM:<' . $m->from . '>', [250]);
            $this->cmd($ch, 'RCPT TO:<' . $m->to . '>', [250, 251]);
            $this->cmd($ch, 'DATA', [354]);
            $headers = $m->headers($this->ehloName, time());
            $headers[] = 'To: <' . $m->to . '>';
            $headers[] = 'Subject: ' . $m->encodedSubject();
            $data = implode("\r\n", $headers) . "\r\n\r\n" . $m->encodedBody();
            $ch->write(self::dotStuff($data) . "\r\n.\r\n");
            $this->expect($ch, [250]);
            try {
                $this->cmd($ch, 'QUIT', [221]);
            } catch (MailException) {
                // QUIT best effort
            }
        } finally {
            $ch->close();
        }
    }

    public static function dotStuff(string $data): string
    {
        $data = str_replace(["\r\n", "\r"], "\n", $data);
        return str_replace("\n", "\r\n", preg_replace('/^\./m', '..', $data) ?? $data);
    }

    /** @return list<string> kapabilitas (huruf besar, kata pertama) */
    private function ehlo(SmtpChannel $ch): array
    {
        $ch->write('EHLO ' . $this->ehloName . "\r\n");
        $lines = $this->read($ch, [250]);
        $caps = [];
        foreach (array_slice($lines, 1) as $l) {
            $caps[] = strtoupper($l);
        }
        return $caps;
    }

    /** @param list<string> $caps */
    private function auth(SmtpChannel $ch, array $caps): void
    {
        $plain = base64_encode("\0" . (string) $this->user . "\0" . (string) $this->pass);
        $supports = false;
        foreach ($caps as $c) {
            if (str_starts_with($c, 'AUTH') && str_contains($c, 'PLAIN')) {
                $supports = true;
            }
        }
        if (!$supports) {
            throw new MailException('Server SMTP tidak mendukung AUTH PLAIN');
        }
        $this->cmd($ch, 'AUTH PLAIN ' . $plain, [235]);
    }

    /** @param list<int> $ok */
    private function cmd(SmtpChannel $ch, string $line, array $ok): void
    {
        if (preg_match('/[\r\n]/', $line) === 1) {
            throw new MailException('Perintah SMTP tidak valid');
        }
        $ch->write($line . "\r\n");
        $this->expect($ch, $ok);
    }

    /** @param list<int> $ok */
    private function expect(SmtpChannel $ch, array $ok): void
    {
        $this->read($ch, $ok);
    }

    /**
     * @param list<int> $ok
     * @return list<string> teks tiap baris balasan (tanpa kode)
     */
    private function read(SmtpChannel $ch, array $ok): array
    {
        $out = [];
        for ($i = 0; $i < 50; $i++) {
            $line = $ch->readLine();
            if (preg_match('/^(\d{3})([ -])(.*)$/D', $line, $m) !== 1) {
                throw new MailException('Balasan SMTP tidak dikenali');
            }
            $out[] = $m[3];
            if ($m[2] === ' ') {
                if (!in_array((int) $m[1], $ok, true)) {
                    throw new MailException('Server SMTP menolak (kode ' . $m[1] . ')');
                }
                return $out;
            }
        }
        throw new MailException('Balasan SMTP terlalu panjang');
    }
}
