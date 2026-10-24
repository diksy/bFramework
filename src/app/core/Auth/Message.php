<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

/**
 * Email teks polos. Konstruktor menolak CR/LF/NUL di alamat dan subjek (cegah header injection);
 * badan dikirim base64 sehingga tidak bisa menyisipkan header atau mengakhiri DATA SMTP.
 */
final readonly class Message
{
    public string $to;
    public string $from;
    public string $subject;
    public string $body;
    public string $fromName;

    public function __construct(string $to, string $subject, string $body, string $from, string $fromName = '')
    {
        $this->to = self::address($to);
        $this->from = self::address($from);
        if (preg_match('/[\x00-\x1F\x7F]/', $subject) === 1 || $subject === '' || strlen($subject) > 200) {
            throw new MailException('Subjek email tidak valid');
        }
        if (str_contains($body, "\0") || preg_match('//u', $body) !== 1) {
            throw new MailException('Isi email tidak valid');
        }
        $name = preg_replace('/[\x00-\x1F\x7F"<>]/u', '', $fromName) ?? '';
        $this->subject = $subject;
        $this->body = $body;
        $this->fromName = mb_substr($name, 0, 80);
    }

    private static function address(string $a): string
    {
        $a = trim($a);
        if ($a === '' || strlen($a) > 254 || preg_match('/[\x00-\x20\x7F<>,;"\\\\]/', $a) === 1
            || filter_var($a, FILTER_VALIDATE_EMAIL) === false) {
            throw new MailException('Alamat email tidak valid');
        }
        return $a;
    }

    /**
     * Header MIME tanpa To/Subject.
     *
     * @return list<string>
     */
    public function headers(string $messageIdHost, int $now): array
    {
        $from = $this->fromName === ''
            ? '<' . $this->from . '>'
            : self::encode($this->fromName) . ' <' . $this->from . '>';
        return [
            'From: ' . $from,
            'Date: ' . gmdate('D, d M Y H:i:s', $now) . ' +0000',
            'Message-ID: <' . bin2hex(random_bytes(12)) . '@' . self::host($messageIdHost) . '>',
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=UTF-8',
            'Content-Transfer-Encoding: base64',
        ];
    }

    public function encodedSubject(): string
    {
        return self::encode($this->subject);
    }

    public function encodedBody(): string
    {
        return rtrim(chunk_split(base64_encode($this->body), 76, "\r\n"));
    }

    private static function encode(string $s): string
    {
        return preg_match('/^[\x20-\x7E]*$/', $s) === 1 ? $s : '=?UTF-8?B?' . base64_encode($s) . '?=';
    }

    private static function host(string $h): string
    {
        return preg_match('/^[A-Za-z0-9.-]{1,200}$/D', $h) === 1 ? $h : 'localhost';
    }
}
