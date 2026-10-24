<?php

declare(strict_types=1);

namespace bFramework\Tests\Auth;

use bFramework\Auth\MailException;
use bFramework\Auth\MailFunctionTransport;
use bFramework\Auth\Mailer;
use bFramework\Auth\Message;
use bFramework\Auth\SmtpChannel;
use bFramework\Auth\SmtpTransport;
use PHPUnit\Framework\TestCase;

/** Saluran SMTP palsu: merekam semua tulisan, membalas dari skrip. */
final class FakeChannel implements SmtpChannel
{
    /** @var list<string> */
    public array $written = [];
    public bool $tls = false;
    public bool $tlsOk = true;
    public bool $closed = false;

    /** @param list<string> $script */
    public function __construct(private array $script)
    {
    }

    public function readLine(): string
    {
        if ($this->script === []) {
            throw new MailException('habis');
        }
        return (string) array_shift($this->script);
    }

    public function write(string $data): void
    {
        $this->written[] = ($this->tls ? '[TLS]' : '[PLAIN]') . $data;
    }

    public function enableTls(): bool
    {
        $this->tls = $this->tlsOk;
        return $this->tlsOk;
    }

    public function close(): void
    {
        $this->closed = true;
    }

    public function wrote(): string
    {
        return implode('', $this->written);
    }
}

final class MailTest extends TestCase
{
    private function msg(string $body = "Halo\n.titik di awal baris\n"): Message
    {
        return new Message('tujuan@contoh.test', 'Atur ulang password', $body, 'noreply@contoh.test', 'Aplikasi Dummy');
    }

    /** @return list<string> */
    private function script(bool $starttls = true, bool $auth = true): array
    {
        $caps = ['250-mail.contoh.test'];
        if ($starttls) {
            $caps[] = '250-STARTTLS';
        }
        $caps[] = $auth ? '250 AUTH PLAIN LOGIN' : '250 8BITMIME';
        return array_merge(['220 siap'], $caps, ['220 mulai tls'], $caps, ['235 ok', '250 ok', '250 ok', '354 data', '250 diterima', '221 bye']);
    }

    public function test_AUTH_06_header_injection_ditolak_di_alamat_dan_subjek(): void
    {
        foreach ([["a@b.test\r\nBcc: x@y.test", 'S'], ["a@b.test\nBcc: x@y.test", 'S'], ['a@b.test', "Subjek\r\nBcc: x@y.test"],
            ['a@b.test', "Subjek\nX: y"], ["<a@b.test>", 'S'], ['"a b"@b.test', 'S'], ['a@b.test,c@d.test', 'S']] as [$to, $subject]) {
            try {
                new Message($to, $subject, 'isi', 'noreply@contoh.test');
                self::fail('harus ditolak: ' . json_encode([$to, $subject]));
            } catch (MailException) {
                $this->addToAssertionCount(1);
            }
        }
        $this->expectException(MailException::class);
        new Message('a@b.test', 'S', 'isi', "x@y.test\r\nBcc: z@y.test");
    }

    public function test_AUTH_06_nama_pengirim_dibersihkan_dan_subjek_non_ascii_dienkode(): void
    {
        $m = new Message('a@b.test', 'Verifikasi akun Anda ✓', 'isi', 'n@b.test', "Evil\r\nBcc: x@y.test\"<");
        $h = implode("\n", $m->headers('contoh.test', 1_700_000_000));
        self::assertStringNotContainsString("\r", $h);
        self::assertStringNotContainsString("\nBcc:", $h);
        self::assertStringStartsWith('=?UTF-8?B?', $m->encodedSubject());
    }

    public function test_AUTH_06_smtp_starttls_sebelum_auth_dan_kredensial_tidak_plaintext(): void
    {
        $ch = new FakeChannel($this->script());
        (new SmtpTransport('mail.contoh.test', 587, 'starttls', 'user', 'sandi-dummy', 'app.contoh.test', fn() => $ch))->send($this->msg());
        $w = $ch->wrote();
        self::assertLessThan(strpos($w, 'AUTH PLAIN'), strpos($w, 'STARTTLS'));
        self::assertStringNotContainsString('[PLAIN]AUTH', $w);
        self::assertStringContainsString('[TLS]AUTH PLAIN ' . base64_encode("\0user\0sandi-dummy"), $w);
        self::assertTrue($ch->closed);
    }

    public function test_AUTH_06_tanpa_starttls_pengiriman_dibatalkan_dan_tidak_ada_kredensial_terkirim(): void
    {
        $ch = new FakeChannel($this->script(starttls: false));
        try {
            (new SmtpTransport('mail.contoh.test', 587, 'starttls', 'user', 'sandi-dummy', 'app.contoh.test', fn() => $ch))->send($this->msg());
            self::fail('harus gagal');
        } catch (MailException) {
        }
        self::assertStringNotContainsString('AUTH', $ch->wrote());
        self::assertStringNotContainsString('MAIL FROM', $ch->wrote());
        self::assertTrue($ch->closed);
    }

    public function test_AUTH_06_negosiasi_tls_gagal_membatalkan(): void
    {
        $ch = new FakeChannel($this->script());
        $ch->tlsOk = false;
        $this->expectException(MailException::class);
        try {
            (new SmtpTransport('mail.contoh.test', 587, 'starttls', 'user', 'sandi', 'app.contoh.test', fn() => $ch))->send($this->msg());
        } finally {
            self::assertStringNotContainsString('AUTH', $ch->wrote());
        }
    }

    public function test_AUTH_06_mode_tidak_aman_tidak_ada(): void
    {
        $this->expectException(MailException::class);
        new SmtpTransport('mail.contoh.test', 25, 'none');
    }

    public function test_AUTH_06_badan_tidak_bisa_mengakhiri_data_atau_menyisipkan_perintah(): void
    {
        $ch = new FakeChannel($this->script());
        $evil = "x\r\n.\r\nMAIL FROM:<evil@x.test>\r\nRCPT TO:<v@x.test>\r\n.\r\n";
        (new SmtpTransport('mail.contoh.test', 587, 'starttls', 'u', 'p', 'app.contoh.test', fn() => $ch))->send($this->msg($evil));
        $w = $ch->wrote();
        self::assertSame(1, substr_count($w, "\r\n.\r\n"), 'hanya terminator DATA yang sah');
        self::assertSame(1, substr_count($w, 'MAIL FROM'));
        self::assertStringNotContainsString('evil@x.test', $w);
        self::assertSame("a\r\n..b\r\n...c", SmtpTransport::dotStuff("a\n.b\n..c"));
    }

    public function test_AUTH_06_server_menolak_menghasilkan_galat_tanpa_isi_pesan(): void
    {
        $s = $this->script();
        $s[5] = '535 gagal auth';
        $ch = new FakeChannel($s);
        try {
            (new SmtpTransport('mail.contoh.test', 587, 'starttls', 'u', 'rahasia-dummy', 'app.contoh.test', fn() => $ch))->send($this->msg());
            self::fail('harus gagal');
        } catch (MailException $e) {
            self::assertStringNotContainsString('rahasia-dummy', $e->getMessage());
            self::assertStringNotContainsString('tujuan@contoh.test', $e->getMessage());
        }
    }

    public function test_AUTH_06_fallback_mail_function_tanpa_smtp(): void
    {
        $calls = [];
        $t = new MailFunctionTransport('app.contoh.test', function (string $to, string $s, string $b, string $h) use (&$calls): bool {
            $calls[] = [$to, $s, $b, $h];
            return true;
        });
        (new Mailer($t))->send($this->msg());
        self::assertCount(1, $calls);
        self::assertSame('tujuan@contoh.test', $calls[0][0]);
        self::assertStringNotContainsString("\r\nBcc", $calls[0][3]);
        self::assertInstanceOf(Mailer::class, Mailer::fromConfig([]));
        $fail = new MailFunctionTransport('x.test', static fn(): bool => false);
        $this->expectException(MailException::class);
        (new Mailer($fail))->send($this->msg());
    }

    public function test_AUTH_06_kegagalan_smtp_tidak_turun_ke_mail_plaintext_dan_log_tidak_memuat_isi(): void
    {
        $log = new \bFramework\Tests\Fixtures\CaptureLogger();
        $ch = new FakeChannel(['554 ditolak']);
        $m = new Mailer(new SmtpTransport('mail.contoh.test', 587, 'starttls', null, null, 'app.contoh.test', fn() => $ch), $log);
        try {
            $m->send($this->msg('tautan rahasia https://x.test/auth/reset/ABC'));
            self::fail();
        } catch (MailException) {
        }
        self::assertStringNotContainsString('rahasia', $log->all());
        self::assertStringNotContainsString('tujuan@contoh.test', $log->all());
    }
}
