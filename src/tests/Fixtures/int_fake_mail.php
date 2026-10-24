<?php

declare(strict_types=1);

namespace bFramework\Auth;

/** Pengganti MailFunctionTransport (tes integrasi): email ditulis ke $INT_SANDBOX/mail.jsonl, tidak ada pengiriman nyata. */
final class MailFunctionTransport implements MailTransport
{
    public function send(Message $m): void
    {
        $line = json_encode(['to' => $m->to, 'from' => $m->from, 'subject' => $m->subject, 'body' => $m->body], JSON_THROW_ON_ERROR);
        file_put_contents((string) getenv('INT_SANDBOX') . '/mail.jsonl', $line . "\n", FILE_APPEND | LOCK_EX);
    }
}
