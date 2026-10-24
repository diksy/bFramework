<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

/** Hook before* menolak aksi (mis. delete); pesan untuk pengguna. */
final class HookRejected extends \RuntimeException
{
    /** @param list<string> $messages */
    public function __construct(public readonly array $messages)
    {
        parent::__construct('Aksi ditolak oleh hook');
    }
}
