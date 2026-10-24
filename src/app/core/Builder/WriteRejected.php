<?php

declare(strict_types=1);

namespace bFramework\Builder;

defined('APP_BOOTED') || exit;

use RuntimeException;

/** Definisi/permintaan ditolak; versi cache aktif dan berkas di disk tidak berubah. */
final class WriteRejected extends RuntimeException
{
    /** @param list<string> $errors pesan aman (tanpa path server) */
    public function __construct(string $message, public readonly array $errors = [], public readonly int $status = 422)
    {
        parent::__construct($message, $status);
    }
}
