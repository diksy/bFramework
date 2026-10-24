<?php

declare(strict_types=1);

namespace bFramework\Install;

defined('APP_BOOTED') || exit;

/** Instal ditolak. Pesan sudah aman ditampilkan (generik, tanpa kredensial/jalur/rahasia). */
final class InstallRejected extends \RuntimeException
{
    /** @param list<string> $errors pesan per bidang (tanpa nilai input) */
    public function __construct(string $message, public readonly array $errors = [], public readonly int $status = 422)
    {
        parent::__construct($message);
    }
}
