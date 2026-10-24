<?php

declare(strict_types=1);

namespace bFramework\Upload;

defined('APP_BOOTED') || exit;

/** Upload ditolak; pesan aman ditampilkan ke pengguna (tanpa path/isi file). */
final class UploadRejected extends \RuntimeException
{
    public function __construct(string $message, public readonly string $reason = 'rejected', int $status = 422)
    {
        parent::__construct($message, $status);
    }
}
