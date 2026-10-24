<?php

declare(strict_types=1);

namespace bFramework\Builder;

defined('APP_BOOTED') || exit;

use RuntimeException;

/** BLD-05: berkas di disk berbeda dari yang dimuat builder; tidak ditimpa (HTTP 409). */
final class WriteConflict extends RuntimeException
{
    /** @param array<mixed>|null $disk isi di disk (null bila berkas dihapus/tak terbaca) */
    public function __construct(public readonly ?array $disk, public readonly string $diskHash)
    {
        parent::__construct('Berkas diubah di luar builder', 409);
    }
}
