<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use RuntimeException;

/** Kegagalan database generik: tanpa SQL, skema, atau nilai (detail hanya di log ter-redact). */
final class DatabaseError extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('Operasi database gagal');
    }
}
