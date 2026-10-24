<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

use RuntimeException;

/** Kegagalan HTTP keluar (jaringan, batas, atau tujuan ditolak). Pesan tidak memuat rahasia. */
class HttpError extends RuntimeException
{
}
