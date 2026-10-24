<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

/** Kesalahan template (sintaks, konteks tidak aman, path tidak diizinkan). Pesan tidak memuat data pengguna. */
final class TemplateError extends \RuntimeException
{
}
