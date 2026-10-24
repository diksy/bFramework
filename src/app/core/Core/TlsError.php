<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

/** Verifikasi sertifikat/host TLS gagal. Tidak ada jalur untuk mengabaikannya (ARCH-06). */
final class TlsError extends HttpError
{
}
