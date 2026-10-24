<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

/** Token tidak lolos verifikasi. Pesan hanya untuk log (tanpa isi token). */
class JwtInvalid extends \RuntimeException
{
}
