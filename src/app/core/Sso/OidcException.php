<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

/** Kegagalan komunikasi/protokol dengan IdP. Pesan aman ditampilkan ke admin (Tes koneksi) dan dicatat. */
class OidcException extends \RuntimeException
{
}
