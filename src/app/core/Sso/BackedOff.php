<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

/** Fetch discovery/JWKS ditunda (negative cache aktif); tidak ada permintaan keluar. */
final class BackedOff extends OidcException
{
}
