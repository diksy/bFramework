<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

/** `kid` pada header token tidak ada di JWKS yang dikenal (memicu refetch JWKS terbatas, SSO-07). */
final class UnknownKid extends JwtInvalid
{
}
