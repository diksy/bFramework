<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

/** Token endpoint menjawab error=invalid_grant (code kedaluwarsa/dipakai ulang, refresh token dicabut). Tidak di-retry (SSO-20). */
final class InvalidGrant extends OidcException
{
}
