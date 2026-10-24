<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

/** Claims token lolos tanda tangan tetapi melanggar aturan OIDC (iss/aud/azp/nonce/events...). */
final class ClaimsInvalid extends \RuntimeException
{
}
