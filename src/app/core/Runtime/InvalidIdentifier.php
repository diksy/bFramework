<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use InvalidArgumentException;

/** Nama tabel/kolom di luar definisi ter-compile atau berbentuk tidak sah (SEC-DATA-01). */
final class InvalidIdentifier extends InvalidArgumentException
{
}
