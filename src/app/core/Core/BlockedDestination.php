<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

/** Tujuan ditolak kebijakan (skema, host, port, IP privat/loopback/link-local/metadata). */
final class BlockedDestination extends HttpError
{
}
