<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

/** Galat pengiriman email; pesan tidak pernah memuat isi email, tautan, atau kredensial. */
final class MailException extends \RuntimeException
{
}
