<?php

declare(strict_types=1);

namespace bFramework\Contracts;

defined('APP_BOOTED') || exit;

use LogicException;

/** Dilempar oleh stub kontrak sampai modul pemiliknya selesai. */
final class NotImplemented extends LogicException
{
    public static function in(string $what): self
    {
        return new self($what . ' belum diimplementasikan');
    }
}
