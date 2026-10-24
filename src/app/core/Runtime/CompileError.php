<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

/** Satu kesalahan compile; `src` = penunjuk sumber, mis. `models/produk.json#/fields/harga`. */
final readonly class CompileError
{
    public function __construct(public string $src, public string $msg)
    {
    }
}
