<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\FieldType;

/** Spesifikasi satu kolom (ARCH-04). Kolom `id` (PK auto-increment) ditambahkan otomatis oleh Grammar. */
final readonly class ColumnSpec
{
    public function __construct(
        public FieldType $type,
        public bool $nullable = true,
        public ?string $default = null,
        public int $length = 255,
        public int $precision = 12,
        public int $scale = 2,
        public bool $unique = false,
    ) {
        if ($length < 1 || $length > 65535 || $precision < 1 || $precision > 38 || $scale < 0 || $scale > $precision) {
            throw new \InvalidArgumentException('Parameter kolom di luar rentang');
        }
    }
}
