<?php

declare(strict_types=1);

namespace bFramework\Install;

defined('APP_BOOTED') || exit;

/** Hasil satu pemeriksaan prasyarat. `fatal` = menggagalkan instal bila !ok; selain itu hanya peringatan. */
final class Check
{
    public function __construct(
        public readonly string $id,
        public readonly bool $ok,
        public readonly string $msg,
        public readonly bool $fatal = true,
    ) {
    }
}
