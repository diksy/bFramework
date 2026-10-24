<?php

declare(strict_types=1);

namespace bFramework\Update;

defined('APP_BOOTED') || exit;

final readonly class UpdateResult
{
    /**
     * @param list<string> $migrations id migrasi yang dijalankan
     * @param list<string> $warnings peringatan non-fatal (mis. rebuild/purge gagal)
     */
    public function __construct(
        public string $version,
        public int $files,
        public array $migrations = [],
        public array $warnings = [],
    ) {
    }
}
