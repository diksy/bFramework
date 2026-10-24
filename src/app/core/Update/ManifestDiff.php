<?php

declare(strict_types=1);

namespace bFramework\Update;

defined('APP_BOOTED') || exit;

/** Hasil CoreManifest::diff(): hanya jalur (tidak ada isi file). Daftar dipotong ke batas tampilan. */
final readonly class ManifestDiff
{
    public const LIMIT = 200;

    /**
     * @param bool $available MANIFEST.sha256 terbaca dan valid
     * @param list<string> $changed
     * @param list<string> $missing
     * @param list<string> $extra
     */
    public function __construct(public bool $available, public array $changed = [], public array $missing = [], public array $extra = [])
    {
    }

    public function clean(): bool
    {
        return $this->available && $this->changed === [] && $this->missing === [] && $this->extra === [];
    }
}
