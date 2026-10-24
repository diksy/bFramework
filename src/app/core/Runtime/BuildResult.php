<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

/** Hasil Compiler::build. `version` null bila ada error (versi lama tetap aktif). */
final readonly class BuildResult
{
    /** @param list<CompileError> $errors */
    public function __construct(public ?string $version, public array $errors = [])
    {
    }

    public function ok(): bool
    {
        return $this->version !== null && $this->errors === [];
    }
}
