<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

/** Hasil create/update: sukses (id terisi) atau gagal (kesalahan per field dan/atau pesan hook). */
final readonly class Result
{
    /**
     * @param array<string,list<string>> $errors
     * @param list<string> $formErrors
     * @param array<string,mixed> $values nilai ter-validasi (untuk menampilkan ulang form)
     */
    public function __construct(
        public ?int $id = null,
        public array $errors = [],
        public array $formErrors = [],
        public array $values = [],
    ) {
    }

    public function ok(): bool
    {
        return $this->id !== null && $this->errors === [] && $this->formErrors === [];
    }
}
