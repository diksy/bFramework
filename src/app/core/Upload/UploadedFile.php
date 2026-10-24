<?php

declare(strict_types=1);

namespace bFramework\Upload;

defined('APP_BOOTED') || exit;

/** Satu entri $_FILES (tunggal). Semua nilai dari klien tidak dipercaya. */
final readonly class UploadedFile
{
    public function __construct(
        public string $name,
        public string $tmpName,
        public int $error,
        public int $size = 0,
    ) {
    }

    /** @param array<string,mixed> $files isi $_FILES / Request::files; entri array-ganda (name[]) ditolak jadi UPLOAD_ERR_NO_FILE */
    public static function fromFiles(array $files, string $field): self
    {
        $e = $files[$field] ?? null;
        if (!is_array($e) || !is_string($e['name'] ?? null) || !is_string($e['tmp_name'] ?? null) || !is_int($e['error'] ?? null)) {
            return new self('', '', UPLOAD_ERR_NO_FILE, 0);
        }
        $size = $e['size'] ?? 0;
        return new self($e['name'], $e['tmp_name'], $e['error'], is_int($size) ? $size : 0);
    }
}
