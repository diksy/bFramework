<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

/** Hasil verifikasi kredensial. `error` selalu pesan generik (tidak membedakan penyebab). */
final readonly class AuthResult
{
    /** @param list<string> $amr */
    public function __construct(
        public bool $ok,
        public ?int $userId = null,
        public array $amr = [],
        public ?string $error = null,
    ) {
    }

    public static function fail(string $error): self
    {
        return new self(false, null, [], $error);
    }

    /** @param list<string> $amr */
    public static function success(int $userId, array $amr): self
    {
        return new self(true, $userId, $amr);
    }
}
