<?php

declare(strict_types=1);

namespace bFramework\Install;

defined('APP_BOOTED') || exit;

/** Tautan reset admin pertama: hanya dikembalikan sekali, tidak disimpan (hanya hash token di DB). */
final class InstallResult
{
    public function __construct(public readonly string $resetUrl)
    {
    }

    public function __debugInfo(): array
    {
        return ['resetUrl' => '[disembunyikan]'];
    }
}
