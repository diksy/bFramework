<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

/** Hook ekstensi tidak lolos verifikasi runtime atau gagal dijalankan (500 + log; tidak pernah dilewati). */
final class HookError extends \RuntimeException
{
}
