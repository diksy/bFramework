<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

/** Pelanggaran aturan bisnis administrasi (admin terakhir, peran sistem, dsb.). Pesan aman ditampilkan ke admin. */
final class RuleViolation extends \RuntimeException
{
}
