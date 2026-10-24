<?php

declare(strict_types=1);

namespace bFramework\Update;

defined('APP_BOOTED') || exit;

/**
 * Kegagalan verifikasi/penerapan update. Pesan getMessage() generik dan aman ditampilkan ke pengguna;
 * alasan teknis ada di $reason (kode pendek untuk log/tes, tanpa isi file atau rahasia).
 */
final class UpdateException extends \RuntimeException
{
    public function __construct(public readonly string $reason)
    {
        parent::__construct('Paket pembaruan ditolak atau gagal diterapkan (kode: ' . $reason . ').');
    }
}
