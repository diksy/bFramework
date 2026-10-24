<?php

declare(strict_types=1);

namespace bFramework\Extensions;

defined('APP_BOOTED') || exit;

/** Contoh hooks developer untuk model produk (kode tepercaya, dummy). */
final class ProdukHooks
{
    /**
     * Tolak stok di atas batas gudang.
     *
     * @param array<string,mixed> $data
     * @return list<string> daftar pesan error
     */
    public static function validasiStok(array $data): array
    {
        if (isset($data['stok']) && (int) $data['stok'] > 10000) {
            return ['Stok melebihi kapasitas gudang (maks. 10.000).'];
        }
        return [];
    }

    /**
     * Rapikan huruf kapital nama.
     *
     * @param array<string,mixed> $data
     * @return list<string> daftar pesan error
     */
    public static function normalisasiNama(array $data): array
    {
        return [];
    }

    /**
     * Catat aktivitas ke log (dummy, tidak melakukan apa-apa).
     *
     * @param array<string,mixed> $data
     * @return list<string> daftar pesan error
     */
    public static function catatAktivitas(array $data): array
    {
        return [];
    }
}
