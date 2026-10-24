<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use bFramework\Core\Request;
use bFramework\Core\SafeHtml;

/**
 * Antarmuka cache halaman (F8) yang dikenal Runtime; implementasi (Cache\PageCache) dirakit bootstrap.php (ARCH-03).
 */
interface PageCacheSink
{
    /** Request boleh dilayani/disimpan sebagai halaman cache: GET, tanpa query, tanpa cookie sesi, rute ber-cache. */
    public function eligible(Request $r): bool;

    /**
     * Ambil generasi tag SEBELUM data dibaca/dirender; berikan ke store() agar simpan-lama setelah invalidasi ditolak.
     *
     * @param list<string> $tags
     * @return array<string,int>
     */
    public function snapshot(array $tags): array;

    /**
     * @param list<string> $tags
     * @param array<string,int>|null $snapshot dari snapshot()
     * @return bool true bila tersimpan
     */
    public function store(string $route, SafeHtml $html, array $tags, ?array $snapshot = null): bool;

    /** Hapus semua halaman bertag model ini dan naikkan generasinya. */
    public function invalidate(string $model): void;
}
