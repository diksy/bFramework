<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

/**
 * Kontrak Runtime -> penyimpanan file (ARCH-03: Runtime tidak `use Upload`; diimplementasikan Upload\UploadService
 * dan dirakit bootstrap.php). Kolom model hanya menyimpan fid (32 hex).
 */
interface FileRefs
{
    /** @return array{owner_id:?int, model:?string, ref_id:?int, mime:string, size:int}|null null bila fid rusak/tidak ada */
    public function meta(string $fid): ?array;

    /** Atomik: UPDATE bersyarat `fid=? AND owner_id=? AND model IS NULL`; true bila tepat 1 baris berubah. */
    public function claim(string $fid, int $userId, string $model, int $refId): bool;

    /** Hapus file (metadata + fisik) yang tak lagi dipakai. */
    public function release(string $fid): void;

    /** Hapus semua file yang ter-attach ke baris; kembalikan jumlah. */
    public function deleteForRef(string $model, int $refId): int;
}
