<?php

declare(strict_types=1);

namespace bFramework\Update;

defined('APP_BOOTED') || exit;

/**
 * Versi core terpasang. Berkas ini ikut diganti oleh paket update (app/core). Versi efektif =
 * max(CURRENT, storage/core.version) sehingga paket lama tidak dapat diputar ulang walau berkas ini dipulihkan.
 */
final class CoreVersion
{
    public const CURRENT = '1.0.0';
    public const STATE_FILE = 'core.version';

    public static function installed(string $storageDir): string
    {
        $v = self::CURRENT;
        $raw = @file_get_contents(rtrim($storageDir, '/') . '/' . self::STATE_FILE);
        if (is_string($raw)) {
            $raw = trim($raw);
            if (UpdateManifest::validVersion($raw) && version_compare($raw, $v, '>')) {
                $v = $raw;
            }
        }
        return $v;
    }
}
