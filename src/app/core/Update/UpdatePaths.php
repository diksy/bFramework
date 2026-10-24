<?php

declare(strict_types=1);

namespace bFramework\Update;

defined('APP_BOOTED') || exit;

/** Aturan jalur paket update: normalisasi ketat dan whitelist. Dipakai verifier, diff, dan alat tanda tangan. */
final class UpdatePaths
{
    public const MANIFEST_FILE = 'MANIFEST.sha256';
    private const EXACT = ['MANIFEST.sha256', 'public_html/index.php', 'app/bootstrap.php'];
    private const PREFIXES = ['app/core/', 'app/cli/', 'public_html/assets/'];
    /** Tidak pernah boleh disentuh (pertahanan berlapis di atas whitelist). */
    private const FORBIDDEN = ['app/config/', 'app/storage/', 'app/definitions/', 'app/extensions/'];
    private const CODE_EXT = ['php', 'tpl', 'json', 'txt', 'md', 'css', 'js'];
    private const ASSET_EXT = ['css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'woff', 'woff2', 'txt', 'map', 'json'];

    /** Sintaks aman: ASCII, tanpa ../, absolut, null/kontrol, backslash, segmen aneh. */
    public static function valid(string $p): bool
    {
        if ($p === '' || strlen($p) > 180 || preg_match('#^[A-Za-z0-9_.\-/]+$#D', $p) !== 1) {
            return false;
        }
        foreach (explode('/', $p) as $seg) {
            if ($seg === '' || ($seg !== '.htaccess' && preg_match('/^[A-Za-z0-9_][A-Za-z0-9._-]*$/D', $seg) !== 1)) {
                return false;
            }
        }
        return true;
    }

    /** Valid dan termasuk area core yang boleh ditimpa. */
    public static function allowed(string $p): bool
    {
        if (!self::valid($p)) {
            return false;
        }
        foreach (self::FORBIDDEN as $f) {
            if (str_starts_with($p, $f)) {
                return false;
            }
        }
        $base = basename($p);
        if ($base === 'installed.lock' || $base === 'config.php' || str_ends_with($p, '.lock')) {
            return false;
        }
        if (in_array($p, self::EXACT, true)) {
            return true;
        }
        $ext = strtolower(pathinfo($base, PATHINFO_EXTENSION));
        foreach (self::PREFIXES as $pre) {
            if (str_starts_with($p, $pre)) {
                if ($base === '.htaccess') {
                    return true;
                }
                $list = $pre === 'public_html/assets/' ? self::ASSET_EXT : self::CODE_EXT;
                return in_array($ext, $list, true);
            }
        }
        return false;
    }

    /** Apakah jalur (dari MANIFEST.sha256) termasuk lingkup core yang diperiksa diff. */
    public static function inScope(string $p): bool
    {
        return self::allowed($p) && $p !== self::MANIFEST_FILE;
    }

    /** @return list<string> akar yang dipindai untuk file tambahan (relatif ke root instalasi) */
    public static function scanRoots(): array
    {
        return ['app/core', 'app/cli', 'public_html/assets'];
    }

    /** @return list<string> file tunggal dalam lingkup */
    public static function scanFiles(): array
    {
        return ['public_html/index.php', 'app/bootstrap.php'];
    }
}
