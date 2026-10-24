<?php

declare(strict_types=1);

/**
 * Membangun zip rilis (M13): app/ + public_html/ dari src/, tanpa tests, tools, prototype, .git, .claude, docs,
 * rahasia (config.php, .env, kunci, database, token/lock instal, isi storage) dan dengan MANIFEST.sha256.
 * Dependensi runtime (jika ada) berada di app/core/vendor dan ikut terbawa; vendor/ dev (composer) tidak.
 *
 * Gerbang rilis (S16): gagal bila kunci publik update (Update\UpdateKey) masih placeholder, kecuali --allow-placeholder-key (build uji).
 *
 * Pemakaian: php tools/build-release.php [--allow-placeholder-key] [keluaran.zip]
 */

defined('APP_BOOTED') || define('APP_BOOTED', true);
require_once dirname(__DIR__) . '/src/app/core/Update/UpdatePaths.php';
require_once dirname(__DIR__) . '/src/app/core/Update/UpdateKey.php';

const RELEASE_ROOTS = ['app', 'public_html'];
/** Pola jalur relatif (terhadap src/) yang tidak boleh masuk zip. */
const RELEASE_FORBIDDEN = [
    '#(^|/)\.(?!htaccess$|gitkeep$)[^/]*$#',               // dotfile selain .htaccess/.gitkeep (.env, .git, .claude)
    '#(^|/)(tests|tools|prototype|docs|\.git|\.claude|node_modules)(/|$)#',
    '#^app/config/config\.php$#',
    '#^app/storage/(?!\.gitkeep$)#',                     // isi storage: sesi, log, cache, db, token, lock
    '#\.(sqlite|sqlite3|db|key|pem|log|tmp|bak|orig|swp)$#i',
    '#^public_html/_pc/.+\.html$#',                       // sisa halaman cache dev (S16)
    '#(^|/)(install_token(_[a-f0-9]+)?|canary(_[a-f0-9]+\.txt|\.proven)|installed\.lock|install\.busy)$#',
    '#(^|/)(composer\.(json|lock)|phpunit\.xml|phpstan\.neon)$#',
];

/** Gerbang rilis S16: true bila kunci publik update sudah dikonfigurasi (bukan placeholder). */
function releaseKeyConfigured(): bool
{
    return \bFramework\Update\UpdateKey::configured();
}

/** @return list<string> jalur relatif yang dimasukkan, terurut */
function releaseFiles(string $srcDir): array
{
    $srcDir = rtrim($srcDir, '/');
    $out = [];
    foreach (RELEASE_ROOTS as $root) {
        if (!is_dir($srcDir . '/' . $root)) {
            throw new RuntimeException('Folder sumber tidak ada: ' . $root);
        }
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($srcDir . '/' . $root, FilesystemIterator::SKIP_DOTS),
        );
        foreach ($it as $f) {
            if (!$f->isFile() || $f->isLink()) {
                continue; // symlink tidak diikuti
            }
            $rel = substr($f->getPathname(), strlen($srcDir) + 1);
            if (!releaseForbidden($rel)) {
                $out[] = $rel;
            }
        }
    }
    sort($out);
    return $out;
}

function releaseForbidden(string $rel): bool
{
    foreach (RELEASE_FORBIDDEN as $re) {
        if (preg_match($re, $rel) === 1) {
            return true;
        }
    }
    return false;
}

/**
 * Isi MANIFEST.sha256 untuk $files: hanya jalur yang diterima UpdatePaths::inManifest (aturan yang sama dengan
 * CoreManifest, sehingga manifest selalu lolos load() dan rilis baru diff-nya bersih). File tetap ada di zip.
 *
 * @param list<string> $files
 */
function releaseManifest(string $srcDir, array $files): string
{
    $manifest = '';
    foreach ($files as $rel) {
        if (\bFramework\Update\UpdatePaths::inManifest($rel)) {
            $manifest .= hash_file('sha256', rtrim($srcDir, '/') . '/' . $rel) . '  ' . $rel . "\n";
        }
    }
    return $manifest;
}

/** @return list<string> daftar file di zip (tanpa MANIFEST) */
function buildRelease(string $srcDir, string $outZip): array
{
    $files = releaseFiles($srcDir);
    $zip = new ZipArchive();
    if (is_file($outZip)) {
        unlink($outZip);
    }
    if ($zip->open($outZip, ZipArchive::CREATE | ZipArchive::EXCL) !== true) {
        throw new RuntimeException('Zip tidak dapat dibuat');
    }
    foreach ($files as $rel) {
        $zip->addFile(rtrim($srcDir, '/') . '/' . $rel, $rel);
    }
    $zip->addFromString('MANIFEST.sha256', releaseManifest($srcDir, $files));
    if (!$zip->close()) {
        throw new RuntimeException('Zip gagal ditutup');
    }
    return $files;
}

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === __FILE__) {
    $args = array_slice($argv, 1);
    $allow = in_array('--allow-placeholder-key', $args, true);
    $args = array_values(array_filter($args, static fn(string $a): bool => $a !== '--allow-placeholder-key'));
    if (!releaseKeyConfigured()) {
        if (!$allow) {
            fwrite(STDERR, "GAGAL: kunci publik update masih placeholder (src/app/core/Update/UpdateKey.php). Jalankan tools/gen-update-key.php dan isi PUBLIC_KEY_HEX; atau pakai --allow-placeholder-key hanya untuk build uji.\n");
            exit(1);
        }
        fwrite(STDERR, "PERINGATAN: build uji dengan kunci placeholder; JANGAN dirilis (updater menolak semua paket).\n");
    }
    $out = $args[0] ?? dirname(__DIR__) . '/release.zip';
    $n = count(buildRelease(dirname(__DIR__) . '/src', $out));
    fwrite(STDOUT, "Rilis dibuat: $out ($n file + MANIFEST.sha256)\n");
}
