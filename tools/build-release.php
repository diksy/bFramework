<?php

declare(strict_types=1);

/**
 * Membangun zip rilis (M13): app/ + public_html/ dari src/, tanpa tests, tools, prototype, .git, .claude, docs,
 * rahasia (config.php, .env, kunci, database, token/lock instal, isi storage) dan dengan MANIFEST.sha256.
 * Dependensi runtime (jika ada) berada di app/core/vendor dan ikut terbawa; vendor/ dev (composer) tidak.
 *
 * Pemakaian: php tools/build-release.php [keluaran.zip]
 */

const RELEASE_ROOTS = ['app', 'public_html'];
/** Pola jalur relatif (terhadap src/) yang tidak boleh masuk zip. */
const RELEASE_FORBIDDEN = [
    '#(^|/)\.(?!htaccess$|gitkeep$)[^/]*$#',               // dotfile selain .htaccess/.gitkeep (.env, .git, .claude)
    '#(^|/)(tests|tools|prototype|docs|\.git|\.claude|node_modules)(/|$)#',
    '#^app/config/config\.php$#',
    '#^app/storage/(?!\.gitkeep$)#',                     // isi storage: sesi, log, cache, db, token, lock
    '#\.(sqlite|sqlite3|db|key|pem|log|tmp|bak|orig|swp)$#i',
    '#(^|/)(install_token|installed\.lock|install\.busy)$#',
    '#(^|/)(composer\.(json|lock)|phpunit\.xml|phpstan\.neon)$#',
];

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
    $manifest = '';
    foreach ($files as $rel) {
        $zip->addFile(rtrim($srcDir, '/') . '/' . $rel, $rel);
        $manifest .= hash_file('sha256', rtrim($srcDir, '/') . '/' . $rel) . '  ' . $rel . "\n";
    }
    $zip->addFromString('MANIFEST.sha256', $manifest);
    if (!$zip->close()) {
        throw new RuntimeException('Zip gagal ditutup');
    }
    return $files;
}

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === __FILE__) {
    $out = $argv[1] ?? dirname(__DIR__) . '/release.zip';
    $n = count(buildRelease(dirname(__DIR__) . '/src', $out));
    fwrite(STDOUT, "Rilis dibuat: $out ($n file + MANIFEST.sha256)\n");
}
