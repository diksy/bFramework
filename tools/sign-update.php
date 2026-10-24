<?php

declare(strict_types=1);

/**
 * Membuat paket update bertanda tangan dari zip rilis (tools/build-release.php) - SEC-UPD-01.
 * Pemakaian:
 *   php tools/sign-update.php --key=/jalur/di/luar/repo/update-private.key --release=release.zip \
 *       --version=1.2.0 [--min-version=1.0.0] [--date=YYYY-MM-DD] [--migrations=migrasi.json] [--delete=a,b] --out=update.zip
 * Kunci privat dibaca dari berkas (bukan repo, bukan env), harus izin 0600 dan di luar repo. Hanya file dalam
 * whitelist updater yang dimasukkan (config, storage, definitions, extensions tidak pernah ikut).
 * migrations.json: [{"id":"0001_x","sql":{"mysql":["..."],"sqlite":["..."]}}]
 */

defined('APP_BOOTED') || define('APP_BOOTED', true);
require_once dirname(__DIR__) . '/src/app/bootstrap.php';

use bFramework\Update\UpdateManifest;
use bFramework\Update\UpdatePaths;

/** @return string kunci rahasia 64 byte */
function loadUpdateSecret(string $path, string $repoRoot): string
{
    $real = realpath($path);
    $repo = realpath($repoRoot);
    if ($real === false || !is_file($real) || is_link($path)) {
        throw new RuntimeException('Berkas kunci tidak ditemukan');
    }
    if ($repo !== false && str_starts_with($real . '/', rtrim($repo, '/') . '/')) {
        throw new RuntimeException('Kunci privat tidak boleh berada di dalam repo');
    }
    if (((int) fileperms($real) & 0077) !== 0) {
        throw new RuntimeException('Izin berkas kunci harus 0600');
    }
    $raw = base64_decode(trim((string) file_get_contents($real)), true);
    if ($raw === false || strlen($raw) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
        throw new RuntimeException('Format kunci tidak valid');
    }
    return $raw;
}

/**
 * @param list<array<string,mixed>> $migrations
 * @param list<string> $delete
 * @return list<string> jalur yang dimasukkan
 */
function buildUpdatePackage(string $releaseZip, string $secret, string $version, string $minVersion, string $date, array $migrations, array $delete, string $outZip): array
{
    $src = new ZipArchive();
    if ($src->open($releaseZip, ZipArchive::RDONLY) !== true) {
        throw new RuntimeException('Zip rilis tidak terbaca');
    }
    $files = [];
    $contents = [];
    for ($i = 0; $i < $src->numFiles; $i++) {
        $n = (string) $src->getNameIndex($i);
        if (!UpdatePaths::allowed($n)) {
            continue; // config.example, definitions, extensions, .htaccess perimeter, dsb. tidak ikut
        }
        $data = $src->getFromIndex($i);
        if ($data === false) {
            throw new RuntimeException('Entri tidak terbaca');
        }
        $contents[$n] = $data;
        $files[$n] = hash('sha256', $data);
    }
    $src->close();
    if (!isset($files[UpdatePaths::MANIFEST_FILE])) {
        throw new RuntimeException('Zip rilis tanpa MANIFEST.sha256');
    }
    ksort($files);
    $manifest = json_encode([
        'format' => 1, 'version' => $version, 'min_version' => $minVersion, 'date' => $date,
        'files' => $files, 'delete' => array_values($delete), 'migrations' => $migrations,
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    UpdateManifest::parse($manifest); // validasi sebelum menandatangani
    $sig = base64_encode(sodium_crypto_sign_detached($manifest, $secret));
    if (is_file($outZip)) {
        unlink($outZip);
    }
    $z = new ZipArchive();
    if ($z->open($outZip, ZipArchive::CREATE | ZipArchive::EXCL) !== true) {
        throw new RuntimeException('Zip keluaran tidak dapat dibuat');
    }
    $z->addFromString('manifest.json', $manifest);
    $z->addFromString('manifest.sig', $sig . "\n");
    foreach ($contents as $n => $d) {
        $z->addFromString($n, $d);
    }
    if (!$z->close()) {
        throw new RuntimeException('Zip keluaran gagal ditutup');
    }
    return array_keys($files);
}

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === __FILE__) {
    $o = getopt('', ['key:', 'release:', 'version:', 'min-version::', 'date::', 'migrations::', 'delete::', 'out:']);
    foreach (['key', 'release', 'version', 'out'] as $req) {
        if (!isset($o[$req]) || !is_string($o[$req])) {
            fwrite(STDERR, "Argumen --$req wajib. Lihat komentar di atas berkas.\n");
            exit(2);
        }
    }
    try {
        $mig = [];
        if (isset($o['migrations']) && is_string($o['migrations'])) {
            $mig = json_decode((string) file_get_contents($o['migrations']), true, 8, JSON_THROW_ON_ERROR);
            if (!is_array($mig)) {
                throw new RuntimeException('migrations.json tidak valid');
            }
        }
        $del = isset($o['delete']) && is_string($o['delete']) && $o['delete'] !== '' ? explode(',', $o['delete']) : [];
        $secret = loadUpdateSecret((string) $o['key'], dirname(__DIR__));
        $list = buildUpdatePackage(
            (string) $o['release'],
            $secret,
            (string) $o['version'],
            is_string($o['min-version'] ?? null) ? $o['min-version'] : '0.0.0',
            is_string($o['date'] ?? null) ? $o['date'] : gmdate('Y-m-d'),
            $mig,
            $del,
            (string) $o['out'],
        );
        $pub = sodium_crypto_sign_publickey_from_secretkey($secret);
        fwrite(STDOUT, 'Paket dibuat: ' . $o['out'] . ' (' . count($list) . " file). Kunci publik: " . bin2hex($pub) . "\n");
        sodium_memzero($secret);
    } catch (Throwable $e) {
        fwrite(STDERR, 'Gagal: ' . $e->getMessage() . "\n");
        exit(1);
    }
}
