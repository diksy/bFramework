<?php

declare(strict_types=1);

/**
 * Membuat pasangan kunci penandatangan update Ed25519 (SEC-UPD-01).
 * Pemakaian: php tools/gen-update-key.php /jalur/di/luar/repo/update-private.key
 * - Kunci PRIVAT ditulis ke jalur itu (izin 0600, tidak menimpa berkas yang ada, menolak jalur di dalam repo).
 * - Hanya kunci PUBLIK (64 heks) dicetak ke layar; tanam di src/app/core/Update/UpdateKey.php (PUBLIC_KEY_HEX).
 * Simpan kunci privat di tempat aman dan cadangkan; jangan pernah di-commit atau dikirim lewat chat.
 */

/** @return string jalur absolut ternormalisasi dari $path yang belum tentu ada (induk harus ada) */
function keyPathResolve(string $path): string
{
    $dir = realpath(dirname($path));
    if ($dir === false || !is_dir($dir)) {
        throw new RuntimeException('Folder tujuan tidak ada');
    }
    return $dir . '/' . basename($path);
}

function keyPathInsideRepo(string $resolved, string $repoRoot): bool
{
    $repo = realpath($repoRoot);
    return $repo !== false && str_starts_with($resolved . '/', rtrim($repo, '/') . '/');
}

/** @return string heks kunci publik */
function generateUpdateKey(string $privatePath, string $repoRoot): string
{
    $resolved = keyPathResolve($privatePath);
    if (keyPathInsideRepo($resolved, $repoRoot)) {
        throw new RuntimeException('Jalur kunci privat tidak boleh berada di dalam repo');
    }
    if (file_exists($resolved) || is_link($resolved)) {
        throw new RuntimeException('Berkas sudah ada; tidak ditimpa');
    }
    $pair = sodium_crypto_sign_keypair();
    $secret = sodium_crypto_sign_secretkey($pair);
    $public = sodium_crypto_sign_publickey($pair);
    $old = umask(0177);
    $fh = @fopen($resolved, 'x');
    umask($old);
    if ($fh === false) {
        throw new RuntimeException('Tidak dapat membuat berkas kunci');
    }
    fwrite($fh, base64_encode($secret) . "\n");
    fclose($fh);
    chmod($resolved, 0600);
    sodium_memzero($secret);
    sodium_memzero($pair);
    return bin2hex($public);
}

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === __FILE__) {
    if (($argv[1] ?? '') === '') {
        fwrite(STDERR, "Pemakaian: php tools/gen-update-key.php /jalur/di/luar/repo/update-private.key\n");
        exit(2);
    }
    try {
        $pub = generateUpdateKey($argv[1], dirname(__DIR__));
    } catch (RuntimeException $e) {
        fwrite(STDERR, $e->getMessage() . "\n");
        exit(1);
    }
    fwrite(STDOUT, "Kunci privat disimpan (0600): {$argv[1]}\nKunci PUBLIK (tanam di UpdateKey::PUBLIC_KEY_HEX):\n$pub\n");
}
