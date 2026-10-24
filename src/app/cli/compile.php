<?php

declare(strict_types=1);

// CLI kompilasi ulang (F5/F12): php app/cli/compile.php [--dry-run] [--apply-migrations [--allow-loss]]
// Mengompilasi app/definitions menjadi versi cache baru (atomik; gagal = versi lama tetap aktif), membuat tabel model
// BARU (create-only, idempoten), dan menampilkan pratinjau perubahan skema tabel yang sudah ada. Perubahan skema
// hanya diterapkan dengan --apply-migrations; peringatan kehilangan data hanya dengan --allow-loss tambahan.
// Sebelum ada yang diaktifkan, kompilasi diuji dulu di folder sementara; bila ada perubahan skema yang belum
// diizinkan, TIDAK ADA yang berubah. --dry-run hanya validasi + pratinjau. Exit: 0 berhasil, 1 gagal/ditolak, 2 salah pakai.

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once dirname(__DIR__) . '/bootstrap.php';

defined('APP_BOOTED') || exit;

use bFramework\Core\Config;
use bFramework\Core\RotatingFileLogger;
use bFramework\Runtime\CacheStore;
use bFramework\Runtime\Compiler;
use bFramework\Runtime\Definitions;
use bFramework\Runtime\Migrator;

$app = dirname(__DIR__);
$argv = $_SERVER['argv'] ?? [];
$out = static function (string $m): void {
    fwrite(STDOUT, $m . "\n");
};
$err = static function (string $m): void {
    fwrite(STDERR, $m . "\n");
};

$flags = array_slice($argv, 1);
$known = ['--dry-run', '--apply-migrations', '--allow-loss'];
if (array_diff($flags, $known) !== [] || count($flags) !== count(array_unique($flags))) {
    $err('Pemakaian: php app/cli/compile.php [--dry-run] [--apply-migrations [--allow-loss]]');
    exit(2);
}
$dry = in_array('--dry-run', $flags, true);
$apply = in_array('--apply-migrations', $flags, true);
$allowLoss = in_array('--allow-loss', $flags, true);
if ($allowLoss && !$apply) {
    $err('--allow-loss hanya berlaku bersama --apply-migrations.');
    exit(2);
}
if (!is_file($app . '/storage/installed.lock') || !is_file($app . '/config/config.php')) {
    $err('Aplikasi belum terpasang.');
    exit(1);
}
if (!is_dir($app . '/definitions')) {
    $err('Folder app/definitions tidak ada.');
    exit(1);
}

Config::load($app . '/config/config.php');
$logger = new RotatingFileLogger($app . '/storage/logs', 5 * 1024 * 1024, 5);
$cacheDir = $app . '/storage/cache';
$store = new CacheStore($cacheDir);
$extDir = $app . '/extensions';

/** @param list<bFramework\Runtime\CompileError> $errors */
$printErrors = static function (array $errors) use ($err): void {
    foreach (array_slice($errors, 0, 30) as $e) {
        $err('  ' . $e->src . ': ' . $e->msg);
    }
    if (count($errors) > 30) {
        $err('  ... dan ' . (count($errors) - 30) . ' galat lain');
    }
};

$lock = null;
$scratch = null;
$main = static function () use (&$lock, &$scratch, $app, $cacheDir, $store, $extDir, $logger, $dry, $apply, $allowLoss, $out, $err, $printErrors): int {
    try {

    $conn = bFramework\connectDatabase($app);
    $store->ensureDir();

    // Kunci yang sama dengan ensureCompiled (first_build.lock); Compiler lalu mengambil build.lock-nya sendiri
    // (urutan kunci selalu first_build -> build, sehingga tidak ada deadlock).
    $lock = @fopen($app . '/storage/first_build.lock', 'c');
    if ($lock === false) {
        $err('Kunci build tidak dapat dibuka (periksa izin app/storage).');
        return 1;
    }
    $deadline = microtime(true) + 20;
    while (!flock($lock, LOCK_EX | LOCK_NB)) {
        if (microtime(true) > $deadline) {
            $err('Build lain sedang berjalan; coba lagi sebentar.');
            return 1;
        }
        usleep(50000);
    }

    $prev = $store->current();
    $oldTables = [];
    if ($prev !== null) {
        try {
            foreach ((new Definitions($store))->tables() as $t) {
                $oldTables[$t->name] = $t;
            }
        } catch (Throwable) {
            $oldTables = [];
        }
    }

    // Tahap 1: validasi + hasil kompilasi di folder sementara (tidak menyentuh versi aktif maupun cache halaman).
    $scratch = $cacheDir . '/dry_' . bin2hex(random_bytes(6));
    $trial = new Compiler(new CacheStore($scratch), $extDir, null, static function (): void {
    }, null, $scratch . '/_nopc');
    $res = $trial->build($app . '/definitions', $conn->dialect());
    if (!$res->ok()) {
        $err('Kompilasi GAGAL; versi aktif tidak diubah. Galat:');
        $printErrors($res->errors);
        return 1;
    }
    $newTables = (new Definitions(new CacheStore($scratch)))->tables();
    $version = (string) $res->version;

    // Tahap 2: bandingkan dengan database.
    $sqlite = $conn->dialect() === bFramework\Contracts\Dialect::Sqlite;
    $exists = $conn->pdo()->prepare(
        $sqlite ? "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?"
            : 'SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?',
    );
    $migrator = new Migrator($conn, $conn->grammar(), $logger);
    $creates = [];
    $alters = [];
    $skipped = [];
    $hasLoss = false;
    foreach ($newTables as $t) {
        if (!bFramework\tableExists($exists, $t->name)) {
            $creates[] = $t;
        } elseif (isset($oldTables[$t->name])) {
            $plan = $migrator->plan($oldTables[$t->name], $t);
            if ($plan->sql !== []) {
                $alters[$t->name] = $plan;
                $hasLoss = $hasLoss || $plan->lossWarnings !== [];
            }
        } else {
            $skipped[] = $t->name;
        }
    }

    $out('Definisi valid. Versi ' . $version . ($prev === $version ? ' (sama dengan versi aktif)' : ' (aktif: ' . ($prev ?? 'belum ada') . ')'));
    foreach ($creates as $t) {
        $out('  + tabel baru: ' . $t->name);
    }
    foreach ($alters as $name => $plan) {
        $out('  ~ perubahan skema tabel ' . $name . ':');
        foreach ($plan->sql as $s) {
            $out('      ' . $s);
        }
        foreach ($plan->lossWarnings as $w) {
            $out('      PERINGATAN KEHILANGAN DATA: ' . $w);
        }
    }
    foreach ($skipped as $name) {
        $out('  ? tabel ' . $name . ' sudah ada tetapi tidak ada di versi sebelumnya; tidak dibandingkan, tidak diubah.');
    }

    if ($dry) {
        $out('--dry-run: tidak ada yang diaktifkan atau diubah.');
        return 0;
    }
    if ($alters !== []) {
        if (!$apply) {
            $err('Ada perubahan skema pada tabel yang sudah ada. TIDAK ADA yang diaktifkan/diubah.');
            $err('Cadangkan database, lalu jalankan ulang dengan --apply-migrations untuk menerapkan.');
            return 1;
        }
        if ($hasLoss && !$allowLoss) {
            $err('DITOLAK: perubahan berpotensi menghapus/memotong data. TIDAK ADA yang diaktifkan/diubah.');
            $err('Cadangkan database, lalu tambahkan --allow-loss bila memang disengaja.');
            return 1;
        }
    }

    // Tahap 3: bangun + aktifkan sungguhan (purge cache halaman _pc; purge gagal = build gagal, versi lama tetap).
    $pc = bFramework\buildPageCache($app, dirname($app) . '/public_html', new Definitions($store), $logger);
    $compiler = new Compiler($store, $extDir, null, $pc->purgeAll(...), $logger);
    $real = $compiler->build($app . '/definitions', $conn->dialect());
    if (!$real->ok()) {
        $err('Build GAGAL; versi aktif sebelumnya dipertahankan. Galat:');
        $printErrors($real->errors);
        return 1;
    }

    // Tahap 4: tabel baru (create-only) lalu perubahan yang diizinkan. Gagal = aktivasi dibatalkan.
    try {
        foreach ($creates as $t) {
            try {
                $migrator->apply($migrator->planCreate($t));
            } catch (Throwable $e) {
                if (!bFramework\tableExists($exists, $t->name)) { // dibuat proses lain = sukses
                    throw $e;
                }
            }
        }
        foreach ($alters as $plan) {
            $migrator->apply($plan, $allowLoss);
        }
        $tmp = $cacheDir . '/.tmp_' . bin2hex(random_bytes(8));
        if (@file_put_contents($tmp, (string) $real->version, LOCK_EX) === false || !@rename($tmp, $cacheDir . '/.schema_ok')) {
            @unlink($tmp);
            throw new RuntimeException('penanda siap tidak dapat ditulis');
        }
        @unlink($cacheDir . '/.build_failed');
    } catch (Throwable $e) {
        $logger->error('compile CLI: migrasi gagal', ['ex' => $e::class]);
        if ($prev !== null) {
            try {
                $store->activate($prev);
                $pc->purgeAll();
            } catch (Throwable) {
                $err('PERINGATAN: versi lama tidak dapat diaktifkan kembali otomatis.');
            }
        }
        $err('Migrasi GAGAL; aktivasi dibatalkan, versi sebelumnya dikembalikan. Lihat storage/logs.');
        return 1;
    }

    $out('Selesai: versi ' . $real->version . ' aktif; ' . count($creates) . ' tabel dibuat, ' . count($alters) . ' tabel diubah.');
    $out('Catatan: OPcache web tidak ter-reset dari CLI. Tidak ada kode PHP yang berubah di sini, jadi biasanya tak perlu; bila');
    $out('Anda ikut mengubah file PHP (extensions/) dan validate_timestamps=0, reset OPcache lewat panel hosting.');
    return 0;
} catch (Throwable $e) {
    $logger->error('compile CLI gagal', ['ex' => $e::class]);
    $err('Gagal (' . $e::class . '). Lihat storage/logs.');
    return 1;
} finally {
    if ($scratch !== null) {
        CacheStore::rmTree($scratch);
    }
    if (is_resource($lock)) {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}
};

exit($main());
