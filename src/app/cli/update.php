<?php

declare(strict_types=1);

// CLI updater (M17): php app/cli/update.php status|verify <paket.zip>|apply <paket.zip> [--yes]
// Hanya dari baris perintah. Tidak membaca rahasia; kunci publik ada di core (UpdateKey).

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once dirname(__DIR__) . '/bootstrap.php';

defined('APP_BOOTED') || exit;

use bFramework\Core\Config;
use bFramework\Core\RotatingFileLogger;
use bFramework\Update\CoreManifest;
use bFramework\Update\UpdateException;
use bFramework\Update\UpdateKey;
use bFramework\Update\UpdateMigrations;
use bFramework\Update\UpdatePackage;

$app = dirname(__DIR__);
$root = dirname($app);
Config::load($app . '/config/config.php');
$logger = new RotatingFileLogger($app . '/storage/logs', 5 * 1024 * 1024, 5);
$pkg = new UpdatePackage($root, UpdateKey::raw(), $logger);
$argv = $_SERVER['argv'] ?? [];
$cmd = $argv[1] ?? '';
$zip = $argv[2] ?? '';
$out = static function (string $m): void {
    fwrite(STDOUT, $m . "\n");
};

if ($cmd === 'status') {
    $out('Versi terpasang: ' . $pkg->installedVersion());
    $out($pkg->keyReady() ? 'Kunci penandatangan: tertanam' : 'PERINGATAN: kunci penandatangan belum ditanam; semua paket ditolak.');
    $d = (new CoreManifest($root))->diff();
    if (!$d->available) {
        $out('MANIFEST.sha256 tidak tersedia/valid.');
    } elseif ($d->clean()) {
        $out('File core cocok dengan MANIFEST.sha256.');
    } else {
        foreach (['changed' => 'DIUBAH', 'missing' => 'HILANG', 'extra' => 'TAMBAHAN'] as $k => $label) {
            foreach ($d->$k as $f) {
                $out("$label: $f");
            }
        }
    }
    exit(0);
}

if (($cmd === 'verify' || $cmd === 'apply') && $zip !== '') {
    try {
        $m = $pkg->verify($zip);
    } catch (UpdateException $e) {
        fwrite(STDERR, $e->getMessage() . "\n");
        exit(1);
    }
    $out('Tanda tangan dan isi paket valid. Versi ' . $pkg->installedVersion() . ' -> ' . $m->version . ' (' . $m->date . ')');
    $out('File ditimpa: ' . count($m->files) . ', dihapus: ' . count($m->delete) . ', migrasi: ' . count($m->migrations));
    foreach (array_keys($m->files) as $f) {
        $out('  ~ ' . $f);
    }
    foreach ($m->delete as $f) {
        $out('  - ' . $f);
    }
    if ($cmd === 'verify') {
        exit(0);
    }
    if (!in_array('--yes', $argv, true)) {
        fwrite(STDOUT, 'Ketik versi ' . $m->version . ' untuk melanjutkan: ');
        if (trim((string) fgets(STDIN)) !== $m->version) {
            $out('Dibatalkan.');
            exit(1);
        }
    }
    try {
        $conn = bFramework\connectDatabase($app);
        $migrations = new UpdateMigrations($conn, $logger);
        $rebuild = static function () use ($app, $root, $conn, $logger): void {
            $pc = new bFramework\Cache\PageCache($root . '/public_html/_pc', $app . '/storage/pagecache', static fn(): array => [], $logger);
            $compiler = new bFramework\Runtime\Compiler(new bFramework\Runtime\CacheStore($app . '/storage/cache'), $app . '/extensions', null, $pc->purgeAll(...), $logger);
            $res = $compiler->build($app . '/definitions', $conn->dialect());
            if (!$res->ok()) {
                throw new RuntimeException('build');
            }
        };
        $res = $pkg->apply($zip, $migrations, $rebuild);
    } catch (Throwable $e) {
        fwrite(STDERR, ($e instanceof UpdateException ? $e->getMessage() : 'Update gagal; file dipulihkan. Lihat log.') . "\n");
        exit(1);
    }
    $out('Update ke ' . $res->version . ' selesai (' . $res->files . ' file, ' . count($res->migrations) . ' migrasi).');
    foreach ($res->warnings as $w) {
        $out('PERINGATAN: ' . $w);
    }
    exit(0);
}

fwrite(STDERR, "Pemakaian: php app/cli/update.php status|verify <paket.zip>|apply <paket.zip> [--yes]\n");
exit(2);
