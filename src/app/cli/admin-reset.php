<?php

declare(strict_types=1);

// CLI pemulihan admin (M13/F14): php app/cli/admin-reset.php <email>
// Menerbitkan tautan reset sekali pakai (TTL 3600 detik) untuk akun ber-peran admin, termasuk admin berstatus pending
// yang tautan awalnya kedaluwarsa. Tautan dicetak SEKALI ke stdout; tidak disimpan, tidak dicatat di log (hanya hash
// token di DB). Tidak mengirim email. Exit: 0 berhasil, 1 ditolak/gagal, 2 salah pakai.

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once dirname(__DIR__) . '/bootstrap.php';

defined('APP_BOOTED') || exit;

use bFramework\Auth\AccountStore;
use bFramework\Auth\OneTimeToken;
use bFramework\Auth\SystemClock;
use bFramework\Core\Config;
use bFramework\Core\RotatingFileLogger;

$app = dirname(__DIR__);
$argv = $_SERVER['argv'] ?? [];
$out = static function (string $m): void {
    fwrite(STDOUT, $m . "\n");
};
$err = static function (string $m): void {
    fwrite(STDERR, $m . "\n");
};

if (count($argv) !== 2 || !is_string($argv[1])) {
    $err('Pemakaian: php app/cli/admin-reset.php <email>');
    exit(2);
}
$email = AccountStore::normalizeEmail($argv[1]);
if ($email === null) {
    $err('Format email tidak valid.');
    exit(2);
}
if (!is_file($app . '/storage/installed.lock') || !is_file($app . '/config/config.php')) {
    $err('Aplikasi belum terpasang.');
    exit(1);
}

Config::load($app . '/config/config.php');
$appUrl = Config::get('APP_URL', '');
$parts = is_string($appUrl) ? parse_url($appUrl) : false;
if (!is_array($parts) || !in_array($parts['scheme'] ?? '', ['http', 'https'], true) || ($parts['host'] ?? '') === '') {
    $err('APP_URL belum dikonfigurasi dengan benar; tautan tidak dapat dibuat.');
    exit(1);
}
if ($parts['scheme'] !== 'https' && !Config::devMode()) {
    $err('APP_URL berskema http:// ditolak di produksi: tautan reset wajib https. Perbaiki APP_URL di config/config.php.');
    exit(1);
}
$base = rtrim($appUrl, '/');

try {
    $conn = bFramework\connectDatabase($app);
    $clock = new SystemClock();
    $accounts = new AccountStore($conn, $clock);
    $acc = $accounts->findByEmail($email);
    if ($acc === null || !in_array($acc->status, ['active', 'pending'], true) || !in_array('admin', $accounts->roles($acc->id), true)) {
        $err('Tidak ada akun admin yang dapat direset untuk email itu.');
        exit(1);
    }
    // issue() mencabut token reset lama akun ini lebih dulu. Status pending tetap sampai tautan dipakai (resetPost).
    $token = (new OneTimeToken($conn, $clock))->issue($acc->id, OneTimeToken::RESET, 3600);
    // Kanal audit terpisah; hanya fakta + id akun. Tanpa tautan/token/email.
    (new RotatingFileLogger($app . '/storage/logs', 5 * 1024 * 1024, 10, 'audit.log', null, false))
        ->info('Reset admin via CLI', ['user' => $acc->id, 'status' => $acc->status]);
} catch (Throwable) {
    $err('Gagal menerbitkan tautan reset. Periksa konfigurasi database dan log.');
    exit(1);
}

$err('PERINGATAN: tautan ini RAHASIA dan sekali pakai. Jangan simpan di riwayat terminal, log hosting, atau chat;');
$err('siapa pun yang memegangnya dapat menguasai akun admin. Pakai segera lalu bersihkan layar/riwayat.');
$out('Tautan reset (sekali pakai, berlaku 60 menit; tidak akan ditampilkan lagi):');
$out($base . '/auth/reset/' . $token);
exit(0);
