<?php

declare(strict_types=1);

// auto_prepend_file untuk server PHP bawaan milik tes integrasi (hanya hidup di sandbox tmp).
// Memasang pengganti transport (HTTP keluar dan email) tanpa menyentuh kode aplikasi; sisanya bootstrap/index.php nyata.
if (getenv('INT_SANDBOX') === false) {
    return;
}
$_SERVER['HTTPS'] = 'on'; // TLS diterminasi di depan server tes; APP_URL memakai https
if (isset($_SERVER['HTTP_X_INT_REMOTE']) && filter_var($_SERVER['HTTP_X_INT_REMOTE'], FILTER_VALIDATE_IP) !== false) {
    $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_X_INT_REMOTE']; // IP klien berbeda untuk tes rate limit
}
spl_autoload_register(static function (string $c): void {
    if ($c === 'bFramework\\Core\\HttpClient') {
        require __DIR__ . '/int_fake_http.php';
    } elseif ($c === 'bFramework\\Auth\\MailFunctionTransport') {
        require __DIR__ . '/int_fake_mail.php';
    }
}, true, true);
