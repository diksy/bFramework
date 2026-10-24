<?php

declare(strict_types=1);

defined('APP_BOOTED') || exit;

// Contoh saja, tanpa rahasia. Installer (/install) membuat config.php sungguhan (izin 0600) dan mengisi APP_KEY acak.
return [
    'APP_ENV' => 'production',
    'APP_URL' => 'https://contoh.example',
    'ALLOWED_HOSTS' => ['contoh.example'],
    'DB_DRIVER' => 'sqlite',
    'DB_FILE' => 'app.sqlite',
    'MAIL_FROM' => 'noreply@contoh.example',
    'auth' => ['registration' => false],
    // Builder (/_builder) mati di produksi (404). Jangan aktifkan kecuali terpaksa; butuh ketiganya:
    // 'builder' => ['unsafeBuilderInProduction' => true, 'allowedIps' => ['203.0.113.7'], 'passwordHash' => '<password_hash() Argon2id>'],
];
