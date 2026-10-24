<?php

declare(strict_types=1);

defined('APP_BOOTED') || exit;

// Contoh saja, tanpa rahasia. Installer (/install) membuat config.php sungguhan (izin 0600) dan mengisi APP_KEY acak.
return [
    'APP_ENV' => 'production',
    'APP_URL' => 'https://contoh.example',
    'ALLOWED_HOSTS' => ['contoh.example'],
    'TRUSTED_PROXIES' => [], // IP/CIDR proxy yang boleh memberi X-Forwarded-Proto (default kosong: tidak dipercaya)
    'DB_DRIVER' => 'sqlite',
    'DB_FILE' => 'app.sqlite',
    'MAIL_FROM' => 'noreply@contoh.example',
    'auth' => ['registration' => false],
    // SSO (F13) opsional: driver local | bikinin_sso | hybrid. Pengaturan non-rahasia dapat dikelola lewat builder
    // (definitions/auth.json); client_secret HANYA di sini atau di env SSO_CLIENT_SECRET (jangan di docroot/definisi).
    // 'auth' => ['driver' => 'hybrid', 'break_glass_path' => '/auth/break-glass',
    //     'sso' => ['issuer' => 'https://sso.contoh.test', 'client_id' => 'app-contoh', 'client_secret' => '...',
    //         'provisioning' => 'jit', 'default_role' => 'staf', 'offline_access' => false, 'session_check_minutes' => 5]],
    // S20: kuota back-channel logout SSO per IP: 'backchannel_rate' => [30, 60] (maks, detik) di dalam blok 'sso'.
    //     Di balik proxy/CDN, REMOTE_ADDR = IP proxy sehingga semua klien berbagi satu kuota. TRUSTED_PROXIES saat ini
    //     HANYA untuk skema (X-Forwarded-Proto); IP klien dari X-Forwarded-For TIDAK dipercaya. Jadi di balik proxy naikkan
    //     'backchannel_rate' (mis. [300, 60]); kuota hanya melindungi dari banjir, token sah tetap diverifikasi penuh.
    // Builder (/_builder) mati di produksi (404). Jangan aktifkan kecuali terpaksa; butuh ketiganya:
    // 'builder' => ['unsafeBuilderInProduction' => true, 'allowedIps' => ['203.0.113.7'], 'passwordHash' => '<password_hash() Argon2id>'],
];
