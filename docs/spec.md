<!-- maks ~1 halaman (60 baris). Pemilik: orchestrator. Dibaca: semua agen (reviewer: fitur terkait saja) -->
# Spesifikasi Produk – BikininFramework

## Tujuan
Framework PHP yang berjalan penuh di shared hosting murah (tanpa SSH/Composer), dengan builder visual
untuk mempercepat developer (freelancer, agensi kecil, tim internal) membangun aplikasi CRUD UMKM.
Prioritas: keamanan > performa > kemudahan. Aturan normatif (ARCH-, SEC-, CACHE-, BLD-, AUTH-, SSO-)
ada di `docs/rules.md`; setiap aturan WAJIB punya test dengan ID di namanya.

## Fitur
| ID | Fitur | Kriteria terima (rujuk aturan) | Data sensitif? |
| --- | --- | --- | --- |
| F1 | Core: bootstrap, routing, request/response, struktur folder, mode cadangan docroot | ARCH-01..03, ARCH-07..08 | tidak |
| F2 | Perimeter & request: .htaccess, header keamanan, CSRF, rate limit, validasi Host | SEC-PER-*, SEC-REQ-* | tidak |
| F3 | Sesi & otorisasi: sesi di storage, aturan `access` & tingkat baris di lapisan query | SEC-SESS-*, SEC-AUTHZ-* | ya |
| F4 | Database & schema: PDO, grammar MySQL/SQLite, migrasi (rebuild table SQLite) | ARCH-04..05, SEC-DATA-01 | tidak |
| F5 | Runtime definisi JSON: model → tabel, validasi, form, daftar, mass assignment | SEC-DATA-02, CACHE-10 | tidak |
| F6 | Template engine auto-escape + CSP nonce | SEC-OUT-* | tidak |
| F7 | Compile cache definisi (versi atomik, lazy, aman OPcache) | CACHE-01..11 | tidak |
| F8 | Cache halaman HTML statis + invalidasi tag model | CACHE-12..14 | tidak |
| F9 | Upload file aman (luar docroot, finfo, whitelist) | SEC-FILE-* | ya |
| F10 | Error & log produksi (halaman generik, rotasi, tanpa rahasia) | SEC-LOG-* | ya |
| F11 | HTTP client cURL + fallback stream, TLS wajib | ARCH-06 | tidak |
| F12 | Autentikasi lokal: AuthDriver, Argon2id, ingat saya, reset/verifikasi, SMTP, TOTP | AUTH-01..08 | ya |
| F13 | Integrasi BikininSSO (OIDC + PKCE, back-channel logout, mode hybrid) | SSO-01..21 | ya |
| F14 | Installer web + paket update bertanda tangan Ed25519 | ARCH-02, SEC-CONF-*, SEC-UPD-* | ya |
| F15 | UI builder `/_builder` (model, halaman, akses, hooks, preview, auth) | BLD-01..10, SEC-BLD-01 | tidak |
| F16 | Manajemen user & peran: `/admin/pengguna`, `/admin/peran`; multi-peran + ganti peran aktif | AUTH-01, SEC-SESS-02, SEC-AUTHZ-* | ya |

## Stack yang direncanakan
- PHP 8.1+ (`declare(strict_types=1)`, PSR-12, PHPStan level 8), tanpa Composer di server; dependensi di-vendor ke zip rilis.
- MySQL/MariaDB dan SQLite lewat PDO. Apache/LiteSpeed (`.htaccess`).
- Namespace `bFramework\Core`, `bFramework\Runtime`, `bFramework\Builder`.
- Frontend builder: vanilla JS tanpa langkah build (pengguna tidak butuh Node.js).
- Tes: PHPUnit (dijalankan di mesin developer/CI, bukan di server).
- Teks UI dan dokumentasi: bahasa Indonesia.

## Roadmap (tahap berikutnya dimulai setelah gerbang lulus)
1. Core aman: F1, F2, F4, F6, F10, F11 — tes ARCH, SEC-PER/REQ/DATA-01/OUT/LOG lulus.
2. Runtime: F3, F5, F7 (dokumen API ekstensi dulu) — tes CACHE-01..11, SEC-AUTHZ, SEC-DATA-02; app "produk" jalan dari JSON.
3. Siap pakai: F12, F16, F9, F14 (installer + zip) — tes AUTH, SEC-FILE; instal via FTP di 1 shared hosting.
4. Builder: F15 — tes BLD, SEC-BLD-01; CRUD baru dibuat lewat `/_builder` tanpa PHP.
5. Lanjutan: F13, F8, F14 (update Ed25519) — tes SSO, CACHE-12..14, SEC-UPD; uji di 2 provider hosting.

## Di luar cakupan (out of scope)
- Pengguna non-developer, code generation PHP, proses berjalan lama (worker/Swoole), server Nginx.
- Ekstensi PHP non-standar; kriptografi buatan sendiri; payment gateway.
