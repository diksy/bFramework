# bFramework (BikininFramework)

Framework PHP yang berjalan penuh di shared hosting murah, tanpa SSH dan tanpa Composer di server. Model dan halaman didefinisikan dalam file JSON (biasanya lewat builder visual `/_builder`); framework menurunkan tabel, form, daftar data, dan aturan akses secara otomatis. Tidak ada kode PHP yang dihasilkan.

Prioritas desain: **keamanan**, lalu performa, lalu kemudahan.

## Fitur utama
- Autentikasi lokal (termasuk 2FA TOTP), manajemen pengguna dan peran, SSO OIDC.
- Perimeter keamanan: CSRF, HostGuard, rate limit, header keamanan.
- Database MySQL/MariaDB atau SQLite, template, page cache, upload file aman.
- Installer web dengan uji kanari, pembaruan bertanda tangan Ed25519.
- Builder visual untuk mendefinisikan model dan halaman (khusus mode dev).

## Persyaratan
- PHP 8.1 atau lebih baru dan HTTPS.
- Ekstensi: `openssl`, `sodium`, `mbstring`, `json`, `fileinfo`, serta `pdo_mysql` dan/atau `pdo_sqlite` (`gd` untuk upload gambar).

## Mulai cepat
1. Unduh `bFramework-vX.Y.Z.zip` dari halaman [Releases](https://github.com/diksy/bFramework/releases) dan verifikasi dengan `SHA256SUMS`.
2. Ekstrak, lalu unggah `public_html/` ke docroot dan `app/` **di luar** docroot.
3. Pastikan `app/storage/` dan `app/config/` dapat ditulis PHP.
4. Buka `https://domain-anda/install` dan ikuti installer.

Langkah lengkap ada di [docs/user/pemasangan.md](docs/user/pemasangan.md).

## Dokumentasi
Panduan pengguna (bahasa Indonesia): [docs/user/README.md](docs/user/README.md). Arsitektur dan keputusan desain: [docs/architecture.md](docs/architecture.md), [docs/decisions.md](docs/decisions.md). Laporan keamanan: [docs/security-report.md](docs/security-report.md).

## Pengembangan
Kode sumber ada di `src/` (`app/` dan `public_html/`), tes di `src/tests/`, alat rilis di `tools/`.
```
composer install
vendor/bin/phpunit
vendor/bin/phpstan analyse
php tools/build-release.php keluaran.zip
```

## Keamanan
Temuan kerentanan sebaiknya dilaporkan secara privat lewat GitHub Security Advisories pada repo ini, bukan lewat issue publik. Known issues dicatat di [CHANGELOG.md](CHANGELOG.md).

## Lisensi
[MIT](LICENSE) © 2026 Diksy M. Firmansyah. Pustaka vendor `firebase/php-jwt` berlisensi BSD-3-Clause.
