<!-- maks 140 baris. Pemilik: doc-writer. Dibaca: pengguna akhir -->
# Konfigurasi

File konfigurasi: `app/config/config.php`. Installer membuatnya (izin 0600) dan mengisi `APP_KEY` acak. Contoh tanpa rahasia: `app/config/config.example.php`.

> **Peringatan.** Jangan menaruh `config.php` di folder web, jangan di-commit ke Git, dan jangan membagikan isinya. Nilai di bawah ini hanya contoh (dummy).

Beberapa rahasia boleh diberikan lewat variabel lingkungan; variabel lingkungan didahulukan: `APP_ENV`, `APP_KEY`, `DB_PASSWORD`, `SMTP_PASSWORD`, `SSO_CLIENT_SECRET`, `BUILDER_PASSWORD_HASH`.

## Kunci utama
| Kunci | Fungsi | Contoh |
| --- | --- | --- |
| `APP_ENV` | Mode aplikasi (lihat di bawah) | `'production'` |
| `APP_URL` | Alamat dasar; semua tautan email dibuat dari sini (bukan dari header Host). Produksi wajib `https` | `'https://example.com'` |
| `ALLOWED_HOSTS` | Host yang diterima; selain itu dijawab 400 | `['example.com']` |
| `TRUSTED_PROXIES` | IP/CIDR proxy atau CDN yang boleh memberi header `X-Forwarded-Proto` | `[]` |
| `APP_KEY` | Kunci acak untuk enkripsi (rahasia 2FA, refresh token SSO). Minimal 32 karakter; dibuat installer (48 byte acak dalam base64). Jangan diubah setelah dipakai | (dibuat installer) |
| `APP_HOST` | Host untuk Message-ID email | `'example.com'` |
| `MAIL_FROM` | Alamat pengirim email | `'noreply@example.com'` |

### APP_ENV: dev atau produksi
Hanya nilai `dev`, `development`, `local`, atau `test` (tidak peka huruf besar-kecil, spasi dipangkas) yang berarti mode **dev**. Nilai lain apa pun, kosong, atau salah ketik (misalnya `prodution`) berarti **produksi**. Mode dev membuka builder `/_builder`, menampilkan lokasi sumber (`_src`) di pesan validasi, dan mengompilasi ulang definisi saat berubah. **Jangan pernah memakai nilai dev di server publik.**

### TRUSTED_PROXIES
Isi bila aplikasi berada di balik proxy atau CDN yang memutus TLS. Header `X-Forwarded-Proto` hanya dipercaya dari alamat di daftar ini (nilai terakhir yang dipakai). Konsekuensi: bila `APP_URL` berawalan `https`, cookie otomatis `Secure` (dan berawalan `__Host-`) serta header HSTS dikirim. Akibatnya **login lewat HTTP polos akan gagal** karena cookie Secure tidak terkirim. Pastikan pengunjung memakai HTTPS. Daftar ini hanya memengaruhi skema; IP klien dari `X-Forwarded-For` **tidak** dipercaya.

## Database
| Kunci | Keterangan |
| --- | --- |
| `DB_DRIVER` | `'sqlite'` atau `'mysql'` |
| `DB_FILE` | Nama berkas SQLite di `app/storage/`, contoh `'app.sqlite'` |
| `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PORT` | Untuk MySQL/MariaDB |
| `DB_PASSWORD` | Password MySQL (boleh lewat env) |

## Email (SMTP)
`SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASSWORD`. Bila SMTP kosong, dipakai `mail()` PHP. Email dikirim setelah respons dikirim ke browser.

## Autentikasi (`auth`)
| Kunci | Bawaan | Keterangan |
| --- | --- | --- |
| `auth.registration` | `false` | `true` menampilkan `/auth/register` (hanya driver `local`) |
| `auth.default_role` | `'staf'` | Peran untuk pengguna baru dari registrasi |
| `auth.remember_days` | 30 | Lama "ingat saya", 1 sampai 90 hari |
| `auth.driver` | `local` | `local`, `bikinin_sso`, atau `hybrid` (lihat [sso.md](sso.md)) |
| `auth.break_glass_path` | `/auth/break-glass` | URL login darurat pada mode hybrid |
| `auth.sso.*` | – | issuer, client_id, client_secret, provisioning, default_role, offline_access, session_check_minutes, backchannel_rate |

Contoh `auth.sso.backchannel_rate` = `[30, 60]` (maks 30 permintaan per 60 detik per IP, bawaan). Di balik proxy/CDN semua klien tampak berasal dari satu IP proxy sehingga berbagi satu kuota; naikkan, misalnya `[300, 60]`. Kuota hanya melindungi dari banjir; token tetap diverifikasi penuh.

## Upload (`upload`)
| Kunci | Bawaan |
| --- | --- |
| `upload.dir` | `app/storage/uploads` (jangan di docroot) |
| `upload.maxFilesPerOwner` | 200 |
| `upload.maxBytesPerOwner` | 209715200 (200 MB) |
| `upload.rateMax` / `upload.rateWindow` | 30 unggahan per 60 detik per pengguna |

## Cache halaman (`page_cache`, opsional)
`maxFiles` (500), `maxFileBytes` (262144), `maxTotalBytes` (20971520), `ttl` (86400 detik).

## Builder (`builder`) – tidak disarankan di produksi
`unsafeBuilderInProduction`, `allowedIps`, `passwordHash`, opsional `loginTtl` (60 sampai 3600 detik, bawaan 900), `rateMax`, `rateWindow`. Lihat [builder.md](builder.md).

## Contoh minimal (dummy)
```php
return [
    'APP_ENV' => 'production',
    'APP_URL' => 'https://example.com',
    'ALLOWED_HOSTS' => ['example.com'],
    'TRUSTED_PROXIES' => [],
    'DB_DRIVER' => 'sqlite',
    'DB_FILE' => 'app.sqlite',
    'MAIL_FROM' => 'noreply@example.com',
    'auth' => ['registration' => false],
];
```
Perubahan konfigurasi berlaku pada request berikutnya. Konfigurasi dan rahasia tidak pernah ikut ke cache hasil compile.
