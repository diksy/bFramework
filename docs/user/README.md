<!-- maks 80 baris. Pemilik: doc-writer. Dibaca: pengguna akhir (developer yang memasang dan memakai BikininFramework) -->
# BikininFramework – Panduan Pengguna

BikininFramework adalah framework PHP yang berjalan penuh di shared hosting murah (tanpa SSH dan tanpa Composer). Anda mendefinisikan model dan halaman dalam file JSON, biasanya lewat builder visual `/_builder`, lalu framework menurunkan tabel, form, daftar data, dan aturan akses secara otomatis. Tidak ada kode PHP yang dihasilkan.

Pembaca panduan ini: developer freelancer, agensi kecil, atau tim internal yang memasang dan memakai framework. Prioritas desain: keamanan, lalu performa, lalu kemudahan.

## Daftar isi
| File | Isi |
| --- | --- |
| [pemasangan.md](pemasangan.md) | Persyaratan, layout folder, unggah FTP, installer web, pemulihan admin |
| [konfigurasi.md](konfigurasi.md) | Semua kunci `config.php` |
| [akun-dan-keamanan.md](akun-dan-keamanan.md) | Login, 2FA, registrasi, pengguna dan peran |
| [membangun-aplikasi.md](membangun-aplikasi.md) | Definisi JSON, komponen, akses, cache halaman, hook, compile di produksi |
| [builder.md](builder.md) | Memakai `/_builder` (khusus mode dev) |
| [upload-file.md](upload-file.md) | Field file dan kebijakan upload |
| [sso.md](sso.md) | Integrasi BikininSSO |
| [pembaruan.md](pembaruan.md) | Membuat rilis, menandatangani, dan memasang update |
| [operasional-dan-keamanan.md](operasional-dan-keamanan.md) | Log, backup, checklist produksi |
| [pemecahan-masalah.md](pemecahan-masalah.md) | Gejala, penyebab, solusi |
| [batasan-dan-di-luar-cakupan.md](batasan-dan-di-luar-cakupan.md) | Batasan yang jujur |

## Alur cepat (10 langkah)
1. Siapkan hosting: PHP 8.1 atau lebih baru dan HTTPS aktif. Baca [pemasangan.md](pemasangan.md).
2. Ambil zip rilis (dibuat dengan `tools/build-release.php`).
3. Ekstrak zip di komputer Anda. Anda akan mendapat folder `app/` dan `public_html/`.
4. Unggah lewat FTP: `public_html/` ke docroot, `app/` **di luar** docroot (layout normal, sangat direkomendasikan).
5. Pastikan folder `app/storage/` dan `app/config/` dapat ditulis oleh PHP.
6. Buka `https://example.com/install` di browser.
7. Ambil `install_token` dari `app/storage/` lewat FTP atau file manager, lalu isi formulir installer (URL aplikasi, database, email pengirim, email admin).
8. Salin tautan pengaturan password admin yang tampil **sekali saja**, buka dalam 1 jam, dan buat password.
9. Login di `https://example.com/login`. Halaman admin akan meminta password lagi (normal).
10. Definisikan model dan halaman Anda (lewat builder di lingkungan lokal, lalu unggah folder `definitions/` dan jalankan `php app/cli/compile.php` di server). Lihat [membangun-aplikasi.md](membangun-aplikasi.md) dan [builder.md](builder.md). Sebelum dipakai nyata, jalankan checklist di [operasional-dan-keamanan.md](operasional-dan-keamanan.md).

## Hal penting yang perlu diketahui sejak awal
- **Builder hanya untuk pengembangan.** Di produksi `/_builder` menjawab 404. Rancang di lokal, lalu unggah hasilnya.
- **Tidak ada password default.** Admin pertama membuat passwordnya sendiri lewat tautan sekali tampil.
- **Jangan menyimpan rahasia di folder web atau di file definisi.** Rahasia hanya di `app/config/config.php` atau variabel lingkungan.
- Kode di `app/extensions/` dianggap tepercaya; definisi JSON diperlakukan sebagai input yang divalidasi.
- Produk ini membantu Anda membangun dengan aman, tetapi tidak menjamin aplikasi Anda "sepenuhnya aman" atau patuh hukum. Lihat [batasan-dan-di-luar-cakupan.md](batasan-dan-di-luar-cakupan.md).

Rujukan aturan (ID seperti ARCH-02, SEC-REQ-01, AUTH-05) ada di `docs/rules.md` bagi yang ingin detail teknis.
