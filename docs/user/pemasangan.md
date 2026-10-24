<!-- maks 150 baris. Pemilik: doc-writer. Dibaca: pengguna akhir -->
# Pemasangan

## 1. Persyaratan
- PHP 8.1 atau lebih baru.
- Ekstensi PHP: `pdo_mysql` dan/atau `pdo_sqlite`, `openssl`, `sodium` (dipakai untuk update bertanda tangan dan SSO), `mbstring`, `json`, `fileinfo`.
- Ekstensi `gd` bila Anda memakai upload gambar (gambar di-encode ulang oleh GD). `curl` opsional; tanpa curl framework memakai cadangan bawaan PHP.
- Apache atau LiteSpeed dengan dukungan `.htaccess` (di Apache: `AllowOverride All`).
- HTTPS aktif dan domain sudah mengarah ke hosting.
- Database MySQL/MariaDB atau SQLite (SQLite cocok untuk aplikasi kecil).

> **Peringatan.** Bila hosting memakai `AllowOverride None` atau Nginx, file `.htaccess` **diabaikan** dan perlindungan folder tidak aktif. Installer tetap bisa lolos pengecekan dasar. Lihat bagian 8.

## 2. Pilih layout folder
**Layout NORMAL (sangat direkomendasikan).** `app/` berada di luar folder web:
```
akun-hosting/
├── app/            (di luar docroot: config, definisi, storage, kode inti)
└── public_html/    (docroot: index.php, .htaccess, assets/)
```
Hanya `public_html/` yang bisa diakses dari internet.

**Mode CADANGAN.** `app/` berada di dalam docroot. Pakai hanya bila hosting benar-benar tidak mengizinkan folder di luar docroot. Perlindungannya bergantung pada `.htaccess` deny-all di `app/`; bila server mengabaikan `.htaccess`, berkas seperti database SQLite, sesi, log, dan konfigurasi bisa terunduh.

Installer menguji mode cadangan dengan **berkas kanari**: browser Anda mencoba mengunduh berkas uji di `app/storage/`. Berkas harus ditolak (403/404). Token instal baru dibuat setelah pengujian lulus. Catatan keputusan pemilik: hasil uji ini dilaporkan oleh browser dan diterima sebagai kontrol terhadap **salah konfigurasi**, bukan terhadap penyerang aktif. Risiko sisa: bila server menampilkan daftar folder (autoindex) atau laporan browser dipalsukan, perlindungan bisa melemah. Karena itu, pilih layout normal bila memungkinkan.

## 3. Unggah lewat FTP
1. Ekstrak zip rilis di komputer.
2. Unggah isi `public_html/` ke docroot domain.
3. Unggah folder `app/` ke lokasi yang sesuai layout pilihan Anda.
4. Pastikan `app/storage/` dan `app/config/` dapat ditulis oleh PHP. Izin yang disarankan: folder 750, berkas 640 (installer menulis `config.php` dengan izin 0600). Peringatan akan muncul di installer bila folder dapat ditulis semua orang (misalnya 777).

Zip rilis tidak berisi `config.php`, isi `storage/`, folder `tests/`, atau berkas rahasia apa pun.

## 4. Jalankan installer
1. Buka `https://example.com/install`.
2. Installer menampilkan pengecekan (versi PHP, ekstensi, izin tulis, layout).
3. **Ambil `install_token`.** Token berupa berkas di `app/storage/` dengan nama `install_token_` diikuti karakter heksadesimal acak. Buka lewat FTP atau file manager hosting, lalu salin isinya ke formulir. Token tidak ditampilkan di web agar orang lain tidak bisa menginstal lebih dulu.
4. Isi formulir:
   - **APP_URL**: alamat lengkap aplikasi, contoh `https://example.com`. Di produksi wajib `https`. `http` di produksi membuat aplikasi menjawab 500.
   - **ALLOWED_HOSTS**: daftar host yang diterima. Bila kosong, dipakai host dari APP_URL.
   - **Database**: SQLite (berkas di `app/storage/`) atau MySQL (host, nama, pengguna, password, port).
   - **SMTP** (opsional): untuk email reset password. Tanpa SMTP, framework memakai fungsi `mail()` bawaan PHP.
   - **Email dan nama admin**, contoh `admin@example.com`.
5. Kirim formulir. Installer menulis `config.php`, membuat tabel, dan membuat akun admin.

## 5. Admin pertama (tanpa password default)
Akun admin dibuat dalam status *pending* tanpa password. Setelah instal selesai, layar menampilkan **tautan pengaturan password satu kali**:
1. Salin tautan itu (bentuknya `https://example.com/auth/reset/...`). Tautan tidak akan ditampilkan lagi.
2. Buka dalam waktu **1 jam**, lalu buat password (10 sampai 128 karakter).
3. Login di `/login`.

Bila tautan kedaluwarsa atau hilang:
- Halaman "lupa password" (`/auth/forgot`) hanya melayani akun berstatus aktif, jadi **tidak menolong admin yang masih *pending***.
- Gunakan skrip pemulihan di server (butuh akses shell/SSH atau terminal hosting):
  1. Dari folder yang berisi `app/`, jalankan `php app/cli/admin-reset.php admin@example.com` (ganti dengan email admin).
  2. Tautan reset baru dicetak **sekali** ke layar (`https://example.com/auth/reset/...`), berlaku 1 jam. Tautan lama akun itu otomatis dicabut.
  3. Buka tautan, buat password, lalu login. Bersihkan layar/riwayat terminal.
- Skrip bekerja untuk admin berstatus aktif maupun pending. Ia menolak bila aplikasi belum terpasang, `APP_URL` berawalan `http://` di produksi (perbaiki ke `https://` di `config.php`), atau email bukan admin/tidak ada/nonaktif (pesan sengaja generik).
- Tautan ini rahasia: jangan simpan di riwayat terminal, log hosting, atau chat. Tidak ada email yang dikirim.
- Tidak perlu lagi menginstal ulang.

## 6. Setelah instal
- `app/storage/installed.lock` dibuat dan `install_token` dihapus. Sejak itu `/install` menjawab 404.
- Instal tidak bisa dijalankan ulang kecuali lock dan config dihapus manual.
- Instalasi baru tidak mengaktifkan registrasi publik.

## 7. Uji cepat
1. Buka `https://example.com/login` dan login sebagai admin.
2. Buka `/admin/pengguna`; Anda akan diminta password lagi (step-up). Ini normal.
3. Coba buka `https://example.com/app/config/config.php` dan `https://example.com/.env`. Keduanya harus ditolak (403/404).

## 8. Bila `.htaccess` diabaikan
Gejala: pengecekan lulus tetapi berkas seperti `.json` atau `.sqlite` bisa dibuka dari browser. Tindakan:
1. Minta penyedia hosting mengaktifkan `AllowOverride All` untuk domain Anda.
2. Atau pindah ke hosting Apache/LiteSpeed yang mendukungnya.
3. Gunakan layout normal agar `app/` tidak bergantung pada `.htaccess`.
Nginx tidak didukung (lihat [batasan-dan-di-luar-cakupan.md](batasan-dan-di-luar-cakupan.md)).
