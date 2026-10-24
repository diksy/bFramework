<!-- maks 90 baris. Pemilik: doc-writer. Dibaca: pengguna akhir -->
# Pemecahan Masalah

Selalu cek `app/storage/logs/app.log` lebih dulu; halaman error sengaja tidak menampilkan detail.

| Gejala | Kemungkinan penyebab | Solusi |
| --- | --- | --- |
| **500** di semua halaman setelah instal | `APP_URL` berawalan `http://` di mode produksi (sengaja ditolak); `APP_ENV` salah; folder `storage/` tidak dapat ditulis; compile pertama gagal | Ubah `APP_URL` ke `https://...`; periksa izin tulis `app/storage/`; baca `app.log`. Bila compile gagal, perbaiki definisi (pesan galat ada di log) |
| **500** setelah mengubah definisi | Definisi tidak valid (kunci tak dikenal, hook tak ditemukan) | Perbaiki JSON/hook di lokal lewat builder, uji dulu |
| **/install 404** | Instalasi sudah selesai (`installed.lock` ada) atau `app/` belum terjangkau | Normal setelah instal. Menginstal ulang hanya dengan menghapus `app/storage/installed.lock` dan `app/config/config.php` (menghapus konfigurasi lama) |
| Installer tidak mau membuat token / mode cadangan ditolak | Uji kanari gagal: server tidak memblokir akses ke `app/` | Pindahkan `app/` ke luar docroot; atau aktifkan `AllowOverride All` |
| Tautan reset/admin pertama kedaluwarsa | Berlaku 1 jam; `/auth/forgot` hanya melayani akun aktif | Jalankan `php app/cli/admin-reset.php <email>` di shell server; lihat [pemasangan.md](pemasangan.md) bagian 5. Pesan "Tidak ada akun admin yang dapat direset" berarti email bukan admin, tidak ada, atau nonaktif |
| `admin-reset.php` menolak karena `APP_URL` | `APP_URL` berawalan `http://` di produksi | Ubah ke `https://...` di `config.php`, jalankan lagi |
| **419** saat mengirim form | Token CSRF kedaluwarsa. Sesi anonim yang hanya berisi token CSRF habis setelah idle umum 30 menit, jadi form anonim yang dibuka lebih lama ditolak; atau cookie tidak tersimpan | Muat ulang halaman lalu kirim lagi. Pastikan cookie diizinkan |
| **429** | Terlalu banyak percobaan (login, reset, unggah, back-channel) | Tunggu sesuai header `Retry-After` atau sampai jendela (mis. 15 menit) habis. Di balik proxy, kuota bisa berbagi (lihat [konfigurasi.md](konfigurasi.md)) |
| **503** | Mode pemeliharaan saat `update apply` berjalan; atau konfigurasi belum lengkap | Tunggu proses update selesai. Bila menetap, baca `app.log` dan periksa berkas `app/storage/maintenance` yang tertinggal setelah proses mati |
| **400** pada semua permintaan | Host tidak ada di `ALLOWED_HOSTS` | Tambahkan domain Anda ke `ALLOWED_HOSTS` |
| Login/cookie gagal di balik proxy | `APP_URL` https memaksa cookie `Secure`, tetapi koneksi ke browser HTTP; atau `TRUSTED_PROXIES` salah | Pakai HTTPS ujung ke ujung; isi `TRUSTED_PROXIES` dengan IP proxy sebenarnya |
| Halaman admin minta password lagi | Verifikasi ulang (step-up) 15 menit; terutama setelah memakai "ingat saya" | Normal. Masukkan password (+ kode OTP bila 2FA) |
| Akun terkunci / "Email atau password salah" terus | Lockout setelah banyak percobaan gagal, atau akun *pending/nonaktif* | Tunggu 15 menit; minta admin memeriksa status akun atau mengirim reset |
| Email tidak terkirim | SMTP salah atau `mail()` diblokir hosting | Periksa `SMTP_*` dan `MAIL_FROM`; lihat log |
| `/_builder` 404 | Mode produksi (sengaja) | Jalankan lokal dengan `APP_ENV` dev ([builder.md](builder.md)) |
| Halaman publik menampilkan data lama | Cache halaman (`cache: true`) basi, terutama bila data diubah di luar form framework | Hapus berkas di `public_html/_pc/` (biarkan `.htaccess`-nya) |
| Definisi baru tidak muncul setelah unggah FTP | Produksi tidak membaca ulang file sumber (CACHE-06); cache belum di-compile ulang | Jalankan `php app/cli/compile.php --dry-run`, lalu `php app/cli/compile.php`. Lihat [membangun-aplikasi.md](membangun-aplikasi.md) langkah 4 |
| `compile.php` menolak (exit 1) | Definisi tidak valid, perubahan skema tabel lama butuh `--apply-migrations`, atau berpotensi kehilangan data (butuh `--allow-loss`) | Baca pesan galat; versi lama tetap aktif. Cadangkan database sebelum memakai opsi tersebut |
| Upload gagal | Tipe/ukuran di luar kebijakan, `gd` tidak ada, kuota penuh, batas PHP | Lihat [upload-file.md](upload-file.md) |
| Kode lama masih jalan setelah update | OPcache web belum direset | Lihat [pembaruan.md](pembaruan.md) bagian F |
| Berkas `.json`/`.sqlite` bisa dibuka dari browser | `.htaccess` diabaikan server | Aktifkan `AllowOverride All`; pakai layout normal |
