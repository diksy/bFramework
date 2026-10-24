<!-- maks 110 baris. Pemilik: doc-writer. Dibaca: pengguna akhir -->
# Rilis dan Pembaruan

Dua peran: **pemilik rilis** (membuat dan menandatangani paket) dan **operator server** (memasang paket). Paket update ditandatangani Ed25519 (SEC-UPD-01); paket dengan tanda tangan salah ditolak tanpa mengubah satu file pun. Memerlukan ekstensi `sodium`.

## A. Membuat zip rilis
```
php tools/build-release.php [keluaran.zip]
```
Zip berisi `app/` dan `public_html/` plus `MANIFEST.sha256` (daftar hash berkas inti). Tidak ikut: tes, tools, `config.php`, isi `storage/`, berkas `.env`, kunci, database. Build **gagal** bila kunci publik update belum ditanam (lihat langkah B).

## B. Langkah satu kali: membuat kunci penandatangan
Dilakukan oleh pemilik rilis di komputernya sendiri.
1. Buat pasangan kunci, simpan kunci privat **di luar repo**:
   `php tools/gen-update-key.php /jalur/aman/update-private.key`
2. Perintah mencetak kunci **publik** (64 karakter heksadesimal). Salin ke konstanta `PUBLIC_KEY_HEX` di `src/app/core/Update/UpdateKey.php`.
3. Bangun ulang zip rilis (langkah A) sehingga kunci publik ikut tertanam.
4. Pasang rilis pertama ini di server.

> **Peringatan.** Kunci privat tidak boleh masuk repo, zip, chat, atau email. Izin berkas harus 0600. **Cadangkan** di tempat aman terpisah: bila hilang, Anda tidak bisa lagi membuat update yang diterima server yang sudah terpasang. Selama kunci publik masih placeholder, semua paket ditolak (aman, tetapi update tidak bisa dipakai).

## C. Menandatangani paket update
1. Naikkan versi, bangun zip rilis baru (langkah A).
2. Tanda tangani:
```
php tools/sign-update.php --key=/jalur/aman/update-private.key \
  --release=release.zip --version=1.2.0 --out=update.zip
```
Opsi lain: `--min-version=`, `--date=YYYY-MM-DD`, `--migrations=migrasi.json`, `--delete=a,b`. Pastikan `--version` sama dengan versi inti di kode (alat tidak memeriksanya).
3. Hanya berkas inti dalam daftar putih yang masuk paket: `config`, `storage`, `definitions`, `extensions` **tidak pernah** ikut dan tidak tertimpa.

## D. Memasang di server
Penerapan hanya lewat baris perintah (SSH, atau terminal/cron cPanel bila ada). Tidak ada tombol terapkan di web.
1. Unggah `update.zip` ke luar docroot, mis. `app/storage/`.
2. `php app/cli/update.php status` melihat versi, kesiapan kunci, dan perbedaan file.
3. `php app/cli/update.php verify update.zip` memeriksa tanda tangan dan isi tanpa mengubah apa pun.
4. `php app/cli/update.php apply update.zip` menerapkan (tambah `--yes` untuk melewati konfirmasi). Selama proses situs menjawab **503** (mode pemeliharaan); bila gagal, berkas dikembalikan.
5. Hapus `update.zip` dari server.

Hosting tanpa akses CLI: belum ada jalur lewat web. Lihat [batasan-dan-di-luar-cakupan.md](batasan-dan-di-luar-cakupan.md).

## E. Migrasi database dalam paket
- Migrasi harus **aditif dan kompatibel mundur** (tambah tabel/kolom; jangan hapus atau ubah kolom lama). Alat menolak `DROP`, `DELETE`, `TRUNCATE`, tetapi tidak menolak semua perubahan berbahaya; periksa sendiri.
- Migrasi berjalan setelah berkas diganti. Bila migrasi kedua gagal, berkas dikembalikan tetapi migrasi pertama tetap berlaku (di MySQL perubahan struktur tidak bisa di-rollback). Karena itu migrasi lama harus tetap kompatibel dengan kode lama.
- Backup database sebelum update ([operasional-dan-keamanan.md](operasional-dan-keamanan.md)).

## E2. Urutan setelah update atau perubahan definisi
1. Cadangkan database dan berkas.
2. Unggah/terapkan kode (paket update, atau FTP untuk `definitions/` dan `extensions/`).
3. Bila definisi berubah, jalankan `php app/cli/compile.php --dry-run`, periksa pratinjau, lalu `php app/cli/compile.php`. Tabel baru dibuat otomatis; perubahan skema tabel lama butuh `--apply-migrations` (dan `--allow-loss` bila ada peringatan kehilangan data). Utamakan perubahan aditif.
4. Periksa log dan reset OPcache bila perlu (bagian F).

## F. OPcache
CLI memiliki OPcache sendiri; `opcache_reset()` dari CLI **tidak** mereset OPcache proses web. Bila hosting menyetel `opcache.validate_timestamps=0`, web bisa tetap menjalankan kode lama setelah update. Minta penyedia hosting mereset OPcache (atau restart PHP-FPM), atau reset lewat panel hosting.
## G. Halaman status `/admin/pembaruan`
Hanya admin (butuh step-up 15 menit). Hanya-baca: menampilkan versi, kesiapan kunci, dan perbedaan terhadap `MANIFEST.sha256` (DIUBAH, HILANG, TAMBAHAN). Berguna mendeteksi file inti yang diubah manual.
Yang **tidak** terpantau: `public_html/.htaccess` dan `app/config/` (juga `definitions/`, `extensions/`, `storage/`). Periksa `.htaccess` sendiri setelah update.
