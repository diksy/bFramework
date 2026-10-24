<!-- maks 70 baris. Pemilik: doc-writer. Dibaca: pengguna akhir -->
# Batasan dan Di Luar Cakupan

Kejujuran lebih penting daripada janji. Baca ini sebelum memakai BikininFramework untuk data nyata.

## Belum teruji atau belum lengkap
- **Apache/`.htaccess` nyata belum diuji otomatis.** Pengujian dilakukan pada server PHP bawaan dan pembacaan kode. Uji manual di hosting Anda sangat disarankan (proteksi berkas, header keamanan, cache halaman `_pc`, uji kanari).
- **MySQL/MariaDB jalur sukses belum diuji di CI.** SQLite lebih teruji. Coba dulu di staging sebelum produksi.
- **SMTP/TLS nyata dan jaringan nyata** hanya teruji sebagian.
- `admin-reset.php` dan `compile.php` hanya lewat shell; hosting tanpa akses CLI tidak bisa memakainya.
- **UI untuk menandai akun `break_glass` belum ada.**
- **Pembaruan lewat web belum ada**; penerapan hanya lewat CLI. Hosting tanpa CLI tidak bisa memasang update bertanda tangan.
- **Komponen kustom (BLD-06)** pasca-rilis. Hanya 7 komponen bawaan.
- Fitur nyaman di builder seperti command palette dan undo/redo (BLD-10) berstatus "sebaiknya".
- Update tidak memantau `public_html/.htaccess` dan `app/config/`; pengubahan di sana tak terdeteksi.
- Migrasi update di MySQL tidak bisa di-rollback bila gagal di tengah.
- Pencocokan lockout login berdasarkan email dan IP; penyerang dengan banyak alamat IPv6 dapat mencoba lebih banyak.

## Di luar cakupan
- **Nginx.** Perlindungan bergantung pada `.htaccess` (Apache/LiteSpeed). Bila Anda menjalankan Nginx, Anda harus menerjemahkan aturan sendiri; ini tidak didukung.
- **Payment gateway.** Tidak ada. Bila kelak ditambah, data kartu tidak boleh menyentuh server Anda (gunakan tokenisasi dari gateway) dan modulnya perlu dibuat baru.
- **Proses berjalan lama** (worker, antrean, Swoole). Pekerjaan latar hanya lewat cron hosting atau saat ada request.
- Pengguna non-developer, code generation PHP, ekstensi PHP non-standar, dan kriptografi buatan sendiri.

## Keamanan: harapan yang realistis
Framework menerapkan banyak kontrol bawaan (CSRF, rate limit, header keamanan, auto-escape, aturan akses di query, upload aman, update bertanda tangan). Namun:
- Produk **tidak** dinyatakan "sepenuhnya aman" atau "compliant" terhadap regulasi apa pun.
- Pemindaian otomatis dan pembacaan kode sudah dilakukan, tetapi **uji penetrasi oleh manusia tetap disarankan** sebelum memproses data sensitif.
- Bila aplikasi Anda memproses data pribadi, konsultasikan dengan **ahli hukum** mengenai UU Pelindungan Data Pribadi (UU PDP) dan kewajiban Anda.
- Kode di `extensions/` dan konfigurasi hosting adalah tanggung jawab Anda.
- Temuan keamanan berisiko rendah yang diketahui (mis. sesi anonim yang menumpuk, batas laju log) tercatat di `docs/security-report.md`.
