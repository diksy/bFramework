<!-- maks 90 baris. Pemilik: doc-writer. Dibaca: pengguna akhir -->
# Operasional dan Keamanan Produksi

## Log
- Lokasi: `app/storage/logs/`. Log aplikasi (`app.log`) dan log audit admin (`audit.log`) terpisah.
- Rotasi otomatis berdasarkan ukuran; log audit disimpan lebih lama dan tidak dibatasi laju. `app.log` membatasi pesan yang sama berulang (ringkasan jumlah tetap dicatat), jadi banjir pesan bisa menutupi peristiwa lain; pantau juga log server hosting.
- Token, password, dan rahasia disamarkan dan tidak boleh muncul di log. Bila Anda menemukannya, anggap bocor dan laporkan.
- Pengguna akhir hanya melihat halaman error generik; detail hanya ada di log.
- Periksa log setelah instal dan setelah tiap update.

## Cache
- Cache compile: `app/storage/cache/` (aman dihapus oleh developer yang paham akibatnya; akan di-build ulang).
- Cache halaman statis: `public_html/_pc/`. Dibersihkan otomatis saat data model berubah dan berdasarkan umur. Bila halaman publik tampak basi, lihat [pemecahan-masalah.md](pemecahan-masalah.md).

## Backup
Cadangkan secara berkala (dan sebelum update):
1. `app/config/config.php` (berisi rahasia; simpan terenkripsi, jangan di-commit).
2. `app/definitions/` dan `app/extensions/` (sebaiknya juga di Git).
3. `app/storage/` terutama `uploads/` (dan berkas SQLite bila memakainya).
4. Database MySQL (ekspor SQL).
5. Kunci privat penandatangan update (milik pemilik rilis, di luar server).
Uji pemulihan sesekali. `APP_KEY` harus ikut di backup: tanpa itu rahasia 2FA dan token SSO terenkripsi tak dapat dibaca lagi.

## Checklist keamanan sebelum produksi
- [ ] Layout **normal**: `app/` di luar docroot.
- [ ] Situs berjalan di **HTTPS** dan `APP_URL` berawalan `https://`.
- [ ] `ALLOWED_HOSTS` hanya berisi domain Anda.
- [ ] Di balik proxy/CDN: `TRUSTED_PROXIES` diisi dengan IP/CIDR proxy yang benar.
- [ ] `APP_ENV` **bukan** `dev`, `development`, `local`, atau `test`.
- [ ] `/_builder` menjawab 404; `unsafeBuilderInProduction` tidak dipakai.
- [ ] `/install` menjawab 404 dan tidak ada berkas `install_token*` di `app/storage/`.
- [ ] Kunci publik update sudah ditanam dan kunci privat dicadangkan di luar server.
- [ ] Izin berkas: `config.php` 0600 (0640 bila PHP harus membacanya lewat grup), folder 750; tidak ada yang 777.
- [ ] Registrasi publik mati kecuali memang dibutuhkan.
- [ ] 2FA diaktifkan untuk akun admin.
- [ ] Uji manual: `/app/config/config.php`, `/.env`, dan berkas `.json`/`.sqlite` dari browser ditolak (uji `.htaccess` di hosting nyata).
- [ ] SMTP berfungsi (tes kirim email reset).
- [ ] Backup terjadwal dan sudah diuji.

## Skrip baris perintah (CLI)
- `app/cli/admin-reset.php`, `compile.php`, dan `update.php` hanya bisa dijalankan dari shell. Bila dipanggil lewat web, skrip menjawab 404; ini juga berlaku di mode cadangan (`app/` di dalam docroot), jadi skrip menolak akses web.
- Tautan dari `admin-reset.php` adalah **rahasia sekali pakai**: pemegangnya bisa menguasai akun admin. Jangan simpan di riwayat terminal, log hosting, atau chat; bersihkan layar setelah dipakai. Tautan tidak ditulis ke log (log audit hanya mencatat id akun).
- Cadangkan database sebelum `compile.php --apply-migrations`.

## Pemeliharaan rutin
- Pantau `app/storage/` agar tidak membengkak (log, sesi, upload; kuota inode hosting terbatas).
- Pasang update inti secara berkala ([pembaruan.md](pembaruan.md)).
- Tinjau daftar pengguna dan peran di `/admin/pengguna`; nonaktifkan akun yang tak dipakai.
