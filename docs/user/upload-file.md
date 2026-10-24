<!-- maks 80 baris. Pemilik: doc-writer. Dibaca: pengguna akhir -->
# Upload File

Rujukan aturan: SEC-FILE-01, SEC-FILE-02, SEC-PER-02.

## Mendefinisikan field file
Field file adalah field `string` dengan blok `upload`. Tidak ada tipe `file` terpisah.
```json
"foto": {
  "type": "string",
  "label": "Foto produk",
  "upload": { "mimes": ["image/png", "image/jpeg"], "maxBytes": 1048576 }
}
```
- `mimes`: daftar tipe yang diizinkan (whitelist). Wajib minimal satu.
- `maxBytes`: batas ukuran per berkas, 1 byte sampai 100 MiB.
- Field file tidak boleh memakai `unique`, `default`, `min`, `max`; tidak bisa dijadikan `owner`, tidak bisa dipakai untuk sort, filter, atau agregat.
- Kolom di database hanya menyimpan ID berkas (32 karakter heksadesimal), bukan nama atau isi berkas.

## Cara kerja untuk pengguna
1. Pilih berkas di form. Unggahan berjalan lebih dulu lewat `POST /files` dan mengembalikan ID.
2. ID terisi otomatis di form; kirim form seperti biasa.
3. Mengganti atau mengosongkan field, atau menghapus barisnya, menghapus berkas lama.
Unggahan multipart langsung di form tidak didukung (selalu dua langkah). Berkas yang diunggah tetapi tidak pernah dipakai dihapus setelah 24 jam.

## Kebijakan tipe berkas
- Tipe sebenarnya dideteksi dari **isi** berkas (finfo), bukan dari nama atau ekstensi. File PHP berekstensi `.jpg` ditolak.
- **SVG ditolak.** Juga ditolak: HTML, XHTML, XML, JavaScript, skrip shell, dan eksekutabel. Definisi yang memakainya gagal saat build.
- Gambar (JPEG, PNG, GIF, WebP) diproses ulang oleh GD sehingga muatan tersembunyi hilang. Ekstensi `gd` wajib bila Anda menerima gambar. Batas gambar: 32 MB per berkas dan sekitar 10 juta piksel.
- Pesan gagal bersifat generik ("tipe/ukuran tidak diizinkan") tanpa membocorkan detail.

## Kuota dan batas laju
Bawaan per pengguna: 200 berkas, total 200 MB, dan 30 unggahan per 60 detik. Atur lewat `upload.*` di [konfigurasi.md](konfigurasi.md). Melebihi kuota: 413; terlalu sering: 429.

## Akses ke berkas
- Berkas disimpan di luar docroot (`app/storage/uploads`) dengan nama acak.
- Dibuka lewat `GET /files/{id}`. Pengguna harus login dan berhak membaca baris model terkait; selain itu dijawab 404 yang sama (tidak membocorkan apakah berkas ada).
- Respons memakai `nosniff` dan CSP sandbox. Hanya gambar yang ditampilkan langsung; tipe lain diunduh.
- Hanya pengunggah yang bisa melampirkan berkasnya ke baris; berkas orang lain tidak bisa dilampirkan.
- Berkas yang barisnya sudah hilang tidak bisa diakses siapa pun, termasuk admin.

## Tips
- Pastikan `upload_max_filesize` dan `post_max_size` PHP di hosting cukup besar untuk `maxBytes` Anda.
- Pada layout normal, folder upload tidak terjangkau web. Pada mode cadangan, andalkan `.htaccess` deny-all (lihat [pemasangan.md](pemasangan.md)).
