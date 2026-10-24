<!-- maks 150 baris. Pemilik: doc-writer. Dibaca: pengguna akhir -->
# Membangun Aplikasi dengan Definisi JSON

Aplikasi Anda berupa file JSON di `app/definitions/`. Anda bisa menulisnya manual atau lewat [builder](builder.md). Dari definisi, framework membuat tabel, validasi, form, daftar, dan aturan akses. Contoh bawaan: `app/definitions/models/produk.json`, `kategori.json`, dan `pages/daftar-produk.json`.

Kunci yang tidak dikenal membuat build gagal (satu error menggagalkan seluruh build). Di produksi definisi di-compile sekali menjadi cache; mengubah file JSON di server tidak berlaku sampai build dijalankan atau paket baru dipasang (CACHE-06).

## Model: `definitions/models/<nama>.json`
Nama file sama dengan nilai `model` dan nama tabel: huruf kecil, angka, garis bawah, diawali huruf, maks 41 karakter. Kolom `id` dibuat otomatis (jangan dideklarasikan).

Contoh (dummy):
```json
{
  "model": "produk",
  "fields": {
    "nama":  { "type": "string", "label": "Nama", "required": true, "max": 100 },
    "harga": { "type": "decimal", "min": 0 },
    "stok":  { "type": "integer", "default": 0 },
    "kategori": { "type": "relasi", "target": "kategori" }
  },
  "hooks": { "beforeSave": "ProdukHooks::validasiStok" },
  "access": { "read": "*", "write": ["admin"] }
}
```

### Tipe field (ARCH-04)
`string`, `text`, `integer`, `decimal`, `boolean`, `date`, `datetime`, `json`, `relasi` (wajib `target` = model lain). `decimal` diproses sebagai angka teks (tanpa galat pembulatan); default presisi 12,2 (`precision`/`scale`).

Opsi field: `label`, `required`, `unique`, `guarded` (tidak pernah diisi dari input form), `min`, `max`, `default`, `format`. `text` dan `json` tidak boleh punya `default` atau `unique`. Tidak ada SQL mentah di definisi.

### Nama yang dicadangkan
Nama model: `users`, `roles`, `user_roles`, `remember_tokens`, `one_time_tokens`, `files`, `sso_sessions`, `sso_refresh_tokens`, `audit_log`, `migrations`, serta awalan `bf_`. Segmen rute: `admin`, `_builder`, `auth`, `login`, `logout`, `install`, `peran-aktif`, `assets`, `files`, `uploads`, `api`, `_pc`, serta awalan `_`.

### Field upload
Field file ditulis sebagai string dengan blok `upload`: `{"type":"string","upload":{"mimes":["image/png"],"maxBytes":1048576}}`. Rincian di [upload-file.md](upload-file.md).

### Akses (`access`)
- `read`, `create`, `update`, `delete`, `write`: `"*"` (semua, termasuk anonim) atau daftar peran. **Tanpa aturan berarti ditolak.**
- `owner`: nama field (integer/relasi) yang berisi ID pemilik baris. Pengguna hanya melihat dan mengubah baris miliknya (SEC-AUTHZ-02).
- `ownerExempt`: daftar peran yang dikecualikan dari aturan owner (misalnya `["admin"]`).
- `requireAmr`: daftar metode autentikasi yang wajib, mis. `["otp"]`, atau per aksi `{"delete": ["otp"]}`.
Aturan ditegakkan di lapisan query, bukan hanya UI; tombol yang tersembunyi tidak menjadi satu-satunya pengaman.

### Hook
Event: `beforeSave`, `afterSave`, `beforeCreate`, `afterCreate`, `beforeUpdate`, `afterUpdate`, `beforeDelete`, `afterDelete`. Nilai: `"NamaKelas::namaMetode"`. Lihat bagian Ekstensi di bawah.

## Halaman: `definitions/pages/<nama>.json`
Kunci: `page` (sama dengan nama file), `route` (mis. `/produk`, unik), `title`, `icon`, `group` (nama grup menu; "Admin" dicadangkan), `order`, `access` (`"*"` atau daftar peran; kosong = ditolak), `cache` (bool), `layout` (daftar komponen).

Menu sidebar dibuat otomatis dari halaman dan disaring menurut peran aktif.

### Tujuh komponen bawaan
Grid 12 kolom (`span` 1 sampai 12). Sumber data: `source` = `{model, filter, sort, perPage}` (`sort` diawali `-` untuk menurun, `perPage` 1 sampai 100). Field/kolom yang disebut harus ada di model sumber.
| Komponen | Kegunaan |
| --- | --- |
| `table` | Daftar data; `columns`, `actions` (`edit`, `hapus`) |
| `form` | Form tambah/ubah berdasar field model |
| `card` | Kartu ringkas |
| `stat` | Angka agregat; `agg` = count, sum, avg, min, max (+ `field`) |
| `chart` | Grafik |
| `text` | Teks statis |
| `image` | Gambar |
Komponen kustom (manifest + renderer sendiri, aturan BLD-06) **belum didukung**; rencananya pasca-rilis.

## Cache halaman (`cache: true`)
Halaman publik bisa disajikan sebagai HTML statis langsung oleh Apache tanpa menjalankan PHP.
- Hanya untuk halaman dengan `access` `"*"`; kombinasi lain membuat build gagal. **Halaman login/yang butuh login tidak bisa di-cache.**
- Menyimpan data sebuah model menghapus halaman cache yang bertag model itu.
- Perubahan data lewat jalur selain form framework (hook, impor langsung ke DB) tidak memicu penghapusan otomatis.
- Halaman ber-cache yang berisi form dengan token CSRF tidak disarankan: form dapat ditolak 419.
- Berkas cache di `public_html/_pc/`. Batas bawaan: 500 berkas, 256 KB per berkas, 20 MB total, umur 24 jam.

## Ekstensi dan hook
- Taruh kelas PHP di `app/extensions/NamaKelas.php`. Kelas harus **global** (tanpa namespace) dengan metode `public static`.
- Tanda tangan hook: `public static function metode(array $data): array`, mengembalikan daftar pesan error (kosong berarti lolos).
- Hook dirujuk dari definisi; bila kelas atau metode tidak ada, build gagal. Hook diverifikasi ulang saat dijalankan.
- Builder menolak hook yang memakai fungsi berbahaya (mis. `exec`, `system`, `eval`, `call_user_func`).
- Kode di `extensions/` dianggap tepercaya. Jaga kualitasnya sendiri. Rujukan teknis: `docs/api-ekstensi.md`.

## Alur kerja yang disarankan
1. Rancang di lokal (mode dev) memakai builder.
2. Periksa hasil JSON di folder `definitions/` (bisa di-commit ke Git).
3. Sertakan `definitions/` dan `extensions/` dalam rilis/instalasi pertama Anda.
4. Compile otomatis berjalan pada **request pertama instalasi baru** (saat belum ada cache), termasuk pembuatan tabel model.
5. Untuk perubahan sesudahnya di produksi, unggah `definitions/` (dan `extensions/`) lewat FTP, lalu jalankan di shell server (builder hanya untuk dev):
   ```
   php app/cli/compile.php --dry-run
   php app/cli/compile.php
   ```
   - `--dry-run`: hanya validasi dan pratinjau; tidak ada yang diaktifkan.
   - Build bersifat atomik di bawah kunci; bila gagal, versi lama tetap aktif.
   - Tabel model **baru** dibuat otomatis.
   - Perubahan skema tabel yang sudah ada hanya ditampilkan sebagai pratinjau dan tidak ada yang berubah, kecuali Anda menambah `--apply-migrations` (cadangkan database dulu).
   - Perubahan yang berpotensi menghapus/memotong data ditolak kecuali ditambah `--allow-loss` (hanya bersama `--apply-migrations`).
   - Exit code: 0 berhasil, 1 gagal/ditolak, 2 salah pakai opsi.
   - Bila Anda juga mengubah PHP di `extensions/` dan OPcache tidak memeriksa timestamp, reset OPcache lewat panel hosting.
   Paket update ([pembaruan.md](pembaruan.md)) tetap jalur untuk kode inti.
