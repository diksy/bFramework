<!-- maks 100 baris. Pemilik: doc-writer. Dibaca: pengguna akhir -->
# Builder Visual (`/_builder`)

Builder adalah alat developer untuk menulis file definisi tanpa mengetik JSON. Builder hanya menulis ke folder `definitions/`, tidak pernah menulis kode PHP (BLD-09). Frontend-nya JavaScript biasa; Anda tidak perlu Node.js.

## Hanya mode dev
- Builder aktif hanya bila `APP_ENV` bernilai dev (`dev`, `development`, `local`, `test`).
- Di produksi, `/_builder` menjawab **404** (SEC-BLD-01).
- Cara yang disarankan: jalankan salinan lokal (mis. `php -S localhost:8000 -t public_html` dari folder proyek) dengan `APP_ENV` dev, rancang di sana, lalu pindahkan hasilnya.

## Panel
1. **Model**: field, tipe, relasi.
2. **Halaman**: susun komponen di grid 12 kolom, hubungkan ke model.
3. **Akses**: peran dikali aksi per model, aturan owner, `requireAmr`.
4. **Hooks**: hubungkan event ke metode di `extensions/` (dipilih dari daftar kelas yang ada).
5. **Pratinjau**: data contoh dibuat otomatis dari tipe field.
6. **Autentikasi**: pilih driver dan atur BikininSSO (tanpa rahasia; `client_secret` tidak disimpan di definisi).
Halaman dan grup menu diatur di panel halaman; grup "Admin" dicadangkan.

## Langkah dasar
1. Buka `http://localhost:8000/_builder` (lokal).
2. Buat model, tambahkan field, atur akses.
3. Buat halaman, tarik komponen ke grid, pilih model sumber.
4. Tekan simpan. File JSON ditulis rapi dan deterministik (menyimpan data yang sama menghasilkan berkas yang sama persis), sehingga mudah di-review lewat diff Git.

## Konflik edit (409)
Sebelum menyimpan, builder membandingkan hash berkas. Bila berkas diubah di luar builder (mis. Anda mengedit manual), simpan **tidak menimpa** dan builder menampilkan perbedaan (kode 409). Muat ulang atau gabungkan perubahan, lalu simpan lagi.

## Perubahan destruktif
Menghapus field atau mengganti tipe menampilkan **pratinjau migrasi** (SQL yang akan berjalan) dan **peringatan kehilangan data**. Anda harus mengonfirmasi sebelum berkas disimpan. Baca peringatan dengan teliti: data di kolom yang dihapus tidak bisa dikembalikan.

## Pemeriksaan hook
Builder memindai file hook dan menolak penggunaan fungsi berbahaya (mis. `exec`, `system`, `eval`). Ini lapisan bantuan, bukan jaminan; tinjau sendiri kode di `extensions/`.

## Tes koneksi SSO
Di panel Autentikasi, tombol "Tes koneksi" memeriksa dokumen discovery dan JWKS issuer (issuer harus persis cocok dan memakai HTTPS). Pesan error menyebutkan penyebabnya (mis. issuer berbeda). Alamat yang didaftarkan ke admin SSO ditampilkan di panel yang sama: `/auth/sso/callback`, `/auth/sso/signed-out`, `/auth/sso/backchannel`. Lihat [sso.md](sso.md).

## `unsafeBuilderInProduction` (tidak disarankan)
Opsi ini memaksa builder aktif di produksi. Menambah permukaan serangan: siapa pun yang berhasil menembus gerbang dapat mengubah definisi aplikasi. Bila terpaksa, **ketiganya wajib**:
```php
'builder' => [
    'unsafeBuilderInProduction' => true,
    'allowedIps' => ['203.0.113.7'],             // IP dummy
    'passwordHash' => '<hasil password_hash() Argon2id>',
],
```
Builder lalu meminta login terpisah (password builder), hanya menerima IP di daftar, dan mencatat audit. Hash juga boleh lewat variabel lingkungan `BUILDER_PASSWORD_HASH`. Bila salah satu kosong, builder tetap 404. Matikan kembali setelah selesai.

## Batasan
- Hanya 7 komponen bawaan (komponen kustom belum didukung).
- Setelah menyimpan di produksi (mode terpaksa), ada jeda singkat sampai tabel baru dibuat; hindari mengubah skema saat trafik tinggi.
- Fitur seperti command palette, undo/redo: berstatus "sebaiknya" (BLD-10) dan tidak dijamin ada; periksa di UI.
