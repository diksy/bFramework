<!-- maks 120 baris. Pemilik: architect (ditulis builder M8). Dibaca: developer ekstensi, builder M9/M14 -->
# API Ekstensi dan Skema Definisi (M8)

Definisi JSON di `app/definitions/` di-compile (`Compiler::build`) menjadi cache PHP; runtime hanya membaca cache lewat `Definitions` (CACHE-06). Kunci yang tidak dikenal = error compile. Validasi tunggal: `bFramework\Runtime\DefinitionSchema` (dipakai ulang oleh DefinitionWriter M14).

## Model `definitions/models/<nama>.json`
Nama file = `model` = nama tabel, `^[a-z][a-z0-9_]{0,40}$`. Dicadangkan: users, roles, user_roles, remember_tokens, one_time_tokens, sso_sessions, migrations. Kolom `id` otomatis (jangan dideklarasikan).
- `fields.<nama>`: `type` (string, text, integer, decimal, boolean, date, datetime, json, relasi; ARCH-04), `label`, `required`, `unique`, `guarded` (dibuang dari input massal), `min`, `max` (string: panjang kolom 1..65535), `default` (sesuai tipe; text/json tidak boleh default/unique), `format` (`^[a-z_]{1,20}$`), `precision`/`scale` (decimal, default 12,2), `target` (wajib untuk relasi, model harus ada). Tanpa SQL mentah (BLD-07).
- `hooks`: event (beforeSave, afterSave, beforeCreate, afterCreate, beforeUpdate, afterUpdate, beforeDelete, afterDelete) => `"Kelas::method"`. File `extensions/<Kelas>.php` harus berisi `class Kelas` dan `public static function method(`; kalau tidak, compile gagal. Signature: `method(array $data): array` mengembalikan daftar pesan error (kosong = lolos). Kode ekstensi tidak pernah di-include saat compile.
- `access` (format yang dibaca `Authorizer`, M7): `read|create|update|delete|write` = `"*"` atau daftar peran; `owner` = nama field (integer/relasi) di model ini; `ownerExempt` = daftar peran; `requireAmr` = daftar amr atau `{aksi: [amr]}`. Tanpa aturan = tolak.

## Halaman `definitions/pages/<nama>.json`
`page` (= nama file, `^[a-z][a-z0-9_-]{0,40}$`), `route` (`/abc/def`; awalan admin, _builder, auth, login, logout, install, peran-aktif, assets, files, _pc dicadangkan; unik), `title`, `icon`, `group` ("Admin" dicadangkan), `order` (int), `access` (`"*"` atau daftar peran; kosong = tolak), `cache` (bool; `true` hanya jika `access` = `"*"`, CACHE-14), `layout` (daftar komponen: table, form, card, stat, chart, text, image; `span` 1..12; `columns`/`fields`/`field` harus ada di model sumber; `agg` count|sum|avg|min|max; `source` = `{model, filter{field:skalar}, sort "-field", perPage 1..100}`).
`auth.json` (opsional): `driver` local|bikinin_sso|hybrid + blok `sso` non-rahasia; `client_secret` ditolak (CACHE-11).

## Hasil compile (`storage/cache/`)
`current` (teks, dibaca `file_get_contents`), `v_<12 hex>/{manifest,routes,access,auth}.php`, `models/<n>.php`, `pages/<n>.php`, `sql/<dialek>/<n>.php`. Semua file memakai guard `APP_BOOTED`, hanya array/skalar. Setiap elemen punya `_src` (mis. `models/produk.json#/fields/harga`).
- Model ter-compile: `model, table, fields, columns (spesifikasi kolom), hooks{event:{ref,class,method,_src}}, access, _src`.
- `Definitions(CacheStore)`: `model(n)`, `page(n)`, `pages()`, `routes()` (baris untuk `Router::fromCompiled`; handler `bFramework\Runtime\PageController::{index,form,save,delete}`, `name` = `<halaman>.<aksi>`, kunci `page` memuat nama halaman), `access()` (`['models'=>..,'pages'=>..]`), `auth()`, `sql(n)`, `tables()` (TableSpec untuk Migrator), `allowlist()` (IdentifierAllowlist untuk Query; memuat semua model).
- Build: `Compiler(CacheStore, ?extDir)->build($defDir, Dialect)`; `isStale()` untuk mode development. Versi lama dibersihkan `CacheStore::gc()` (aktif + 2 terbaru).

## Field file (M12b, F9)
Definisi: `{"type":"string","upload":{"mimes":["image/png"],"maxBytes":1048576}}` (SVG/HTML/XML/skrip ditolak saat compile; tanpa `unique`/`default`/`min`/`max`; bukan kolom owner; tak bisa sort/filter/agregat). Kolom model hanya menyimpan fid (32 hex).
Alur dua langkah: `POST /files` (`file`, `model`, `field`, `_csrf`; login + hak Create/Update) mengembalikan JSON `{id,mime,size,name}`; fid dikirim bersama form dan di-claim atomik oleh `ModelRepository` (milik pengunggah, belum ter-attach). Ganti/kosongkan field atau hapus baris menghapus berkas. Hook tidak perlu menyentuh Upload; antarmuka Runtime: `Runtime\FileRefs`.
