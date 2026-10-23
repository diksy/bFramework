# Desain Framework PHP Ramah Shared Hosting

Oct 24, 2026 · @Diksy M. Firmansyah

## Ringkasan dan keputusan kunci

Kita membangun framework PHP yang berjalan penuh di shared hosting murah, dengan builder visual yang mempercepat developer. Urutan prioritasnya: keamanan, performa, lalu kemudahan.

Target utama adalah developer yang ingin cepat: freelancer, agensi kecil, dan tim internal yang membangun aplikasi CRUD untuk UMKM. Pengguna non-developer bukan target utama.

| Keputusan | Pilihan | Alasan |
| --- | --- | --- |
| Target pengguna | Developer yang ingin cepat | Builder menjadi akselerator, bukan pengganti coding |
| Model eksekusi | Aplikasi berjalan di atas runtime framework | Tidak ada code generation PHP; definisi diterjemahkan runtime |
| Sumber kebenaran | File definisi JSON di folder proyek | Bisa di-commit ke Git dan di-review lewat diff |
| Versi PHP | 8.1 ke atas | Enum, readonly property, first-class callable |
| Database | MySQL/MariaDB dan SQLite | MySQL standar di cPanel; SQLite untuk lokal dan aplikasi kecil |
| Builder | Hanya development, nonaktif di produksi | Mengurangi permukaan serangan |
| Autentikasi | Bawaan framework, BikininSSO opsional | Peran dan hak akses selalu dikelola framework |
| Instalasi | Upload zip via FTP + installer web | Shared hosting sering tanpa SSH dan Composer |

## Cara membaca dokumen ini (untuk agen AI)

Setiap aturan normatif punya ID unik dan satu kriteria uji. Agen WAJIB merujuk ID tersebut di kode, pesan commit, dan nama test.

- **WAJIB**: harus diimplementasikan. Pelanggaran dianggap bug dan memblokir rilis.
- **SEBAIKNYA**: diimplementasikan kecuali ada alasan tertulis di catatan keputusan.
- **Prefix ID**: `ARCH-` arsitektur, `SEC-` keamanan, `CACHE-` compile cache, `BLD-` builder, `AUTH-` autentikasi bawaan, `SSO-` integrasi BikininSSO.
- **Kriteria uji** ditulis sebagai perilaku yang bisa diamati. Setiap aturan WAJIB minimal punya satu test otomatis dengan ID aturan di namanya, misalnya `test_SEC_REQ_01_post_tanpa_token_ditolak`.
- **Default aman**: bila dokumen ini tidak mengatur suatu hal, pilih opsi yang paling ketat, lalu catat sebagai pertanyaan terbuka.
- **Dilarang** menambah dependensi yang membutuhkan Composer di server, ekstensi PHP non-standar, atau proses yang berjalan lama.

Ekstensi PHP yang boleh diasumsikan ada: `pdo_mysql`, `pdo_sqlite`, `openssl`, `sodium`, `mbstring`, `json`, `fileinfo`. Ekstensi `curl` diasumsikan *mungkin* ada, sehingga selalu butuh fallback.

## Arsitektur

Framework terdiri dari tiga lapisan: Core, Runtime, dan Builder. Setiap lapisan bisa dipakai tanpa lapisan di atasnya, sehingga developer yang tidak memakai builder tetap mendapat micro-framework yang utuh.

### Batasan shared hosting yang menjadi asumsi desain

- Tidak ada SSH dan Composer; instalasi lewat upload zip dan installer web.
- Tidak ada proses yang berjalan lama (Swoole, RoadRunner, worker antrean). Pekerjaan latar memakai cron cPanel bila ada, atau pseudo-cron yang berjalan saat ada request.
- Docroot sering terkunci di `public_html`. OPcache tidak bisa dikonfigurasi, dan `opcache_invalidate` bisa diblokir.
- `memory_limit` sering 128 MB, kuota disk kecil, dan `/tmp` bisa dipakai bersama akun lain.

### Struktur folder

```
proyek/
├── public_html/      ← satu-satunya yang terekspos
│   ├── index.php
│   ├── .htaccess
│   └── assets/
└── app/              ← di luar docroot
    ├── definitions/  ← hasil builder (JSON), sumber kebenaran
    ├── extensions/   ← hooks, action, komponen, data provider (PHP)
    ├── storage/      ← cache, log, sesi, SQLite, upload
    ├── config/       ← config.php, di luar docroot
    └── core/         ← kode framework
```

### Contoh definisi model

```json
{
  "model": "produk",
  "fields": {
    "nama":  { "type": "string", "max": 100, "required": true },
    "harga": { "type": "decimal", "min": 0 },
    "stok":  { "type": "integer", "default": 0 }
  },
  "hooks": { "beforeSave": "ProdukHooks::validasiStok" },
  "access": { "read": "*", "write": ["admin"] }
}
```

Dari satu file ini runtime menurunkan tabel, migrasi, validasi, form, daftar data, dan izin akses.

### Aturan arsitektur

| ID | Aturan | Kriteria uji |
| --- | --- | --- |
| ARCH-01 | WAJIB: hanya `index.php` dan `assets/` yang berada di docroot. | Request ke path apa pun di `app/` mengembalikan 403 atau 404. |
| ARCH-02 | WAJIB: bila hosting tidak mengizinkan folder di luar docroot, installer beralih ke mode cadangan: `app/` di dalam docroot, dikunci `.htaccess` deny-all, dan setiap file PHP mengecek konstanta `APP_BOOTED`. | Akses langsung ke file PHP di `app/` mengembalikan 403 dan tidak mengeksekusi kode. |
| ARCH-03 | WAJIB: Core tidak bergantung pada Runtime, dan Runtime tidak bergantung pada Builder. | Test arsitektur gagal bila ada `use` dari lapisan bawah ke lapisan atas. |
| ARCH-04 | WAJIB: tipe field dibatasi ke irisan yang didukung MySQL dan SQLite: string, text, integer, decimal, boolean, date, datetime, json, relasi. | Definisi dengan tipe di luar daftar gagal di tahap compile. |
| ARCH-05 | WAJIB: schema builder berbasis PDO dengan dua grammar (MySQL, SQLite). Migrasi SQLite yang mengubah kolom memakai pola rebuild table (buat baru, salin, ganti nama). | Mengubah tipe kolom di SQLite berhasil tanpa kehilangan data. |
| ARCH-06 | WAJIB: HTTP client memakai cURL dengan fallback stream wrapper; verifikasi TLS selalu aktif. | Dengan cURL dinonaktifkan, request HTTPS tetap berhasil; sertifikat tidak valid ditolak. |
| ARCH-07 | SEBAIKNYA: bootstrap minimal dan semua modul dimuat lazy. | Request ke halaman statis memuat kurang dari 2 MB memori. |
| ARCH-08 | WAJIB: framework rilis sebagai satu zip berisi semua dependensi (vendored). | Instalasi di server tanpa Composer berhasil dari zip saja. |

## Lapisan keamanan

Semua proteksi aktif tanpa konfigurasi, dan mematikannya harus eksplisit lewat opsi bernama `unsafe*`. Tanpa aturan akses berarti akses ditolak. Definisi JSON diperlakukan sebagai input yang divalidasi; kode di `extensions/` dianggap kode tepercaya.

### Perimeter dan request

| ID | Aturan | Kriteria uji |
| --- | --- | --- |
| SEC-PER-01 | WAJIB: `.htaccess` mengarahkan semua request ke `index.php` dan memblokir dotfile, `.json`, `.sqlite`, `.log`. | GET `/.env`, `/x.json`, `/x.sqlite` mengembalikan 403. |
| SEC-PER-02 | WAJIB: eksekusi PHP dimatikan di `assets/` dan folder upload. | File `.php` yang diletakkan di `assets/` tidak dieksekusi. |
| SEC-PER-03 | WAJIB: header `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options` selalu dikirim; HSTS bila HTTPS aktif. | Setiap respons memuat header tersebut. |
| SEC-REQ-01 | WAJIB: CSRF token per sesi untuk semua method selain GET/HEAD; cookie `SameSite=Lax`. | POST tanpa token atau dengan token salah mengembalikan 419. |
| SEC-REQ-02 | WAJIB: rate limit berbasis SQLite atau file untuk login, reset password, dan form publik. | Percobaan login gagal ke-6 dalam 15 menit mengembalikan 429. |
| SEC-REQ-03 | WAJIB: header `Host` divalidasi terhadap whitelist di config. | Request dengan `Host` di luar whitelist mengembalikan 400; link reset tidak memakai host tersebut. |

### Sesi dan otorisasi

| ID | Aturan | Kriteria uji |
| --- | --- | --- |
| SEC-SESS-01 | WAJIB: file sesi disimpan di `app/storage/sessions`, tidak di `/tmp`, karena `/tmp` sering dipakai bersama akun lain. | `session_save_path()` menunjuk ke folder storage aplikasi. |
| SEC-SESS-02 | WAJIB: ID sesi diregenerasi saat login dan saat hak akses naik. | ID sesi sebelum dan sesudah login berbeda. |
| SEC-SESS-03 | WAJIB: cookie sesi `HttpOnly`, `Secure` (bila HTTPS), prefix `__Host-` bila memungkinkan. | Header `Set-Cookie` memuat atribut tersebut. |
| SEC-AUTHZ-01 | WAJIB: aturan `access` ditegakkan di lapisan query runtime, bukan hanya di UI. | Request langsung ke endpoint tanpa hak akses mengembalikan 403 meski tombolnya tersembunyi. |
| SEC-AUTHZ-02 | WAJIB: aturan tingkat baris (`"owner": "user_id"`) diterapkan ke semua query baca, ubah, dan hapus. | User A tidak bisa membaca atau mengubah baris milik user B lewat ID langsung. |

### Data dan output

| ID | Aturan | Kriteria uji |
| --- | --- | --- |
| SEC-DATA-01 | WAJIB: hanya prepared statement; nama tabel dan kolom hanya dari definisi hasil compile. | Parameter sort atau filter dengan nama kolom di luar definisi ditolak. |
| SEC-DATA-02 | WAJIB: proteksi mass assignment; hanya field di definisi yang bisa diisi, field `"guarded": true` tidak pernah dari input. | POST yang menyertakan `role=admin` tidak mengubah kolom guarded. |
| SEC-OUT-01 | WAJIB: template auto-escape sesuai konteks (HTML, atribut, JS, URL); output mentah harus eksplisit `{!! !!}`. | Payload `<script>` di field teks tampil sebagai teks. |
| SEC-OUT-02 | WAJIB: CSP dengan nonce; komponen builder tidak memakai inline event handler. | Respons memuat CSP dengan nonce; HTML komponen tidak berisi atribut `on*`. |

### File, rahasia, dan integritas

| ID | Aturan | Kriteria uji |
| --- | --- | --- |
| SEC-FILE-01 | WAJIB: upload disimpan di luar docroot dengan nama acak, disajikan lewat controller yang mengecek hak akses. | URL upload langsung tidak bisa diakses tanpa sesi yang berhak. |
| SEC-FILE-02 | WAJIB: tipe file dicek dengan `finfo`, whitelist dan batas ukuran; SVG ditolak secara default. | File PHP berekstensi `.jpg` ditolak; SVG ditolak. |
| SEC-CONF-01 | WAJIB: installer membuat `APP_KEY` acak 32 byte; config berada di luar docroot. | Dua instalasi menghasilkan `APP_KEY` berbeda. |
| SEC-CONF-02 | SEBAIKNYA: installer memeriksa permission (640 file, 750 folder) dan memperingatkan folder yang bisa ditulis semua orang. | Folder 777 memunculkan peringatan di installer. |
| SEC-BLD-01 | WAJIB: builder nonaktif di produksi; bila diaktifkan butuh autentikasi terpisah, whitelist IP, dan audit log. | `/_builder` mengembalikan 404 pada mode produksi default. |
| SEC-UPD-01 | WAJIB: paket update ditandatangani Ed25519 (`sodium`); public key ditanam di core. | Paket dengan tanda tangan salah ditolak tanpa mengubah file. |
| SEC-UPD-02 | SEBAIKNYA: manifest hash file core untuk mendeteksi modifikasi. | File core yang diubah terdeteksi di halaman status. |
| SEC-LOG-01 | WAJIB: mode produksi mematikan `display_errors`, menampilkan halaman error generik, dan mencatat detail ke `storage/logs` dengan rotasi ukuran. | Exception di produksi tidak menampilkan stack trace; file log tidak melebihi batas ukuran. |
| SEC-LOG-02 | WAJIB: token, password, secret, dan kode otorisasi tidak pernah masuk log. | Pencarian pola token di log setelah alur login tidak menemukan apa pun. |

## Compile cache

Di produksi tidak ada parsing JSON sama sekali: semua definisi di-compile menjadi file PHP berisi array yang bisa di-cache OPcache.

### Pipeline

1. **Load**: baca semua file di `definitions/`.
2. **Validate**: cek dengan JSON Schema; satu error menggagalkan seluruh compile.
3. **Resolve**: sambungkan relasi, isi default, pastikan class hook ada.
4. **Optimize**: hitung di muka tabel route, template SQL per dialek, aturan validasi, aturan akses.
5. **Emit**: tulis `<?php return [...];` dengan `var_export`.
6. **Activate**: tulis ID versi baru ke file penunjuk `current` secara atomik.

### Hasil compile

```
storage/cache/
├── current            ← ID versi aktif (teks biasa)
└── v_a1b2c3/
    ├── manifest.php   ← versi, hash sumber, waktu build
    ├── routes.php     ← route statis + regex dinamis berkelompok
    ├── access.php
    ├── models/produk.php
    ├── sql/mysql/produk.php
    ├── sql/sqlite/produk.php
    └── views/…        ← template hasil compile
```

### Aturan compile cache

| ID | Aturan | Kriteria uji |
| --- | --- | --- |
| CACHE-01 | WAJIB: satu file cache per model, dimuat lazy; tidak ada satu file raksasa. | Request yang hanya menyentuh model A tidak memuat file model B. |
| CACHE-02 | WAJIB: SQL hanya di-compile untuk dialek yang aktif di environment. | Build dengan driver MySQL tidak menghasilkan folder `sql/sqlite`. |
| CACHE-03 | WAJIB: setiap build ditulis ke folder versi baru `v_<hash>`; file lama tidak pernah ditimpa. | Dua build dengan definisi berbeda menghasilkan dua folder berbeda. |
| CACHE-04 | WAJIB: file `current` dibaca dengan `file_get_contents`, bukan `include`, agar tidak di-cache OPcache. | Mengganti isi `current` langsung berlaku di request berikutnya dengan OPcache aktif. |
| CACHE-05 | WAJIB: semua penulisan memakai file temp lalu `rename()`; versi lama dihapus setelah dua build berikutnya. | Request paralel selama build tidak pernah membaca file setengah tertulis. |
| CACHE-06 | WAJIB: mode produksi tidak pernah memeriksa file sumber; cache hanya berubah lewat Build atau paket deploy. | Mengubah file di `definitions/` di produksi tidak mengubah perilaku sampai Build dijalankan. |
| CACHE-07 | WAJIB: rebuild di server dikunci dengan `flock`. | Dua permintaan build bersamaan hanya menghasilkan satu build. |
| CACHE-08 | WAJIB: hanya array dan skalar yang di-emit; objek dilarang karena menghasilkan `__set_state`. | Compiler melempar error bila menerima objek. |
| CACHE-09 | WAJIB: setiap file cache diawali pengecekan konstanta `APP_BOOTED`. | Include langsung file cache tanpa bootstrap tidak mengembalikan data. |
| CACHE-10 | WAJIB: setiap elemen hasil compile menyimpan peta sumber `_src`, misalnya `produk.json#/fields/harga`. | Error validasi runtime menampilkan path definisi sumbernya. |
| CACHE-11 | WAJIB: kredensial dan secret tidak pernah ikut di-compile ke cache. | Pencarian nilai `DB_PASSWORD` di folder cache tidak menemukan apa pun. |

Di mode development, setiap request membandingkan `filemtime` file definisi dengan manifest dan compile ulang otomatis bila berubah.

### Cache halaman HTML

Lapisan terpisah untuk halaman publik: HTML statis disajikan langsung oleh `.htaccess` tanpa menyentuh PHP. Invalidasi berbasis tag model.

| ID | Aturan | Kriteria uji |
| --- | --- | --- |
| CACHE-12 | SEBAIKNYA: halaman publik yang ditandai `cache: true` di-cache sebagai HTML statis. | Request kedua ke halaman tersebut tidak menjalankan PHP. |
| CACHE-13 | WAJIB: menyimpan data sebuah model menghapus semua halaman cache bertag model itu. | Setelah produk diubah, halaman daftar produk menampilkan data baru. |
| CACHE-14 | WAJIB: halaman yang membutuhkan login tidak pernah di-cache sebagai HTML statis. | Definisi halaman dengan `access` selain `*` dan `cache: true` gagal di compile. |

## UI builder

Builder adalah alat developer yang berjalan di lokal, hanya menulis file definisi, dan tidak pernah menulis kode PHP. Builder memanggil kode developer lewat titik ekstensi, bukan menggantikannya.

### Panel

1. **Model designer**: field, tipe, relasi, dan diagram ERD.
2. **Page designer**: grid 12 kolom, komponen dari palet (tabel, form, kartu, grafik, teks) yang di-bind ke model.
3. **Access designer**: matriks peran × model × aksi, aturan tingkat baris, dan `requireAmr`.
4. **Actions & hooks**: event dihubungkan ke method di `extensions/`, dipilih dari daftar hasil Reflection.
5. **Live preview**: SQLite dengan data contoh yang dibuat dari tipe field.
6. **Autentikasi**: pilihan driver dan konfigurasi BikininSSO (lihat bagian Autentikasi).

### Contoh definisi halaman

```json
{
  "page": "daftar-produk",
  "route": "/produk",
  "access": ["admin", "staf"],
  "layout": [
    { "component": "table", "span": 12,
      "source": { "model": "produk", "sort": "-stok", "perPage": 20 },
      "columns": ["nama", "harga", "stok"],
      "actions": ["edit", "hapus"] }
  ]
}
```

### Titik ekstensi

- **Hooks**: `beforeSave`, `afterCreate`, `beforeDelete`, dan seterusnya, dirujuk berdasarkan nama ke class PHP.
- **Custom action**: tombol di UI yang memanggil method PHP.
- **Custom component**: manifest props + renderer PHP + JS opsional, muncul di palet builder.
- **Data provider**: query kompleks yang ditulis di PHP, tetap melalui aturan akses runtime.

### Aturan builder

| ID | Aturan | Kriteria uji |
| --- | --- | --- |
| BLD-01 | WAJIB: builder adalah aplikasi di atas runtime framework sendiri, diakses di `/_builder`. | Builder berjalan tanpa dependensi di luar framework. |
| BLD-02 | WAJIB: frontend builder dikirim sebagai bundle JS jadi; pengguna tidak perlu Node.js. | Builder berjalan di instalasi baru tanpa langkah build frontend. |
| BLD-03 | WAJIB: output JSON deterministik (urutan key stabil, format rapi). | Menyimpan definisi yang tidak berubah menghasilkan file identik byte per byte. |
| BLD-04 | WAJIB: builder memantau perubahan file dan memuat ulang bila file diedit manual. | Edit manual pada JSON muncul di UI dalam 3 detik. |
| BLD-05 | WAJIB: sebelum menyimpan, builder membandingkan hash file; bila berubah di luar builder, tampilkan diff dan jangan menimpa. | Simpan setelah edit eksternal memunculkan dialog konflik. |
| BLD-06 | WAJIB: panel properti komponen dibuat otomatis dari skema props di manifest. | Komponen kustom baru tampil dengan panel properti tanpa kode UI tambahan. |
| BLD-07 | WAJIB: sumber data hanya deklarasi (model, filter, urutan); tidak ada SQL mentah di builder. | Skema definisi menolak field berisi SQL. |
| BLD-08 | WAJIB: perubahan destruktif (hapus field, ganti tipe) menampilkan pratinjau migrasi dan peringatan kehilangan data. | Menghapus field memunculkan pratinjau sebelum file disimpan. |
| BLD-09 | WAJIB: builder tidak pernah menulis file `.php`. | Test memverifikasi builder hanya menulis ke `definitions/`. |
| BLD-10 | SEBAIKNYA: command palette, shortcut keyboard, undo/redo, dan tombol "lihat JSON" di setiap panel. | Fitur tersedia di rilis pertama builder. |

## Autentikasi

Pengguna framework memilih satu driver: `local` (bawaan), `bikinin_sso`, atau `hybrid`. Driver hanya menjawab "siapa user ini"; peran dan hak akses selalu dikelola framework.

### Driver bawaan dan kontrak bersama

| ID | Aturan | Kriteria uji |
| --- | --- | --- |
| AUTH-01 | WAJIB: semua driver mengimplementasikan interface `AuthDriver` yang sama; runtime, hooks, dan builder tidak tahu driver mana yang aktif. | Test suite akses berjalan identik dengan driver `local` dan `bikinin_sso`. |
| AUTH-02 | WAJIB: penautan akun lokal ke SSO hanya terjadi bila user membuktikan kepemilikan akun lokal (memasukkan password lama). Setelah tertaut, pencocokan memakai `sub`. | Login SSO dengan email yang sama dengan akun lokal tidak otomatis masuk ke akun itu. |
| AUTH-03 | WAJIB: password di-hash dengan Argon2id, fallback bcrypt. | Kolom password berawalan `$argon2id$` atau `$2y$`. |
| AUTH-04 | WAJIB: "ingat saya" memakai token acak yang disimpan dalam bentuk hash di database. | Isi tabel token tidak sama dengan nilai cookie. |
| AUTH-05 | WAJIB: reset password dan verifikasi email memakai token sekali pakai berumur maksimal 60 menit. | Token yang sudah dipakai atau kedaluwarsa ditolak. |
| AUTH-06 | WAJIB: pengiriman email mendukung SMTP dengan fallback `mail()`. | Email reset terkirim dengan konfigurasi SMTP maupun tanpa SMTP. |
| AUTH-07 | SEBAIKNYA: modul TOTP 2FA untuk driver lokal, mengisi `amr` dengan `pwd` dan `otp`. | Peran dengan `requireAmr: ["otp"]` menolak sesi tanpa OTP. |
| AUTH-08 | WAJIB: registrasi publik bisa dimatikan lewat config dan mati secara default. | Instalasi baru tidak menampilkan halaman registrasi. |

### Integrasi opsional BikininSSO

BikininSSO adalah OIDC Provider dengan Authorization Code + PKCE S256, token RS256, dan back-channel logout. Domainnya berbeda per instalasi karena platformnya open source. Rujukan: [Panduan Integrasi BikininSSO](https://sso.bikinin.id/panduan-integrasi.md).

Konfigurasi minimal:

```php
'auth' => [
  'driver' => 'bikinin_sso',            // local | bikinin_sso | hybrid
  'sso' => [
    'issuer'        => 'https://sso.contoh.test',
    'client_id'     => 'app-contoh',
    'client_secret' => '...',           // di config, di luar docroot
    'provisioning'  => 'jit',           // jit | pre_registered
    'default_role'  => 'staf',
    'offline_access'=> false,
    'session_check_minutes' => 5,       // cadangan bila back-channel gagal
  ],
],
```

URL yang didaftarkan ke admin SSO (ditampilkan builder dengan tombol salin): callback login `/auth/sso/callback`, post-logout `/auth/sso/signed-out`, back-channel `/auth/sso/backchannel`.

| ID | Aturan | Kriteria uji |
| --- | --- | --- |
| SSO-01 | WAJIB: mode `hybrid` hanya mengizinkan login lokal untuk akun bertanda `break_glass`, lewat URL terpisah yang tidak ditautkan di halaman login. | Akun biasa tidak bisa login lokal di mode hybrid. |
| SSO-02 | WAJIB: framework mendaftar sebagai confidential client memakai `client_secret_basic`. | Request ke `/token` memakai header `Authorization: Basic`. |
| SSO-03 | WAJIB: semua endpoint diambil dari discovery document; tidak ada path yang di-hardcode. | Instance SSO dengan path non-standar tetap berfungsi. |
| SSO-04 | WAJIB: `issuer` di discovery dan claim `iss` cocok persis dengan config. | Discovery dengan `issuer` berbeda ditolak saat tes koneksi dan saat login. |
| SSO-05 | WAJIB: library JWT di-vendor ke paket rilis; tidak ada implementasi kriptografi buatan sendiri. | Verifikasi JWT berjalan tanpa Composer di server. |
| SSO-06 | WAJIB: `alg` selain RS256 ditolak, termasuk `none` dan `HS256`. | Token ber-`alg: HS256` atau `none` ditolak. |
| SSO-07 | WAJIB: discovery dan JWKS di-cache di `storage/` sesuai `Cache-Control`; fetch ulang karena `kid` tidak dikenal maksimal sekali per menit. | Seratus token dengan `kid` asing dalam satu menit hanya memicu satu fetch JWKS. |
| SSO-08 | WAJIB: setiap login memakai PKCE S256, `state`, dan `nonce` acak, dicek dengan `hash_equals`. | Callback dengan `state` salah mengembalikan 400. |
| SSO-09 | WAJIB: akun lokal dikaitkan lewat `sub` (kolom `sso_sub`), bukan email. | Perubahan email di SSO tidak membuat akun baru. |
| SSO-10 | WAJIB: provisioning bisa `jit` (akun dibuat otomatis dengan `default_role`) atau `pre_registered` (hanya `sub` terdaftar yang boleh masuk). | Mode `pre_registered` menolak `sub` yang belum terdaftar. |
| SSO-11 | WAJIB: `offline_access` tidak diminta kecuali diaktifkan di config. | Scope default di `/authorize` adalah `openid profile email`. |
| SSO-12 | WAJIB: refresh token dikunci per user dengan `flock`, karena rotasi BikininSSO mencabut seluruh sesi bila token lama dipakai ulang. | Dua request paralel yang sama-sama butuh refresh hanya mengirim satu request refresh. |
| SSO-13 | WAJIB: refresh token disimpan terenkripsi dengan `sodium_crypto_secretbox` memakai kunci turunan `APP_KEY`. | Nilai di database tidak sama dengan refresh token asli. |
| SSO-14 | WAJIB: logout menghapus sesi lokal lalu redirect ke endpoint logout SSO dengan `id_token_hint`. | Setelah logout, sesi lokal tidak ada dan browser diarahkan ke SSO. |
| SSO-15 | WAJIB: back-channel logout memverifikasi tanda tangan, `iss`, `aud`, `events`, tidak ada `nonce`, dan menolak `jti` yang sama dalam 2 menit. | Logout token tanpa claim `events` atau dengan `nonce` mengembalikan 400; replay `jti` ditolak. |
| SSO-16 | WAJIB: endpoint back-channel adalah satu-satunya pengecualian CSRF, ditulis eksplisit per route. | Route lain di `/auth/sso/*` tetap butuh token CSRF untuk POST. |
| SSO-17 | WAJIB: tabel pemetaan `sid` → sesi lokal; logout token menghapus semua sesi terkait dan membalas 204 dalam kurang dari 1 detik. | Setelah back-channel logout, request berikutnya dari sesi itu harus login ulang. |
| SSO-18 | SEBAIKNYA: verifikasi sesi berkala via `/introspect` setiap `session_check_minutes` sebagai cadangan bila back-channel diblokir WAF hosting. | Sesi yang dicabut di SSO berakhir di aplikasi dalam batas menit yang dikonfigurasi. |
| SSO-19 | WAJIB: bila driver bukan `bikinin_sso` atau `hybrid`, route `/auth/sso/*` tidak didaftarkan dan library JWT tidak dimuat. | Dengan driver `local`, `/auth/sso/callback` mengembalikan 404. |
| SSO-20 | WAJIB: error `invalid_grant` di callback menampilkan halaman ramah dengan tombol login ulang, tanpa retry otomatis. | Code kedaluwarsa menampilkan halaman login ulang, bukan stack trace. |
| SSO-21 | SEBAIKNYA: builder menyediakan tombol "Tes koneksi" yang memvalidasi discovery dan JWKS. | Issuer salah memunculkan pesan error yang spesifik. |

## Roadmap

Pengerjaan dibagi lima tahap berurutan, dan setiap tahap baru dianggap selesai bila gerbang ujinya lulus. Framework sudah berguna sejak tahap 3, sebelum builder visual ada.

&#91;embedded content: roadmap · 5 tahap, 5 gerbang uji\]

Agen tidak memulai tahap berikutnya sebelum gerbang tahap sebelumnya lulus. Pekerjaan riset atau prototipe untuk tahap selanjutnya boleh dilakukan di branch terpisah.

## Pertanyaan terbuka

Hal berikut belum diputuskan. Sampai ada keputusan, agen memakai default yang tertulis dan menandainya di catatan keputusan.

- [ ] **Nama framework dan namespace PHP.** Default sementara: namespace `App\Core`.
- [ ] **Lisensi framework.** Default: belum dirilis publik sampai diputuskan.
- [ ] **Dukungan server selain Apache.** LiteSpeed kompatibel dengan `.htaccess`; hosting khusus Nginx butuh contoh konfigurasi terpisah. Default: Apache dan LiteSpeed saja.
- [ ] **Matriks pengujian CI.** Usulan: PHP 8.1 sampai 8.4 × MySQL 8, MariaDB 10.6, SQLite 3, dengan uji akhir di minimal dua provider shared hosting lokal.
- [ ] **Daftar komponen bawaan builder versi pertama.** Usulan: tabel, form, kartu, statistik, grafik, teks, gambar.
- [ ] **Konvensi kode.** Usulan: PSR-12, `declare(strict_types=1)` di semua file, analisis statis PHPStan level 8.
- [ ] **Internasionalisasi.** Default: teks UI bawaan dalam Bahasa Indonesia dan Inggris lewat file terjemahan.
- [ ] **Spesifikasi detail API ekstensi** (signature hooks, action, data provider, manifest komponen) perlu dokumen tersendiri sebelum tahap 2 dimulai.

## Sumber

- [Panduan Integrasi BikininSSO](https://sso.bikinin.id/panduan-integrasi.md)
