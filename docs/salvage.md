<!-- maks 60 baris. Pemilik: architect. Dibaca: orchestrator, builder (baris modulnya saja), reviewer -->
# Audit Salvage `prototype/` → `src/` (mode hybrid)

Patokan: batasan `APPROVED.md`. File yang tidak disebut di sana diputuskan architect (default aman: tulis ulang). Semua yang dibawa wajib lolos `rules.md` (auto-escape, CSP nonce, tes ber-ID aturan). Tampilan & alur prototype = acuan UI.
Keputusan: **P+R** = pertahankan + refactor · **TU** = tulis ulang (tampilan prototype boleh jadi acuan) · **B** = buang.

| File / folder `prototype/` | Keputusan | Modul | Alasan / refactor wajib |
| --- | --- | --- | --- |
| `app/core/Core/Router.php` | P+R | M1 | Pindahkan CSRF & `View::error` ke middleware/HttpException; `RouteOpts`; HEAD; `fromCompiled()` |
| `app/core/Core/Request.php` | P+R | M1 | Tambah `files`, `isHttps`, `remoteAddr`; jangan percaya header proxy |
| `app/core/Core/Response.php` | P+R | M1/M2 | CSP hardcode → `SecurityHeaders` + nonce; HSTS; `withCookie` |
| `app/core/Core/Json.php` | P+R | M1 | Pastikan deterministik (BLD-03) + `JSON_THROW_ON_ERROR` |
| `app/core/Core/Csrf.php` | TU | M2 | Bergantung pada `Session` statis yang ditulis ulang; pakai `SessionStore` |
| `app/core/Core/Session.php` | TU | M7 | Batasan APPROVED (sesi) |
| `app/core/Core/View.php` | TU | M4 | Diganti `Template` auto-escape kontekstual; `extract()`+`include` mentah tidak memenuhi SEC-OUT-01 |
| `app/core/Core/views/layout.php` | P+R | M4 | Konversi ke sintaks template; `$content` → `SafeHtml`; `<script nonce>`; footer "data dummy" dihapus |
| `app/core/Core/views/error.php` | P+R | M5 | Konversi ke template; pesan generik |
| `app/core/Runtime/ComponentRenderer.php` | P+R | M9 | Kembalikan `SafeHtml` via template, bukan konkatenasi string; pakai `ModelRepository` + `Authorizer` |
| `app/core/Runtime/views/{table,form,page}.php` | P+R | M9 | Konversi ke template; tanpa `on*` |
| `app/core/Runtime/Validator.php` | P+R | M9 | Tambah `datetime`, `json`, `guarded`; `decimal` sebagai numeric-string (bukan float) |
| `app/core/Runtime/Format.php` | P+R | M9 | Tambah tes; format angka/tanggal id-ID |
| `app/core/Runtime/HookRunner.php` | P+R | M9 | Hook tidak ditemukan harus gagal di compile (Resolve), bukan diabaikan diam-diam |
| `app/core/Runtime/Definitions.php` | TU | M8 | Diganti `Definitions(CacheStore)` dari hasil compile; produksi tidak membaca JSON (CACHE-06) |
| `app/core/Runtime/Access.php` | TU | M7 | Hanya cek UI; harus jadi `Authorizer::can/scope` di lapisan query (SEC-AUTHZ-01/02), `requireAmr` |
| `app/core/Runtime/Database.php` | TU | M3 | SQLite saja; butuh dua dialek |
| `app/core/Runtime/Repository.php` | TU | M3/M9 | Batasan APPROVED; schema otomatis di request, SQLite-only, tanpa row scope |
| `app/core/Runtime/Mocks.php` | B | – | Seed data dummy, tidak boleh di `src/` |
| `app/core/Runtime/Routes.php` | TU | M1/M8 | Rute diturunkan dari `routes.php` hasil compile |
| `app/core/Runtime/PageController.php` | TU | M9 | Bergantung pada `Auth`/`Repository`/`Access` yang ditulis ulang |
| `app/core/Runtime/Auth.php`, `AuthController.php` | TU | M10 | Batasan APPROVED (auth) |
| `app/core/Runtime/UserStore.php`, `AdminController.php` | TU | M11 | Batasan APPROVED (data pribadi) |
| `app/core/Runtime/views/{login,admin_*}.php` | TU | M10/M11 | Modul auth & data pribadi; tampilan jadi acuan |
| `app/core/Runtime/InstallerController.php`, `views/installer.php` | TU | M13 | Batasan APPROVED; menyentuh rahasia & config |
| `app/core/Runtime/views/sso.php` | TU | M15 | Simulasi SSO dibuang (menyimpang dari SSO-01) |
| `app/core/Builder/DefinitionWriter.php` | P+R | M14 | Hash sha256 + konflik BLD-05; nama tmp unik; `guarded`, `cache`; validasi dipindah/dibagi dengan Compiler M8 |
| `app/core/Builder/HookScanner.php` | P+R | M14 | Batasi ke realpath `extensions/`; jangan `require` di produksi |
| `app/core/Builder/Sampler.php` | P+R | M14 | Hanya untuk live preview SQLite terpisah |
| `app/core/Builder/BuilderController.php`, `Routes.php` | TU | M14 | Butuh `BuilderGate` (SEC-BLD-01), audit log, auth terpisah; bergantung pada simulasi auth |
| `app/core/Builder/views/builder.php` | P+R | M14 | Konversi ke template + nonce; tata letak = acuan |
| `public_html/assets/app.css`, `sidebar.js` | P+R | M4 | Pertahankan; pastikan tanpa inline style/script |
| `public_html/assets/builder.js` | P+R | M14 | Kirim CSRF header; dialog konflik; polling BLD-04; hindari `innerHTML` untuk data |
| `public_html/assets/app.js` | P+R | M9 | Audit sesuai CSP |
| `public_html/index.php` | TU | M1 | Bootstrap minimal via `app/bootstrap.php`; hapus `MOCKS_PATH` dan router `php -S` dari produksi |
| `public_html/.htaccess`, `app/.htaccess` | P+R | M2 | Tambah blok `.json/.sqlite/.log`, PHP mati di `assets/`, header SEC-PER-03 |
| `app/config/config.php` | TU | M13 | Jadi `config.example.php` tanpa nilai rahasia |
| `app/definitions/**/*.json` | P+R | M8/M9 | Jadi fixture app "produk" (kriteria tahap 2) + tes skema |
| `app/extensions/*Hooks.php` | P+R | M9 | Contoh ekstensi, ikut kontrak `docs/api-ekstensi.md` |
| `prototype/mocks/`, `app/storage/` (sesi, `app.sqlite`) | B | – | Batasan APPROVED; jangan di-commit (file sesi sudah ada di disk) |
