<!-- maks 130 baris. Pemilik: doc-writer. Dibaca: pengguna akhir -->
# Akun, Login, dan Keamanan Akun

Bagian ini berlaku untuk driver `local` (bawaan). Untuk SSO, lihat [sso.md](sso.md). Rujukan aturan: AUTH-01..08, SEC-SESS-*, SEC-REQ-02.

## Login
1. Buka `/login`, isi email dan password.
2. Bila akun memakai 2FA, masukkan kode 6 digit dari aplikasi autentikator (halaman `/auth/otp`).
3. Pesan gagal selalu sama ("Email atau password salah.") agar email tidak bisa ditebak.

## Kebijakan password
Panjang 10 sampai 128 karakter. Password umum yang mudah ditebak dan password yang memuat email Anda ditolak. Password disimpan dengan Argon2id (cadangan bcrypt).

## Ingat saya
Menyimpan sesi hingga `auth.remember_days` hari (bawaan 30) lewat token acak yang berputar tiap dipakai.
- Pemulihan sesi lewat "ingat saya" **tidak melewati OTP**: sesi hanya dianggap terbukti lewat cookie.
- Karena itu, **akses ke halaman admin tetap meminta password** (dan kode OTP bila akun ber-2FA), lihat bagian berikut.

## Verifikasi ulang (step-up) untuk halaman admin
Semua halaman `/admin/*` (termasuk `/admin/pengguna`, `/admin/peran`, `/admin/pembaruan`) hanya terbuka bila salah satu benar:
- Anda login lewat SSO; atau
- Anda login dengan password (dan OTP bila akun ber-2FA) pada sesi ini; atau
- Anda baru melakukan verifikasi ulang di `/auth/step-up` dalam **15 menit** terakhir.
Jendela 15 menit berlaku untuk membaca maupun mengubah. Admin yang masuk lewat "ingat saya" akan diminta password (+ kode OTP) sekali, lalu diarahkan kembali ke halaman tujuan.

## 2FA (TOTP)
1. Buka `/auth/2fa`.
2. Pilih aktifkan dan masukkan **password** Anda.
3. Pindai kode QR/secret dengan aplikasi autentikator, lalu masukkan kode 6 digit untuk konfirmasi.
4. Simpan **10 kode pemulihan** di tempat aman. Tiap kode sekali pakai.
5. Menonaktifkan 2FA membutuhkan password **dan** kode lama.

Setiap perubahan 2FA mengirim email pemberitahuan, mencabut "ingat saya", dan mengeluarkan sesi lain. 2FA membutuhkan `APP_KEY` minimal 32 karakter; bila kurang, fitur 2FA mati dan peringatan dicatat di log.

## Lupa password dan verifikasi email
- `/auth/forgot`: masukkan email. Respons selalu sama, ada atau tidak akunnya.
- Tautan reset `/auth/reset/<token>` sekali pakai dan berlaku maksimal 60 menit. Membukanya menampilkan form password baru.
- Setelah password diganti, semua tautan lain dan semua perangkat "ingat saya" dicabut.
- Tautan verifikasi email (`/auth/verify/<token>`) meminta konfirmasi lewat tombol, supaya pemindai tautan email tidak menghanguskannya. Form lupa password hanya bekerja untuk akun berstatus **aktif**.

## Registrasi publik
Mati secara default. Untuk mengaktifkan, set `'auth' => ['registration' => true]` di `config.php`; halaman `/auth/register` lalu tersedia (hanya driver `local`).
Password yang diketik saat mendaftar **tidak disimpan**. Akun dibuat berstatus *pending*; pemilik email menetapkan password lewat tautan yang dikirim ke emailnya. Akun pending yang tidak pernah dipakai dibersihkan setelah 7 hari (atau lewat tombol bersihkan di `/admin/pengguna`).

## Pengguna dan peran (admin)
Tersedia untuk peran `admin` di `/admin/pengguna` dan `/admin/peran`.
1. **Buat pengguna**: `/admin/pengguna/baru`. Pengguna menerima tautan untuk menetapkan password.
2. **Ubah peran/nama/email**: buka detail pengguna. Seorang pengguna boleh punya beberapa peran.
3. **Nonaktifkan**: ubah status. Penonaktifan **mencabut semua sesi** pengguna itu.
4. **Reset password**: tombol reset di detail pengguna mengirim tautan baru.
5. **Hapus**: tombol hapus. **Admin aktif terakhir tidak bisa dihapus atau dinonaktifkan.**
6. **Peran**: `/admin/peran` untuk membuat peran baru. Peran sistem `admin` dan `staf` tidak bisa dihapus.

### Ganti peran aktif
Pengguna multi-peran memakai satu peran aktif pada satu waktu; hak akses mengikuti peran aktif. Ganti lewat pemilih peran di menu. Berpindah ke peran lebih tinggi membuat ID sesi baru (SEC-SESS-02).

## Pembatasan percobaan (lockout dan rate limit)
- Per akun: 5 gagal dalam 15 menit, 10 dalam 1 jam, 20 dalam 24 jam, lalu dijawab **429** (dengan header `Retry-After`).
- Per IP: 30 percobaan per 15 menit dan 100 per 24 jam.
- Reset password, registrasi, dan form publik juga dibatasi.
- Batas ini berbasis berkas di `app/storage/ratelimit`; tunggu hingga jendela habis.

## Sesi dan cookie
Sesi disimpan di `app/storage/sessions`, cookie `HttpOnly`, `SameSite=Lax`, dan `Secure` bila HTTPS. Seluruh form POST memakai token CSRF; token kedaluwarsa menghasilkan 419 (lihat [pemecahan-masalah.md](pemecahan-masalah.md)).
