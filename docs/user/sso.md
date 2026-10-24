<!-- maks 100 baris. Pemilik: doc-writer. Dibaca: pengguna akhir -->
# Integrasi BikininSSO

BikininSSO adalah penyedia login (OIDC Provider) dengan Authorization Code + PKCE S256 dan token RS256. Domainnya berbeda per instalasi. Panduan integrasi resmi: https://sso.bikinin.id/panduan-integrasi.md. Rujukan aturan: SSO-01..21.

Driver hanya menjawab "siapa pengguna ini". Peran dan hak akses tetap dikelola framework.

## Pilih mode (`auth.driver`)
| Mode | Perilaku |
| --- | --- |
| `local` (bawaan) | Login lokal. Rute `/auth/sso/*` tidak ada (404). |
| `bikinin_sso` | Semua login lewat SSO. Sesi lokal biasa dan "ingat saya" ditolak. |
| `hybrid` | Login lewat SSO; login lokal hanya untuk akun bertanda `break_glass` lewat URL terpisah yang tidak ditautkan (bawaan `/auth/break-glass`). |

## Langkah menghubungkan
1. Daftarkan aplikasi Anda ke admin BikininSSO sebagai *confidential client*. Daftarkan tiga alamat (ada tombol salin di panel Autentikasi builder), contoh untuk `https://example.com`:
   - callback login: `https://example.com/auth/sso/callback`
   - setelah logout: `https://example.com/auth/sso/signed-out`
   - back-channel logout: `https://example.com/auth/sso/backchannel`
2. Isi pengaturan non-rahasia lewat builder (disimpan di `definitions/auth.json`) atau di `config.php`:
```php
'auth' => ['driver' => 'hybrid', 'sso' => [
    'issuer' => 'https://sso.example.test',
    'client_id' => 'app-contoh',
    'provisioning' => 'jit',
    'default_role' => 'staf',
]],
```
3. Isi `client_secret` **hanya** di `config.php` (`auth.sso.client_secret`) atau variabel lingkungan `SSO_CLIENT_SECRET`. Builder menolak menyimpannya di definisi.
4. Di builder (mode dev) tekan "Tes koneksi" untuk memeriksa discovery dan JWKS.
5. Uji login di jendela privat. Pastikan akun darurat (lihat di bawah) siap **sebelum** mengaktifkan mode `bikinin_sso`.

`issuer` harus HTTPS dan persis sama dengan yang diumumkan server SSO. Endpoint diambil dari discovery document, tidak ditulis manual.

## Provisioning pengguna
- `jit`: akun dibuat otomatis dengan `default_role` pada login pertama. **Hanya bila SSO menyatakan `email_verified` bernilai true**; selain itu ditolak.
- `pre_registered`: hanya pengguna yang sudah didaftarkan admin (`sub` terdaftar) yang boleh masuk.
Akun dicocokkan lewat `sub`, bukan email, sehingga mengganti email di SSO tidak membuat akun baru. Menautkan akun lokal lama ke SSO butuh bukti kepemilikan (password lokal lama); login SSO dengan email yang sama tidak otomatis masuk ke akun lokal.

## Akun darurat (`break_glass`) pada mode hybrid
Akun bertanda `break_glass` bisa login lokal di URL darurat bila SSO bermasalah. **Saat ini belum ada antarmuka (UI) untuk menandai akun**. Kolom `break_glass` hanya dapat diubah lewat kode (`DbUserStore::update`) atau langsung di database oleh Anda. Rencanakan hal ini sebelum memakai hybrid. Halaman darurat tidak menyediakan "ingat saya", lupa password, atau registrasi.

## Logout dan back-channel logout
Logout menghapus sesi lokal lalu mengarahkan ke SSO. Saat pengguna logout di SSO, server SSO memanggil `/auth/sso/backchannel` dan semua sesi lokal terkait dicabut. Endpoint ini memverifikasi tanda tangan dan klaim token, serta menolak token yang diulang.
- Dibatasi 30 permintaan per 60 detik per IP (bawaan). Di balik proxy/CDN semua klien berbagi satu IP proxy; naikkan `auth.sso.backchannel_rate`, mis. `[300, 60]` (lihat [konfigurasi.md](konfigurasi.md)).
- Bila WAF hosting memblokir back-channel, sesi tetap berakhir lewat pemeriksaan berkala setiap `session_check_minutes` (bawaan 5 menit).

## offline_access
Bawaan mati; scope yang diminta hanya `openid profile email`. Aktifkan `offline_access` hanya bila aplikasi perlu bertindak atas nama pengguna saat mereka offline. Refresh token disimpan terenkripsi (kunci diturunkan dari `APP_KEY`; jangan ganti `APP_KEY` setelah dipakai).

## Admin dan SSO
Pengguna yang masuk lewat SSO langsung memenuhi syarat step-up halaman admin, jadi keamanan akun admin bergantung pada pengaturan SSO Anda (mis. 2FA di sisi SSO).
