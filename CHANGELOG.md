# Changelog

Format mengikuti [Keep a Changelog](https://keepachangelog.com/) dan [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-25

Rilis publik pertama, berlisensi MIT.

### Ditambahkan
- Core (router, request/response, kernel), perimeter (CSRF, HostGuard, rate limit), database, template, errorlog, HTTP client, sesi & otorisasi.
- Autentikasi lokal (termasuk TOTP), manajemen user & peran, SSO OIDC (back-channel logout), upload file.
- Installer web dengan uji kanari, page cache, compile cache, runtime komponen, builder aplikasi.
- Updater bertanda tangan Ed25519 dan CLI admin (`admin-reset`, compile).
- Dokumentasi pengguna di `docs/user/`.

### Keamanan
- Tidak ada temuan kritis, tinggi, atau sedang yang terbuka (lihat `docs/security-report.md`).

### Known issues (rendah/info)
- S12: migrasi update tanpa rollback DDL.
- S13: host MySQL installer bebas (butuh token); port probe SSO dari issuer.
- S14: lockout login per email; dapat dilewati dengan rotasi IPv6.
- S15: dry-run builder menulis ke direktori temp sistem.
- S18: belum ada `composer audit` di CI.
- S19: pola escape template rawan bila dipakai tidak sesuai.
- S22: batas laju log dapat menekan peristiwa keamanan tertentu.
