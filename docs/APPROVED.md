<!-- maks 20 baris. Hanya ditulis lewat /approve -->
# Persetujuan Prototype

- Mode: hybrid
- Tanggal: 2026-10-24
- Fitur disetujui: F1–F16 (semua fitur di spec), dikerjakan mengikuti roadmap 5 tahap
- Batasan: Pertahankan + refactor: Builder (DefinitionWriter, HookScanner, builder.js); Runtime (ComponentRenderer + views komponen, Validator, Format, skema definisi JSON); Core (Router, Request, Response, Json); UI (app.css, sidebar.js, layout.php). Tulis ulang: Auth, AuthController, Session, UserStore, AdminController, InstallerController, simulasi SSO, Repository. Tidak dibawa ke src/: prototype/mocks/, prototype/app/storage/. Semua kode yang dipertahankan wajib memenuhi docs/rules.md (auto-escape, CSP nonce, tes ber-ID aturan). Tampilan & alur prototype = acuan UI.
