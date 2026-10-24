<?php

declare(strict_types=1);

namespace bFramework\Install;

defined('APP_BOOTED') || exit;

use bFramework\Auth\AccountStore;
use bFramework\Auth\AuthSchema;
use bFramework\Auth\AuthTables;
use bFramework\Auth\OneTimeToken;
use bFramework\Contracts\Clock;
use bFramework\Contracts\Logger;
use bFramework\Runtime\Connection;
use bFramework\Runtime\Migrator;
use bFramework\Runtime\Query;
use bFramework\Runtime\Where;
use bFramework\Upload\FilesTable;

/**
 * Installer (F14, instal): prasyarat, token pemilik, skema, admin pertama tanpa password, config, kunci.
 *
 * Keamanan: (1) install_token acak (CSPRNG) di storage/install_token (0600) harus diberikan pemilik;
 * (2) flock eksklusif serta installed.lock dibuat dengan mode "x" (tanpa TOCTOU); (3) sesudah terpasang
 * installer menjawab 404; (4) config ditulis atomik 0600 lewat var_export (nilai ter-escape, tanpa injeksi
 * PHP); (5) APP_KEY 48 byte CSPRNG, tidak pernah dikembalikan/dicatat; (6) admin pertama berstatus pending
 * tanpa password, hanya tautan reset sekali pakai (hash di DB) yang dikembalikan sekali; (7) tes koneksi DB
 * tidak membuka URL apa pun dan pesan galat generik.
 */
final class Installer
{
    public const TOKEN_FILE = 'install_token';
    public const LOCK_FILE = 'installed.lock';
    private const BUSY_FILE = 'install.busy';
    private const RESET_TTL = 3600;

    private readonly string $storage;
    private readonly string $configFile;

    public function __construct(
        private readonly string $appDir,
        private readonly string $docroot,
        private readonly Clock $clock,
        private readonly ?Logger $logger = null,
    ) {
        $this->storage = rtrim($appDir, '/\\') . '/storage';
        $this->configFile = rtrim($appDir, '/\\') . '/config/config.php';
    }

    public function isInstalled(): bool
    {
        return is_file($this->storage . '/' . self::LOCK_FILE);
    }

    /** Membuat install_token bila belum ada (tidak pernah dikembalikan/ditampilkan; pemilik membaca file-nya). */
    public function ensureToken(): void
    {
        if ($this->isInstalled() || is_file($this->tokenPath()) || !$this->ensureDir($this->storage)) {
            return;
        }
        // ARCH-02: di mode cadangan penjaga harus berfungsi SEBELUM token ada; bila gagal, token tidak dibuat
        if (!$this->ensureGuard()) {
            return;
        }
        $old = umask(0077);
        $fh = @fopen($this->tokenPath(), 'x');
        umask($old);
        if ($fh === false) {
            return; // balapan: pihak lain sudah membuatnya
        }
        fwrite($fh, bin2hex(random_bytes(24)));
        fclose($fh);
        @chmod($this->tokenPath(), 0600);
    }

    public function tokenPath(): string
    {
        return $this->storage . '/' . self::TOKEN_FILE;
    }

    public function isFallbackLayout(): bool
    {
        $a = realpath($this->appDir);
        $d = realpath($this->docroot);
        return $a !== false && $d !== false && ($a === $d || str_starts_with($a, $d . DIRECTORY_SEPARATOR));
    }

    /** @return list<Check> */
    public function checks(): array
    {
        $out = [];
        $out[] = new Check('php', PHP_VERSION_ID >= 80100, PHP_VERSION_ID >= 80100 ? 'PHP ' . PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION : 'Butuh PHP 8.1 atau lebih baru');
        $missing = array_values(array_filter(['pdo', 'mbstring', 'openssl', 'sodium', 'json', 'ctype'], static fn(string $e): bool => !extension_loaded($e)));
        $out[] = new Check('ext', $missing === [], $missing === [] ? 'Ekstensi wajib tersedia' : 'Ekstensi belum aktif: ' . implode(', ', $missing));
        $drv = extension_loaded('pdo_sqlite') || extension_loaded('pdo_mysql');
        $out[] = new Check('pdo_driver', $drv, $drv ? 'Driver database tersedia' : 'Butuh pdo_sqlite atau pdo_mysql');
        $writable = $this->ensureDir($this->storage) && is_writable($this->storage)
            && $this->ensureDir(dirname($this->configFile)) && is_writable(dirname($this->configFile));
        $out[] = new Check('storage', $writable, $writable ? 'storage/ dan config/ dapat ditulis' : 'storage/ atau config/ tidak dapat ditulis');
        $fallback = $this->isFallbackLayout();
        $out[] = new Check(
            'layout',
            true,
            $fallback ? 'Mode cadangan: app/ berada di dalam docroot' : 'Mode normal: app/ di luar docroot',
            false,
        );
        $out[] = new Check(
            'app_outside_docroot',
            !$fallback,
            $fallback
                ? 'PERINGATAN: app/ di dalam docroot. Akses dikunci .htaccess deny-all (hanya Apache); pindahkan app/ ke luar docroot bila hosting mengizinkan.'
                : 'app/ berada di luar docroot',
            false,
        );
        if ($fallback) {
            $guardOk = $this->ensureGuard();
            $out[] = new Check('guard', $guardOk, $guardOk ? 'Penjaga .htaccess app/ aktif (deny-all)' : 'app/.htaccess penjaga tidak ada atau tidak menolak akses dan tidak dapat dibuat; pindahkan app/ ke luar docroot');
        }
        $perms = (int) @fileperms($this->storage);
        $loose = is_dir($this->storage) && ($perms & 0002) !== 0;
        $out[] = new Check('perm', !$loose, $loose ? 'PERINGATAN: storage/ dapat ditulis semua orang; ubah ke 750.' : 'Izin storage/ aman', false);
        $out[] = new Check('config_absent', !is_file($this->configFile), is_file($this->configFile) ? 'config.php sudah ada; instal otomatis ditolak' : 'Belum ada config.php');
        return $out;
    }

    /**
     * @return list<string> pesan per bidang (tanpa nilai input)
     */
    public function validate(InstallInput $in): array
    {
        $e = [];
        $url = HostPolicy::parse($in->appUrl);
        if ($url === null) {
            $e[] = 'APP_URL tidak valid (https://domain atau http://localhost[:port], tanpa path).';
        }
        if (AccountStore::normalizeEmail($in->adminEmail) === null) {
            $e[] = 'Email admin tidak valid.';
        }
        $name = trim($in->adminName);
        if ($name === '' || mb_strlen($name) > 120 || preg_match('/[\x00-\x1F\x7F]/u', $name) === 1 || !mb_check_encoding($name, 'UTF-8')) {
            $e[] = 'Nama admin tidak valid.';
        }
        if (count($in->allowedHosts) > 20) {
            $e[] = 'Terlalu banyak host yang diizinkan.';
        }
        foreach ($in->allowedHosts as $h) {
            if (!HostPolicy::validHost($h)) {
                $e[] = 'Host yang diizinkan tidak valid.';
                break;
            }
        }
        if ($in->dbDriver === 'sqlite') {
            if (preg_match('/^[A-Za-z0-9_-]{1,64}\.(sqlite|sqlite3)$/D', $in->dbFile) !== 1) {
                $e[] = 'Nama file database tidak valid.';
            }
        } elseif ($in->dbDriver === 'mysql') {
            if (preg_match('/^[A-Za-z0-9._-]{1,255}$/D', $in->dbHost) !== 1) {
                $e[] = 'Host database tidak valid.';
            }
            if (preg_match('/^[A-Za-z0-9_]{1,64}$/D', $in->dbName) !== 1) {
                $e[] = 'Nama database tidak valid.';
            }
            if (preg_match('/^[^\x00-\x1F\x7F]{1,64}$/Du', $in->dbUser) !== 1) {
                $e[] = 'User database tidak valid.';
            }
            if ($in->dbPort < 1 || $in->dbPort > 65535) {
                $e[] = 'Port database tidak valid.';
            }
            if (strlen($in->dbPassword) > 256 || str_contains($in->dbPassword, "\0")) {
                $e[] = 'Password database tidak valid.';
            }
        } else {
            $e[] = 'Jenis database tidak didukung.';
        }
        if ($in->mailFrom !== '' && AccountStore::normalizeEmail($in->mailFrom) === null) {
            $e[] = 'Alamat pengirim email tidak valid.';
        }
        if ($in->smtpHost !== '') {
            if (preg_match('/^[A-Za-z0-9._-]{1,255}$/D', $in->smtpHost) !== 1) {
                $e[] = 'Host SMTP tidak valid.';
            }
            if ($in->smtpPort < 1 || $in->smtpPort > 65535 || !in_array($in->smtpSecure, ['tls', 'starttls'], true)) {
                $e[] = 'Port atau mode SMTP tidak valid.';
            }
            if (preg_match('/^[^\x00-\x1F\x7F]{0,254}$/Du', $in->smtpUser) !== 1
                || strlen($in->smtpPassword) > 256 || str_contains($in->smtpPassword, "\0")) {
                $e[] = 'Kredensial SMTP tidak valid.';
            }
        }
        return $e;
    }

    public function install(InstallInput $in): InstallResult
    {
        if ($this->isInstalled()) {
            throw new InstallRejected('Tidak ditemukan', [], 404);
        }
        if (!$this->ensureDir($this->storage)) {
            throw new InstallRejected('Instalasi gagal: folder penyimpanan tidak dapat ditulis.', [], 500);
        }
        if (!$this->ensureGuard()) {
            throw new InstallRejected('Prasyarat belum terpenuhi: penjaga app/.htaccess tidak dapat dipasang; pindahkan app/ ke luar docroot.', [], 422);
        }
        $busy = @fopen($this->storage . '/' . self::BUSY_FILE, 'c');
        if ($busy === false || !flock($busy, LOCK_EX | LOCK_NB)) {
            if ($busy !== false) {
                fclose($busy);
            }
            throw new InstallRejected('Instalasi sedang berjalan.', [], 409);
        }
        try {
            // periksa ulang di bawah kunci (TOCTOU); berkas bisa muncul di antara dua pemeriksaan
            // @phpstan-ignore if.alwaysFalse
            if ($this->isInstalled()) {
                throw new InstallRejected('Tidak ditemukan', [], 404);
            }
            if (!$this->tokenValid($in->installToken)) {
                $this->logger?->warning('Instal ditolak: token salah');
                throw new InstallRejected('Token instal salah.', [], 403);
            }
            $errors = $this->validate($in);
            if ($errors !== []) {
                throw new InstallRejected('Periksa isian formulir.', $errors);
            }
            foreach ($this->checks() as $c) {
                if ($c->fatal && !$c->ok) {
                    throw new InstallRejected('Prasyarat belum terpenuhi: ' . $c->msg, [], 422);
                }
            }
            $conn = $this->connect($in);
            $resetUrl = $this->provision($conn, $in);
            $this->writeConfig($in);
            if (!$this->createLock()) {
                @unlink($this->configFile);
                throw new InstallRejected('Tidak ditemukan', [], 404);
            }
            @unlink($this->tokenPath());
            $this->logger?->info('Instalasi selesai');
            return new InstallResult($resetUrl);
        } finally {
            flock($busy, LOCK_UN);
            fclose($busy);
        }
    }

    private function tokenValid(string $given): bool
    {
        $stored = @file_get_contents($this->tokenPath());
        if (!is_string($stored) || strlen(trim($stored)) < 32) {
            return false;
        }
        return hash_equals(trim($stored), $given);
    }

    private function connect(InstallInput $in): Connection
    {
        try {
            if ($in->dbDriver === 'mysql') {
                return Connection::mysql($in->dbHost, $in->dbName, $in->dbUser, $in->dbPassword, $in->dbPort);
            }
            $path = $this->storage . '/' . $in->dbFile;
            $conn = Connection::sqlite($path);
            @chmod($path, 0600);
            return $conn;
        } catch (\Throwable) {
            throw new InstallRejected('Koneksi database gagal. Periksa pengaturan database.');
        }
    }

    /** Skema + peran + admin pending; mengembalikan tautan reset. */
    private function provision(Connection $conn, InstallInput $in): string
    {
        try {
            AuthSchema::install($conn);
            $exists = $conn->pdo()->prepare(
                $conn->dialect() === \bFramework\Contracts\Dialect::Sqlite
                    ? "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?"
                    : 'SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?',
            );
            $exists->execute([FilesTable::NAME]);
            if ($exists->fetchColumn() === false) {
                $m = new Migrator($conn, $conn->grammar());
                $m->apply($m->planCreate(FilesTable::spec()));
            }
            $q = new Query($conn, $conn->grammar(), AuthTables::allowlist());
            foreach (['admin' => 'Administrator', 'staf' => 'Staf'] as $name => $label) {
                if ($q->select(AuthTables::ROLES, ['id'], new Where([['name', '=', $name]]), null, 1, 0) === []) {
                    $q->insert(AuthTables::ROLES, ['name' => $name, 'label' => $label]);
                }
            }
            $accounts = new AccountStore($conn, $this->clock, $this->logger);
            $email = (string) AccountStore::normalizeEmail($in->adminEmail);
            $acc = $accounts->findByEmail($email);
            if ($acc === null) {
                $uid = $accounts->create($email, $in->adminName, null, 'pending');
            } elseif ($acc->status === 'pending' && $acc->passwordHash === null) {
                $uid = $acc->id; // sisa instal yang terputus
            } else {
                $uid = null;
            }
            if ($uid === null) {
                throw new InstallRejected('Akun admin tidak dapat dibuat.');
            }
            if (!in_array('admin', $accounts->roles($uid), true)) {
                $accounts->assignRole($uid, 'admin');
            }
            $token = (new OneTimeToken($conn, $this->clock))->issue($uid, OneTimeToken::RESET, self::RESET_TTL);
            $p = HostPolicy::parse($in->appUrl);
            return ($p['scheme'] ?? 'https') . '://' . ($p['authority'] ?? '') . '/auth/reset/' . $token;
        } catch (InstallRejected $e) {
            throw $e;
        } catch (\Throwable $e) {
            $this->logger?->error('Instal gagal menyiapkan database', ['class' => $e::class]);
            throw new InstallRejected('Instalasi gagal menyiapkan database.', [], 500);
        }
    }

    private function writeConfig(InstallInput $in): void
    {
        $p = HostPolicy::parse($in->appUrl);
        $hosts = array_values(array_unique(array_map('strtolower', $in->allowedHosts)));
        $cfg = [
            'APP_ENV' => 'production',
            'APP_URL' => ($p['scheme'] ?? 'https') . '://' . ($p['authority'] ?? ''),
            'APP_HOST' => $p['host'] ?? 'localhost',
            'ALLOWED_HOSTS' => $hosts,
            'APP_KEY' => base64_encode(random_bytes(48)),
            'DB_DRIVER' => $in->dbDriver,
        ];
        if ($in->dbDriver === 'mysql') {
            $cfg += ['DB_HOST' => $in->dbHost, 'DB_PORT' => $in->dbPort, 'DB_NAME' => $in->dbName, 'DB_USER' => $in->dbUser, 'DB_PASSWORD' => $in->dbPassword];
        } else {
            $cfg['DB_FILE'] = $in->dbFile;
        }
        $cfg['MAIL_FROM'] = $in->mailFrom !== '' ? (string) AccountStore::normalizeEmail($in->mailFrom) : 'noreply@example.invalid';
        if ($in->smtpHost !== '') {
            $cfg += ['SMTP_HOST' => $in->smtpHost, 'SMTP_PORT' => $in->smtpPort, 'SMTP_SECURE' => $in->smtpSecure];
            if ($in->smtpUser !== '') {
                $cfg['SMTP_USER'] = $in->smtpUser;
                $cfg['SMTP_PASSWORD'] = $in->smtpPassword;
            }
        }
        $cfg['auth'] = ['registration' => $in->registration];

        $php = "<?php\n\ndeclare(strict_types=1);\n\ndefined('APP_BOOTED') || exit;\n\n// Dibuat oleh installer. Berisi rahasia: izin 0600, jangan di-commit atau dibagikan.\nreturn "
            . var_export($cfg, true) . ";\n";
        $tmp = dirname($this->configFile) . '/.config.' . bin2hex(random_bytes(6)) . '.tmp';
        $old = umask(0077);
        $ok = @file_put_contents($tmp, $php, LOCK_EX) === strlen($php);
        umask($old);
        if (!$ok || !@chmod($tmp, 0600) || !@rename($tmp, $this->configFile)) {
            @unlink($tmp);
            throw new InstallRejected('Instalasi gagal menulis konfigurasi.', [], 500);
        }
    }

    private function createLock(): bool
    {
        $fh = @fopen($this->storage . '/' . self::LOCK_FILE, 'x');
        if ($fh === false) {
            return false;
        }
        fwrite($fh, (string) $this->clock->now()->getTimestamp());
        fclose($fh);
        return true;
    }

    private function guardPresent(): bool
    {
        $h = @file_get_contents($this->appDir . '/.htaccess');
        return is_string($h) && str_contains($h, 'Require all denied') && str_contains($h, 'Deny from all');
    }

    /** Mode normal: true tanpa berbuat apa-apa. Mode cadangan: pastikan penjaga ada dan menolak akses. */
    private function ensureGuard(): bool
    {
        if (!$this->isFallbackLayout()) {
            return true;
        }
        if (!$this->guardPresent()) {
            $this->writeGuard();
        }
        return $this->guardPresent();
    }

    private function writeGuard(): void
    {
        $body = "# ARCH-02 (mode cadangan): tolak semua akses langsung\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n"
            . "<IfModule !mod_authz_core.c>\n    Order allow,deny\n    Deny from all\n</IfModule>\n";
        @file_put_contents($this->appDir . '/.htaccess', $body);
        if (!is_file($this->appDir . '/index.html')) {
            @file_put_contents($this->appDir . '/index.html', '');
        }
    }

    private function ensureDir(string $dir): bool
    {
        return is_dir($dir) || @mkdir($dir, 0750, true) || is_dir($dir);
    }
}
