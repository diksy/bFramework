<?php

declare(strict_types=1);

namespace bFramework\Tests\Fixtures;

/**
 * Sandbox tmp berisi salinan app/ + public_html/ nyata, dilayani server PHP bawaan (php -S) dengan index.php asli.
 * Hanya transport HTTP keluar dan email yang diganti (auto_prepend_file). Aturan .htaccess untuk _pc disimulasikan
 * di sini (Apache nyata tidak tersedia). Hanya data dummy.
 */
final class KernelApp
{
    public const HOST = 'app.contoh.test';
    public const ADMIN_EMAIL = 'admin@contoh.test';
    public const PASSWORD = 'kata sandi dummy panjang 42';

    public string $root;
    public int $port = 0;
    /** Jumlah request yang benar-benar sampai ke PHP (bukan dilayani dari _pc). */
    public int $phpHits = 0;
    private mixed $proc = null;

    private function __construct()
    {
        $this->root = sys_get_temp_dir() . '/int_' . bin2hex(random_bytes(6));
    }

    public function __destruct()
    {
        $this->stop();
        self::rm($this->root);
    }

    /** Salin tanpa instal (config belum ada): untuk tes /install. */
    public static function fresh(): self
    {
        $a = new self();
        $src = dirname(__DIR__, 2);
        mkdir($a->root, 0700, true);
        self::copy($src . '/app', $a->root . '/app');
        self::copy($src . '/public_html', $a->root . '/public_html');
        foreach (glob($a->root . '/app/storage/*') ?: [] as $f) {
            is_dir($f) ? self::rm($f) : @unlink($f);
        }
        @mkdir($a->root . '/app/storage', 0700, true);
        foreach (glob($a->root . '/public_html/_pc/*.html') ?: [] as $f) {
            @unlink($f);
        }
        foreach (['int_prepend.php', 'int_fake_http.php', 'int_fake_mail.php'] as $f) {
            copy(__DIR__ . '/' . $f, $a->root . '/' . $f);
        }
        $a->start();
        return $a;
    }

    /**
     * Instal sungguhan lewat /install lalu atur password admin lewat tautan reset, kemudian compile definisi contoh.
     *
     * @param array<string,mixed> $config tambahan/penimpa config.php (mis. APP_ENV, auth, builder)
     */
    public static function installed(array $config = [], bool $deploy = true): self
    {
        $a = self::fresh();
        $b = $a->browser();
        $b->get('/install');
        $token = trim((string) file_get_contents($a->root . '/app/storage/install_token'));
        $r = $b->post('/install', [
            'app_url' => 'https://' . self::HOST, 'admin_email' => self::ADMIN_EMAIL, 'admin_name' => 'Admin Dummy',
            'db_driver' => 'sqlite', 'db_file' => 'app.sqlite', 'mail_from' => 'noreply@contoh.test',
            'install_token' => $token,
        ]);
        if ($r->status !== 200) {
            throw new \RuntimeException('instal gagal: ' . $r->status . ' ' . substr(strip_tags($r->body), 0, 300));
        }
        if ($config !== []) {
            $a->mergeConfig($config);
        }
        if ($deploy) {
            $a->deploy(); // rilis nyata belum membawa cache compile; tanpa ini semua request 500 (lihat INT-01b)
        }
        $res = $a->setPasswordFromResetLink($r->body, self::ADMIN_EMAIL);
        if ($res->status >= 400) {
            throw new \RuntimeException('set password gagal: ' . $res->status);
        }
        return $a;
    }

    private function start(): void
    {
        $s = stream_socket_server('tcp://127.0.0.1:0', $en, $es);
        if ($s === false) {
            throw new \RuntimeException('tidak ada port');
        }
        $this->port = (int) substr((string) stream_socket_get_name($s, false), strrpos((string) stream_socket_get_name($s, false), ':') + 1);
        fclose($s);
        $env = ['PATH' => (string) getenv('PATH'), 'INT_SANDBOX' => $this->root, 'HOME' => $this->root];
        $cmd = [PHP_BINARY, '-d', 'opcache.enable=0', '-d', 'auto_prepend_file=' . $this->root . '/int_prepend.php', '-S', '127.0.0.1:' . $this->port,
            '-t', $this->root . '/public_html', $this->root . '/public_html/index.php'];
        $p = proc_open($cmd, [0 => ['file', '/dev/null', 'r'], 1 => ['file', $this->root . '/server.out', 'w'], 2 => ['file', $this->root . '/server.err', 'w']], $pipes, $this->root, $env);
        if (!is_resource($p)) {
            throw new \RuntimeException('server gagal start');
        }
        $this->proc = $p;
        for ($i = 0; $i < 100; $i++) {
            $c = @fsockopen('127.0.0.1', $this->port, $en, $es, 0.2);
            if ($c !== false) {
                fclose($c);
                return;
            }
            usleep(50000);
        }
        throw new \RuntimeException('server tidak siap');
    }

    public function destroy(): void
    {
        $this->stop();
        self::rm($this->root);
    }

    public function stop(): void
    {
        if ($this->proc !== null) {
            proc_terminate($this->proc);
            proc_close($this->proc);
            $this->proc = null;
        }
    }

    public function browser(string $ip = '198.51.100.10'): KernelBrowser
    {
        return new KernelBrowser($this, $ip);
    }

    /**
     * @param array<string,mixed> $post
     * @param array<string,string> $files
     * @param array<string,string> $headers
     */
    public function send(string $method, string $path, array $post = [], array $files = [], array $headers = [], bool $raw = false, ?string $body = null): KernelResp
    {
        if (!$raw && ($st = $this->staticCache($method, $path, $headers)) !== null) {
            return $st;
        }
        $this->phpHits++;
        $ch = curl_init('http://127.0.0.1:' . $this->port . $path);
        $hdr = isset($headers['Host']) ? [] : ['Host: ' . self::HOST];
        foreach ($headers as $k => $v) {
            $hdr[] = $k . ': ' . $v;
        }
        $resp = ['h' => []];
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method, CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false, CURLOPT_TIMEOUT => 60,
            CURLOPT_HEADERFUNCTION => static function ($c, string $line) use (&$resp): int {
                if (str_contains($line, ':')) {
                    [$k, $v] = explode(':', $line, 2);
                    $resp['h'][strtolower(trim($k))][] = trim($v);
                } elseif (str_starts_with($line, 'HTTP/')) {
                    $resp['h'] = [];
                }
                return strlen($line);
            },
        ]);
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            $hdr[] = 'Content-Type: application/json';
        } elseif ($method === 'POST' || $method === 'PUT') {
            if ($files !== []) {
                $f = $post;
                foreach ($files as $n => $p) {
                    $f[$n] = new \CURLFile($p, null, basename($p));
                }
                curl_setopt($ch, CURLOPT_POSTFIELDS, $f);
            } else {
                curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
            }
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $hdr);
        $out = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        if ($out === false) {
            throw new \RuntimeException('curl gagal; ' . (string) @file_get_contents($this->root . '/server.err'));
        }
        return new KernelResp($status, $resp['h'], (string) $out);
    }

    /**
     * Simulasi RewriteRule .htaccess (F8 / CACHE-12).
     *
     * @param array<string,string> $headers
     */
    private function staticCache(string $method, string $path, array $headers): ?KernelResp
    {
        $cookie = $headers['Cookie'] ?? '';
        if (!in_array($method, ['GET', 'HEAD'], true) || str_contains($path, '?')
            || preg_match('/(^|;\s*)(__Host-)?bf_(sid|remember)=/', $cookie) === 1 || isset($headers['Authorization'])
            || preg_match('#^/([a-z0-9_-]+(?:/[a-z0-9_-]+)*)/?$#', $path, $m) !== 1) {
            return null;
        }
        $f = $this->root . '/public_html/_pc/' . $m[1] . '.html';
        clearstatcache(true, $f);
        if (!is_file($f)) {
            return null;
        }
        return new KernelResp(200, ['content-type' => ['text/html; charset=utf-8']], (string) file_get_contents($f), true);
    }

    /** @return list<array{to:string,from:string,subject:string,body:string}> */
    public function mails(): array
    {
        $this->send('GET', '/__settle', raw: true); // server tunggal: baru dilayani setelah pekerjaan tunda (email) selesai
        $this->phpHits--;
        $f = $this->root . '/mail.jsonl';
        $out = [];
        foreach (is_file($f) ? (file($f, FILE_IGNORE_NEW_LINES) ?: []) : [] as $l) {
            $out[] = json_decode($l, true);
        }
        /** @var list<array{to:string,from:string,subject:string,body:string}> $out */
        return $out;
    }

    /** Token (bagian setelah /auth/reset/ atau /auth/verify/) dari email terakhir ke $to. */
    public function lastMailToken(string $to): string
    {
        foreach (array_reverse($this->mails()) as $m) {
            if ($m['to'] === $to && preg_match('#/auth/(?:reset|verify)/([A-Za-z0-9._-]+)#', $m['body'], $mm) === 1) {
                return $mm[1];
            }
        }
        throw new \RuntimeException('tidak ada email berisi token untuk ' . $to);
    }

    /** Buka tautan reset (dari body halaman instal atau email), lalu set password. */
    public function setPasswordFromResetLink(string $textWithLink, string $email, string $password = self::PASSWORD): KernelResp
    {
        if (preg_match('#/auth/reset/([A-Za-z0-9._-]+)#', $textWithLink, $m) !== 1) {
            throw new \RuntimeException('tautan reset tidak ditemukan');
        }
        $b = $this->browser('198.51.100.99');
        $r = $b->get('/auth/reset/' . $m[1]);
        $r = $b->follow($r);
        return $b->post('/auth/reset', ['password' => $password, 'password_confirm' => $password, 'password2' => $password]);
    }

    /**
     * Aktifkan SSO: tulis konfigurasi auth + keadaan IdP palsu (discovery/JWKS dari FakeIdp). Driver: bikinin_sso|hybrid.
     *
     * @param array<string,mixed> $sso
     */
    public function useSso(string $driver, FakeIdp $idp, array $sso = []): void
    {
        $kp = (new \ReflectionClass($idp))->getProperty('keys');
        /** @var array<string,array{jwk:array<string,string>}> $keys */
        $keys = $kp->getValue($idp);
        file_put_contents($this->root . '/idp.json', json_encode([
            'discovery' => $idp->discoveryDoc(),
            'jwks' => ['keys' => array_values(array_map(static fn(array $k): array => $k['jwk'], $keys))],
            'tokens' => [], 'introspect' => true,
        ], JSON_THROW_ON_ERROR));
        $this->mergeConfig(['auth' => ['driver' => $driver, 'sso' => $sso + [
            'issuer' => FakeIdp::ISSUER, 'client_id' => FakeIdp::CLIENT_ID, 'client_secret' => FakeIdp::SECRET,
            'provisioning' => 'jit', 'default_role' => 'staf', 'offline_access' => false, 'session_check_minutes' => 5,
        ]]]);
    }

    /** Set jawaban token endpoint IdP palsu (menggantikan sisa antrean).
     *
     * @param array<string,mixed> $body
     */
    public function queueToken(array $body, int $status = 200): void
    {
        $f = $this->root . '/idp.json';
        /** @var array<string,mixed> $st */
        $st = json_decode((string) file_get_contents($f), true);
        $st['tokens'] = [[$status, $body]]; // satu jawaban saja: sisa antrean lama tidak boleh bocor ke login berikutnya
        file_put_contents($f, json_encode($st, JSON_THROW_ON_ERROR));
    }

    /** @return list<array{m:string,host:string,path:string}> */
    public function idpCalls(): array
    {
        $f = $this->root . '/idp_calls.jsonl';
        $out = [];
        foreach (is_file($f) ? (file($f, FILE_IGNORE_NEW_LINES) ?: []) : [] as $l) {
            $out[] = json_decode($l, true);
        }
        /** @var list<array{m:string,host:string,path:string}> $out */
        return $out;
    }

    /** @param array<string,mixed> $extra */
    public function mergeConfig(array $extra): void
    {
        $f = $this->root . '/app/config/config.php';
        $cur = (static function (string $f): array {
            if (!defined('APP_BOOTED')) {
                define('APP_BOOTED', true);
            }
            /** @var array<string,mixed> */
            return require $f;
        })($f);
        $new = self::mergeConf($cur, $extra);
        file_put_contents($f, "<?php\n\ndeclare(strict_types=1);\n\ndefined('APP_BOOTED') || exit;\n\nreturn " . var_export($new, true) . ";\n");
        @chmod($f, 0600);
    }

    /**
     * Gabung rekursif untuk peta; daftar (list) diganti utuh.
     *
     * @param array<mixed> $a
     * @param array<mixed> $b
     * @return array<mixed>
     */
    private static function mergeConf(array $a, array $b): array
    {
        foreach ($b as $k => $v) {
            $a[$k] = is_array($v) && !array_is_list($v) && isset($a[$k]) && is_array($a[$k]) ? self::mergeConf($a[$k], $v) : $v;
        }
        return $a;
    }

    /**
     * Tulis definisi (model/page) ke sandbox.
     *
     * @param array<string,mixed> $def
     */
    public function writeDefinition(string $kind, string $name, array $def): void
    {
        $dir = $this->root . '/app/definitions/' . $kind;
        @mkdir($dir, 0700, true);
        file_put_contents($dir . '/' . $name . '.json', json_encode($def, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    public function removeDefinition(string $kind, string $name): void
    {
        @unlink($this->root . '/app/definitions/' . $kind . '/' . $name . '.json');
    }

    /** Definisi 'produk' ber-owner (pemilik) + kategori ber-owner + halaman publik ber-cache; lalu compile ulang. */
    public function defineProdukOwner(): void
    {
        $acc = ['read' => ['staf', 'admin'], 'write' => ['staf', 'admin'], 'owner' => 'pemilik', 'ownerExempt' => ['admin']];
        $this->writeDefinition('models', 'kategori', [
            'model' => 'kategori',
            'fields' => ['nama' => ['type' => 'string', 'label' => 'Nama kategori', 'required' => true, 'max' => 60], 'pemilik' => ['type' => 'integer', 'guarded' => true]],
            'access' => $acc,
        ]);
        $this->writeDefinition('models', 'produk', [
            'model' => 'produk',
            'fields' => [
                'nama' => ['type' => 'string', 'label' => 'Nama produk', 'required' => true, 'max' => 100],
                'catatan' => ['type' => 'text', 'label' => 'Catatan'],
                'stok' => ['type' => 'integer', 'label' => 'Stok', 'min' => 0, 'default' => 0],
                'kategori' => ['type' => 'relasi', 'label' => 'Kategori', 'target' => 'kategori'],
                'berkas' => ['type' => 'string', 'label' => 'Berkas', 'upload' => ['mimes' => ['image/png'], 'maxBytes' => 100000]],
                'pemilik' => ['type' => 'integer', 'guarded' => true],
            ],
            'hooks' => ['beforeSave' => 'ProdukHooks::validasiStok'],
            'access' => $acc,
        ]);
        $this->writeDefinition('pages', 'daftar-produk', [
            'page' => 'daftar-produk', 'route' => '/produk', 'title' => 'Produk', 'group' => 'Penjualan', 'order' => 10,
            'access' => ['admin', 'staf'],
            'layout' => [
                ['component' => 'table', 'span' => 12, 'actions' => ['edit', 'hapus'], 'columns' => ['nama', 'catatan', 'stok', 'kategori', 'berkas'],
                    'source' => ['model' => 'produk', 'sort' => '-stok', 'perPage' => 20]],
            ],
        ]);
        $this->writeDefinition('models', 'artikel', [
            'model' => 'artikel',
            'fields' => ['judul' => ['type' => 'string', 'label' => 'Judul', 'required' => true, 'max' => 80]],
            'access' => ['read' => '*', 'write' => ['admin']],
        ]);
        $this->writeDefinition('pages', 'katalog', [
            'page' => 'katalog', 'route' => '/katalog', 'title' => 'Katalog', 'access' => '*', 'cache' => true,
            'layout' => [['component' => 'table', 'span' => 12, 'columns' => ['judul'], 'source' => ['model' => 'artikel', 'perPage' => 20]]],
        ]);
        $this->writeDefinition('pages', 'kelola-artikel', [
            'page' => 'kelola-artikel', 'route' => '/kelola-artikel', 'title' => 'Kelola artikel', 'access' => ['admin'],
            'layout' => [['component' => 'table', 'span' => 12, 'actions' => ['edit', 'hapus'], 'columns' => ['judul'], 'source' => ['model' => 'artikel', 'perPage' => 20]]],
        ]);
        $this->pdo()->exec('DROP TABLE IF EXISTS produk');
        $this->pdo()->exec('DROP TABLE IF EXISTS kategori');
        $this->deploy();
    }

    public function deploy(): void
    {
        $out = [];
        exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/int_deploy.php') . ' ' . escapeshellarg($this->root) . ' 2>&1', $out, $code);
        if ($code !== 0) {
            throw new \RuntimeException('deploy gagal: ' . implode("\n", $out));
        }
    }

    /**
     * Admin membuat pengguna (undangan lewat email), lalu pengguna menyetel password dari tautan. Mengembalikan id.
     *
     * @param list<string> $roles
     */
    public function newUser(string $email, array $roles = ['staf'], string $password = self::PASSWORD): int
    {
        $admin = $this->browser('198.51.100.200');
        $admin->login(self::ADMIN_EMAIL, self::PASSWORD);
        $admin->get('/admin/pengguna/baru');
        $r = $admin->post('/admin/pengguna', ['email' => $email, 'name' => 'Pengguna ' . $email, 'roles' => $roles]);
        if ($r->status !== 302) {
            throw new \RuntimeException('buat pengguna gagal: ' . $r->status);
        }
        $this->setPasswordFromResetLink('/auth/reset/' . $this->lastMailToken($email), $email, $password);
        $st = $this->pdo()->prepare('SELECT id FROM users WHERE email = ?');
        $st->execute([$email]);
        return (int) $st->fetchColumn();
    }

    /** Peramban yang sudah login sebagai $email. */
    public function loggedIn(string $email = self::ADMIN_EMAIL, string $ip = '198.51.100.10', string $password = self::PASSWORD): KernelBrowser
    {
        $b = $this->browser($ip);
        $r = $b->login($email, $password);
        if ($r->status !== 302) {
            throw new \RuntimeException('login gagal ' . $r->status);
        }
        $b->get('/');
        return $b;
    }

    public function pdo(): IntPdo
    {
        $p = new IntPdo('sqlite:' . $this->root . '/app/storage/app.sqlite');
        $p->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        $p->exec('PRAGMA busy_timeout=5000');
        return $p;
    }

    public function appLog(): string
    {
        $s = '';
        foreach (glob($this->root . '/app/storage/logs/*') ?: [] as $f) {
            $s .= (string) file_get_contents($f);
        }
        return $s . (string) @file_get_contents($this->root . '/server.err');
    }

    private static function copy(string $a, string $b): void
    {
        mkdir($b, 0700, true);
        foreach (scandir($a) ?: [] as $f) {
            if ($f === '.' || $f === '..') {
                continue;
            }
            is_dir($a . '/' . $f) ? self::copy($a . '/' . $f, $b . '/' . $f) : copy($a . '/' . $f, $b . '/' . $f);
        }
    }

    public static function rm(string $d): void
    {
        if (!is_dir($d) || is_link($d)) {
            @unlink($d);
            return;
        }
        foreach (scandir($d) ?: [] as $f) {
            if ($f !== '.' && $f !== '..') {
                self::rm($d . '/' . $f);
            }
        }
        @rmdir($d);
    }
}
