<?php

declare(strict_types=1);

namespace bFramework\Tests\Integration;

use bFramework\Tests\Fixtures\KernelApp;
use PHPUnit\Framework\TestCase;

/**
 * INT-F5 (F14/F12/F5): CLI app/cli/admin-reset.php dan app/cli/compile.php dijalankan nyata (proc_open php)
 * terhadap sandbox hasil instal. Hanya data dummy.
 */
final class CliToolsTest extends TestCase
{
    private ?KernelApp $app = null;

    protected function tearDown(): void
    {
        $this->app?->destroy();
        $this->app = null;
    }

    private function boot(): KernelApp
    {
        return $this->app = KernelApp::installed();
    }

    /** @return array{0:int,1:string,2:string} exit, stdout, stderr */
    private function cli(KernelApp $a, string $script, string ...$args): array
    {
        $cmd = [PHP_BINARY, '-d', 'opcache.enable=0', $a->root . '/app/cli/' . $script, ...$args];
        $p = proc_open($cmd, [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $a->root);
        self::assertIsResource($p);
        [$o, $e, $timedOut, $code] = $this->drain($p, $pipes);
        proc_close($p);
        self::assertFalse($timedOut, 'CLI melewati batas waktu 30 detik');
        return [$code, $o, $e];
    }

    /**
     * @param resource $p
     * @param array<int,resource> $pipes
     * @return array{0:string,1:string,2:bool,3:int}
     */
    private function drain($p, array $pipes, int $limit = 30): array
    {
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $o = $e = '';
        $end = microtime(true) + $limit;
        while (true) {
            $r = [$pipes[1], $pipes[2]];
            $w = $x = null;
            if (@stream_select($r, $w, $x, 0, 200000) > 0) {
                foreach ($r as $s) {
                    $chunk = (string) fread($s, 8192);
                    $s === $pipes[1] ? $o .= $chunk : $e .= $chunk;
                }
            }
            $st = proc_get_status($p);
            if (!$st['running']) {
                $o .= (string) stream_get_contents($pipes[1]);
                $e .= (string) stream_get_contents($pipes[2]);
                return [$o, $e, false, $st['exitcode']];
            }
            if (microtime(true) > $end) {
                proc_terminate($p, 9);
                return [$o, $e, true, -1];
            }
        }
    }

    private function link(string $stdout): string
    {
        self::assertSame(1, preg_match('#https://' . preg_quote(KernelApp::HOST, '#') . '/auth/reset/([A-Za-z0-9._-]+)#', $stdout, $m), $stdout);
        return $m[0];
    }

    private function auditAndLogs(KernelApp $a): string
    {
        return $a->appLog() . (string) @file_get_contents($a->root . '/app/storage/logs/audit.log');
    }

    private function current(KernelApp $a): string
    {
        return trim((string) file_get_contents($a->root . '/app/storage/cache/current'));
    }

    private function hasColumn(KernelApp $a, string $table, string $col): bool
    {
        foreach ($a->pdo()->query('PRAGMA table_info(' . $table . ')')->fetchAll(\PDO::FETCH_ASSOC) as $r) {
            if ($r['name'] === $col) {
                return true;
            }
        }
        return false;
    }

    private function catatan(KernelApp $a, string ...$extra): void
    {
        $fields = ['judul' => ['type' => 'string', 'label' => 'Judul', 'required' => true, 'max' => 80]];
        foreach ($extra as $f) {
            $fields[$f] = ['type' => 'string', 'label' => ucfirst($f), 'max' => 50];
        }
        $a->writeDefinition('models', 'catatan', ['model' => 'catatan', 'fields' => $fields, 'access' => ['read' => ['admin'], 'write' => ['admin']]]);
    }

    public function testAdminResetPendingKedaluwarsaLaluLogin(): void
    {
        $a = $this->boot();
        $pdo = $a->pdo();
        $pdo->exec("UPDATE users SET status = 'pending', password_hash = NULL, email_verified_at = NULL");
        $pdo->exec('UPDATE one_time_tokens SET expires_at = 1');
        [$code, $out, $err] = $this->cli($a, 'admin-reset.php', strtoupper(KernelApp::ADMIN_EMAIL));
        self::assertSame(0, $code, $err);
        $url = $this->link($out);
        self::assertStringNotContainsString('password_hash', $out);
        // pending tanpa password sampai tautan dipakai
        $row = $pdo->query('SELECT status, password_hash FROM users')->fetch(\PDO::FETCH_ASSOC);
        self::assertSame('pending', $row['status']);
        self::assertNull($row['password_hash']);
        $new = 'kata sandi baru dummy 77';
        $r = $a->setPasswordFromResetLink($url, KernelApp::ADMIN_EMAIL, $new);
        self::assertLessThan(400, $r->status);
        $b = $a->browser('198.51.100.77');
        self::assertSame(302, $b->login(KernelApp::ADMIN_EMAIL, $new)->status);
        // sekali pakai
        self::assertGreaterThanOrEqual(400, $a->setPasswordFromResetLink($url, KernelApp::ADMIN_EMAIL, $new . 'x')->status);
    }

    public function testTautanLamaDicabutTanpaTokenDiLogDanAudit(): void
    {
        $a = $this->boot();
        [$c1, $o1] = $this->cli($a, 'admin-reset.php', KernelApp::ADMIN_EMAIL);
        [$c2, $o2] = $this->cli($a, 'admin-reset.php', KernelApp::ADMIN_EMAIL);
        self::assertSame([0, 0], [$c1, $c2]);
        $u1 = $this->link($o1);
        $u2 = $this->link($o2);
        self::assertNotSame($u1, $u2);
        $t1 = substr($u1, strrpos($u1, '/') + 1);
        $t2 = substr($u2, strrpos($u2, '/') + 1);
        $n = (int) $a->pdo()->query("SELECT COUNT(*) FROM one_time_tokens WHERE purpose = 'reset'")->fetchColumn();
        self::assertSame(1, $n);
        $b = $a->browser('198.51.100.88');
        try { // tautan lama tidak berlaku: password tidak berubah
            $a->setPasswordFromResetLink($u1, KernelApp::ADMIN_EMAIL, 'sandi tautan lama 99');
        } catch (\Throwable) {
        }
        self::assertNotSame(302, $b->login(KernelApp::ADMIN_EMAIL, 'sandi tautan lama 99')->status);
        // hanya hash di DB
        $dump = json_encode($a->pdo()->query('SELECT * FROM one_time_tokens')->fetchAll(\PDO::FETCH_ASSOC), JSON_THROW_ON_ERROR);
        self::assertStringNotContainsString(explode('.', $t2)[1], $dump);
        // log + audit: ada catatan, tanpa tautan/token/email
        $logs = $this->auditAndLogs($a);
        self::assertStringContainsString('Reset admin via CLI', (string) file_get_contents($a->root . '/app/storage/logs/audit.log'));
        foreach ([$t1, $t2, explode('.', $t1)[1], explode('.', $t2)[1], '/auth/reset/', KernelApp::ADMIN_EMAIL] as $secret) {
            self::assertStringNotContainsString($secret, $logs);
        }
    }

    public function testTolakNonAdminDanTidakAdaDenganPesanSama(): void
    {
        $a = $this->boot();
        $a->newUser('staf@contoh.test', ['staf']);
        $before = (int) $a->pdo()->query('SELECT COUNT(*) FROM one_time_tokens')->fetchColumn();
        [$c1, $o1, $e1] = $this->cli($a, 'admin-reset.php', 'staf@contoh.test');
        [$c2, $o2, $e2] = $this->cli($a, 'admin-reset.php', 'tidak.ada@contoh.test');
        self::assertSame([1, 1], [$c1, $c2]);
        self::assertSame($e1, $e2);
        self::assertSame('', $o1 . $o2);
        self::assertStringNotContainsString('/auth/reset/', $e1);
        self::assertSame($before, (int) $a->pdo()->query('SELECT COUNT(*) FROM one_time_tokens')->fetchColumn());
        // admin dinonaktifkan: ditolak pula
        $a->pdo()->exec("UPDATE users SET status = 'disabled' WHERE email = '" . KernelApp::ADMIN_EMAIL . "'");
        [$c3, , $e3] = $this->cli($a, 'admin-reset.php', KernelApp::ADMIN_EMAIL);
        self::assertSame([1, $e1], [$c3, $e3]);
    }

    public function testValidasiPemakaianDanGerbang(): void
    {
        $a = $this->boot();
        self::assertSame(2, $this->cli($a, 'admin-reset.php')[0]);
        self::assertSame(2, $this->cli($a, 'admin-reset.php', 'bukan-email')[0]);
        self::assertSame(2, $this->cli($a, 'admin-reset.php', "a@b.test\nc@d.test")[0]);
        self::assertSame(2, $this->cli($a, 'compile.php', '--aneh')[0]);
        self::assertSame(2, $this->cli($a, 'compile.php', '--allow-loss')[0]);
        unlink($a->root . '/app/storage/installed.lock');
        self::assertSame(1, $this->cli($a, 'admin-reset.php', KernelApp::ADMIN_EMAIL)[0]);
        self::assertSame(1, $this->cli($a, 'compile.php')[0]);
    }

    public function testCompileDefinisiBaruMembuatTabelDanIdempoten(): void
    {
        $a = $this->boot();
        $this->catatan($a);
        [$code, $out, $err] = $this->cli($a, 'compile.php');
        self::assertSame(0, $code, $out . $err);
        self::assertStringContainsString('tabel baru: catatan', $out);
        self::assertTrue($this->hasColumn($a, 'catatan', 'judul'));
        $cur = $this->current($a);
        self::assertSame($cur, trim((string) file_get_contents($a->root . '/app/storage/cache/.schema_ok')));
        $a->pdo()->exec("INSERT INTO catatan (judul) VALUES ('tetap ada')");
        [$c2, $o2] = $this->cli($a, 'compile.php');
        self::assertSame(0, $c2, $o2);
        self::assertSame($cur, $this->current($a));
        self::assertSame(1, (int) $a->pdo()->query('SELECT COUNT(*) FROM catatan')->fetchColumn());
        self::assertSame([], glob($a->root . '/app/storage/cache/dry_*') ?: []);
    }

    public function testDefinisiTidakValidGagalVersiLamaTetapAktif(): void
    {
        $a = $this->boot();
        $cur = $this->current($a);
        $a->writeDefinition('models', 'rusak', ['model' => 'rusak', 'fields' => ['x' => ['type' => 'tipe_ngawur']], 'access' => ['read' => ['admin'], 'write' => ['admin']]]);
        [$code, $out, $err] = $this->cli($a, 'compile.php');
        self::assertSame(1, $code);
        self::assertStringContainsString('rusak', $err);
        self::assertStringNotContainsString($a->root, $err);
        self::assertSame($cur, $this->current($a));
        self::assertSame([], glob($a->root . '/app/storage/cache/dry_*') ?: []);
        $a->removeDefinition('models', 'rusak');
        self::assertSame(0, $this->cli($a, 'compile.php')[0]);
    }

    public function testPerubahanSkemaButuhFlagDanDryRunTidakMengaktifkan(): void
    {
        $a = $this->boot();
        $this->catatan($a);
        self::assertSame(0, $this->cli($a, 'compile.php')[0]);
        $cur = $this->current($a);
        $this->catatan($a, 'ringkasan');
        // dry-run: pratinjau, tidak mengaktifkan
        [$c0, $o0] = $this->cli($a, 'compile.php', '--dry-run');
        self::assertSame(0, $c0);
        self::assertStringContainsString('ALTER TABLE', $o0);
        self::assertSame($cur, $this->current($a));
        self::assertFalse($this->hasColumn($a, 'catatan', 'ringkasan'));
        // tanpa flag: pratinjau saja, tidak ada yang berubah
        [$c1, $o1, $e1] = $this->cli($a, 'compile.php');
        self::assertSame(1, $c1);
        self::assertStringContainsString('ALTER TABLE', $o1);
        self::assertStringContainsString('--apply-migrations', $e1);
        self::assertSame($cur, $this->current($a));
        self::assertFalse($this->hasColumn($a, 'catatan', 'ringkasan'));
        // dengan flag, tanpa loss: diterapkan, data tetap
        $a->pdo()->exec("INSERT INTO catatan (judul) VALUES ('a')");
        [$c2, $o2, $e2] = $this->cli($a, 'compile.php', '--apply-migrations');
        self::assertSame(0, $c2, $o2 . $e2);
        self::assertTrue($this->hasColumn($a, 'catatan', 'ringkasan'));
        self::assertNotSame($cur, $this->current($a));
        self::assertSame($this->current($a), trim((string) file_get_contents($a->root . '/app/storage/cache/.schema_ok')));
        self::assertSame(1, (int) $a->pdo()->query('SELECT COUNT(*) FROM catatan')->fetchColumn());
    }

    public function testLossWarningDitolakTanpaAllowLoss(): void
    {
        $a = $this->boot();
        $this->catatan($a, 'ringkasan');
        self::assertSame(0, $this->cli($a, 'compile.php')[0]);
        $a->pdo()->exec("INSERT INTO catatan (judul, ringkasan) VALUES ('a', 'penting')");
        $cur = $this->current($a);
        $this->catatan($a); // kolom ringkasan dihapus
        [$c1, $o1, $e1] = $this->cli($a, 'compile.php', '--apply-migrations');
        self::assertSame(1, $c1);
        self::assertStringContainsString('KEHILANGAN DATA', $o1);
        self::assertStringContainsString('--allow-loss', $e1);
        self::assertSame($cur, $this->current($a));
        self::assertTrue($this->hasColumn($a, 'catatan', 'ringkasan'));
        [$c2, $o2, $e2] = $this->cli($a, 'compile.php', '--apply-migrations', '--allow-loss');
        self::assertSame(0, $c2, $o2 . $e2);
        self::assertFalse($this->hasColumn($a, 'catatan', 'ringkasan'));
        self::assertNotSame($cur, $this->current($a));
    }

    public function testKonkurensiDenganEnsureCompiledMemakaiKunciSama(): void
    {
        $a = $this->boot();
        $this->catatan($a);
        $lock = fopen($a->root . '/app/storage/first_build.lock', 'c');
        self::assertNotFalse($lock);
        self::assertTrue(flock($lock, LOCK_EX)); // seolah ensureCompiled sedang membangun
        $cmd = [PHP_BINARY, '-d', 'opcache.enable=0', $a->root . '/app/cli/compile.php'];
        $p = proc_open($cmd, [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $a->root);
        self::assertIsResource($p);
        usleep(1200000);
        self::assertTrue((bool) proc_get_status($p)['running'], 'CLI harus menunggu kunci');
        self::assertFalse($this->hasColumn($a, 'catatan', 'judul'));
        flock($lock, LOCK_UN);
        fclose($lock);
        [$out, $err, $timedOut, $code] = $this->drain($p, $pipes);
        proc_close($p);
        self::assertFalse($timedOut);
        self::assertSame(0, $code, $out . $err);
        self::assertTrue($this->hasColumn($a, 'catatan', 'judul'));
    }

    public function testSkripMenolakNonCliSebelumMelakukanApaPun(): void
    {
        $a = $this->boot();
        $before = (int) $a->pdo()->query('SELECT COUNT(*) FROM one_time_tokens')->fetchColumn();
        $cur = $this->current($a);
        $s = stream_socket_server('tcp://127.0.0.1:0', $en, $es);
        self::assertNotFalse($s);
        $name = (string) stream_socket_get_name($s, false);
        $port = (int) substr($name, strrpos($name, ':') + 1);
        fclose($s);
        $p = proc_open([PHP_BINARY, '-S', '127.0.0.1:' . $port, '-t', $a->root . '/app/cli'], [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes, $a->root);
        self::assertIsResource($p);
        try {
            for ($i = 0; $i < 100 && !($c = @fsockopen('127.0.0.1', $port, $en, $es, 0.2)); $i++) {
                usleep(50000);
            }
            foreach (['admin-reset.php', 'compile.php'] as $f) {
                $ch = curl_init('http://127.0.0.1:' . $port . '/' . $f . '?x=1');
                curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20]);
                $body = (string) curl_exec($ch);
                self::assertSame(404, curl_getinfo($ch, CURLINFO_RESPONSE_CODE), $f);
                self::assertStringNotContainsString('/auth/reset/', $body);
            }
        } finally {
            proc_terminate($p);
            proc_close($p);
        }
        self::assertSame($before, (int) $a->pdo()->query('SELECT COUNT(*) FROM one_time_tokens')->fetchColumn());
        self::assertSame($cur, $this->current($a));
    }
}
