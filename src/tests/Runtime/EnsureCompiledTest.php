<?php

declare(strict_types=1);

namespace bFramework\Tests\Runtime;

use bFramework\Contracts\Dialect;
use bFramework\Runtime\CacheStore;
use bFramework\Runtime\Compiler;
use bFramework\Runtime\Connection;
use bFramework\Tests\Fixtures\CaptureLogger;
use PHPUnit\Framework\TestCase;

/** INT-F1: build pertama + tabel model aman dari race, fail-closed tanpa mencabut versi aktif yang valid. */
final class EnsureCompiledTest extends TestCase
{
    private string $root;
    private string $app;
    private string $db;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/ec_' . bin2hex(random_bytes(6));
        $this->app = $this->root . '/app';
        $src = dirname(__DIR__, 2) . '/app';
        mkdir($this->app . '/storage/cache', 0700, true);
        foreach (['definitions/models', 'definitions/pages', 'extensions'] as $d) {
            mkdir($this->app . '/' . $d, 0700, true);
            foreach (glob($src . '/' . $d . '/*') ?: [] as $f) {
                copy($f, $this->app . '/' . $d . '/' . basename($f));
            }
        }
        $this->db = $this->root . '/db.sqlite';
    }

    protected function tearDown(): void
    {
        CacheStore::rmTree($this->root);
    }

    public function test_dua_pemanggil_bersamaan_tabel_dibuat_sekali_dan_keduanya_siap(): void
    {
        Connection::sqlite($this->db); // file DB ada sebelum proses paralel
        $script = __DIR__ . '/../Fixtures/ensure_runner.php';
        $procs = [];
        $pipes = [];
        for ($i = 0; $i < 4; $i++) {
            $p = proc_open([PHP_BINARY, $script, $this->app, $this->db], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes[$i]);
            self::assertIsResource($p);
            $procs[$i] = $p;
        }
        $created = [];
        foreach ($procs as $i => $p) {
            $out = (string) stream_get_contents($pipes[$i][1]);
            $err = (string) stream_get_contents($pipes[$i][2]);
            proc_close($p);
            $r = json_decode($out, true);
            self::assertIsArray($r, $out . $err);
            self::assertTrue($r['ready'], $out);
            foreach ($r['log'] as $line) {
                self::assertStringNotContainsString('gagal', $line);
                if (str_contains($line, 'tabel model dibuat')) {
                    $created[] = $line;
                }
            }
        }
        self::assertCount(count($this->modelTables()), $created, implode("\n", $created));
        self::assertCount(count(array_unique($created)), $created);
        $cur = (new CacheStore($this->app . '/storage/cache'))->current();
        self::assertNotNull($cur);
        self::assertSame($cur, file_get_contents($this->app . '/storage/cache/.schema_ok'));
        self::assertSame([], array_diff($this->modelTables(), $this->tables()));
    }

    public function test_migrasi_gagal_fail_closed_tanpa_mencabut_current_lalu_kedaluwarsa(): void
    {
        $cur = $this->compile();
        $pdo = Connection::sqlite($this->db)->pdo();
        $pdo->exec('CREATE VIEW produk AS SELECT 1 AS x'); // CREATE TABLE produk pasti gagal
        $log = new CaptureLogger();
        self::assertFalse(\bFramework\ensureCompiled($this->app, Connection::sqlite($this->db), $log));
        self::assertSame($cur, (new CacheStore($this->app . '/storage/cache'))->current(), 'versi aktif valid tidak boleh dicabut');
        self::assertFileExists($this->app . '/storage/cache/.build_failed');
        self::assertFileDoesNotExist($this->app . '/storage/cache/.schema_ok');
        self::assertStringContainsString('build pertama gagal', $log->all());
        self::assertStringNotContainsString($this->root, $log->all());

        $pdo->exec('DROP VIEW produk');
        self::assertFalse(\bFramework\ensureCompiled($this->app, Connection::sqlite($this->db)), 'negative cache masih berlaku');
        touch($this->app . '/storage/cache/.build_failed', time() - 61);
        self::assertTrue(\bFramework\ensureCompiled($this->app, Connection::sqlite($this->db)));
        self::assertFileDoesNotExist($this->app . '/storage/cache/.build_failed');
        self::assertSame($cur, (new CacheStore($this->app . '/storage/cache'))->current());
        self::assertContains('produk', $this->tables());
    }

    public function test_current_ada_tapi_tabel_hilang_tabel_dibuat_tabel_lama_tidak_disentuh(): void
    {
        $cur = $this->compile();
        $pdo = Connection::sqlite($this->db)->pdo();
        $pdo->exec('CREATE TABLE kategori (id INTEGER PRIMARY KEY, lama TEXT)');
        $pdo->exec("INSERT INTO kategori (lama) VALUES ('x')");
        self::assertTrue(\bFramework\ensureCompiled($this->app, Connection::sqlite($this->db)));
        self::assertContains('produk', $this->tables());
        self::assertSame('x', $pdo->query('SELECT lama FROM kategori')->fetchColumn());
        self::assertSame($cur, file_get_contents($this->app . '/storage/cache/.schema_ok'));
    }

    public function test_versi_baru_dari_builder_diberi_jendela_lalu_tabel_hilang_dibuat(): void
    {
        $cur = $this->compile();
        file_put_contents($this->app . '/storage/cache/.schema_ok', 'v_000000000000'); // versi lama siap
        self::assertTrue(\bFramework\ensureCompiled($this->app, Connection::sqlite($this->db)));
        self::assertSame([], $this->tables(), 'dalam jendela 30 detik migrasi milik builder');
        touch($this->app . '/storage/cache/' . $cur, time() - 31);
        self::assertTrue(\bFramework\ensureCompiled($this->app, Connection::sqlite($this->db)));
        self::assertSame([], array_diff($this->modelTables(), $this->tables()));
        self::assertSame($cur, file_get_contents($this->app . '/storage/cache/.schema_ok'));
    }

    public function test_compile_gagal_negative_cache_kedaluwarsa(): void
    {
        $f = $this->app . '/definitions/models/kategori.json';
        $good = (string) file_get_contents($f);
        file_put_contents($f, '{rusak');
        self::assertFalse(\bFramework\ensureCompiled($this->app, Connection::sqlite($this->db)));
        self::assertNull((new CacheStore($this->app . '/storage/cache'))->current());
        file_put_contents($f, $good);
        self::assertFalse(\bFramework\ensureCompiled($this->app, Connection::sqlite($this->db)));
        touch($this->app . '/storage/cache/.build_failed', time() - 61);
        self::assertTrue(\bFramework\ensureCompiled($this->app, Connection::sqlite($this->db)));
        self::assertNotNull((new CacheStore($this->app . '/storage/cache'))->current());
    }

    private function compile(): string
    {
        $r = (new Compiler(new CacheStore($this->app . '/storage/cache'), $this->app . '/extensions'))->build($this->app . '/definitions', Dialect::Sqlite);
        self::assertTrue($r->ok());
        return (string) $r->version;
    }

    /** @return list<string> */
    private function modelTables(): array
    {
        return array_map(static fn(string $f): string => basename($f, '.json'), glob($this->app . '/definitions/models/*.json') ?: []);
    }

    /** @return list<string> */
    private function tables(): array
    {
        $q = Connection::sqlite($this->db)->pdo()->query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name");
        return $q === false ? [] : array_values(array_map('strval', $q->fetchAll(\PDO::FETCH_COLUMN)));
    }
}
