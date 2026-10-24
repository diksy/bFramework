<?php

declare(strict_types=1);

namespace bFramework\Tests\Runtime;

use bFramework\Contracts\FieldType as T;
use bFramework\Runtime\ColumnSpec;
use bFramework\Runtime\Connection;
use bFramework\Runtime\IdentifierAllowlist;
use bFramework\Runtime\InvalidIdentifier;
use bFramework\Runtime\Migrator;
use bFramework\Runtime\MySqlGrammar;
use bFramework\Runtime\Query;
use bFramework\Runtime\Sort;
use bFramework\Runtime\SqliteGrammar;
use bFramework\Runtime\TableSpec;
use bFramework\Runtime\Where;
use PHPUnit\Framework\TestCase;

final class DatabaseTest extends TestCase
{
    private string $file;
    private Connection $conn;

    protected function setUp(): void
    {
        $this->file = sys_get_temp_dir() . '/app_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->conn = Connection::sqlite($this->file);
    }

    protected function tearDown(): void
    {
        unset($this->conn);
        foreach ([$this->file, $this->file . '-journal'] as $f) {
            if (is_file($f)) {
                unlink($f);
            }
        }
    }

    private function spec(): TableSpec
    {
        return new TableSpec('produk', [
            'nama' => new ColumnSpec(T::String, false),
            'harga' => new ColumnSpec(T::Decimal, true, null, 255, 12, 2),
            'aktif' => new ColumnSpec(T::Boolean, false, '1'),
        ]);
    }

    private function q(?TableSpec $s = null): Query
    {
        $s ??= $this->spec();
        return new Query($this->conn, new SqliteGrammar(), new IdentifierAllowlist([$s]));
    }

    private function create(TableSpec $s): void
    {
        $m = new Migrator($this->conn, new SqliteGrammar());
        $m->apply($m->planCreate($s));
    }

    public function test_ARCH_04_tipe_di_luar_irisan_gagal(): void
    {
        self::assertNull(T::tryFrom('enum'));
        self::assertCount(9, T::cases());
    }

    public function test_ARCH_05_grammar_mysql_dan_sqlite_membuat_tabel(): void
    {
        $my = (new MySqlGrammar())->createTable($this->spec())[0];
        self::assertStringContainsString('`nama` VARCHAR(255) NOT NULL', $my);
        self::assertStringContainsString('DECIMAL(12,2)', $my);
        self::assertStringContainsString('TINYINT(1)', $my);
        $sq = (new SqliteGrammar())->createTable($this->spec())[0];
        self::assertStringContainsString('"id" INTEGER PRIMARY KEY AUTOINCREMENT', $sq);
        $this->create($this->spec());
        self::assertSame(0, $this->q()->count('produk', Where::none()));
    }

    public function test_ARCH_05_alter_mysql(): void
    {
        $old = $this->spec();
        $new = new TableSpec('produk', [
            'nama' => new ColumnSpec(T::Text, false),
            'stok' => new ColumnSpec(T::Integer),
        ]);
        $sql = (new MySqlGrammar())->alter($old, $new);
        self::assertContains('ALTER TABLE `produk` DROP COLUMN `harga`', $sql);
        self::assertContains('ALTER TABLE `produk` ADD COLUMN `stok` BIGINT', $sql);
        self::assertContains('ALTER TABLE `produk` MODIFY COLUMN `nama` TEXT NOT NULL', $sql);
    }

    public function test_ARCH_05_sqlite_ubah_tipe_kolom_tanpa_kehilangan_data(): void
    {
        $old = new TableSpec('produk', [
            'nama' => new ColumnSpec(T::String, false),
            'stok' => new ColumnSpec(T::String),
        ]);
        $this->create($old);
        $q = $this->q($old);
        $q->insert('produk', ['nama' => 'Kopi', 'stok' => '42']);
        $q->insert('produk', ['nama' => 'Teh', 'stok' => '7']);

        $new = new TableSpec('produk', [
            'nama' => new ColumnSpec(T::String, false),
            'stok' => new ColumnSpec(T::Integer),
            'catatan' => new ColumnSpec(T::Text),
        ]);
        $m = new Migrator($this->conn, new SqliteGrammar());
        $plan = $m->plan($old, $new);
        self::assertNotSame([], $plan->lossWarnings);
        self::assertCount(4, $plan->sql); // rebuild
        $m->apply($plan, true);

        $rows = $this->q($new)->select('produk', ['id', 'nama', 'stok', 'catatan'], Where::none(), new Sort('id'), 10, 0);
        self::assertCount(2, $rows);
        self::assertSame('Kopi', $rows[0]['nama']);
        self::assertSame(42, $rows[0]['stok']);
        self::assertSame(7, $rows[1]['stok']);
        self::assertNull($rows[0]['catatan']);
    }

    public function test_ARCH_05_tambah_kolom_nullable_pakai_add_column_dan_hapus_kolom_memberi_peringatan(): void
    {
        $old = $this->spec();
        $add = new TableSpec('produk', $old->cols + ['warna' => new ColumnSpec(T::String)]);
        $m = new Migrator($this->conn, new SqliteGrammar());
        $p = $m->plan($old, $add);
        self::assertCount(1, $p->sql);
        self::assertStringStartsWith('ALTER TABLE "produk" ADD COLUMN', $p->sql[0]);
        self::assertSame([], $p->lossWarnings);

        $drop = new TableSpec('produk', ['nama' => $old->cols['nama']]);
        self::assertNotSame([], $m->plan($old, $drop)->lossWarnings);
        $this->create($old);
        $this->expectException(\RuntimeException::class);
        $m->apply($m->plan($old, $drop)); // tanpa konfirmasi ditolak
    }

    public function test_ARCH_05_apply_rollback_bila_gagal(): void
    {
        $this->create($this->spec());
        $m = new Migrator($this->conn, new SqliteGrammar());
        $plan = new \bFramework\Runtime\MigrationPlan(['ALTER TABLE "produk" ADD COLUMN "x" TEXT', 'SELEKSI RUSAK']);
        try {
            $m->apply($plan);
            self::fail('harus gagal');
        } catch (\bFramework\Runtime\DatabaseError) {
        }
        $cols = array_column($this->conn->pdo()->query('PRAGMA table_info("produk")')->fetchAll(), 'name'); // @phpstan-ignore-line
        self::assertNotContains('x', $cols);
    }

    public function test_SEC_DATA_01_nilai_injeksi_hanya_data(): void
    {
        $this->create($this->spec());
        $q = $this->q();
        $evil = "x'); DROP TABLE produk; --";
        $q->insert('produk', ['nama' => $evil]);
        $rows = $q->select('produk', ['nama'], new Where([['nama', '=', "' OR 1=1 --"]]), null, 10, 0);
        self::assertSame([], $rows);
        $rows = $q->select('produk', ['nama'], new Where([['nama', '=', $evil]]), null, 10, 0);
        self::assertSame($evil, $rows[0]['nama']);
        self::assertSame(1, $q->count('produk', new Where([['nama', 'in', [$evil, "1' OR '1'='1"]]])));
        self::assertSame(1, $q->update('produk', ['nama' => "a'b"], new Where([['id', '=', 1]])));
        self::assertSame(1, $q->delete('produk', new Where([['id', '=', '1 OR 1=1']])) + 1);
    }

    /** @return array<string,array{string}> */
    public static function badIdents(): array
    {
        return [
            'drop' => ['nama; DROP TABLE produk'],
            'quote' => ['nama"'],
            'backtick' => ['nama`'],
            'komentar' => ['nama--'],
            'diluar definisi' => ['password_hash'],
            'kosong' => [''],
            'subquery' => ['(SELECT 1)'],
        ];
    }

    /** @dataProvider badIdents */
    public function test_SEC_DATA_01_kolom_filter_sort_dan_select_di_luar_definisi_ditolak(string $bad): void
    {
        $this->create($this->spec());
        $q = $this->q();
        foreach ([
            fn () => $q->select('produk', ['nama'], new Where([[$bad, '=', 1]]), null, 5, 0),
            fn () => $q->select('produk', ['nama'], Where::none(), new Sort($bad), 5, 0),
            fn () => $q->select('produk', [$bad], Where::none(), null, 5, 0),
            fn () => $q->insert('produk', [$bad => 'x']),
            fn () => $q->update('produk', [$bad => 'x'], new Where([['id', '=', 1]])),
            fn () => $q->aggregate('produk', 'count', $bad, Where::none()),
        ] as $f) {
            try {
                $f();
                self::fail('harus ditolak');
            } catch (InvalidIdentifier) {
                self::addToAssertionCount(1);
            }
        }
        self::assertSame(0, $q->count('produk', Where::none())); // tabel utuh
    }

    public function test_SEC_DATA_01_tabel_di_luar_definisi_dan_quote_ditolak(): void
    {
        $q = $this->q();
        foreach (['sqlite_master', 'produk; DROP TABLE produk', 'users'] as $t) {
            try {
                $q->count($t, Where::none());
                self::fail('harus ditolak');
            } catch (InvalidIdentifier) {
                self::addToAssertionCount(1);
            }
        }
        $this->expectException(InvalidIdentifier::class);
        (new SqliteGrammar())->quoteIdent('a"b');
    }

    public function test_SEC_DATA_01_identifier_tablespec_ber_injeksi_ditolak(): void
    {
        $this->expectException(InvalidIdentifier::class);
        new TableSpec('t', ['a" TEXT); DROP TABLE t; --' => new ColumnSpec(T::String)]);
    }

    public function test_SEC_DATA_01_operator_arah_fungsi_dan_default_dibatasi(): void
    {
        $this->create($this->spec());
        $q = $this->q();
        foreach ([
            fn () => new Where([['nama', '= 1 OR 1=1 --', 'x']]),
            fn () => new Sort('nama', 'asc; DROP'),
            fn () => $q->aggregate('produk', 'count(*);--', 'nama', Where::none()),
            fn () => $q->update('produk', ['nama' => 'x'], Where::none()),
            fn () => $q->delete('produk', Where::none()),
            fn () => $q->insert('produk', ['harga' => 1.5]),
        ] as $f) {
            try {
                $f();
                self::fail('harus ditolak');
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
        $bad = new TableSpec('t', ['a' => new ColumnSpec(T::String, true, "x'; DROP TABLE t; --\\")]);
        $this->expectException(\InvalidArgumentException::class);
        (new SqliteGrammar())->createTable($bad);
    }

    public function test_decimal_numeric_string_dan_boolean_serta_agregat(): void
    {
        $this->create($this->spec());
        $q = $this->q();
        $q->insert('produk', ['nama' => 'A', 'harga' => '12345678.10', 'aktif' => true]);
        $q->insert('produk', ['nama' => 'B', 'harga' => '0.20', 'aktif' => false]);
        $r = $q->select('produk', ['harga', 'aktif'], new Where([['aktif', '=', true]]), null, 10, 0);
        self::assertSame('12345678.10', $r[0]['harga']);
        self::assertSame(1, $r[0]['aktif']);
        self::assertSame(2, $q->count('produk', Where::none()));
        self::assertSame('2', $q->aggregate('produk', 'count', 'id', Where::none()));
        self::assertNull($q->aggregate('produk', 'max', 'nama', new Where([['id', '=', 999]])));
    }

    public function test_koneksi_gagal_tidak_membocorkan_path_atau_sandi(): void
    {
        try {
            Connection::mysql('bad host;', 'db', 'u', 'rahasia123');
            self::fail();
        } catch (\RuntimeException $e) {
            self::assertStringNotContainsString('rahasia123', $e->getMessage());
        }
        try {
            Connection::sqlite('/nonexistent_dir_xyz/a.sqlite');
            self::fail();
        } catch (\RuntimeException $e) {
            self::assertStringNotContainsString('nonexistent', $e->getMessage());
        }
    }

    public function test_decimal_sort_compare_dan_agregat_numerik(): void
    {
        $this->create($this->spec());
        $q = $this->q();
        foreach (['10.00', '9.00', '0.10', '-2.50', '123456789.99'] as $i => $h) {
            $q->insert('produk', ['nama' => "P$i", 'harga' => $h]);
        }
        $q->insert('produk', ['nama' => 'N']);
        $r = $q->select('produk', ['harga'], new Where([['harga', 'notnull']]), new Sort('harga', 'asc'), 10, 0);
        self::assertSame(['-2.50', '0.10', '9.00', '10.00', '123456789.99'], array_column($r, 'harga'));
        $r = $q->select('produk', ['harga'], new Where([['harga', '>', '9.5']]), new Sort('harga', 'desc'), 10, 0);
        self::assertSame(['123456789.99', '10.00'], array_column($r, 'harga'));
        self::assertSame('123456806.59', $q->aggregate('produk', 'sum', 'harga', Where::none()));
        self::assertSame('-2.50', $q->aggregate('produk', 'min', 'harga', Where::none()));
        self::assertSame('123456789.99', $q->aggregate('produk', 'max', 'harga', Where::none()));
        self::assertSame('24691361.318000', $q->aggregate('produk', 'avg', 'harga', Where::none()));
        self::assertSame('-2.40', $q->aggregate('produk', 'sum', 'harga', new Where([['harga', '<', '1']])));
    }

    private function bigSpec(): TableSpec
    {
        return new TableSpec('produk', [
            'nama' => new ColumnSpec(T::String, false),
            'harga' => new ColumnSpec(T::Decimal, true, null, 255, 18, 0),
        ]);
    }

    public function test_decimal_avg_mendekati_batas_dan_negatif(): void
    {
        $s = $this->bigSpec();
        $this->create($s);
        $q = $this->q($s);
        $lim = (string) intdiv(PHP_INT_MAX, 10000);
        $q->insert('produk', ['nama' => 'a', 'harga' => $lim]);
        self::assertSame($lim . '.0000', $q->aggregate('produk', 'avg', 'harga', Where::none()));
        $q->delete('produk', new Where([['nama', '=', 'a']]));
        $q->insert('produk', ['nama' => 'a', 'harga' => '-' . $lim]);
        self::assertSame('-' . $lim . '.0000', $q->aggregate('produk', 'avg', 'harga', Where::none()));
        $q->insert('produk', ['nama' => 'b', 'harga' => '-1']);
        try {
            $q->aggregate('produk', 'avg', 'harga', Where::none());
            self::fail('harus RangeException');
        } catch (\RangeException) {
            self::addToAssertionCount(1);
        }
    }

    public function test_decimal_avg_negatif_dibulatkan_menjauhi_nol(): void
    {
        $this->create($this->spec());
        $q = $this->q();
        foreach (['-0.01', '-0.02', '-0.02'] as $i => $h) {
            $q->insert('produk', ['nama' => "P$i", 'harga' => $h]);
        }
        self::assertSame('-0.016667', $q->aggregate('produk', 'avg', 'harga', Where::none()));
    }

    public function test_decimal_sum_overflow_melempar_range_exception(): void
    {
        $s = $this->bigSpec();
        $this->create($s);
        $q = $this->q($s);
        for ($i = 0; $i < 10; $i++) {
            $q->insert('produk', ['nama' => "P$i", 'harga' => '999999999999999999']);
        }
        $this->expectException(\RangeException::class);
        $q->aggregate('produk', 'sum', 'harga', Where::none());
    }

    public function test_decimal_agregat_semua_null_mengembalikan_null(): void
    {
        $this->create($this->spec());
        $q = $this->q();
        $q->insert('produk', ['nama' => 'A']);
        $q->insert('produk', ['nama' => 'B']);
        foreach (['sum', 'avg', 'min', 'max'] as $f) {
            self::assertNull($q->aggregate('produk', $f, 'harga', Where::none()), $f);
        }
    }

    public function test_pdo_exception_dibungkus_tanpa_sql_atau_nilai(): void
    {
        $q = $this->q(); // tabel belum dibuat -> PDOException
        $log = new class () implements \bFramework\Contracts\Logger {
            /** @var list<string> */
            public array $lines = [];
            public function error(string $msg, array $ctx = []): void
            {
                $this->lines[] = $msg . json_encode($ctx);
            }
            public function warning(string $msg, array $ctx = []): void
            {
            }
            public function info(string $msg, array $ctx = []): void
            {
            }
        };
        $q = new Query($this->conn, new SqliteGrammar(), new IdentifierAllowlist([$this->spec()]), $log);
        try {
            $q->insert('produk', ['nama' => 'RAHASIA-NILAI']);
            self::fail();
        } catch (\bFramework\Runtime\DatabaseError $e) {
            self::assertStringNotContainsString('produk', $e->getMessage());
            self::assertStringNotContainsString('RAHASIA', $e->getMessage());
            self::assertNull($e->getPrevious());
        }
        self::assertStringNotContainsString('RAHASIA', implode('', $log->lines));
        self::assertStringNotContainsString('produk', implode('', $log->lines));
        $m = new Migrator($this->conn, new SqliteGrammar());
        try {
            $m->apply(new \bFramework\Runtime\MigrationPlan(['SELECT rahasia_kolom FROM tabel_x']));
            self::fail();
        } catch (\bFramework\Runtime\DatabaseError $e) {
            self::assertStringNotContainsString('rahasia_kolom', $e->getMessage());
        }
    }

    public function test_text_json_dengan_default_atau_unique_ditolak(): void
    {
        foreach ([new SqliteGrammar(), new MySqlGrammar()] as $g) {
            foreach ([T::Text, T::Json] as $type) {
                foreach ([new ColumnSpec($type, true, 'x'), new ColumnSpec($type, true, null, 255, 12, 2, true)] as $c) {
                    try {
                        $g->createTable(new TableSpec('t', ['a' => $c]));
                        self::fail();
                    } catch (\InvalidArgumentException) {
                    }
                }
                self::assertCount(1, $g->createTable(new TableSpec('t', ['a' => new ColumnSpec($type)])));
            }
        }
        self::assertCount(1, (new MySqlGrammar())->createTable(new TableSpec('t', ['a' => new ColumnSpec(T::String, true, 'x', 50, 12, 2, true)])));
    }
}
