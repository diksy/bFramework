<?php

declare(strict_types=1);

namespace bFramework\Update;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Dialect;
use bFramework\Contracts\FieldType;
use bFramework\Contracts\Logger;
use bFramework\Runtime\ColumnSpec;
use bFramework\Runtime\Connection;
use bFramework\Runtime\MigrationPlan;
use bFramework\Runtime\Migrator;
use bFramework\Runtime\TableSpec;

/**
 * Migrasi skema core via Migrator (M3). Tabel `migrations` mencatat id yang sudah jalan (idempoten, urut).
 * Migrasi destruktif (DROP/DELETE/TRUNCATE) dijadikan lossWarnings sehingga Migrator menolaknya: allowLoss
 * TIDAK PERNAH diaktifkan otomatis. Pencatatan id ada di dalam transaksi yang sama dengan SQL migrasi.
 */
final class UpdateMigrations
{
    public const TABLE = 'migrations';

    public function __construct(private readonly Connection $conn, private readonly ?Logger $logger = null)
    {
    }

    public static function spec(): TableSpec
    {
        return new TableSpec(self::TABLE, [
            'version' => new ColumnSpec(FieldType::String, false, null, 64, unique: true),
            'applied_at' => new ColumnSpec(FieldType::String, false, null, 32),
        ]);
    }

    public function ensureTable(): void
    {
        try {
            $st = $this->conn->pdo()->query('SELECT 1 FROM ' . self::TABLE . ' LIMIT 1');
            if ($st !== false) {
                $st->closeCursor();
            }
        } catch (\PDOException) {
            $m = new Migrator($this->conn, $this->conn->grammar(), $this->logger);
            $m->apply($m->planCreate(self::spec()));
        }
    }

    /** @return list<string> */
    public function applied(): array
    {
        $this->ensureTable();
        $st = $this->conn->pdo()->query('SELECT version FROM ' . self::TABLE . ' ORDER BY version');
        $out = [];
        if ($st !== false) {
            foreach ($st->fetchAll(\PDO::FETCH_COLUMN) as $v) {
                $out[] = (string) $v;
            }
        }
        return $out;
    }

    /**
     * @param list<array{id:string, sql:array{mysql:list<string>, sqlite:list<string>}}> $migrations
     * @return list<string> id yang dijalankan
     */
    public function run(array $migrations): array
    {
        $done = array_flip($this->applied());
        $ran = [];
        $m = new Migrator($this->conn, $this->conn->grammar(), $this->logger);
        $key = $this->conn->dialect() === Dialect::MySql ? 'mysql' : 'sqlite';
        foreach ($migrations as $mig) {
            if (isset($done[$mig['id']])) {
                continue; // idempoten
            }
            $sql = $mig['sql'][$key];
            $loss = [];
            foreach ($sql as $s) {
                if (preg_match('/\b(DROP|DELETE|TRUNCATE)\b/i', $s) === 1) {
                    $loss[] = 'Migrasi ' . $mig['id'] . ' berpotensi menghapus data';
                }
            }
            $sql[] = "INSERT INTO migrations (version, applied_at) VALUES ('" . $mig['id'] . "', '" . gmdate('Y-m-d\TH:i:s\Z') . "')";
            try {
                $m->apply(new MigrationPlan($sql, $loss), false);
            } catch (\Throwable $e) {
                $this->logger?->error('Migrasi update gagal', ['id' => $mig['id'], 'ex' => $e::class]);
                throw new UpdateException('migrasi_gagal');
            }
            $ran[] = $mig['id'];
        }
        return $ran;
    }
}
