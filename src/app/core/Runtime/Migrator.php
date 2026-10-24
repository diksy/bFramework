<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Logger;
use RuntimeException;

final class Migrator
{
    public function __construct(private readonly Connection $conn, private readonly Grammar $grammar, private readonly ?Logger $logger = null)
    {
    }

    /** $old tanpa kolom dan tabel belum ada = CREATE; gunakan planCreate() untuk eksplisit. */
    public function plan(TableSpec $old, TableSpec $new): MigrationPlan
    {
        return new MigrationPlan(
            $this->grammar->alter($old, $new),
            $this->grammar->lossWarnings($old, $new)
        );
    }

    public function planCreate(TableSpec $new): MigrationPlan
    {
        return new MigrationPlan($this->grammar->createTable($new));
    }

    /** Menolak rencana dengan peringatan kehilangan data kecuali $allowLoss. Dalam transaksi. */
    public function apply(MigrationPlan $plan, bool $allowLoss = false): void
    {
        if ($plan->lossWarnings !== [] && !$allowLoss) {
            throw new RuntimeException('Migrasi berpotensi kehilangan data: konfirmasi diperlukan');
        }
        $pdo = $this->conn->pdo();
        try {
            $pdo->beginTransaction();
            foreach ($plan->sql as $s) {
                $pdo->exec($s);
            }
            if ($pdo->inTransaction()) { // MySQL: DDL meng-commit implisit
                $pdo->commit();
            }
        } catch (\PDOException $e) {
            $this->logger?->error('Migrasi gagal', ['class' => $e::class, 'sqlstate' => (string) $e->getCode()]);
            try {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
            } catch (\PDOException) {
            }
            throw new DatabaseError();
        }
    }
}
