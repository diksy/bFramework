<?php

declare(strict_types=1);

namespace bFramework\Builder;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Clock;
use bFramework\Contracts\FieldType;
use bFramework\Contracts\Logger;
use bFramework\Runtime\ColumnSpec;
use bFramework\Runtime\Connection;
use bFramework\Runtime\IdentifierAllowlist;
use bFramework\Runtime\Migrator;
use bFramework\Runtime\Query;
use bFramework\Runtime\TableSpec;
use Throwable;

/**
 * Jejak audit builder (tabel cadangan `audit_log`). Hanya metadata: waktu, pelaku (id), aksi, target (path
 * definisi), IP. Tidak pernah isi definisi, kata sandi, atau token. Kegagalan mencatat tidak menggagalkan request.
 */
final class AuditLog
{
    public const TABLE = 'audit_log';
    private bool $ready = false;

    public function __construct(private readonly Connection $conn, private readonly Clock $clock, private readonly ?Logger $logger = null)
    {
    }

    public static function spec(): TableSpec
    {
        $s = static fn(int $len, bool $null = false): ColumnSpec => new ColumnSpec(FieldType::String, $null, null, $len);
        return new TableSpec(self::TABLE, [
            'at' => new ColumnSpec(FieldType::Integer, false),
            'actor' => new ColumnSpec(FieldType::Integer, true),
            'action' => $s(64),
            'target' => $s(200, true),
            'ip' => $s(45, true),
        ]);
    }

    public function record(?int $actor, string $action, ?string $target = null, string $ip = ''): void
    {
        try {
            $this->ensure();
            $q = new Query($this->conn, $this->conn->grammar(), new IdentifierAllowlist([self::spec()]), $this->logger);
            $q->insert(self::TABLE, [
                'at' => $this->clock->now()->getTimestamp(),
                'actor' => $actor,
                'action' => self::safe($action, 64),
                'target' => $target === null ? null : self::safe($target, 200),
                'ip' => $ip === '' ? null : self::safe($ip, 45),
            ]);
        } catch (Throwable $e) {
            $this->logger?->error('Audit log gagal ditulis', ['class' => $e::class]);
        }
    }

    /** @return list<array<string,mixed>> entri terbaru (untuk tes/diagnosa) */
    public function recent(int $n = 50): array
    {
        $this->ensure();
        $q = new Query($this->conn, $this->conn->grammar(), new IdentifierAllowlist([self::spec()]), $this->logger);
        return $q->select(self::TABLE, ['id', 'at', 'actor', 'action', 'target', 'ip'], \bFramework\Runtime\Where::none(), null, $n, 0);
    }

    private function ensure(): void
    {
        if ($this->ready) {
            return;
        }
        try {
            $this->conn->pdo()->query('SELECT 1 FROM ' . self::TABLE . ' LIMIT 1');
        } catch (\PDOException) {
            $m = new Migrator($this->conn, $this->conn->grammar(), $this->logger);
            $m->apply($m->planCreate(self::spec()));
        }
        $this->ready = true;
    }

    private static function safe(string $s, int $max): string
    {
        return mb_substr((string) preg_replace('/[\x00-\x1F\x7F]/u', '?', $s), 0, $max);
    }
}
