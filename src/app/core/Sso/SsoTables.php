<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Dialect;
use bFramework\Contracts\FieldType;
use bFramework\Runtime\ColumnSpec;
use bFramework\Runtime\Connection;
use bFramework\Runtime\IdentifierAllowlist;
use bFramework\Runtime\Migrator;
use bFramework\Runtime\TableSpec;

/**
 * Tabel core SSO (nama dicadangkan di decisions.md). Dibuat idempoten saat driver SSO diaktifkan, sehingga
 * instalasi lama tanpa tabel ini aman (hanya menambah tabel; tidak mengubah tabel yang ada).
 */
final class SsoTables
{
    public const SESSIONS = 'sso_sessions';
    public const REFRESH = 'sso_refresh_tokens';

    /** @return list<TableSpec> */
    public static function specs(): array
    {
        $int = new ColumnSpec(FieldType::Integer, false);
        $intN = new ColumnSpec(FieldType::Integer, true);
        $str = static fn(int $len, bool $unique = false): ColumnSpec => new ColumnSpec(FieldType::String, false, null, $len, 12, 2, $unique);
        return [
            new TableSpec(self::SESSIONS, [
                'user_id' => $int,
                'sid' => $str(255),
                'sub' => $str(255),
                'created_at' => $int,
                'revoked_at' => $intN,
            ]),
            new TableSpec(self::REFRESH, [
                'user_id' => new ColumnSpec(FieldType::Integer, false, null, 255, 12, 2, true),
                'token_sealed' => new ColumnSpec(FieldType::Text, false),
                'version' => $int,
                'updated_at' => $int,
            ]),
        ];
    }

    public static function allowlist(): IdentifierAllowlist
    {
        return new IdentifierAllowlist(self::specs());
    }

    /** @return list<string> tabel yang dibuat */
    public static function install(Connection $conn): array
    {
        $migrator = new Migrator($conn, $conn->grammar());
        $created = [];
        foreach (self::specs() as $spec) {
            $sql = $conn->dialect() === Dialect::Sqlite
                ? "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?"
                : 'SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?';
            $st = $conn->pdo()->prepare($sql);
            $st->execute([$spec->name]);
            if ($st->fetchColumn() !== false) {
                continue;
            }
            $migrator->apply($migrator->planCreate($spec));
            $created[] = $spec->name;
        }
        return $created;
    }
}
