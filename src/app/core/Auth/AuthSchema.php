<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Dialect;
use bFramework\Runtime\Connection;
use bFramework\Runtime\Migrator;

/** Membuat tabel core autentikasi yang belum ada (idempoten); dipakai installer (M13) dan tes. */
final class AuthSchema
{
    /** @return list<string> nama tabel yang dibuat */
    public static function install(Connection $conn): array
    {
        $migrator = new Migrator($conn, $conn->grammar());
        $created = [];
        foreach (AuthTables::specs() as $spec) {
            if (self::exists($conn, $spec->name)) {
                continue;
            }
            $migrator->apply($migrator->planCreate($spec));
            $created[] = $spec->name;
        }
        return $created;
    }

    private static function exists(Connection $conn, string $table): bool
    {
        $sql = $conn->dialect() === Dialect::Sqlite
            ? "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?"
            : 'SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?';
        $st = $conn->pdo()->prepare($sql);
        $st->execute([$table]);
        return $st->fetchColumn() !== false;
    }
}
