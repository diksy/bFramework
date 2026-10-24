<?php

declare(strict_types=1);

namespace bFramework\Builder;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\FieldType;
use bFramework\Runtime\Connection;
use bFramework\Runtime\Definitions;
use bFramework\Runtime\IdentifierAllowlist;
use bFramework\Runtime\Query;
use bFramework\Runtime\Where;
use RuntimeException;

/**
 * Data contoh untuk live preview. HANYA data dummy yang dibangkitkan dari tipe field dan HANYA di mode dev.
 * Baris ditanam ke SQLite :memory: terpisah (tidak pernah ke database aplikasi) lalu dibaca lewat Query M3.
 */
final class Sampler
{
    private const WORDS = ['Alfa', 'Bravo', 'Cakra', 'Delta', 'Elang', 'Fajar', 'Gita', 'Harum'];
    private const TEXT = ['Contoh deskripsi pendek.', 'Teks uji untuk pratinjau.', 'Data dummy, bukan data asli.'];

    /**
     * @param array<string,mixed> $model hasil DefinitionSchema::model()
     * @return list<array<string,mixed>>
     */
    public static function seed(array $model, int $n, bool $devMode): array
    {
        if (!$devMode) {
            throw new RuntimeException('Sampler hanya tersedia di mode dev');
        }
        $n = max(1, min(20, $n));
        $spec = Definitions::tableSpec($model);
        $conn = Connection::sqlite(':memory:');
        foreach ($conn->grammar()->createTable($spec) as $sql) {
            $conn->pdo()->exec($sql);
        }
        $q = new Query($conn, $conn->grammar(), new IdentifierAllowlist([$spec]));
        $cols = array_keys($spec->cols);
        for ($i = 0; $i < $n; $i++) {
            $row = [];
            foreach ($spec->cols as $name => $c) {
                $row[(string) $name] = self::value($c->type, $c->length, $c->scale, $i, isset(((array) ($model['fields'] ?? []))[$name]['upload']));
            }
            if ($row !== []) {
                $q->insert($spec->name, $row);
            }
        }
        return $q->select($spec->name, array_merge(['id'], array_map('strval', $cols)), Where::none(), null, $n, 0);
    }

    private static function value(FieldType $t, int $len, int $scale, int $i, bool $isFile): int|string|null
    {
        if ($isFile) {
            return null;
        }
        $w = self::WORDS[$i % count(self::WORDS)];
        return match ($t) {
            FieldType::String => mb_substr($w . ' ' . ($i + 1), 0, $len),
            FieldType::Text => self::TEXT[$i % count(self::TEXT)],
            FieldType::Integer => (($i * 37) % 90) + 5,
            FieldType::Decimal => number_format((($i * 7919) % 90000) + 1000, $scale, '.', ''),
            FieldType::Boolean => $i % 3 === 0 ? 0 : 1,
            FieldType::Date => gmdate('Y-m-d', 1767225600 + $i * 9 * 86400),
            FieldType::Datetime => gmdate('Y-m-d H:i:s', 1767225600 + $i * 9 * 86400),
            FieldType::Relasi => ($i % 3) + 1,
            FieldType::Json => '{}',
        };
    }
}
