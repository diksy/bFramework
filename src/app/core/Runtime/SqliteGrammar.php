<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\FieldType;

final class SqliteGrammar extends AbstractGrammar
{
    public function quoteIdent(string $name): string
    {
        IdentifierAllowlist::assertShape($name);
        return '"' . $name . '"';
    }

    /** Decimal disimpan TEXT (numeric-string); urutan/perbandingan memakai CAST REAL (eksak hingga ~15 digit). */
    public function numericExpr(string $quoted): string
    {
        return 'CAST(' . $quoted . ' AS REAL)';
    }

    public function nativeDecimal(): bool
    {
        return false;
    }

    protected function idDef(): string
    {
        return '"id" INTEGER PRIMARY KEY AUTOINCREMENT';
    }

    protected function columnType(ColumnSpec $c): string
    {
        return match ($c->type) {
            FieldType::Integer, FieldType::Boolean, FieldType::Relasi => 'INTEGER',
            // decimal disimpan TEXT agar tetap numeric-string (tidak jadi float)
            default => 'TEXT',
        };
    }

    public function alter(TableSpec $old, TableSpec $new): array
    {
        if ($old->name !== $new->name) {
            throw new \InvalidArgumentException('Nama tabel harus sama');
        }
        $t = $this->quoteIdent($new->name);
        $simple = true;
        foreach ($old->cols as $n => $c) {
            if (!isset($new->cols[$n]) || $new->cols[$n] != $c) {
                $simple = false;
            }
        }
        if ($simple) {
            $sql = [];
            foreach ($new->cols as $n => $c) {
                if (isset($old->cols[$n])) {
                    continue;
                }
                if ((!$c->nullable && $c->default === null) || $c->unique) {
                    $simple = false;
                    break;
                }
                $sql[] = "ALTER TABLE $t ADD COLUMN " . $this->columnDef((string) $n, $c);
            }
            if ($simple) {
                return $sql;
            }
        }
        return $this->rebuild($old, $new);
    }

    /**
     * Pola rebuild (ARCH-05): buat tabel baru, salin data, hapus lama, ganti nama.
     * @return list<string>
     */
    private function rebuild(TableSpec $old, TableSpec $new): array
    {
        $tmp = new TableSpec('_rb_' . substr($new->name, 0, 55), $new->cols);
        $create = $this->createTable($tmp)[0];
        $copy = ['id'];
        $sel = [$this->quoteIdent('id')];
        foreach ($new->cols as $n => $c) {
            $n = (string) $n;
            if (!isset($old->cols[$n])) {
                continue;
            }
            $copy[] = $n;
            $q = $this->quoteIdent($n);
            $sel[] = $old->cols[$n]->type === $c->type
                ? $q
                : 'CAST(' . $q . ' AS ' . $this->columnType($c) . ')';
        }
        $ins = array_map(fn (string $x): string => $this->quoteIdent($x), $copy);
        return [
            $create,
            'INSERT INTO ' . $this->quoteIdent($tmp->name) . ' (' . implode(', ', $ins) . ') SELECT '
                . implode(', ', $sel) . ' FROM ' . $this->quoteIdent($old->name),
            'DROP TABLE ' . $this->quoteIdent($old->name),
            'ALTER TABLE ' . $this->quoteIdent($tmp->name) . ' RENAME TO ' . $this->quoteIdent($new->name),
        ];
    }
}
