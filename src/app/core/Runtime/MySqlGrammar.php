<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\FieldType;

final class MySqlGrammar extends AbstractGrammar
{
    public function quoteIdent(string $name): string
    {
        IdentifierAllowlist::assertShape($name);
        return '`' . $name . '`';
    }

    public function numericExpr(string $quoted): string
    {
        return $quoted;
    }

    public function nativeDecimal(): bool
    {
        return true;
    }

    protected function idDef(): string
    {
        return '`id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY';
    }

    protected function columnType(ColumnSpec $c): string
    {
        return match ($c->type) {
            FieldType::String => 'VARCHAR(' . $c->length . ')',
            FieldType::Text => 'TEXT',
            FieldType::Integer => 'BIGINT',
            FieldType::Decimal => 'DECIMAL(' . $c->precision . ',' . $c->scale . ')',
            FieldType::Boolean => 'TINYINT(1)',
            FieldType::Date => 'DATE',
            FieldType::Datetime => 'DATETIME',
            FieldType::Json => 'LONGTEXT',
            FieldType::Relasi => 'BIGINT UNSIGNED',
        };
    }

    public function alter(TableSpec $old, TableSpec $new): array
    {
        if ($old->name !== $new->name) {
            throw new \InvalidArgumentException('Nama tabel harus sama');
        }
        $t = $this->quoteIdent($new->name);
        $sql = [];
        foreach ($old->cols as $n => $_) {
            if (!isset($new->cols[$n])) {
                $sql[] = "ALTER TABLE $t DROP COLUMN " . $this->quoteIdent((string) $n);
            }
        }
        foreach ($new->cols as $n => $c) {
            $n = (string) $n;
            if (!isset($old->cols[$n])) {
                $sql[] = "ALTER TABLE $t ADD COLUMN " . $this->columnDef($n, $c);
            } elseif ($old->cols[$n] != $c) {
                $sql[] = "ALTER TABLE $t MODIFY COLUMN " . $this->columnDef($n, $c);
            }
        }
        return $sql;
    }
}
