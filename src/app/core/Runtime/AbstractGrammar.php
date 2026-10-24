<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\FieldType;

abstract class AbstractGrammar implements Grammar
{
    abstract protected function columnType(ColumnSpec $c): string;

    abstract protected function idDef(): string;

    abstract public function quoteIdent(string $name): string;

    abstract public function alter(TableSpec $old, TableSpec $new): array;

    protected function columnDef(string $name, ColumnSpec $c): string
    {
        if (($c->type === FieldType::Text || $c->type === FieldType::Json) && ($c->default !== null || $c->unique)) {
            throw new \InvalidArgumentException('Kolom text/json tidak boleh memakai default atau unique (tidak portabel di MySQL)');
        }
        $sql = $this->quoteIdent($name) . ' ' . $this->columnType($c);
        if (!$c->nullable) {
            $sql .= ' NOT NULL';
        }
        if ($c->default !== null) {
            $sql .= ' DEFAULT ' . $this->literal($c);
        }
        if ($c->unique) {
            $sql .= ' UNIQUE';
        }
        return $sql;
    }

    /** Default dibatasi: angka/boolean/string aman; string di-escape sebagai literal SQL standar. */
    private function literal(ColumnSpec $c): string
    {
        $d = (string) $c->default;
        switch ($c->type) {
            case FieldType::Integer:
            case FieldType::Relasi:
            case FieldType::Boolean:
                if (preg_match('/^-?[0-9]{1,18}$/D', $d) !== 1) {
                    throw new \InvalidArgumentException('Default integer tidak valid');
                }
                return $d;
            case FieldType::Decimal:
                if (preg_match('/^-?[0-9]{1,30}(\.[0-9]{1,30})?$/D', $d) !== 1) {
                    throw new \InvalidArgumentException('Default decimal tidak valid');
                }
                return "'" . $d . "'";
            default:
                if (str_contains($d, "\0") || str_contains($d, '\\')) {
                    throw new \InvalidArgumentException('Default mengandung karakter terlarang');
                }
                return "'" . str_replace("'", "''", $d) . "'";
        }
    }

    public function createTable(TableSpec $t): array
    {
        $defs = [$this->idDef()];
        foreach ($t->cols as $n => $c) {
            $defs[] = $this->columnDef((string) $n, $c);
        }
        return ['CREATE TABLE ' . $this->quoteIdent($t->name) . ' (' . implode(', ', $defs) . ')'];
    }

    /** @return list<string> */
    public function lossWarnings(TableSpec $old, TableSpec $new): array
    {
        $w = [];
        foreach ($old->cols as $n => $c) {
            if (!isset($new->cols[$n])) {
                $w[] = "Kolom $n dihapus: datanya hilang";
                continue;
            }
            $nc = $new->cols[$n];
            if ($nc->type !== $c->type) {
                $w[] = "Kolom $n berubah tipe {$c->type->value} -> {$nc->type->value}: data dapat terpotong";
            } elseif ($nc->length < $c->length && $c->type === FieldType::String) {
                $w[] = "Kolom $n diperpendek: data dapat terpotong";
            } elseif ($c->nullable && !$nc->nullable) {
                $w[] = "Kolom $n menjadi NOT NULL: baris bernilai NULL dapat gagal";
            }
        }
        return $w;
    }
}
