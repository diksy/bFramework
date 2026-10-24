<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Logger;
use PDOException;
use PDOStatement;

final class Query
{
    private const AGG = ['count', 'sum', 'avg', 'min', 'max'];

    public function __construct(
        private readonly Connection $conn,
        private readonly Grammar $grammar,
        private readonly IdentifierAllowlist $allow,
        private readonly ?Logger $logger = null,
    ) {
    }

    /**
     * @param list<string> $cols
     * @return list<array<string,mixed>>
     */
    public function select(string $table, array $cols, Where $w, ?Sort $s, int $limit, int $offset): array
    {
        if ($cols === []) {
            throw new \InvalidArgumentException('Kolom select kosong');
        }
        $t = $this->tbl($table);
        $list = [];
        foreach ($cols as $c) {
            $list[] = $this->col($table, $c);
        }
        [$where, $bind] = $this->where($table, $w);
        $sql = 'SELECT ' . implode(', ', $list) . " FROM $t" . $where;
        if ($s !== null) {
            $sql .= ' ORDER BY ' . $this->num($table, $s->column) . ($s->desc ? ' DESC' : ' ASC');
        }
        $sql .= ' LIMIT ' . max(0, min($limit, 10000)) . ' OFFSET ' . max(0, $offset);
        /** @var list<array<string,mixed>> $rows */
        $rows = $this->run($sql, $bind)->fetchAll();
        return $rows;
    }

    /** @param array<string,mixed> $values */
    public function insert(string $table, array $values): int
    {
        if ($values === []) {
            throw new \InvalidArgumentException('Nilai insert kosong');
        }
        $t = $this->tbl($table);
        $cols = [];
        $bind = [];
        foreach ($values as $c => $v) {
            $cols[] = $this->col($table, (string) $c);
            $bind[] = $this->val($v);
        }
        $this->run("INSERT INTO $t (" . implode(', ', $cols) . ') VALUES (' . implode(', ', array_fill(0, count($cols), '?')) . ')', $bind);
        return (int) $this->conn->pdo()->lastInsertId();
    }

    /** @param array<string,mixed> $values */
    public function update(string $table, array $values, Where $w): int
    {
        if ($values === [] || $w->isEmpty()) {
            throw new \InvalidArgumentException('Update memerlukan nilai dan kondisi');
        }
        $t = $this->tbl($table);
        $set = [];
        $bind = [];
        foreach ($values as $c => $v) {
            $set[] = $this->col($table, (string) $c) . ' = ?';
            $bind[] = $this->val($v);
        }
        [$where, $wb] = $this->where($table, $w);
        return $this->run("UPDATE $t SET " . implode(', ', $set) . $where, array_merge($bind, $wb))->rowCount();
    }

    public function delete(string $table, Where $w): int
    {
        if ($w->isEmpty()) {
            throw new \InvalidArgumentException('Delete memerlukan kondisi');
        }
        $t = $this->tbl($table);
        [$where, $bind] = $this->where($table, $w);
        return $this->run("DELETE FROM $t" . $where, $bind)->rowCount();
    }

    public function count(string $table, Where $w): int
    {
        $t = $this->tbl($table);
        [$where, $bind] = $this->where($table, $w);
        return (int) $this->run("SELECT COUNT(*) FROM $t" . $where, $bind)->fetchColumn();
    }

    /** Hasil sebagai string numerik (bukan float) atau null. */
    public function aggregate(string $table, string $fn, string $column, Where $w): ?string
    {
        $f = strtolower($fn);
        if (!in_array($f, self::AGG, true)) {
            throw new \InvalidArgumentException('Fungsi agregat tidak diizinkan');
        }
        $t = $this->tbl($table);
        $c = $this->col($table, $column);
        [$where, $bind] = $this->where($table, $w);
        if ($f !== 'count' && !$this->grammar->nativeDecimal() && $this->allow->isDecimal($table, $column)) {
            return $this->decimalAggregate($f, $table, $c, $this->allow->scale($table, $column), $where, $bind);
        }
        $v = $this->run('SELECT ' . strtoupper($f) . "($c) FROM $t" . $where, $bind)->fetchColumn();
        return $v === false || $v === null ? null : (string) $v;
    }

    /**
     * Agregat decimal eksak tanpa float untuk DB tanpa tipe decimal native (SQLite):
     * dihitung sebagai integer berskala; hasil string numerik.
     *
     * @param list<int|string|null> $bind
     */
    private function decimalAggregate(string $f, string $table, string $c, int $scale, string $where, array $bind): ?string
    {
        $t = $this->tbl($table);
        $cond = $where === '' ? " WHERE $c IS NOT NULL" : $where . " AND $c IS NOT NULL";
        $rows = $this->run("SELECT $c FROM $t" . $cond, $bind)->fetchAll(\PDO::FETCH_COLUMN);
        if ($rows === []) {
            return null;
        }
        $ints = [];
        foreach ($rows as $r) {
            $ints[] = $this->scaled((string) $r, $scale);
        }
        $outScale = $scale;
        if ($f === 'min' || $f === 'max') {
            $v = $f === 'min' ? min($ints) : max($ints);
        } else {
            $v = 0;
            foreach ($ints as $i) {
                $v += $i;
                if (!is_int($v) || $v === PHP_INT_MIN) {
                    throw new \RangeException('Agregat decimal melebihi rentang');
                }
            }
            if ($f === 'avg') {
                $outScale = $scale + 4;
                $n = count($ints);
                $lim = intdiv(PHP_INT_MAX, 10000);
                if ($v > $lim || $v < -$lim) {
                    throw new \RangeException('Agregat decimal melebihi rentang');
                }
                $abs = ($v < 0 ? -$v : $v) * 10000; // <= PHP_INT_MAX, tetap int
                $q = intdiv($abs, $n);
                if (($abs % $n) * 2 >= $n) { // sisa < n, tidak overflow; setengah menjauhi nol
                    $q++;
                }
                $v = $v < 0 ? -$q : $q;
            }
        }
        $neg = $v < 0;
        $d = str_pad((string) abs($v), $outScale + 1, '0', STR_PAD_LEFT);
        $s = $outScale === 0 ? $d : substr($d, 0, -$outScale) . '.' . substr($d, -$outScale);
        return ($neg ? '-' : '') . $s;
    }

    private function scaled(string $s, int $scale): int
    {
        if (preg_match('/^(-?)([0-9]{1,18})(?:\.([0-9]{1,18}))?$/D', $s, $m) !== 1) {
            throw new \RangeException('Nilai decimal tidak valid');
        }
        $frac = substr(str_pad($m[3] ?? '', $scale, '0'), 0, $scale);
        $digits = ltrim($m[2] . $frac, '0');
        if (strlen($digits) > 18) {
            throw new \RangeException('Nilai decimal melebihi rentang');
        }
        $n = (int) ($digits === '' ? '0' : $digits);
        return $m[1] === '-' ? -$n : $n;
    }

    /** Kolom quoted; decimal dibungkus ekspresi numerik agar urutan/perbandingan numerik (bukan teks). */
    private function num(string $t, string $c): string
    {
        $q = $this->col($t, $c);
        return $this->allow->isDecimal($t, $c) ? $this->grammar->numericExpr($q) : $q;
    }

    private function tbl(string $t): string
    {
        return $this->grammar->quoteIdent($this->allow->table($t));
    }

    private function col(string $t, string $c): string
    {
        return $this->grammar->quoteIdent($this->allow->column($t, $c));
    }

    /** @return array{0:string,1:list<int|string|null>} */
    private function where(string $table, Where $w): array
    {
        $parts = [];
        $bind = [];
        foreach ($w->conds as $c) {
            $col = $this->col($table, $c[0]);
            $dec = $this->allow->isDecimal($table, $c[0]);
            $nc = $dec ? $this->grammar->numericExpr($col) : $col;
            $ph = $dec ? $this->grammar->numericExpr('?') : '?';
            $op = $c[1];
            $v = $c[2] ?? null;
            switch ($op) {
                case 'null':
                    $parts[] = "$col IS NULL";
                    break;
                case 'notnull':
                    $parts[] = "$col IS NOT NULL";
                    break;
                case 'in':
                    if (!is_array($v) || $v === []) {
                        $parts[] = '0 = 1';
                        break;
                    }
                    $parts[] = "$nc IN (" . implode(', ', array_fill(0, count($v), $ph)) . ')';
                    foreach ($v as $x) {
                        $bind[] = $this->val($x);
                    }
                    break;
                case 'like':
                    $parts[] = "$col LIKE ?";
                    $bind[] = $this->val($v);
                    break;
                default: // operator sudah di-whitelist oleh Where
                    $parts[] = "$nc $op $ph";
                    $bind[] = $this->val($v);
            }
        }
        return [$parts === [] ? '' : ' WHERE ' . implode(' AND ', $parts), $bind];
    }

    private function val(mixed $v): int|string|null
    {
        if (is_bool($v)) {
            return $v ? 1 : 0;
        }
        if ($v === null || is_int($v) || is_string($v)) {
            return $v;
        }
        throw new \InvalidArgumentException('Tipe nilai tidak didukung (decimal harus string numerik)');
    }

    /** @param list<int|string|null> $bind */
    private function run(string $sql, array $bind): PDOStatement
    {
        try {
            $st = $this->conn->pdo()->prepare($sql);
            $st->execute($bind);
            return $st;
        } catch (PDOException $e) {
            // Pesan PDO memuat SQL/skema/nilai: hanya kelas dan SQLSTATE yang dicatat.
            $this->logger?->error('Query database gagal', ['class' => $e::class, 'sqlstate' => (string) $e->getCode()]);
            throw new DatabaseError();
        }
    }
}
