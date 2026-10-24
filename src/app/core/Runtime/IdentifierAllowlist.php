<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\FieldType;

/** Whitelist identifier dari definisi ter-compile (SEC-DATA-01). */
final class IdentifierAllowlist
{
    /** @var array<string,array<string,true>> */
    private array $map = [];

    /** @var array<string,array<string,FieldType>> */
    private array $types = [];

    /** @var array<string,array<string,int>> */
    private array $scales = [];

    /** @param iterable<TableSpec> $tables */
    public function __construct(iterable $tables)
    {
        foreach ($tables as $t) {
            $cols = ['id' => true];
            foreach ($t->cols as $c => $spec) {
                $cols[(string) $c] = true;
                $this->types[$t->name][(string) $c] = $spec->type;
                $this->scales[$t->name][(string) $c] = $spec->scale;
            }
            $this->map[$t->name] = $cols;
        }
    }

    public static function assertShape(string $name): void
    {
        if (preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}$/D', $name) !== 1) {
            throw new InvalidIdentifier('Bentuk identifier tidak sah');
        }
    }

    public function table(string $t): string
    {
        if (!isset($this->map[$t])) {
            throw new InvalidIdentifier('Tabel tidak ada dalam definisi');
        }
        return $t;
    }

    public function isDecimal(string $t, string $c): bool
    {
        return ($this->types[$t][$c] ?? null) === FieldType::Decimal;
    }

    public function scale(string $t, string $c): int
    {
        return $this->scales[$t][$c] ?? 0;
    }

    public function column(string $t, string $c): string
    {
        $this->table($t);
        if (!isset($this->map[$t][$c])) {
            throw new InvalidIdentifier('Kolom tidak ada dalam definisi');
        }
        return $c;
    }
}
