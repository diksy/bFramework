<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

interface Grammar
{
    public function quoteIdent(string $name): string;

    /** Ekspresi numerik untuk kolom decimal (ORDER BY / perbandingan); $quoted sudah di-quote. */
    public function numericExpr(string $quoted): string;

    /** True bila DB menghitung decimal secara eksak (agregat dipercayakan ke DB). */
    public function nativeDecimal(): bool;

    /** @return list<string> */
    public function createTable(TableSpec $t): array;

    /**
     * @return list<string>
     */
    public function alter(TableSpec $old, TableSpec $new): array;

    /**
     * Peringatan kehilangan data untuk perubahan old -> new.
     *
     * @return list<string>
     */
    public function lossWarnings(TableSpec $old, TableSpec $new): array;
}
