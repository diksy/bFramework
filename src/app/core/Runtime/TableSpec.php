<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

/** Definisi tabel: nama + kolom (tanpa `id`, otomatis). */
final readonly class TableSpec
{
    /** @param array<string,ColumnSpec> $cols */
    public function __construct(public string $name, public array $cols = [])
    {
        IdentifierAllowlist::assertShape($name);
        foreach ($cols as $c => $_) {
            IdentifierAllowlist::assertShape((string) $c);
            if ($c === 'id') {
                throw new InvalidIdentifier('Kolom id dicadangkan');
            }
        }
    }
}
