<?php

declare(strict_types=1);

namespace bFramework\Upload;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\FieldType;
use bFramework\Runtime\ColumnSpec;
use bFramework\Runtime\IdentifierAllowlist;
use bFramework\Runtime\TableSpec;

/** Tabel core `files` (metadata). Isi file ada di storage, bukan di DB. `fid` = id publik acak. */
final class FilesTable
{
    public const NAME = 'files';

    public static function spec(): TableSpec
    {
        $s = static fn(int $len, bool $null = false, bool $unique = false): ColumnSpec => new ColumnSpec(FieldType::String, $null, null, $len, 12, 2, $unique);
        return new TableSpec(self::NAME, [
            'fid' => $s(32, false, true),
            'mime' => $s(100),
            'size' => new ColumnSpec(FieldType::Integer, false),
            'orig_name' => $s(255, true),
            'owner_id' => new ColumnSpec(FieldType::Integer, true),
            'model' => $s(64, true),
            'ref_id' => new ColumnSpec(FieldType::Integer, true),
            'created_at' => new ColumnSpec(FieldType::Integer, false),
        ]);
    }

    public static function allowlist(): IdentifierAllowlist
    {
        return new IdentifierAllowlist([self::spec()]);
    }
}
