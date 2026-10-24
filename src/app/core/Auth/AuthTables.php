<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\FieldType;
use bFramework\Runtime\ColumnSpec;
use bFramework\Runtime\IdentifierAllowlist;
use bFramework\Runtime\TableSpec;

/**
 * Tabel core autentikasi (bukan dari definisi JSON; dibuat installer lewat Migrator::planCreate).
 * Waktu disimpan sebagai epoch detik (Integer). Token hanya disimpan sebagai hash (AUTH-04/05).
 */
final class AuthTables
{
    public const USERS = 'users';
    public const ROLES = 'roles';
    public const USER_ROLES = 'user_roles';
    public const REMEMBER = 'remember_tokens';
    public const ONE_TIME = 'one_time_tokens';

    /** @return list<TableSpec> */
    public static function specs(): array
    {
        $int = new ColumnSpec(FieldType::Integer, false);
        $intN = new ColumnSpec(FieldType::Integer, true);
        $str = static fn(int $len, bool $null = false, bool $unique = false): ColumnSpec => new ColumnSpec(FieldType::String, $null, null, $len, 12, 2, $unique);
        return [
            new TableSpec(self::USERS, [
                'email' => $str(254, false, true),
                'name' => $str(120),
                'password_hash' => $str(255, true),
                'status' => new ColumnSpec(FieldType::String, false, 'active', 16),
                'email_verified_at' => $intN,
                'totp_secret' => new ColumnSpec(FieldType::Text, true),
                'totp_enabled' => new ColumnSpec(FieldType::Boolean, false, '0'),
                'totp_last_step' => $intN,
                'recovery_codes' => new ColumnSpec(FieldType::Text, true),
                'pw_changed_at' => new ColumnSpec(FieldType::Integer, false, '0'),
                'sso_sub' => $str(255, true, true),
                'break_glass' => new ColumnSpec(FieldType::Boolean, false, '0'),
                'created_at' => $int,
            ]),
            new TableSpec(self::ROLES, ['name' => $str(64, false, true), 'label' => $str(120, true)]),
            new TableSpec(self::USER_ROLES, ['user_id' => $int, 'role_id' => $int]),
            new TableSpec(self::REMEMBER, [
                'user_id' => $int,
                'selector' => $str(32, false, true),
                'token_hash' => $str(64),
                'family' => $str(32),
                'expires_at' => $int,
                'used_at' => $intN,
                'created_at' => $int,
            ]),
            new TableSpec(self::ONE_TIME, [
                'user_id' => $int,
                'purpose' => $str(32),
                'selector' => $str(32, false, true),
                'token_hash' => $str(64),
                'expires_at' => $int,
                'used_at' => $intN,
                'created_at' => $int,
            ]),
        ];
    }

    public static function allowlist(): IdentifierAllowlist
    {
        return new IdentifierAllowlist(self::specs());
    }
}
