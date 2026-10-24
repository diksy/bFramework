<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Action;
use bFramework\Contracts\Forbidden;
use bFramework\Contracts\Identity;

/**
 * Otorisasi (SEC-AUTHZ-01/02). Definisi model:
 *   access: { read|create|update|delete: "*" | [peran...], write: (fallback create/update/delete),
 *             owner: "kolom", ownerExempt: [peran...], requireAmr: [amr...] | {aksi: [amr...]} }
 * Tanpa aturan = tolak. Peran yang diperiksa hanya peran aktif.
 */
final class Authorizer
{
    /** @param array<string,mixed> $modelDef */
    public function can(array $modelDef, Action $action, ?Identity $who): bool
    {
        $acc = self::access($modelDef);
        if (self::ownerInvalid($modelDef)) {
            return false; // fail-closed: batas baris tak dapat ditentukan
        }
        $rule = $acc[$action->value] ?? ($action === Action::Read ? null : ($acc['write'] ?? null));
        if ($rule === '*') {
            // Model berpemilik tidak pernah terbuka untuk anonim (baris tak bisa dibatasi).
            if ($who === null && self::ownerColumn($modelDef) !== null) {
                return false;
            }
        } elseif ($who === null || !is_array($rule) || !in_array($who->activeRole, $rule, true)) {
            return false;
        }
        return $this->amrOk($acc, $action, $who);
    }

    /**
     * Syarat Where yang wajib disuntik ke setiap select/update/delete/count/aggregate.
     *
     * @param array<string,mixed> $modelDef
     */
    public function scope(array $modelDef, Action $action, Identity $who): Where
    {
        if (!$this->can($modelDef, $action, $who)) {
            throw new Forbidden('Akses ditolak');
        }
        $col = self::ownerColumn($modelDef);
        if ($col === null || $this->exempt($modelDef, $who)) {
            return Where::none();
        }
        return new Where([[$col, '=', $who->userId]]);
    }

    /**
     * Gabungkan scope ke Where pemanggil (AND).
     *
     * @param array<string,mixed> $modelDef
     */
    public function constrain(array $modelDef, Action $action, Identity $who, Where $w): Where
    {
        $s = $this->scope($modelDef, $action, $who);
        return new Where([...$w->conds, ...$s->conds]);
    }

    /**
     * Anti mass-owner: pada create kolom owner dipaksa = user saat ini; pada update dibuang
     * (pemilik baris tak bisa dipindahkan). Peran ownerExempt boleh mengatur sendiri saat create bila diisi.
     *
     * @param array<string,mixed> $modelDef
     * @param array<string,mixed> $values
     * @return array<string,mixed>
     */
    public function forceOwner(array $modelDef, Action $action, Identity $who, array $values): array
    {
        $col = self::ownerColumn($modelDef);
        if ($col === null) {
            return $values;
        }
        if ($action === Action::Create) {
            if (!($this->exempt($modelDef, $who) && isset($values[$col]))) {
                $values[$col] = $who->userId;
            }
        } elseif ($action === Action::Update && !$this->exempt($modelDef, $who)) {
            unset($values[$col]);
        }
        return $values;
    }

    /** @param array<string,mixed> $modelDef */
    public static function ownerColumn(array $modelDef): ?string
    {
        $o = self::access($modelDef)['owner'] ?? null;
        return is_string($o) && preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}$/D', $o) === 1 ? $o : null;
    }

    /**
     * Kunci owner ada tetapi bukan nama kolom valid.
     *
     * @param array<string,mixed> $modelDef
     */
    private static function ownerInvalid(array $modelDef): bool
    {
        return array_key_exists('owner', self::access($modelDef)) && self::ownerColumn($modelDef) === null;
    }

    /** @param array<string,mixed> $modelDef */
    private function exempt(array $modelDef, Identity $who): bool
    {
        $e = self::access($modelDef)['ownerExempt'] ?? null;
        return is_array($e) && in_array($who->activeRole, $e, true);
    }

    /** @param array<string,mixed> $acc */
    private function amrOk(array $acc, Action $action, ?Identity $who): bool
    {
        $req = $acc['requireAmr'] ?? [];
        if (is_array($req) && array_key_exists($action->value, $req)) {
            $req = $req[$action->value];
        } elseif (is_array($req) && !array_is_list($req)) {
            $req = [];
        }
        if (!is_array($req)) {
            return false; // salah bentuk = tolak
        }
        foreach ($req as $m) {
            if (!is_string($m) || $who === null || !in_array($m, $who->amr, true)) {
                return false;
            }
        }
        return true;
    }

    /**
     * @param array<string,mixed> $modelDef
     * @return array<string,mixed>
     */
    private static function access(array $modelDef): array
    {
        $a = $modelDef['access'] ?? [];
        /** @var array<string,mixed> */
        return is_array($a) ? $a : [];
    }
}
