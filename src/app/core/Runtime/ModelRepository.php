<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Action;
use bFramework\Contracts\Forbidden;
use bFramework\Contracts\Identity;
use bFramework\Contracts\NotFound;

/**
 * Akses data satu model (F5). Setiap select/count/aggregate/update/delete melewati Authorizer::constrain()
 * (SEC-AUTHZ-01/02); find/update/delete = id AND scope; baris di luar scope = NotFound (eksistensi tidak bocor).
 * Insert/update melewati Validator lalu forceOwner(). Identifier selalu lewat allowlist Query (SEC-DATA-01).
 * Anonim (Identity null) hanya diizinkan pada model tanpa owner; Authorizer::can() menjaga ini.
 */
final class ModelRepository
{
    private const MAX_PER_PAGE = 100;
    private const MAX_PAGE = 100000;

    /**
     * @param array<string,mixed> $def model ter-compile
     * @param list<string>|null $writable batasi field yang boleh diisi dari input (mis. field form halaman); null = semua non-guarded
     * @param (\Closure(string):(array<string,mixed>|null))|null $targets resolver definisi model target relasi; tanpa itu nilai relasi non-null ditolak (fail-closed)
     * @param FileRefs|null $files penyimpanan file; null + nilai field file non-null = ditolak (fail-closed)
     */
    public function __construct(
        private readonly array $def,
        private readonly Query $query,
        private readonly Authorizer $authz,
        private readonly ?Identity $who,
        private readonly HookRunner $hooks,
        private readonly ?array $writable = null,
        private readonly ?\Closure $targets = null,
        private readonly bool $devMode = false,
        private readonly ?\bFramework\Contracts\Logger $logger = null,
        private readonly ?FileRefs $files = null,
    ) {
        $own = Authorizer::ownerColumn($def);
        if ($own !== null && !isset($this->fields()[$own])) {
            // Fail-closed: kolom owner harus field model (tanggung jawab M8/M9, lihat catatan M7).
            throw new \LogicException('Kolom owner bukan field model');
        }
    }

    public function can(Action $a): bool
    {
        return $this->authz->can($this->def, $a, $this->who);
    }

    /**
     * @param array<string,mixed> $filters kolom => nilai skalar (=); kolom harus field non-guarded model
     * @return array{rows:list<array<string,mixed>>,total:int}
     */
    public function paginate(?string $sort, int $page, int $perPage, array $filters = []): array
    {
        $s = $this->normalizeSort($sort);
        $perPage = max(1, min(self::MAX_PER_PAGE, $perPage));
        $page = max(1, min(self::MAX_PAGE, $page));
        $w = $this->scoped(Action::Read, $this->filterWhere($filters));
        $total = $this->query->count($this->table(), $w);
        $rows = $this->query->select($this->table(), $this->columns(), $w, $s ?? new Sort('id'), $perPage, ($page - 1) * $perPage);
        return ['rows' => $rows, 'total' => $total];
    }

    /** @return array<string,mixed> */
    public function find(int $id): array
    {
        $rows = $this->query->select($this->table(), $this->columns(), $this->byId(Action::Read, $id), null, 1, 0);
        return $rows[0] ?? throw new NotFound();
    }

    /** @param array<string,mixed> $input */
    public function create(array $input): Result
    {
        $this->need(Action::Create);
        [$clean, $errors] = Validator::validate($this->validationDef(), $input, $this->devMode, $this->logger);
        $errors = $errors + $this->relationErrors($clean) + $this->fileErrors($clean, null);
        if ($errors !== []) {
            return new Result(null, $errors, [], $clean);
        }
        if ($this->who !== null) {
            $clean = $this->authz->forceOwner($this->def, Action::Create, $this->who, $clean);
        }
        $msgs = [...$this->hooks->run($this->def, 'beforeSave', $clean), ...$this->hooks->run($this->def, 'beforeCreate', $clean)];
        if ($msgs !== []) {
            return new Result(null, [], $msgs, $clean);
        }
        $id = $this->query->insert($this->table(), $clean);
        $claimErr = $this->claimAll($clean, $id);
        if ($claimErr !== []) {
            // Race: fid diambil pihak lain di antara pemeriksaan dan claim. Batalkan baris (tanpa file yatim).
            $this->query->delete($this->table(), new Where([['id', '=', $id]]));
            $this->files?->deleteForRef($this->table(), $id);
            return new Result(null, $claimErr, [], $clean);
        }
        $after = $clean + ['id' => $id];
        $this->hooks->run($this->def, 'afterCreate', $after);
        $this->hooks->run($this->def, 'afterSave', $after);
        return new Result($id, [], [], $clean);
    }

    /** @param array<string,mixed> $input */
    public function update(int $id, array $input): Result
    {
        $this->need(Action::Update);
        // Baris harus ada di dalam scope sebelum input diproses (tak membocorkan eksistensi lewat error validasi).
        $current = $this->query->select($this->table(), $this->columns(), $this->byId(Action::Update, $id), null, 1, 0)[0] ?? throw new NotFound();
        // Field file yang tidak dikirim = tetap (tidak divalidasi, tidak diubah).
        $skip = array_values(array_filter(array_keys($this->fileFields()), static fn(string $n): bool => !array_key_exists($n, $input)));
        [$clean, $errors] = Validator::validate($this->validationDef($skip), $input, $this->devMode, $this->logger);
        $errors = $errors + $this->relationErrors($clean) + $this->fileErrors($clean, $current);
        if ($errors !== []) {
            return new Result($id, $errors, [], $clean);
        }
        $own = Authorizer::ownerColumn($this->def);
        if ($own !== null && !array_key_exists($own, $input)) {
            unset($clean[$own]); // pembaruan tanpa owner tidak boleh mengosongkannya
        }
        if ($this->who !== null) {
            $clean = $this->authz->forceOwner($this->def, Action::Update, $this->who, $clean);
        }
        $data = $clean + ['id' => $id];
        $msgs = [...$this->hooks->run($this->def, 'beforeSave', $data), ...$this->hooks->run($this->def, 'beforeUpdate', $data)];
        if ($msgs !== []) {
            return new Result($id, [], $msgs, $clean);
        }
        $changed = $this->changedFiles($clean, $current);
        $claimErr = $this->claimAll($changed, $id);
        if ($claimErr !== []) {
            return new Result($id, $claimErr, [], $clean);
        }
        if ($clean !== []) {
            // rowCount 0 di MySQL juga berarti "tidak berubah"; keberadaan baris sudah dipastikan di atas.
            $this->query->update($this->table(), $clean, $this->byId(Action::Update, $id));
        }
        foreach (array_keys($this->fileFields()) as $n) {
            $old = $current[$n] ?? null;
            if (array_key_exists($n, $clean) && is_string($old) && $old !== '' && $clean[$n] !== $old) {
                $this->releaseOwned($old, $id); // ganti/hapus file: berkas lama ikut terhapus
            }
        }
        $this->hooks->run($this->def, 'afterUpdate', $data);
        $this->hooks->run($this->def, 'afterSave', $data);
        return new Result($id, [], [], $clean);
    }

    public function delete(int $id): void
    {
        $this->need(Action::Delete);
        $rows = $this->query->select($this->table(), $this->columns(), $this->byId(Action::Delete, $id), null, 1, 0);
        if ($rows === []) {
            throw new NotFound();
        }
        $msgs = $this->hooks->run($this->def, 'beforeDelete', $rows[0]);
        if ($msgs !== []) {
            throw new HookRejected($msgs);
        }
        if ($this->query->delete($this->table(), $this->byId(Action::Delete, $id)) < 1) {
            throw new NotFound();
        }
        if ($this->files !== null) {
            try {
                $this->files->deleteForRef($this->table(), $id);
            } catch (\Throwable $e) {
                $this->logger?->error('hapus file baris gagal', ['model' => $this->table(), 'ex' => $e::class]);
            }
        }
        $this->hooks->run($this->def, 'afterDelete', $rows[0]);
    }

    /** @return string|null string numerik (decimal tanpa float) atau null */
    public function aggregate(string $fn, ?string $field): ?string
    {
        $fn = strtolower($fn);
        if (!in_array($fn, DefinitionSchema::AGGS, true)) {
            throw new \InvalidArgumentException('Fungsi agregat tidak diizinkan');
        }
        $w = $this->scoped(Action::Read, Where::none());
        if ($field === null) {
            if ($fn !== 'count') {
                throw new \InvalidArgumentException('Agregat ini butuh field');
            }
            return (string) $this->query->count($this->table(), $w);
        }
        if (!$this->queryable($field)) {
            throw new \InvalidArgumentException('Field tidak diizinkan');
        }
        $type = $this->fieldType($field);
        $numeric = in_array($type, ['integer', 'decimal'], true);
        if (($fn === 'sum' || $fn === 'avg') && !$numeric) {
            throw new \InvalidArgumentException('Agregat hanya untuk field numerik');
        }
        if (!$numeric && !in_array($type, ['date', 'datetime', 'id', 'relasi'], true) && $fn !== 'count') {
            throw new \InvalidArgumentException('Tipe field tidak mendukung agregat');
        }
        return $this->query->aggregate($this->table(), $fn, $field, $w);
    }

    /**
     * Label singkat untuk pilihan relasi: id => nilai field string pertama (atau "#id").
     *
     * @return array<int,string>
     */
    public function labels(int $limit = 500): array
    {
        $label = null;
        foreach ($this->fields() as $n => $f) {
            if (in_array($f['type'] ?? '', ['string', 'text'], true) && ($f['guarded'] ?? false) !== true) {
                $label = $n;
                break;
            }
        }
        $w = $this->scoped(Action::Read, Where::none());
        $rows = $this->query->select($this->table(), $label === null ? ['id'] : ['id', $label], $w, new Sort('id'), max(1, min(1000, $limit)), 0);
        $out = [];
        foreach ($rows as $r) {
            $out[(int) $r['id']] = $label === null ? '#' . $r['id'] : (string) ($r[$label] ?? '#' . $r['id']);
        }
        return $out;
    }

    /**
     * "field" / "-field". Hanya id atau field non-guarded; selainnya InvalidArgumentException.
     */
    public function normalizeSort(?string $sort): ?Sort
    {
        if ($sort === null || $sort === '') {
            return null;
        }
        $desc = $sort[0] === '-';
        $col = $desc ? substr($sort, 1) : $sort;
        if (!$this->queryable($col)) {
            throw new \InvalidArgumentException('Kolom urut tidak diizinkan');
        }
        return new Sort($col, $desc ? 'desc' : 'asc');
    }

    // ---------- internal ----------

    private function table(): string
    {
        $t = $this->def['table'] ?? null;
        if (!is_string($t) || $t === '') {
            throw new \LogicException('Definisi model tanpa tabel');
        }
        return $t;
    }

    /** @return array<string,array<string,mixed>> */
    private function fields(): array
    {
        $f = $this->def['fields'] ?? [];
        /** @var array<string,array<string,mixed>> */
        return is_array($f) ? $f : [];
    }

    /** @return list<string> */
    private function columns(): array
    {
        return ['id', ...array_map('strval', array_keys($this->fields()))];
    }

    /**
     * Tiap relasi non-null harus menunjuk baris yang boleh dibaca user lewat constrain() target (SEC-AUTHZ-02).
     * "Tidak ada" dan "bukan milik" menghasilkan pesan identik agar eksistensi id tidak bocor.
     *
     * @param array<string,mixed> $clean
     * @return array<string,list<string>>
     */
    private function relationErrors(array $clean): array
    {
        $errors = [];
        $owner = Authorizer::ownerColumn($this->def);
        foreach ($this->fields() as $name => $f) {
            $name = (string) $name;
            if (($f['type'] ?? '') !== 'relasi' || $name === $owner || !isset($clean[$name]) || !is_int($clean[$name])) {
                continue;
            }
            $tdef = is_string($f['target'] ?? null) && $this->targets !== null ? ($this->targets)($f['target']) : null;
            if (!is_array($tdef) || !$this->targetVisible($tdef, $clean[$name])) {
                $label = is_string($f['label'] ?? null) ? $f['label'] : ucfirst($name);
                $errors[$name][] = "$label tidak valid.";
            }
        }
        return $errors;
    }

    /** @param array<string,mixed> $tdef */
    private function targetVisible(array $tdef, int $id): bool
    {
        $table = $tdef['table'] ?? null;
        if (!is_string($table) || $table === '' || !$this->authz->can($tdef, Action::Read, $this->who)) {
            return false;
        }
        $w = new Where([['id', '=', $id]]);
        if ($this->who === null) {
            if (Authorizer::ownerColumn($tdef) !== null) {
                return false;
            }
        } else {
            $w = $this->authz->constrain($tdef, Action::Read, $this->who, $w);
        }
        try {
            return $this->query->select($table, ['id'], $w, null, 1, 0) !== [];
        } catch (\Throwable) {
            return false;
        }
    }

    /** @return array<string,array<string,mixed>> field file (string + upload), tidak guarded */
    private function fileFields(): array
    {
        $out = [];
        foreach ($this->fields() as $n => $f) {
            if (is_array($f) && is_array($f['upload'] ?? null) && ($f['guarded'] ?? false) !== true) {
                $out[(string) $n] = $f;
            }
        }
        return $out;
    }

    /**
     * Tiap fid baru harus: ada, milik user ini, belum ter-attach, mime/ukuran sesuai policy field.
     * Semua kegagalan satu pesan generik (tak ada oracle eksistensi/kepemilikan fid).
     *
     * @param array<string,mixed> $clean
     * @param array<string,mixed>|null $current baris saat ini (update); nilai yang sama dilewati
     * @return array<string,list<string>>
     */
    private function fileErrors(array $clean, ?array $current): array
    {
        $errors = [];
        $seen = [];
        foreach ($this->fileFields() as $name => $f) {
            $v = $clean[$name] ?? null;
            if (!is_string($v) || $v === '' || ($current !== null && ($current[$name] ?? null) === $v)) {
                continue;
            }
            $label = is_string($f['label'] ?? null) ? $f['label'] : ucfirst($name);
            $policy = (array) $f['upload'];
            $meta = $this->who !== null && $this->files !== null && !isset($seen[$v]) ? $this->files->meta($v) : null;
            $seen[$v] = true;
            $mimes = is_array($policy['mimes'] ?? null) ? $policy['mimes'] : [];
            $ok = $meta !== null && $this->who !== null
                && $meta['owner_id'] === $this->who->userId
                && $meta['model'] === null
                && in_array($meta['mime'], $mimes, true)
                && is_int($policy['maxBytes'] ?? null) && $meta['size'] <= $policy['maxBytes'];
            if (!$ok) {
                $errors[$name][] = "$label tidak valid.";
            }
        }
        return $errors;
    }

    /**
     * File yang berubah pada update (nilai baru non-null berbeda dari baris saat ini).
     *
     * @param array<string,mixed> $clean
     * @param array<string,mixed> $current
     * @return array<string,mixed> nama field => fid baru, hanya yang perlu di-claim atau dilepas
     */
    private function changedFiles(array $clean, array $current): array
    {
        $out = [];
        foreach (array_keys($this->fileFields()) as $n) {
            if (array_key_exists($n, $clean) && is_string($clean[$n]) && $clean[$n] !== '' && ($current[$n] ?? null) !== $clean[$n]) {
                $out[$n] = $clean[$n];
            }
        }
        return $out;
    }

    /**
     * Claim atomik tiap fid ke baris ini. Gagal satu = lepas yang sudah di-claim pada panggilan ini.
     *
     * @param array<string,mixed> $values
     * @return array<string,list<string>>
     */
    private function claimAll(array $values, int $id): array
    {
        $done = [];
        foreach ($this->fileFields() as $name => $f) {
            $v = $values[$name] ?? null;
            if (!is_string($v) || $v === '') {
                continue;
            }
            $ok = false;
            try {
                $ok = $this->who !== null && $this->files !== null && $this->files->claim($v, $this->who->userId, $this->table(), $id);
            } catch (\Throwable $e) {
                $this->logger?->error('claim file gagal', ['model' => $this->table(), 'ex' => $e::class]);
            }
            if (!$ok) {
                foreach ($done as $d) {
                    $this->files?->release($d);
                }
                $label = is_string($f['label'] ?? null) ? $f['label'] : ucfirst($name);
                return [$name => ["$label tidak valid."]];
            }
            $done[] = $v;
        }
        return [];
    }

    /** Lepas file lama hanya bila memang ter-attach ke baris ini. */
    private function releaseOwned(string $fid, int $id): void
    {
        try {
            $m = $this->files?->meta($fid);
            if ($m !== null && $m['model'] === $this->table() && $m['ref_id'] === $id) {
                $this->files?->release($fid);
            }
        } catch (\Throwable $e) {
            $this->logger?->error('release file gagal', ['model' => $this->table(), 'ex' => $e::class]);
        }
    }

    private function queryable(string $col): bool
    {
        if ($col === 'id') {
            return true;
        }
        $f = $this->fields()[$col] ?? null;
        // Field file (fid) tidak untuk sort/filter/agregat: akan membocorkan/mengurutkan id acak.
        return is_array($f) && ($f['guarded'] ?? false) !== true && !isset($f['upload']);
    }

    private function fieldType(string $col): string
    {
        if ($col === 'id') {
            return 'id';
        }
        $f = $this->fields()[$col] ?? null;
        if (!is_array($f) || !is_string($f['type'] ?? null)) {
            throw new \InvalidArgumentException('Field tidak ada di model');
        }
        return $f['type'];
    }

    private function need(Action $a): void
    {
        if (!$this->authz->can($this->def, $a, $this->who)) {
            throw new Forbidden('Akses ditolak');
        }
    }

    /** Semua jalur baca/ubah/hapus lewat sini: constrain() untuk user login; anonim hanya model tanpa owner. */
    private function scoped(Action $a, Where $w): Where
    {
        $this->need($a);
        if ($this->who === null) {
            if (Authorizer::ownerColumn($this->def) !== null) {
                throw new Forbidden('Akses ditolak');
            }
            return $w;
        }
        return $this->authz->constrain($this->def, $a, $this->who, $w);
    }

    private function byId(Action $a, int $id): Where
    {
        return $this->scoped($a, new Where([['id', '=', $id]]));
    }

    /**
     * @param array<string,mixed> $filters
     */
    private function filterWhere(array $filters): Where
    {
        $conds = [];
        foreach ($filters as $col => $v) {
            $col = (string) $col;
            if (!$this->queryable($col)) {
                throw new \InvalidArgumentException('Kolom filter tidak diizinkan');
            }
            if ($v === null) {
                $conds[] = [$col, 'null'];
            } elseif (is_int($v) || is_string($v) || is_bool($v)) {
                $conds[] = [$col, '=', $v];
            } else {
                throw new \InvalidArgumentException('Nilai filter harus skalar');
            }
        }
        return new Where($conds);
    }

    /**
     * Kolom owner diisi sistem (forceOwner), bukan pengguna: jangan wajibkan dalam validasi.
     *
     * @param list<string> $skip field yang dikeluarkan dari validasi (field file tak dikirim saat update)
     * @return array<string,mixed>
     */
    private function validationDef(array $skip = []): array
    {
        $col = Authorizer::ownerColumn($this->def);
        $def = $this->def;
        $fields = $this->fields();
        if ($this->writable !== null) {
            $fields = array_intersect_key($fields, array_flip($this->writable));
        }
        if ($col !== null && isset($fields[$col])) {
            $fields[$col]['required'] = false;
        }
        foreach ($skip as $n) {
            unset($fields[$n]);
        }
        $def['fields'] = $fields;
        return $def;
    }
}
