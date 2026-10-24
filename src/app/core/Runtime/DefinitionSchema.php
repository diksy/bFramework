<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\FieldType;

/**
 * Skema definisi JSON (model, halaman, auth): validasi ketat + normalisasi. Dipakai Compiler (M8) dan
 * dapat dipakai DefinitionWriter (M14) agar aturan tidak ganda. Kunci tak dikenal = error.
 * Setiap elemen hasil membawa `_src` (CACHE-10).
 */
final class DefinitionSchema
{
    public const NAME_RE = '/^[a-z][a-z0-9_]{0,40}$/D';
    public const PAGE_RE = '/^[a-z][a-z0-9_-]{0,40}$/D';
    public const ROUTE_RE = '#^/[a-z0-9_-]+(/[a-z0-9_-]+)*$#D';
    public const ROLE_RE = '/^[A-Za-z][A-Za-z0-9_-]{0,40}$/D';
    public const RESERVED_MODELS = [
        'users', 'roles', 'user_roles', 'remember_tokens', 'one_time_tokens', 'files',
        'sso_sessions', 'sso_refresh_tokens', 'audit_log', 'migrations',
    ];
    /** Awalan nama model yang dicadangkan untuk tabel core masa depan. */
    public const RESERVED_MODEL_PREFIX = 'bf_';
    public const RESERVED_ROUTES = [
        'admin', '_builder', 'auth', 'login', 'logout', 'install', 'peran-aktif',
        'assets', 'files', 'uploads', 'api', '_pc',
    ];
    public const HOOK_EVENTS = [
        'beforeSave', 'afterSave', 'beforeCreate', 'afterCreate',
        'beforeUpdate', 'afterUpdate', 'beforeDelete', 'afterDelete',
    ];
    public const COMPONENTS = ['table', 'form', 'card', 'stat', 'chart', 'text', 'image'];
    public const AGGS = ['count', 'sum', 'avg', 'min', 'max'];
    public const ACTIONS = ['read', 'create', 'update', 'delete'];

    private const FIELD_KEYS = [
        'type', 'label', 'target', 'required', 'min', 'max', 'default', 'format',
        'guarded', 'unique', 'precision', 'scale',
    ];
    private const COMPONENT_KEYS = [
        'component', 'span', 'label', 'title', 'text', 'agg', 'field', 'columns', 'fields',
        'actions', 'source', 'kind', 'src', 'alt',
    ];

    /** @var list<CompileError> */
    private array $errors = [];

    /** @return list<CompileError> */
    public function errors(): array
    {
        return $this->errors;
    }

    public function error(string $src, string $msg): void
    {
        // Penunjuk bisa memuat nama dari input; netralkan karakter di luar set aman (tampilan UI/log).
        $this->errors[] = new CompileError(mb_substr(preg_replace('/[^A-Za-z0-9_.\/#-]/', '?', $src) ?? '', 0, 200), $msg);
    }

    public static function isReservedGroup(string $g): bool
    {
        return mb_strtolower(trim($g)) === 'admin';
    }

    /**
     * @param array<mixed> $d
     * @return array<string,mixed>|null
     */
    public function model(string $name, array $d): ?array
    {
        $src = "models/$name.json";
        $before = count($this->errors);
        $this->unknownKeys($d, ['model', 'fields', 'hooks', 'access'], $src);
        if (($d['model'] ?? null) !== $name) {
            $this->error($src . '#/model', 'Nilai "model" harus sama dengan nama file');
        }
        if (preg_match(self::NAME_RE, $name) !== 1 || in_array($name, self::RESERVED_MODELS, true)
            || str_starts_with($name, self::RESERVED_MODEL_PREFIX)) {
            $this->error($src, 'Nama model tidak valid atau dicadangkan');
        }
        $fieldsIn = $d['fields'] ?? [];
        $fields = [];
        $cols = [];
        if (!is_array($fieldsIn) || ($fieldsIn !== [] && array_is_list($fieldsIn))) {
            $this->error($src . '#/fields', '"fields" harus objek');
            $fieldsIn = [];
        }
        foreach ($fieldsIn as $fn => $f) {
            $fn = (string) $fn;
            $fsrc = "$src#/fields/$fn";
            if (preg_match(self::NAME_RE, $fn) !== 1 || $fn === 'id') {
                $this->error($fsrc, 'Nama field tidak valid atau dicadangkan');
                continue;
            }
            if (!is_array($f)) {
                $this->error($fsrc, 'Field harus objek');
                continue;
            }
            $r = $this->field($f, $fsrc);
            if ($r !== null) {
                $fields[$fn] = $r[0] + ['_src' => $fsrc];
                $cols[$fn] = $r[1];
            }
        }
        $hooks = $this->hooks($d['hooks'] ?? [], $src);
        $access = $this->access($d['access'] ?? [], $fields, $src . '#/access');
        if (count($this->errors) > $before) {
            return null;
        }
        return [
            'model' => $name,
            'table' => $name,
            'fields' => $fields,
            'columns' => $cols,
            'hooks' => $hooks,
            'access' => $access + ['_src' => $src . '#/access'],
            '_src' => $src . '#',
        ];
    }

    /**
     * @param array<mixed> $f
     * @return array{0:array<string,mixed>,1:array<string,mixed>}|null [field, kolom]
     */
    private function field(array $f, string $src): ?array
    {
        $n = count($this->errors);
        $this->unknownKeys($f, self::FIELD_KEYS, $src);
        $type = is_string($f['type'] ?? null) ? FieldType::tryFrom($f['type']) : null;
        if ($type === null) {
            $this->error($src . '/type', 'Tipe tidak didukung (ARCH-04)');
            return null;
        }
        $out = ['type' => $type->value];
        foreach (['required', 'guarded', 'unique'] as $k) {
            if (array_key_exists($k, $f)) {
                if (!is_bool($f[$k])) {
                    $this->error("$src/$k", 'Harus boolean');
                } else {
                    $out[$k] = $f[$k];
                }
            }
        }
        foreach (['label' => 100, 'format' => 20] as $k => $max) {
            if (array_key_exists($k, $f)) {
                if (!is_string($f[$k]) || mb_strlen($f[$k]) > $max || preg_match('/[\x00-\x1F\x7F]/', $f[$k]) === 1
                    || ($k === 'format' && preg_match('/^[a-z_]{1,20}$/D', $f[$k]) !== 1)) {
                    $this->error("$src/$k", 'Nilai tidak valid');
                } elseif ($this->hasSql($f[$k])) {
                    $this->error("$src/$k", 'SQL mentah tidak diizinkan (BLD-07)');
                } else {
                    $out[$k] = $f[$k];
                }
            }
        }
        foreach (['min', 'max'] as $k) {
            if (array_key_exists($k, $f)) {
                if ((!is_int($f[$k]) && !is_float($f[$k])) || !is_finite((float) $f[$k])) {
                    $this->error("$src/$k", 'Harus angka');
                } else {
                    $out[$k] = $f[$k];
                }
            }
        }
        if (isset($out['min'], $out['max']) && $out['min'] > $out['max']) {
            $this->error($src, 'min lebih besar dari max');
        }
        if ($type === FieldType::Relasi) {
            $t = $f['target'] ?? null;
            if (!is_string($t) || preg_match(self::NAME_RE, $t) !== 1) {
                $this->error($src . '/target', 'Field relasi butuh model target yang valid');
            } else {
                $out['target'] = $t;
            }
        } elseif (array_key_exists('target', $f)) {
            $this->error($src . '/target', '"target" hanya untuk tipe relasi');
        }
        $length = 255;
        if ($type === FieldType::String && isset($out['max'])) {
            if (!is_int($out['max']) || $out['max'] < 1 || $out['max'] > 65535) {
                $this->error($src . '/max', 'max string harus bilangan bulat 1..65535');
            } else {
                $length = $out['max'];
            }
        }
        $prec = 12;
        $scale = 2;
        foreach (['precision', 'scale'] as $k) {
            if (array_key_exists($k, $f)) {
                if ($type !== FieldType::Decimal || !is_int($f[$k])) {
                    $this->error("$src/$k", 'Hanya untuk decimal dan harus bilangan bulat');
                } else {
                    $out[$k] = $f[$k];
                }
            }
        }
        $prec = is_int($out['precision'] ?? null) ? $out['precision'] : $prec;
        $scale = is_int($out['scale'] ?? null) ? $out['scale'] : $scale;
        if ($prec < 1 || $prec > 38 || $scale < 0 || $scale > $prec) {
            $this->error($src, 'precision/scale di luar rentang');
            $prec = 12;
            $scale = 2;
        }
        $default = null;
        if (array_key_exists('default', $f)) {
            $default = $this->defaultValue($type, $f['default'], $src . '/default');
            if ($default !== null) {
                $out['default'] = $f['default'];
            }
        }
        if (($type === FieldType::Text || $type === FieldType::Json) && (($out['unique'] ?? false) || $default !== null)) {
            $this->error($src, 'Tipe text/json tidak boleh memakai default atau unique');
        }
        if (count($this->errors) > $n) {
            return null;
        }
        return [$out, [
            'type' => $type->value,
            'nullable' => !($out['required'] ?? false),
            'default' => $default,
            'length' => $length,
            'precision' => $prec,
            'scale' => $scale,
            'unique' => $out['unique'] ?? false,
        ]];
    }

    /** @return string|null nilai default sebagai string kolom */
    private function defaultValue(FieldType $t, mixed $v, string $src): ?string
    {
        if ($v === null) {
            return null;
        }
        $ok = match ($t) {
            FieldType::Integer, FieldType::Relasi => is_int($v),
            FieldType::Boolean => is_bool($v),
            FieldType::Decimal => is_int($v) || (is_string($v) && preg_match('/^-?[0-9]{1,30}(\.[0-9]{1,30})?$/D', $v) === 1),
            FieldType::Date => is_string($v) && preg_match('/^\d{4}-\d{2}-\d{2}$/D', $v) === 1,
            FieldType::Datetime => is_string($v) && preg_match('/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?$/D', $v) === 1,
            FieldType::String, FieldType::Text, FieldType::Json => is_string($v),
        };
        if (!$ok) {
            $this->error($src, 'Default tidak sesuai tipe');
            return null;
        }
        if (is_string($v) && (preg_match('/[\x00-\x1F\x7F\\\\]/', $v) === 1 || mb_strlen($v) > 255)) {
            $this->error($src, 'Default mengandung karakter terlarang atau terlalu panjang');
            return null;
        }
        if (is_string($v) && $this->hasSql($v)) {
            $this->error($src, 'SQL mentah tidak diizinkan (BLD-07)');
            return null;
        }
        return is_bool($v) ? ($v ? '1' : '0') : (string) $v;
    }

    /**
     * @return array<string,array{ref:string,class:string,method:string,_src:string}>
     */
    private function hooks(mixed $h, string $src): array
    {
        $out = [];
        if (!is_array($h) || ($h !== [] && array_is_list($h))) {
            $this->error($src . '#/hooks', '"hooks" harus objek');
            return [];
        }
        foreach ($h as $ev => $ref) {
            $ev = (string) $ev;
            $hs = "$src#/hooks/$ev";
            if (!in_array($ev, self::HOOK_EVENTS, true)) {
                $this->error($hs, 'Event hook tidak dikenal');
            } elseif (!is_string($ref) || preg_match('/^([A-Z][A-Za-z0-9_]{0,63})::([A-Za-z_][A-Za-z0-9_]{0,63})$/D', $ref, $m) !== 1) {
                $this->error($hs, 'Hook harus berbentuk Kelas::method');
            } else {
                $out[$ev] = ['ref' => $ref, 'class' => $m[1], 'method' => $m[2], '_src' => $hs];
            }
        }
        ksort($out);
        return $out;
    }

    /**
     * Format sama dengan yang dipakai Authorizer (M7).
     *
     * @param array<string,array<string,mixed>> $fields
     * @return array<string,mixed>
     */
    private function access(mixed $a, array $fields, string $src): array
    {
        if (!is_array($a) || ($a !== [] && array_is_list($a))) {
            $this->error($src, '"access" harus objek');
            return [];
        }
        $this->unknownKeys($a, ['read', 'create', 'update', 'delete', 'write', 'owner', 'ownerExempt', 'requireAmr'], $src);
        $out = [];
        foreach (['read', 'create', 'update', 'delete', 'write'] as $k) {
            if (array_key_exists($k, $a)) {
                $r = $this->roles($a[$k], "$src/$k", true);
                if ($r !== null) {
                    $out[$k] = $r;
                }
            }
        }
        if (array_key_exists('ownerExempt', $a)) {
            $r = $this->roles($a['ownerExempt'], "$src/ownerExempt", false);
            if ($r !== null) {
                $out['ownerExempt'] = $r;
            }
        }
        if (array_key_exists('owner', $a)) {
            $o = $a['owner'];
            if (!is_string($o) || preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}$/D', $o) !== 1) {
                $this->error("$src/owner", 'owner harus nama kolom yang valid');
            } elseif (!isset($fields[$o])) {
                $this->error("$src/owner", 'Kolom owner tidak ada di model');
            } elseif (!in_array($fields[$o]['type'], ['integer', 'relasi'], true)) {
                $this->error("$src/owner", 'Kolom owner harus bertipe integer atau relasi');
            } else {
                $out['owner'] = $o;
            }
        }
        if (array_key_exists('requireAmr', $a)) {
            $r = $this->amr($a['requireAmr'], "$src/requireAmr");
            if ($r !== null) {
                $out['requireAmr'] = $r;
            }
        }
        return $out;
    }

    /** @return '*'|list<string>|null */
    private function roles(mixed $v, string $src, bool $allowStar): string|array|null
    {
        if ($allowStar && $v === '*') {
            return '*';
        }
        if (!is_array($v) || !array_is_list($v) || count($v) > 50) {
            $this->error($src, $allowStar ? 'Harus "*" atau daftar peran' : 'Harus daftar peran');
            return null;
        }
        foreach ($v as $r) {
            if (!is_string($r) || preg_match(self::ROLE_RE, $r) !== 1) {
                $this->error($src, 'Nama peran tidak valid');
                return null;
            }
        }
        return array_values(array_unique($v));
    }

    /** @return list<string>|array<string,list<string>>|null */
    private function amr(mixed $v, string $src): ?array
    {
        if (!is_array($v)) {
            $this->error($src, 'requireAmr harus daftar atau objek per aksi');
            return null;
        }
        $list = static function (mixed $l): bool {
            if (!is_array($l) || !array_is_list($l)) {
                return false;
            }
            foreach ($l as $m) {
                if (!is_string($m) || preg_match('/^[a-z0-9_-]{1,20}$/D', $m) !== 1) {
                    return false;
                }
            }
            return true;
        };
        if ($v === [] || array_is_list($v)) {
            if (!$list($v)) {
                $this->error($src, 'Daftar amr tidak valid');
                return null;
            }
            return array_values(array_unique($v));
        }
        $out = [];
        foreach ($v as $act => $l) {
            if (!in_array($act, self::ACTIONS, true) || !$list($l)) {
                $this->error("$src/$act", 'Aksi atau daftar amr tidak valid');
                return null;
            }
            $out[$act] = array_values(array_unique($l));
        }
        return $out;
    }

    /**
     * @param array<mixed> $d
     * @return array<string,mixed>|null
     */
    public function page(string $name, array $d): ?array
    {
        $src = "pages/$name.json";
        $n = count($this->errors);
        $this->unknownKeys($d, ['page', 'route', 'title', 'icon', 'group', 'order', 'access', 'cache', 'layout'], $src);
        if (($d['page'] ?? null) !== $name || preg_match(self::PAGE_RE, $name) !== 1) {
            $this->error($src . '#/page', 'Nilai "page" harus sama dengan nama file dan valid');
        }
        $route = $d['route'] ?? null;
        if (!is_string($route) || preg_match(self::ROUTE_RE, $route) !== 1) {
            $this->error($src . '#/route', 'Rute harus diawali "/" dengan huruf kecil/angka/-/_');
            $route = '';
        } elseif (in_array(explode('/', $route)[1], self::RESERVED_ROUTES, true)
            || str_starts_with(explode('/', $route)[1], '_')) {
            $this->error($src . '#/route', 'Awalan rute dicadangkan');
        }
        $out = ['page' => $name, 'route' => $route];
        foreach (['title' => 60, 'icon' => 16] as $k => $max) {
            if (array_key_exists($k, $d)) {
                if (!is_string($d[$k]) || mb_strlen($d[$k]) > $max || preg_match('/[\x00-\x1F\x7F]/', $d[$k]) === 1) {
                    $this->error("$src#/$k", 'Nilai tidak valid');
                } else {
                    $out[$k] = $d[$k];
                }
            }
        }
        if (array_key_exists('group', $d)) {
            $g = is_string($d['group']) ? trim($d['group']) : null;
            if ($g === null || mb_strlen($g) > 40 || preg_match('/[\x00-\x1F\x7F]/', $g) === 1) {
                $this->error($src . '#/group', 'Grup tidak valid');
            } elseif (self::isReservedGroup($g)) {
                $this->error($src . '#/group', 'Grup "Admin" dicadangkan untuk menu bawaan');
            } elseif ($g !== '') {
                $out['group'] = $g;
            }
        }
        if (array_key_exists('order', $d)) {
            if (!is_int($d['order']) || $d['order'] < -9999 || $d['order'] > 9999) {
                $this->error($src . '#/order', 'order harus bilangan bulat -9999..9999');
            } else {
                $out['order'] = $d['order'];
            }
        }
        $access = array_key_exists('access', $d) ? $this->roles($d['access'], $src . '#/access', true) : [];
        $out['access'] = $access ?? [];
        $cache = $d['cache'] ?? false;
        if (!is_bool($cache)) {
            $this->error($src . '#/cache', 'cache harus boolean');
        } elseif ($cache && $out['access'] !== '*') {
            $this->error($src . '#/cache', 'Halaman yang butuh login tidak boleh cache:true (CACHE-14)');
        }
        $out['cache'] = $cache === true;
        $layoutIn = $d['layout'] ?? [];
        $layout = [];
        if (!is_array($layoutIn) || !array_is_list($layoutIn) || count($layoutIn) > 100) {
            $this->error($src . '#/layout', '"layout" harus daftar komponen');
        } else {
            foreach ($layoutIn as $i => $c) {
                $r = is_array($c) ? $this->component($c, "$src#/layout/$i") : null;
                if (is_array($c) === false) {
                    $this->error("$src#/layout/$i", 'Komponen harus objek');
                }
                if ($r !== null) {
                    $layout[] = $r;
                }
            }
        }
        $out['layout'] = $layout;
        $out['_src'] = $src . '#';
        return count($this->errors) > $n ? null : $out;
    }

    /**
     * @param array<mixed> $c
     * @return array<string,mixed>|null
     */
    private function component(array $c, string $src): ?array
    {
        $n = count($this->errors);
        $this->unknownKeys($c, self::COMPONENT_KEYS, $src);
        $kind = $c['component'] ?? null;
        if (!is_string($kind) || !in_array($kind, self::COMPONENTS, true)) {
            $this->error($src . '/component', 'Komponen tidak dikenal');
            return null;
        }
        $out = ['component' => $kind, 'span' => 12];
        if (array_key_exists('span', $c)) {
            if (!is_int($c['span']) || $c['span'] < 1 || $c['span'] > 12) {
                $this->error($src . '/span', 'span harus 1..12');
            } else {
                $out['span'] = $c['span'];
            }
        }
        foreach (['label' => 100, 'title' => 100, 'text' => 2000, 'alt' => 200, 'kind' => 30] as $k => $max) {
            if (array_key_exists($k, $c)) {
                if (!is_string($c[$k]) || mb_strlen($c[$k]) > $max || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $c[$k]) === 1) {
                    $this->error("$src/$k", 'Teks tidak valid');
                } else {
                    $out[$k] = $c[$k];
                }
            }
        }
        if (array_key_exists('src', $c)) {
            if (!is_string($c['src']) || preg_match('#^(https?://|/)[^\s\x00-\x1F]{1,500}$#Di', $c['src']) !== 1) {
                $this->error($src . '/src', 'src harus URL http/https atau path relatif');
            } else {
                $out['src'] = $c['src'];
            }
        }
        if (array_key_exists('agg', $c)) {
            if (!is_string($c['agg']) || !in_array($c['agg'], self::AGGS, true)) {
                $this->error($src . '/agg', 'Agregat tidak dikenal');
            } else {
                $out['agg'] = $c['agg'];
            }
        }
        if (array_key_exists('field', $c)) {
            if (!is_string($c['field']) || preg_match(self::NAME_RE, $c['field']) !== 1) {
                $this->error($src . '/field', 'Nama field tidak valid');
            } else {
                $out['field'] = $c['field'];
            }
        }
        foreach (['columns', 'fields'] as $k) {
            if (array_key_exists($k, $c)) {
                $l = $c[$k];
                if (!is_array($l) || !array_is_list($l) || count($l) > 100) {
                    $this->error("$src/$k", 'Harus daftar nama field');
                    continue;
                }
                foreach ($l as $x) {
                    if (!is_string($x) || preg_match(self::NAME_RE, $x) !== 1) {
                        $this->error("$src/$k", 'Nama field tidak valid');
                        continue 2;
                    }
                }
                $out[$k] = $l;
            }
        }
        if (array_key_exists('actions', $c)) {
            $l = $c['actions'];
            if (!is_array($l) || !array_is_list($l) || array_diff($l, ['edit', 'hapus', 'baru']) !== []) {
                $this->error($src . '/actions', 'Aksi harus subset dari edit, hapus, baru');
            } else {
                $out['actions'] = array_values(array_unique($l));
            }
        }
        if (array_key_exists('source', $c)) {
            $s = $this->source($c['source'], $src . '/source');
            if ($s !== null) {
                $out['source'] = $s;
            }
        }
        $out['_src'] = $src;
        return count($this->errors) > $n ? null : $out;
    }

    /** @return array<string,mixed>|null */
    private function source(mixed $s, string $src): ?array
    {
        if (!is_array($s) || ($s !== [] && array_is_list($s))) {
            $this->error($src, 'source harus objek');
            return null;
        }
        $n = count($this->errors);
        $this->unknownKeys($s, ['model', 'filter', 'sort', 'perPage'], $src);
        $out = [];
        if (!is_string($s['model'] ?? null) || preg_match(self::NAME_RE, $s['model']) !== 1) {
            $this->error($src . '/model', 'source.model wajib dan valid');
        } else {
            $out['model'] = $s['model'];
        }
        if (array_key_exists('sort', $s)) {
            if (!is_string($s['sort']) || preg_match('/^-?[a-z][a-z0-9_]{0,40}$/D', $s['sort']) !== 1) {
                $this->error($src . '/sort', 'sort tidak valid (BLD-07)');
            } else {
                $out['sort'] = $s['sort'];
            }
        }
        if (array_key_exists('perPage', $s)) {
            if (!is_int($s['perPage']) || $s['perPage'] < 1 || $s['perPage'] > 100) {
                $this->error($src . '/perPage', 'perPage harus 1..100');
            } else {
                $out['perPage'] = $s['perPage'];
            }
        }
        if (array_key_exists('filter', $s)) {
            $f = $s['filter'];
            $ok = is_array($f) && ($f === [] || !array_is_list($f)) && count($f) <= 20;
            foreach ($ok ? $f : [] as $k => $v) {
                if (preg_match(self::NAME_RE, (string) $k) !== 1 || !(is_int($v) || is_bool($v) || (is_string($v) && mb_strlen($v) <= 200))
                    || (is_string($v) && $this->hasSql($v))) {
                    $ok = false;
                }
            }
            if (!$ok) {
                $this->error($src . '/filter', 'filter harus objek field => nilai skalar tanpa SQL (BLD-07)');
            } else {
                $out['filter'] = $f;
            }
        }
        return count($this->errors) > $n ? null : $out;
    }

    /**
     * Resolve lintas-definisi: target relasi, sumber komponen, kolom, urutan.
     *
     * @param array<string,array<string,mixed>> $models
     * @param array<string,array<string,mixed>> $pages
     */
    public function resolve(array $models, array $pages): void
    {
        foreach ($models as $m) {
            foreach ($m['fields'] as $f) {
                if (($f['type'] ?? '') === 'relasi' && !isset($models[(string) $f['target']])) {
                    $this->error((string) $f['_src'] . '/target', 'Model target tidak ditemukan');
                }
            }
        }
        $routes = [];
        foreach ($pages as $name => $p) {
            $route = (string) $p['route'];
            if (isset($routes[$route])) {
                $this->error((string) $p['_src'], 'Rute ganda dengan halaman ' . $routes[$route]);
            }
            $routes[$route] = $name;
            foreach ($p['layout'] as $c) {
                $this->resolveComponent($c, $models);
            }
        }
    }

    /**
     * @param array<string,mixed> $c
     * @param array<string,array<string,mixed>> $models
     */
    private function resolveComponent(array $c, array $models): void
    {
        $src = (string) $c['_src'];
        $fields = null;
        if (isset($c['source']['model'])) {
            $mn = (string) $c['source']['model'];
            if (!isset($models[$mn])) {
                $this->error($src . '/source/model', 'Model sumber tidak ditemukan');
                return;
            }
            $fields = $models[$mn]['fields'];
            if (isset($c['source']['sort']) && !isset($fields[ltrim((string) $c['source']['sort'], '-')]) && ltrim((string) $c['source']['sort'], '-') !== 'id') {
                $this->error($src . '/source/sort', 'Field sort tidak ada di model');
            }
            foreach (array_keys((array) ($c['source']['filter'] ?? [])) as $k) {
                if (!isset($fields[(string) $k]) && $k !== 'id') {
                    $this->error($src . '/source/filter', 'Field filter tidak ada di model');
                }
            }
        }
        $refs = [...(array) ($c['columns'] ?? []), ...(array) ($c['fields'] ?? []), ...(isset($c['field']) ? [$c['field']] : [])];
        if ($refs !== [] && $fields === null) {
            $this->error($src, 'Komponen merujuk field tanpa source.model');
            return;
        }
        foreach ($refs as $r) {
            if (!isset($fields[(string) $r])) {
                $this->error($src, 'Field "' . (string) $r . '" tidak ada di model sumber');
            }
        }
        if (($c['agg'] ?? 'count') !== 'count' && !isset($c['field'])) {
            $this->error($src . '/agg', 'Agregat selain count butuh "field"');
        }
    }

    /**
     * @param array<mixed> $d
     * @return array<string,mixed>|null
     */
    public function auth(array $d): ?array
    {
        $src = 'auth.json';
        $n = count($this->errors);
        $this->unknownKeys($d, ['driver', 'sso'], $src);
        $driver = $d['driver'] ?? null;
        if (!in_array($driver, ['local', 'bikinin_sso', 'hybrid'], true)) {
            $this->error($src . '#/driver', 'Driver harus local, bikinin_sso, atau hybrid');
            return null;
        }
        $out = ['driver' => $driver];
        $sso = $d['sso'] ?? null;
        if ($sso !== null) {
            if (!is_array($sso)) {
                $this->error($src . '#/sso', 'sso harus objek');
                return null;
            }
            // Rahasia tidak pernah boleh ada di definisi/cache (CACHE-11); client_secret hanya di config.php.
            $this->unknownKeys($sso, ['issuer', 'client_id', 'provisioning', 'default_role', 'offline_access', 'session_check_minutes'], $src . '#/sso');
            $issuer = $sso['issuer'] ?? '';
            if (!is_string($issuer) && $driver === 'local') {
                $this->error($src . '#/sso/issuer', 'Issuer harus string');
                $issuer = '';
            }
            if ($driver !== 'local' && (!is_string($issuer) || preg_match('#^https://[a-z0-9.-]+(:\d+)?$#Di', $issuer) !== 1)) {
                $this->error($src . '#/sso/issuer', 'Issuer harus URL https tanpa path');
            }
            $prov = $sso['provisioning'] ?? 'jit';
            $role = $sso['default_role'] ?? 'staf';
            $cid = $sso['client_id'] ?? '';
            $min = $sso['session_check_minutes'] ?? 5;
            if (!in_array($prov, ['jit', 'pre_registered'], true)) {
                $this->error($src . '#/sso/provisioning', 'Provisioning harus jit atau pre_registered');
            }
            if (!is_string($role) || preg_match(self::ROLE_RE, $role) !== 1) {
                $this->error($src . '#/sso/default_role', 'Peran tidak valid');
            }
            if (!is_string($cid) || preg_match('/^[A-Za-z0-9._-]{0,100}$/D', $cid) !== 1) {
                $this->error($src . '#/sso/client_id', 'client_id tidak valid');
            }
            if (!is_int($min) || $min < 1 || $min > 1440) {
                $this->error($src . '#/sso/session_check_minutes', 'Harus 1..1440');
            }
            if (!is_bool($sso['offline_access'] ?? false)) {
                $this->error($src . '#/sso/offline_access', 'Harus boolean');
            }
            $out['sso'] = [
                'issuer' => $issuer, 'client_id' => $cid, 'provisioning' => $prov, 'default_role' => $role,
                'offline_access' => ($sso['offline_access'] ?? false) === true, 'session_check_minutes' => $min,
            ];
        } elseif ($driver !== 'local') {
            $this->error($src . '#/sso', 'Driver SSO butuh blok sso');
        }
        $out['_src'] = $src . '#';
        return count($this->errors) > $n ? null : $out;
    }

    /**
     * @param array<mixed> $a
     * @param list<string> $allowed
     */
    private function unknownKeys(array $a, array $allowed, string $src): void
    {
        foreach (array_keys($a) as $k) {
            if (!in_array($k, $allowed, true)) {
                $this->error($src, 'Kunci tidak dikenal: ' . mb_substr(preg_replace('/[^\x20-\x7E]/', '?', (string) $k) ?? '', 0, 40));
            }
        }
    }

    private function hasSql(string $v): bool
    {
        // Pola struktur SQL (bukan sekadar kata): label wajar seperti "Update stok" tetap sah.
        return preg_match(
            '/;|--|\/\*|\bselect\b.+\bfrom\b|\binsert\s+into\b|\bdelete\s+from\b|\bdrop\s+(table|database|view|index)\b'
            . '|\bunion\s+(all\s+)?select\b|\balter\s+table\b|\btruncate\s+table\b|\bupdate\s+\S+\s+set\b|\bexec(ute)?\s*\(/is',
            $v
        ) === 1;
    }
}
