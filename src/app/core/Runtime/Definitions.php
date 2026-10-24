<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Dialect;
use bFramework\Contracts\FieldType;
use RuntimeException;

/**
 * Pembaca definisi ter-compile (CACHE-01: lazy per model; CACHE-06: tidak pernah menyentuh JSON sumber).
 * Versi aktif dibaca sekali per instance (satu request).
 */
final class Definitions
{
    private ?string $version = null;

    /** @var array<string,mixed> */
    private array $memo = [];

    public function __construct(private readonly CacheStore $store)
    {
    }

    public function version(): string
    {
        return $this->version ??= $this->store->current() ?? throw new RuntimeException('Cache belum dibangun');
    }

    /** @return array<string,mixed> */
    public function manifest(): array
    {
        return $this->load('manifest.php');
    }

    /** @return array<string,mixed>|null */
    public function model(string $name): ?array
    {
        if (preg_match(DefinitionSchema::NAME_RE, $name) !== 1 || !in_array($name, $this->manifestList('models'), true)) {
            return null;
        }
        return $this->load("models/$name.php");
    }

    /** @return array<string,mixed>|null */
    public function page(string $name): ?array
    {
        if (preg_match(DefinitionSchema::PAGE_RE, $name) !== 1 || !in_array($name, $this->manifestList('pages'), true)) {
            return null;
        }
        return $this->load("pages/$name.php");
    }

    /**
     * Semua halaman (untuk navigasi); memuat file halaman saja, bukan model.
     *
     * @return array<string,array<string,mixed>>
     */
    public function pages(): array
    {
        $out = [];
        foreach ($this->manifestList('pages') as $n) {
            $out[$n] = $this->load("pages/$n.php");
        }
        return $out;
    }

    /** @return list<string> */
    public function modelNames(): array
    {
        return $this->manifestList('models');
    }

    /**
     * Baris untuk Router::fromCompiled.
     *
     * @return list<array<string,mixed>>
     */
    public function routes(): array
    {
        /** @var list<array<string,mixed>> */
        return $this->load('routes.php');
    }

    /**
     * Aturan akses: ['models' => nama => access (format Authorizer), 'pages' => nama => ['access','route']].
     *
     * @return array<string,mixed>
     */
    public function access(): array
    {
        return $this->load('access.php');
    }

    /** @return array<string,mixed>|null konfigurasi auth non-rahasia */
    public function auth(): ?array
    {
        return ($this->manifest()['hasAuth'] ?? false) === true ? $this->load('auth.php') : null;
    }

    /**
     * SQL ter-compile untuk dialek aktif.
     *
     * @return array<string,mixed>|null
     */
    public function sql(string $model): ?array
    {
        if ($this->model($model) === null) {
            return null;
        }
        $d = (string) ($this->manifest()['dialect'] ?? '');
        return Dialect::tryFrom($d) === null ? null : $this->load("sql/$d/$model.php");
    }

    /**
     * Seluruh TableSpec (memuat semua model; dipakai Migrator/allowlist, bukan jalur request biasa).
     *
     * @return list<TableSpec>
     */
    public function tables(): array
    {
        $t = [];
        foreach ($this->modelNames() as $n) {
            $m = $this->model($n);
            if ($m !== null) {
                $t[] = self::tableSpec($m);
            }
        }
        return $t;
    }

    public function allowlist(): IdentifierAllowlist
    {
        return new IdentifierAllowlist($this->tables());
    }

    /** @param array<string,mixed> $model definisi model ter-compile */
    public static function tableSpec(array $model): TableSpec
    {
        $cols = [];
        foreach ((array) $model['columns'] as $n => $c) {
            $c = (array) $c;
            $cols[(string) $n] = new ColumnSpec(
                FieldType::from((string) $c['type']),
                (bool) $c['nullable'],
                is_string($c['default']) ? $c['default'] : null,
                (int) $c['length'],
                (int) $c['precision'],
                (int) $c['scale'],
                (bool) $c['unique'],
            );
        }
        return new TableSpec((string) $model['table'], $cols);
    }

    /** @return list<string> */
    private function manifestList(string $k): array
    {
        $l = $this->manifest()[$k] ?? [];
        /** @var list<string> */
        return is_array($l) ? $l : [];
    }

    /** @return array<string,mixed> */
    private function load(string $rel): array
    {
        $key = $this->version() . '/' . $rel;
        if (!isset($this->memo[$key])) {
            $d = $this->store->read($key);
            if ($d === null) {
                throw new RuntimeException('File cache hilang: ' . $rel);
            }
            $this->memo[$key] = $d;
        }
        /** @var array<string,mixed> */
        return $this->memo[$key];
    }
}
