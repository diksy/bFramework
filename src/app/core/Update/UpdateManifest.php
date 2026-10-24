<?php

declare(strict_types=1);

namespace bFramework\Update;

defined('APP_BOOTED') || exit;

/**
 * Manifest paket update (ditandatangani). Format JSON ketat, kunci tepat, batas ukuran.
 * {"format":1,"version":"1.2.0","min_version":"1.0.0","date":"2026-01-31",
 *  "files":{"app/core/X.php":"<sha256>",...},"delete":["app/core/Old.php"],
 *  "migrations":[{"id":"0001_x","sql":{"mysql":["..."],"sqlite":["..."]}}]}
 */
final readonly class UpdateManifest
{
    public const MAX_BYTES = 262144;
    public const MAX_FILES = 2000;
    private const KEYS = ['format', 'version', 'min_version', 'date', 'files', 'delete', 'migrations'];

    /**
     * @param array<string,string> $files jalur => sha256
     * @param list<string> $delete
     * @param list<array{id:string, sql:array{mysql:list<string>, sqlite:list<string>}}> $migrations
     */
    public function __construct(
        public string $version,
        public string $minVersion,
        public string $date,
        public array $files,
        public array $delete,
        public array $migrations,
    ) {
    }

    public static function validVersion(string $v): bool
    {
        return preg_match('/^\d{1,4}\.\d{1,4}\.\d{1,4}$/D', $v) === 1;
    }

    public static function parse(string $json): self
    {
        if (strlen($json) > self::MAX_BYTES || $json === '') {
            throw new UpdateException('manifest_ukuran');
        }
        try {
            $d = json_decode($json, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new UpdateException('manifest_json');
        }
        if (!is_array($d) || array_is_list($d) || array_diff(array_keys($d), self::KEYS) !== [] || array_diff(self::KEYS, array_keys($d)) !== []) {
            throw new UpdateException('manifest_kunci');
        }
        $ver = $d['version'];
        $min = $d['min_version'];
        $date = $d['date'];
        if ($d['format'] !== 1 || !is_string($ver) || !self::validVersion($ver) || !is_string($min) || !self::validVersion($min)
            || !is_string($date) || preg_match('/^(\d{4})-(\d{2})-(\d{2})$/D', $date, $m) !== 1 || !checkdate((int) $m[2], (int) $m[3], (int) $m[1])) {
            throw new UpdateException('manifest_meta');
        }
        $files = $d['files'];
        if (!is_array($files) || $files === [] || count($files) > self::MAX_FILES) {
            throw new UpdateException('manifest_files');
        }
        $seen = [];
        $outFiles = [];
        foreach ($files as $path => $hash) {
            $path = (string) $path;
            $low = strtolower($path);
            if (!UpdatePaths::allowed($path) || isset($seen[$low]) || !is_string($hash) || preg_match('/^[a-f0-9]{64}$/D', $hash) !== 1) {
                throw new UpdateException('manifest_path');
            }
            $seen[$low] = true;
            $outFiles[$path] = $hash;
        }
        if (!isset($outFiles[UpdatePaths::MANIFEST_FILE])) {
            throw new UpdateException('manifest_tanpa_hash_core');
        }
        $del = $d['delete'];
        if (!is_array($del) || !array_is_list($del) || count($del) > 500) {
            throw new UpdateException('manifest_delete');
        }
        $outDel = [];
        foreach ($del as $p) {
            if (!is_string($p) || !UpdatePaths::inScope($p) || isset($seen[strtolower($p)])) {
                throw new UpdateException('manifest_delete');
            }
            $seen[strtolower($p)] = true;
            $outDel[] = $p;
        }
        return new self($ver, $min, $date, $outFiles, $outDel, self::migrations($d['migrations']));
    }

    /** @return list<array{id:string, sql:array{mysql:list<string>, sqlite:list<string>}}> */
    private static function migrations(mixed $raw): array
    {
        if (!is_array($raw) || !array_is_list($raw) || count($raw) > 50) {
            throw new UpdateException('manifest_migrasi');
        }
        $out = [];
        $prev = '';
        foreach ($raw as $m) {
            if (!is_array($m) || array_keys($m) !== ['id', 'sql'] || !is_string($m['id']) || preg_match('/^[A-Za-z0-9_.-]{1,64}$/D', $m['id']) !== 1
                || strcmp($m['id'], $prev) <= 0 || !is_array($m['sql']) || array_diff(array_keys($m['sql']), ['mysql', 'sqlite']) !== []) {
                throw new UpdateException('manifest_migrasi');
            }
            $prev = $m['id'];
            $sql = ['mysql' => [], 'sqlite' => []];
            /** @var array<string,mixed> $dl */
            $dl = $m['sql'];
            foreach ($dl as $dialect => $list) {
                if (!is_array($list) || !array_is_list($list) || count($list) > 50) {
                    throw new UpdateException('manifest_migrasi');
                }
                $strs = [];
                foreach ($list as $s) {
                    if (!is_string($s) || $s === '' || strlen($s) > 8000 || str_contains($s, ';') || str_contains($s, "\0")) {
                        throw new UpdateException('manifest_migrasi'); // satu pernyataan per entri, tanpa ';'
                    }
                    $strs[] = $s;
                }
                $sql[$dialect === 'mysql' ? 'mysql' : 'sqlite'] = $strs;
            }
            $out[] = ['id' => $m['id'], 'sql' => $sql];
        }
        return $out;
    }
}
