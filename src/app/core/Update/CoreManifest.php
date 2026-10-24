<?php

declare(strict_types=1);

namespace bFramework\Update;

defined('APP_BOOTED') || exit;

/**
 * SEC-UPD-02: membandingkan MANIFEST.sha256 terpasang (dibuat tools/build-release.php, "<sha256>  <jalur>")
 * dengan isi disk, hanya untuk lingkup core (UpdatePaths::inScope). Konfigurasi, definisi, ekstensi, dan
 * storage tidak pernah dibandingkan. Hasil berupa jalur saja, tanpa isi file. Baca-saja.
 */
final class CoreManifest
{
    private const MAX_BYTES = 1048576;
    private readonly string $root;

    public function __construct(string $root)
    {
        $this->root = rtrim($root, '/');
    }

    /** @return ?array<string,string> jalur => sha256, null bila tak terbaca/tidak valid */
    public function load(): ?array
    {
        $f = $this->root . '/' . UpdatePaths::MANIFEST_FILE;
        $size = is_file($f) ? filesize($f) : false;
        if ($size === false || $size > self::MAX_BYTES) {
            return null;
        }
        $raw = file_get_contents($f);
        if ($raw === false) {
            return null;
        }
        $out = [];
        foreach (explode("\n", $raw) as $line) {
            if ($line === '') {
                continue;
            }
            if (preg_match('/^([a-f0-9]{64})  (.{1,180})$/D', $line, $m) !== 1 || !UpdatePaths::valid($m[2])) {
                return null;
            }
            $out[$m[2]] = $m[1];
        }
        return $out === [] ? null : $out;
    }

    public function diff(): ManifestDiff
    {
        $m = $this->load();
        if ($m === null) {
            return new ManifestDiff(false);
        }
        $changed = [];
        $missing = [];
        $known = [];
        foreach ($m as $rel => $hash) {
            if (!UpdatePaths::inScope($rel)) {
                continue;
            }
            $known[$rel] = true;
            $f = $this->root . '/' . $rel;
            if (!is_file($f) || is_link($f)) {
                $missing[] = $rel;
            } elseif (!hash_equals($hash, (string) hash_file('sha256', $f))) {
                $changed[] = $rel;
            }
        }
        $extra = [];
        foreach ($this->scan() as $rel) {
            if (!isset($known[$rel])) {
                $extra[] = $rel;
            }
        }
        sort($changed);
        sort($missing);
        sort($extra);
        $cut = static fn(array $l): array => array_slice($l, 0, ManifestDiff::LIMIT);
        return new ManifestDiff(true, $cut($changed), $cut($missing), $cut($extra));
    }

    /** @return list<string> */
    private function scan(): array
    {
        $out = [];
        foreach (UpdatePaths::scanFiles() as $rel) {
            if (is_file($this->root . '/' . $rel)) {
                $out[] = $rel;
            }
        }
        foreach (UpdatePaths::scanRoots() as $sub) {
            $base = $this->root . '/' . $sub;
            if (!is_dir($base) || is_link($base)) {
                continue;
            }
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($base, \FilesystemIterator::SKIP_DOTS));
            $n = 0;
            foreach ($it as $f) {
                if (++$n > 20000) {
                    break;
                }
                if ($f instanceof \SplFileInfo && !$f->isDir()) {
                    $out[] = substr($f->getPathname(), strlen($this->root) + 1); // symlink juga dihitung (tak ada di manifest)
                }
            }
        }
        return $out;
    }
}
