<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

/**
 * Mesin template aman (F6, SEC-OUT-01/02). Template ditafsirkan (bukan dikompilasi ke PHP):
 * tidak ada eval/include dari template maupun input. Cache hanya berisi AST JSON.
 *
 * Sintaks: {{ x }} {{ x|attr }} {{ x|js }} {{ x|url }} {!! x !!} {{ nonce }}
 *          {% if x %}{% else %}{% endif %} {% if a == b %} {% if not x %}
 *          {% for i in list %}{% endfor %} {% include 'nama' %} {% extends 'nama' %} {% block n %}{% endblock %}
 * Konteks default (HTML/atribut/JS) dideteksi dari posisi tag; output tanpa kutip di dalam tag ditolak.
 */
final class Template
{
    private const NAME = '/^[a-z0-9_]+(\/[a-z0-9_]+)*$/';
    private const PATH = '/^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)*$/';
    private const MAX_DEPTH = 10;
    private const EXT = '.tpl';
    private const CACHE_VERSION = 1;

    private readonly string $viewDir;

    public function __construct(string $viewDir, private readonly string $cacheDir)
    {
        $real = realpath($viewDir);
        if ($real === false || !is_dir($real)) {
            throw new TemplateError('Direktori view tidak ditemukan');
        }
        $this->viewDir = $real;
    }

    /** @param array<string,mixed> $vars */
    public function render(string $view, array $vars): SafeHtml
    {
        unset($vars['nonce']);
        $scope = $vars + ['nonce' => Nonce::current()];
        return SafeHtml::fromTrusted($this->renderView($view, $scope, [], 0));
    }

    // ---------- pemuatan & path ----------

    private function resolve(string $name): string
    {
        if (preg_match(self::NAME, $name) !== 1) {
            throw new TemplateError('Nama view tidak diizinkan');
        }
        $file = realpath($this->viewDir . '/' . $name . self::EXT);
        if ($file === false || !str_starts_with($file, $this->viewDir . DIRECTORY_SEPARATOR) || !is_file($file)) {
            throw new TemplateError('View tidak ditemukan');
        }
        return $file;
    }

    /** @return array{extends:?string,nodes:list<array<int|string,mixed>>} */
    private function load(string $name): array
    {
        $file = $this->resolve($name);
        $mtime = (int) filemtime($file);
        $size = (int) filesize($file);
        $cacheFile = rtrim($this->cacheDir, '/\\') . '/tpl_' . hash('sha256', $file) . '.json';
        if (is_file($cacheFile)) {
            $raw = file_get_contents($cacheFile);
            $c = $raw === false ? null : json_decode($raw, true);
            if (
                is_array($c) && ($c['v'] ?? null) === self::CACHE_VERSION && ($c['m'] ?? null) === $mtime
                && ($c['s'] ?? null) === $size && is_array($c['nodes'] ?? null)
                && (($c['extends'] ?? null) === null || is_string($c['extends']))
            ) {
                /** @var array{extends:?string,nodes:list<array<int|string,mixed>>} $ast */
                $ast = ['extends' => $c['extends'] ?? null, 'nodes' => $c['nodes']];
                return $ast;
            }
        }
        $src = file_get_contents($file);
        if ($src === false) {
            throw new TemplateError('View tidak terbaca');
        }
        $ast = $this->parse($src);
        if (is_dir($this->cacheDir) && is_writable($this->cacheDir)) {
            $tmp = $cacheFile . '.' . bin2hex(random_bytes(4)) . '.tmp';
            $json = json_encode(['v' => self::CACHE_VERSION, 'm' => $mtime, 's' => $size] + $ast);
            if ($json !== false && file_put_contents($tmp, $json, LOCK_EX) !== false) {
                rename($tmp, $cacheFile);
            }
        }
        return $ast;
    }

    // ---------- parser ----------

    /** @return array{extends:?string,nodes:list<array<int|string,mixed>>} */
    private function parse(string $src): array
    {
        if (str_contains($src, "\x01")) {
            throw new TemplateError('Karakter kontrol tidak diizinkan di template');
        }
        $parts = preg_split('/(\{!!.*?!!\}|\{\{.*?\}\}|\{%.*?%\})/s', $src, -1, PREG_SPLIT_DELIM_CAPTURE);
        if ($parts === false) {
            throw new TemplateError('Template tidak dapat diurai');
        }
        // Lewat 1: deteksi konteks tiap output pada teks datar dengan penanda.
        $flat = '';
        $n = 0;
        foreach ($parts as $i => $p) {
            if ($i % 2 === 0) {
                $flat .= $p;
            } elseif (str_starts_with($p, '{{') || str_starts_with($p, '{!!')) {
                $flat .= "\x01" . $n++ . "\x01";
            }
        }
        $ctx = $this->scanContexts($flat);

        // Lewat 2: bangun AST.
        $root = ['extends' => null, 'nodes' => []];
        /** @var list<array{type:string,node:array<int|string,mixed>,list:list<array<int|string,mixed>>}> $stack */
        $stack = [];
        $cur = [];
        $k = 0;
        foreach ($parts as $i => $p) {
            if ($i % 2 === 0) {
                if ($p !== '') {
                    $cur[] = ['t', $p];
                }
                continue;
            }
            if (str_starts_with($p, '{!!')) {
                $path = trim(substr($p, 3, -3));
                $this->checkPath($path);
                if ($ctx[$k++] === 'bad') {
                    throw new TemplateError('Output di posisi tag/style tanpa kutip tidak diizinkan');
                }
                $cur[] = ['r', $path];
            } elseif (str_starts_with($p, '{{')) {
                $cur[] = $this->outputNode(trim(substr($p, 2, -2)), $ctx[$k++]);
            } else {
                $this->statement(trim(substr($p, 2, -2)), $root, $stack, $cur);
            }
        }
        if ($stack !== []) {
            throw new TemplateError('Blok template tidak ditutup');
        }
        $root['nodes'] = $cur;
        /** @var array{extends:?string,nodes:list<array<int|string,mixed>>} $root */
        return $root;
    }

    /**
     * @param array{extends:?string,nodes:array<mixed>} $root
     * @param list<array{type:string,node:array<int|string,mixed>,list:list<array<int|string,mixed>>}> $stack
     * @param list<array<int|string,mixed>> $cur
     * @param-out list<array<int|string,mixed>> $cur
     */
    private function statement(string $s, array &$root, array &$stack, array &$cur): void
    {
        if (preg_match('/^(extends|include)\s+\'([a-z0-9_\/]+)\'$/', $s, $m) === 1) {
            if (preg_match(self::NAME, $m[2]) !== 1) {
                throw new TemplateError('Nama view tidak diizinkan');
            }
            if ($m[1] === 'extends') {
                $root['extends'] = $m[2];
            } else {
                $cur[] = ['inc', $m[2]];
            }
        } elseif (preg_match('/^if\s+(not\s+)?(\S+)(?:\s*==\s*(\S+))?$/', $s, $m) === 1) {
            $this->checkPath($m[2]);
            $rhs = $m[3] ?? null;
            if ($rhs !== null) {
                $this->checkPath($rhs);
            }
            $stack[] = ['type' => 'if', 'node' => ['if', $m[2], $m[1] !== '', $rhs], 'list' => $cur];
            $cur = [];
        } elseif ($s === 'else') {
            $top = $stack[count($stack) - 1] ?? null;
            if ($top === null || $top['type'] !== 'if') {
                throw new TemplateError('else tanpa if');
            }
            $stack[count($stack) - 1]['node'][4] = $cur; // cabang then
            $cur = [];
        } elseif (preg_match('/^for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+(\S+)$/', $s, $m) === 1) {
            $this->checkPath($m[2]);
            $stack[] = ['type' => 'for', 'node' => ['for', $m[1], $m[2]], 'list' => $cur];
            $cur = [];
        } elseif (preg_match('/^block\s+([a-z0-9_]+)$/', $s, $m) === 1) {
            $stack[] = ['type' => 'block', 'node' => ['block', $m[1]], 'list' => $cur];
            $cur = [];
        } elseif (in_array($s, ['endif', 'endfor', 'endblock'], true)) {
            $top = array_pop($stack);
            if ($top === null || 'end' . $top['type'] !== $s) {
                throw new TemplateError('Penutup blok tidak cocok');
            }
            $node = $top['node'];
            if ($top['type'] === 'if') {
                if (isset($node[4])) {
                    $node[5] = $cur;
                } else {
                    $node[4] = $cur;
                    $node[5] = [];
                }
            } else {
                $node[] = $cur;
            }
            $cur = $top['list'];
            $cur[] = $node;
        } else {
            throw new TemplateError('Pernyataan template tidak dikenal');
        }
    }

    /** @return array<int|string,mixed> */
    private function outputNode(string $expr, string $ctx): array
    {
        if ($ctx === 'bad') {
            throw new TemplateError('Output di posisi tag/style tanpa kutip tidak diizinkan');
        }
        $bits = explode('|', $expr);
        $path = trim($bits[0]);
        $this->checkPath($path);
        if (count($bits) > 2) {
            throw new TemplateError('Hanya satu filter per ekspresi');
        }
        $filter = isset($bits[1]) ? trim($bits[1]) : ($ctx === 'js' ? 'js' : ($ctx === 'url' ? 'url' : 'attr'));
        if (!in_array($filter, ['attr', 'js', 'url'], true)) {
            throw new TemplateError('Filter tidak dikenal');
        }
        if ($ctx === 'url' && $filter !== 'url') {
            throw new TemplateError('Atribut URL (href/src/action, dll.) hanya boleh memakai filter url');
        }
        if ($ctx === 'js' && $filter !== 'js') {
            throw new TemplateError('Di dalam <script> hanya filter js yang diizinkan');
        }
        return ['e', $path, $filter];
    }

    private const URL_ATTRS = [
        'href', 'src', 'action', 'formaction', 'poster', 'data', 'cite', 'background',
        'longdesc', 'manifest', 'ping', 'srcset', 'xlink:href', 'usemap', 'codebase', 'profile', 'icon',
    ];

    private function checkPath(string $p): void
    {
        if (preg_match(self::PATH, $p) !== 1) {
            throw new TemplateError('Nama variabel tidak valid');
        }
    }

    /**
     * Pindai HTML datar; kembalikan konteks tiap penanda: html|attr|js|bad.
     * Juga menolak atribut on* statis (SEC-OUT-02).
     * @return list<string>
     */
    private function scanContexts(string $flat): array
    {
        $out = [];
        $mode = 'text';
        $tag = '';
        $urlAttr = false;
        $len = strlen($flat);
        $i = 0;
        while ($i < $len) {
            $c = $flat[$i];
            if ($c === "\x01") {
                $end = strpos($flat, "\x01", $i + 1);
                $out[] = match ($mode) {
                    'text' => 'html', 'dq', 'sq' => $urlAttr ? 'url' : 'attr', 'script' => 'js', default => 'bad',
                };
                $i = ($end === false ? $len : $end) + 1;
                continue;
            }
            switch ($mode) {
                case 'text':
                    if (substr($flat, $i, 4) === '<!--') {
                        $e = strpos($flat, '-->', $i + 4);
                        $seg = substr($flat, $i, $e === false ? null : $e + 3 - $i);
                        // Satu konteks per penanda agar indeks tetap sejajar.
                        $cnt = (int) preg_match_all('/\x01\d+\x01/', $seg);
                        for ($q = 0; $q < $cnt; $q++) {
                            $out[] = 'html';
                        }
                        $i = $e === false ? $len : $e + 3;
                        continue 2;
                    }
                    if ($c === '<' && preg_match('/\G<([a-zA-Z][a-zA-Z0-9]*)/', $flat, $m, 0, $i) === 1) {
                        $mode = 'tag';
                        $tag = strtolower($m[1]);
                        $i += strlen($m[0]);
                        continue 2;
                    }
                    break;
                case 'tag':
                    if ($c === '"' || $c === "'") {
                        $mode = $c === '"' ? 'dq' : 'sq';
                        $urlAttr = preg_match('/([a-zA-Z][a-zA-Z0-9:_-]*)\s*=\s*$/', substr($flat, max(0, $i - 40), min($i, 40)), $am) === 1
                            && in_array(strtolower($am[1]), self::URL_ATTRS, true);
                    } elseif ($c === '>') {
                        $mode = in_array($tag, ['script', 'style'], true) ? $tag : 'text';
                    } elseif (preg_match('/\G[\s"\'\/]on[a-z]+\s*=/i', $flat, $m, 0, $i) === 1) {
                        throw new TemplateError('Atribut on* tidak diizinkan (SEC-OUT-02)');
                    }
                    break;
                case 'dq':
                case 'sq':
                    if ($c === ($mode === 'dq' ? '"' : "'")) {
                        $mode = 'tag';
                        if (preg_match('/\Gon[a-z]+\s*=/i', $flat, $m, 0, $i + 1) === 1) {
                            throw new TemplateError('Atribut on* tidak diizinkan (SEC-OUT-02)');
                        }
                    }
                    break;
                case 'script':
                case 'style':
                    if ($c === '<' && preg_match('/\G<\/' . $mode . '/i', $flat, $m, 0, $i) === 1) {
                        $tag = '/' . $mode;
                        $mode = 'tag';
                        $i += strlen($m[0]);
                        continue 2;
                    }
                    break;
            }
            $i++;
        }
        return $out;
    }

    // ---------- render ----------

    /**
     * @param array<string,mixed> $scope
     * @param array<string,list<array<int|string,mixed>>> $overrides
     */
    private function renderView(string $name, array $scope, array $overrides, int $depth): string
    {
        if ($depth > self::MAX_DEPTH) {
            throw new TemplateError('Kedalaman template melebihi batas');
        }
        $ast = $this->load($name);
        if ($ast['extends'] !== null) {
            foreach ($ast['nodes'] as $node) {
                if (($node[0] ?? null) === 'block' && is_string($node[1]) && is_array($node[2] ?? null)) {
                    /** @var list<array<int|string,mixed>> $body */
                    $body = $node[2];
                    $overrides += [$node[1] => $body]; // override dari anak menang
                }
            }
            return $this->renderView($ast['extends'], $scope, $overrides, $depth + 1);
        }
        return $this->renderNodes($ast['nodes'], $scope, $overrides, $depth);
    }

    /**
     * @param list<array<int|string,mixed>> $nodes
     * @param array<string,mixed> $scope
     * @param array<string,list<array<int|string,mixed>>> $ov
     */
    private function renderNodes(array $nodes, array $scope, array $ov, int $depth): string
    {
        $out = '';
        foreach ($nodes as $n) {
            $type = $n[0] ?? null;
            switch ($type) {
                case 't':
                    $out .= is_string($n[1]) ? $n[1] : '';
                    break;
                case 'e':
                    $out .= $this->escape($this->scalar($this->lookup($scope, (string) $n[1])), (string) $n[2]);
                    break;
                case 'r':
                    $v = $this->lookup($scope, (string) $n[1]);
                    if (!$v instanceof SafeHtml) {
                        throw new TemplateError('{!! !!} hanya menerima SafeHtml');
                    }
                    $out .= $v->toString();
                    break;
                case 'inc':
                    $out .= $this->renderView((string) $n[1], $scope, [], $depth + 1);
                    break;
                case 'if':
                    $a = $this->lookup($scope, (string) $n[1]);
                    $res = $n[3] !== null ? $a === $this->lookup($scope, (string) $n[3]) : !empty($a);
                    if ($n[2] === true) {
                        $res = !$res;
                    }
                    $branch = $res ? ($n[4] ?? []) : ($n[5] ?? []);
                    $out .= $this->renderNodes(is_array($branch) ? $branch : [], $scope, $ov, $depth);
                    break;
                case 'for':
                    $list = $this->lookup($scope, (string) $n[2]);
                    if (is_array($list)) {
                        foreach ($list as $item) {
                            $out .= $this->renderNodes(is_array($n[3] ?? null) ? $n[3] : [], [(string) $n[1] => $item] + $scope, $ov, $depth);
                        }
                    }
                    break;
                case 'block':
                    $body = $ov[(string) $n[1]] ?? ($n[2] ?? []);
                    $out .= $this->renderNodes(is_array($body) ? $body : [], $scope, $ov, $depth);
                    break;
                default:
                    throw new TemplateError('Node template tidak valid');
            }
        }
        return $out;
    }

    /**
     * Hanya kunci array; tanpa properti/metode objek.
     * @param array<string,mixed> $scope
     */
    private function lookup(array $scope, string $path): mixed
    {
        $cur = $scope;
        foreach (explode('.', $path) as $seg) {
            if (!is_array($cur) || !array_key_exists($seg, $cur)) {
                return null;
            }
            $cur = $cur[$seg];
        }
        return $cur;
    }

    private function scalar(mixed $v): string
    {
        if ($v === null || $v === false) {
            return '';
        }
        if ($v === true) {
            return '1';
        }
        if (is_scalar($v) || $v instanceof \Stringable) {
            return (string) $v;
        }
        throw new TemplateError('Nilai tidak dapat dicetak (array/objek)');
    }

    private function escape(string $s, string $filter): string
    {
        switch ($filter) {
            case 'js':
                $j = json_encode($s, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_INVALID_UTF8_SUBSTITUTE);
                return $j === false ? '""' : str_replace(["\u{2028}", "\u{2029}"], [' ', ' '], $j);
            case 'url':
                return $this->h($this->safeUrl($s));
            default:
                return $this->h($s);
        }
    }

    private function h(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /** Hanya http/https atau relatif; selain itu "#". */
    private function safeUrl(string $u): string
    {
        $probe = preg_replace('/[\x00-\x20\x7f]+/', '', $u) ?? '';
        if ($probe === '' || str_contains($probe, '\\')) {
            return $probe === '' ? '' : '#';
        }
        if (preg_match('/^([a-z][a-z0-9+.\-]*):/i', $probe, $m) === 1) {
            return in_array(strtolower($m[1]), ['http', 'https', 'mailto', 'tel'], true) ? $probe : '#';
        }
        return $probe;
    }
}
