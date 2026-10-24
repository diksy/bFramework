<?php

declare(strict_types=1);

namespace bFramework\Builder;

defined('APP_BOOTED') || exit;

/**
 * Mendaftar hook di extensions/ lewat analisis token (TIDAK pernah require/eval/include kode ekstensi).
 * Kelas berisi konstruksi berbahaya ditandai `blocked` dan tidak boleh dirujuk dari definisi; konstruksi
 * yang patut dicurigai hanya ditandai `warnings`.
 */
final class HookScanner
{
    private const MAX_BYTES = 262144;
    /** Fungsi yang membuat kelas ditolak (eksekusi kode/perintah, deserialisasi objek). */
    private const DANGEROUS_CALLS = [
        'exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open', 'pcntl_exec', 'assert', 'create_function',
        'unserialize', 'eval', 'putenv', 'dl', 'set_include_path',
        'call_user_func', 'call_user_func_array', 'forward_static_call', 'forward_static_call_array', 'extract',
        'parse_str', 'register_shutdown_function', 'register_tick_function', 'iterator_apply', 'get_defined_vars',
        'fromcallable',
    ];
    /** Kelas reflection yang dapat memanggil fungsi/method secara tidak langsung. */
    private const DANGEROUS_CLASSES = [
        'reflectionfunction', 'reflectionmethod', 'reflectionclass', 'reflectionobject', 'reflectionproperty',
        'reflectionenum', 'reflectiongenerator',
    ];
    /** Fungsi yang hanya diberi peringatan. */
    private const SUSPICIOUS_CALLS = [
        'file_put_contents', 'fwrite', 'unlink', 'rename', 'copy', 'mkdir', 'rmdir', 'chmod', 'curl_exec', 'curl_init',
        'fsockopen', 'stream_socket_client', 'mail', 'base64_decode',
        'file_get_contents', 'fopen', 'move_uploaded_file', 'header', 'ini_set',
    ];

    public function __construct(private readonly string $extDir)
    {
    }

    /**
     * @return list<array{class:string,blocked:bool,warnings:list<string>,methods:list<array{name:string,doc:string,ref:string}>}>
     */
    public function scan(): array
    {
        $base = realpath($this->extDir);
        if ($base === false || !is_dir($base)) {
            return [];
        }
        $out = [];
        $files = scandir($base) ?: [];
        sort($files);
        foreach ($files as $f) {
            if (preg_match('/^([A-Z][A-Za-z0-9_]{0,63})\.php$/D', $f, $m) !== 1) {
                continue;
            }
            $path = $base . '/' . $f;
            $real = realpath($path);
            if (is_link($path) || $real === false || !str_starts_with($real, $base . '/') || !is_file($real)) {
                continue;
            }
            $code = (int) filesize($real) <= self::MAX_BYTES ? @file_get_contents($real) : false;
            if (!is_string($code)) {
                $out[] = ['class' => $m[1], 'blocked' => true, 'warnings' => ['Berkas terlalu besar atau tidak terbaca'], 'methods' => []];
                continue;
            }
            $r = self::inspect($code, $m[1]);
            $out[] = ['class' => $m[1]] + $r;
        }
        return $out;
    }

    /** Apakah kelas ada, tidak ditandai berbahaya, dan memiliki method static publik tersebut. */
    public function isUsable(string $class, string $method): bool
    {
        foreach ($this->scan() as $c) {
            if ($c['class'] === $class && !$c['blocked']) {
                foreach ($c['methods'] as $x) {
                    if ($x['name'] === $method) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static function lastSegment(string $name): string
    {
        $p = strrpos($name, '\\');
        return $p === false ? $name : substr($name, $p + 1);
    }

    /**
     * @return array{blocked:bool,warnings:list<string>,methods:list<array{name:string,doc:string,ref:string}>}
     */
    public static function inspect(string $code, string $class): array
    {
        try {
            $tokens = token_get_all($code, TOKEN_PARSE);
        } catch (\ParseError) {
            return ['blocked' => true, 'warnings' => ['Sintaks PHP tidak valid'], 'methods' => []];
        }
        $blocked = false;
        $warn = [];
        $methods = [];
        $sig = [];
        foreach ($tokens as $t) {
            if (is_array($t) && in_array($t[0], [T_WHITESPACE, T_COMMENT], true)) {
                continue;
            }
            $sig[] = $t;
        }
        $hasClass = false;
        $n = count($sig);
        for ($i = 0; $i < $n; $i++) {
            $t = $sig[$i];
            if ($t === '`') {
                $blocked = true;
                $warn[] = 'Operator backtick (eksekusi shell)';
                continue;
            }
            if (!is_array($t)) {
                if ($t === '(' && $i > 0 && in_array($sig[$i - 1], [')', ']', '}'], true)) {
                    $blocked = true;
                    $warn[] = 'Panggilan dinamis: ' . $sig[$i - 1] . '(';
                } elseif ($t === '$') {
                    $blocked = true;
                    $warn[] = 'Variable-variable ($$)';
                }
                continue;
            }
            [$id, $text] = $t;
            if (in_array($id, [T_EVAL, T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE, T_HALT_COMPILER], true)) {
                $blocked = true;
                $warn[] = 'Konstruksi berbahaya: ' . strtolower($text);
            } elseif (in_array($id, [T_STRING, T_NAME_FULLY_QUALIFIED, T_NAME_QUALIFIED, T_NAME_RELATIVE], true)) {
                $next = $sig[$i + 1] ?? null;
                $prev = $sig[$i - 1] ?? null;
                $pid = is_array($prev) ? $prev[0] : null;
                $fn = strtolower(self::lastSegment($text));
                if (in_array($fn, self::DANGEROUS_CLASSES, true)) {
                    $blocked = true;
                    $warn[] = 'Reflection: ' . $fn;
                }
                $isMember = $pid !== null && in_array($pid, [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_FUNCTION], true);
                if ($next === '(' && !$isMember && $pid !== T_NEW) {
                    $static = $pid === T_DOUBLE_COLON;
                    if (in_array($fn, self::DANGEROUS_CALLS, true) && (!$static || $fn === 'fromcallable')) {
                        $blocked = true;
                        $warn[] = 'Pemanggilan berbahaya: ' . $fn . '()';
                    } elseif ($fn === 'preg_replace' && !$static) {
                        $lit = $sig[$i + 2] ?? null;
                        if (!is_array($lit) || $lit[0] !== T_CONSTANT_ENCAPSED_STRING || preg_match('/^.(.).*\1[a-zA-Z]*e[a-zA-Z]*.$/Ds', $lit[1]) === 1) {
                            $blocked = true;
                            $warn[] = 'preg_replace dengan pola dinamis atau modifier /e';
                        }
                    } elseif (!$static && in_array($fn, self::SUSPICIOUS_CALLS, true)) {
                        $warn[] = 'Perlu ditinjau: ' . $fn . '()';
                    }
                } elseif ($pid === T_DOUBLE_COLON && $fn === 'fromcallable') {
                    $blocked = true;
                    $warn[] = 'Closure::fromCallable';
                }
            } elseif ($id === T_CONSTANT_ENCAPSED_STRING || $id === T_ENCAPSED_AND_WHITESPACE) {
                $str = strtolower(ltrim(trim($text, "'\""), '\\'));
                $last = strtolower(self::lastSegment($str));
                if (in_array($last, self::DANGEROUS_CALLS, true) || in_array($last, self::DANGEROUS_CLASSES, true)) {
                    $blocked = true;
                    $warn[] = 'String nama fungsi berbahaya: ' . $last;
                }
                if (($sig[$i + 1] ?? null) === '(') {
                    $blocked = true;
                    $warn[] = 'Panggilan dinamis dari string';
                }
            } elseif ($id === T_VARIABLE && ($sig[$i + 1] ?? null) === '(') {
                $blocked = true;
                $warn[] = 'Panggilan dinamis: variabel sebagai fungsi';
            } elseif ($id === T_NEW) {
                $nx = $sig[$i + 1] ?? null;
                if (is_array($nx) && ($nx[0] === T_CLASS || $nx[0] === T_VARIABLE)) {
                    $blocked = true;
                    $warn[] = $nx[0] === T_CLASS ? 'Kelas anonim (new class)' : 'Instansiasi dinamis (new $var)';
                } elseif ($nx === '(') {
                    $blocked = true;
                    $warn[] = 'Instansiasi dinamis';
                }
            } elseif ($id === T_CLASS && !(is_array($sig[$i - 1] ?? null) && ($sig[$i - 1][0] === T_DOUBLE_COLON))) {
                $nm = $sig[$i + 1] ?? null;
                if (is_array($nm) && $nm[0] === T_STRING && $nm[1] === $class) {
                    $hasClass = true;
                }
            } elseif ($id === T_FUNCTION) {
                // public static function name -> cari modifier di belakang tanpa melewati batas statement.
                $name = $sig[$i + 1] ?? null;
                if (is_array($name) && $name[0] === T_STRING) {
                    $mods = [];
                    for ($j = $i - 1; $j >= 0 && is_array($sig[$j]) && in_array($sig[$j][0], [T_PUBLIC, T_PROTECTED, T_PRIVATE, T_STATIC, T_FINAL, T_ABSTRACT, T_DOC_COMMENT], true); $j--) {
                        $mods[$sig[$j][0]] = $sig[$j][1];
                    }
                    if (isset($mods[T_PUBLIC], $mods[T_STATIC])) {
                        $doc = isset($mods[T_DOC_COMMENT])
                            ? trim((string) preg_replace('#^\s*/\*+|\*+/\s*$|^\s*\*\s?#m', '', $mods[T_DOC_COMMENT]))
                            : '';
                        $methods[] = ['name' => $name[1], 'doc' => mb_substr($doc, 0, 200), 'ref' => $class . '::' . $name[1]];
                    }
                }
            }
        }
        if (!$hasClass) {
            $blocked = true;
            $warn[] = 'Kelas ' . $class . ' tidak ditemukan di berkas';
        }
        return ['blocked' => $blocked, 'warnings' => array_values(array_unique($warn)), 'methods' => $blocked ? [] : $methods];
    }
}
