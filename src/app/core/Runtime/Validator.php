<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

/**
 * Validasi berbasis definisi (SEC-DATA-02): hanya field yang terdaftar yang diambil; field `guarded`
 * dan kunci asing (role, id, owner, dst.) tidak pernah masuk hasil. decimal = numeric-string (bukan float).
 * Pesan error memuat path sumber definisi (CACHE-10).
 */
final class Validator
{
    /**
     * @param array<string,mixed> $def model ter-compile
     * @param array<string,mixed> $input
     * @param bool $showSrc true hanya di mode dev; produksi: `_src` hanya ke log
     * @return array{0:array<string,mixed>,1:array<string,list<string>>}
     */
    public static function validate(array $def, array $input, bool $showSrc = false, ?\bFramework\Contracts\Logger $logger = null): array
    {
        $clean = [];
        $errors = [];
        $fields = is_array($def['fields'] ?? null) ? $def['fields'] : [];
        foreach ($fields as $name => $f) {
            $name = (string) $name;
            if (!is_array($f) || ($f['guarded'] ?? false) === true) {
                continue;
            }
            $label = is_string($f['label'] ?? null) ? $f['label'] : ucfirst($name);
            $type = (string) ($f['type'] ?? 'string');
            $suffix = is_string($f['_src'] ?? null) ? ' [' . $f['_src'] . ']' : '';
            $err = static function (string $m) use (&$errors, $name, $suffix, $showSrc, $logger): void {
                $logger?->warning(\bFramework\Core\Redactor::message('Validasi gagal: ' . $m . $suffix), ['field' => $name]);
                $errors[$name][] = $showSrc ? $m . $suffix : $m;
            };
            $raw = array_key_exists($name, $input) ? $input[$name] : null;
            if ($type === 'boolean') {
                $clean[$name] = $raw === true || $raw === 1 || (is_string($raw) && in_array(strtolower(trim($raw)), ['1', 'on', 'true', 'ya'], true)) ? 1 : 0;
                continue;
            }
            if (is_array($raw) && $type === 'json') {
                $enc = json_encode($raw, JSON_UNESCAPED_UNICODE);
                $raw = $enc === false ? null : $enc;
            }
            if (is_string($raw)) {
                $raw = trim($raw);
            } elseif ($raw !== null && !is_int($raw) && !is_float($raw)) {
                $err("$label tidak valid.");
                continue;
            }
            if ($raw === null || $raw === '') {
                if (($f['required'] ?? false) === true) {
                    $err("$label wajib diisi.");
                } else {
                    $clean[$name] = array_key_exists('default', $f) ? self::defaultFor($type, $f['default']) : null;
                }
                continue;
            }
            $v = self::typed($type, $raw, $f, $label, $err);
            if ($v !== null) {
                $clean[$name] = $v;
            }
        }
        return [$clean, $errors];
    }

    /**
     * @param array<string,mixed> $f
     * @param callable(string):void $err
     */
    private static function typed(string $type, mixed $raw, array $f, string $label, callable $err): int|string|null
    {
        $min = $f['min'] ?? null;
        $max = $f['max'] ?? null;
        $s = (string) $raw;
        switch ($type) {
            case 'integer':
            case 'relasi':
                $i = filter_var($s, FILTER_VALIDATE_INT);
                if ($i === false || is_float($raw) || ($type === 'relasi' && $i < 1)) {
                    $err("$label harus berupa bilangan bulat.");
                    return null;
                }
                if (is_numeric($min) && $i < $min) {
                    $err("$label minimal $min.");
                    return null;
                }
                if (is_numeric($max) && $i > $max) {
                    $err("$label maksimal $max.");
                    return null;
                }
                return $i;
            case 'decimal':
                return self::decimal($s, $f, $label, $err);
            case 'date':
                $d = \DateTimeImmutable::createFromFormat('!Y-m-d', $s);
                if ($d === false || $d->format('Y-m-d') !== $s) {
                    $err("$label harus tanggal valid (TTTT-BB-HH).");
                    return null;
                }
                return $s;
            case 'datetime':
                foreach (['Y-m-d H:i:s', 'Y-m-d\TH:i:s', 'Y-m-d H:i', 'Y-m-d\TH:i'] as $fmt) {
                    $d = \DateTimeImmutable::createFromFormat('!' . $fmt, $s);
                    if ($d !== false && $d->format($fmt) === $s) {
                        return $d->format('Y-m-d H:i:s');
                    }
                }
                $err("$label harus tanggal-waktu valid.");
                return null;
            case 'json':
                if (mb_strlen($s) > 65535) {
                    $err("$label terlalu panjang.");
                    return null;
                }
                try {
                    json_decode($s, true, 32, JSON_THROW_ON_ERROR);
                } catch (\JsonException) {
                    $err("$label harus JSON valid.");
                    return null;
                }
                return $s;
            default: // string, text
                if (preg_match('//u', $s) !== 1 || ($type === 'string' && preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $s) === 1)) {
                    $err("$label mengandung karakter tidak valid.");
                    return null;
                }
                $len = mb_strlen($s);
                $limit = $type === 'text' ? 65535 : 255;
                if (is_int($max) && $max > 0) {
                    $limit = $max;
                }
                if ($len > $limit) {
                    $err("$label maksimal $limit karakter.");
                    return null;
                }
                if (is_int($min) && $len < $min) {
                    $err("$label minimal $min karakter.");
                    return null;
                }
                return $s;
        }
    }

    /**
     * @param array<string,mixed> $f
     * @param callable(string):void $err
     */
    private static function decimal(string $s, array $f, string $label, callable $err): ?string
    {
        $n = str_replace(',', '.', $s);
        if (preg_match('/^(-?)([0-9]{1,30})(?:\.([0-9]{1,30}))?$/D', $n, $m) !== 1) {
            $err("$label harus berupa angka.");
            return null;
        }
        $scale = is_int($f['scale'] ?? null) ? $f['scale'] : 2;
        $prec = is_int($f['precision'] ?? null) ? $f['precision'] : 12;
        $int = ltrim($m[2], '0');
        $frac = rtrim($m[3] ?? '', '0');
        if (strlen($frac) > $scale) {
            $err("$label maksimal $scale angka desimal.");
            return null;
        }
        if (strlen($int) > $prec - $scale) {
            $err("$label terlalu besar.");
            return null;
        }
        $out = ($int === '' ? '0' : $int) . ($frac === '' ? '' : '.' . $frac);
        if ($m[1] === '-' && $out !== '0') {
            $out = '-' . $out;
        }
        foreach (['min' => -1, 'max' => 1] as $k => $dir) {
            $lim = $f[$k] ?? null;
            if ((is_int($lim) || is_float($lim)) && self::cmp($out, self::limitString($lim)) === $dir) {
                $err("$label " . ($k === 'min' ? 'minimal' : 'maksimal') . " $lim.");
                return null;
            }
        }
        return $out;
    }

    private static function limitString(int|float $v): string
    {
        $s = is_int($v) ? (string) $v : rtrim(rtrim(number_format($v, 10, '.', ''), '0'), '.');
        return $s === '' || $s === '-' ? '0' : $s;
    }

    /** Bandingkan dua numeric-string desimal tanpa float: -1, 0, 1. */
    private static function cmp(string $a, string $b): int
    {
        $parse = static function (string $x): array {
            $neg = str_starts_with($x, '-');
            $x = ltrim($x, '-');
            [$i, $f] = array_pad(explode('.', $x, 2), 2, '');
            return [$neg, ltrim($i, '0'), rtrim($f, '0')];
        };
        [$na, $ia, $fa] = $parse($a);
        [$nb, $ib, $fb] = $parse($b);
        $zeroA = $ia === '' && $fa === '';
        $zeroB = $ib === '' && $fb === '';
        $na = $na && !$zeroA;
        $nb = $nb && !$zeroB;
        if ($na !== $nb) {
            return $na ? -1 : 1;
        }
        $len = max(strlen($fa), strlen($fb));
        $x = str_pad($ia, 40, '0', STR_PAD_LEFT) . str_pad($fa, $len, '0');
        $y = str_pad($ib, 40, '0', STR_PAD_LEFT) . str_pad($fb, $len, '0');
        $c = strcmp($x, $y);
        $c = $c <=> 0;
        return $na ? -$c : $c;
    }

    private static function defaultFor(string $type, mixed $d): int|string|null
    {
        return match (true) {
            $d === null => null,
            is_bool($d) => $d ? 1 : 0,
            is_int($d) && $type === 'decimal' => (string) $d,
            is_int($d) || is_string($d) => $d,
            default => null,
        };
    }
}
