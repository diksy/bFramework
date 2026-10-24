<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

/** Format tampilan id-ID (pemisah ribuan ".", desimal ","). Hasil teks biasa; escape dilakukan Template. */
final class Format
{
    /** @param int|string|null $n numeric-string/int (decimal tidak melewati float) */
    public static function number(int|string|null $n, string $format = ''): string
    {
        $s = (string) $n;
        if (preg_match('/^(-?)([0-9]+)(?:\.([0-9]+))?$/D', $s, $m) !== 1) {
            return $s === '' ? '-' : $s;
        }
        $int = ltrim($m[2], '0');
        $int = $int === '' ? '0' : $int;
        $grouped = strrev(implode('.', str_split(strrev($int), 3)));
        $frac = rtrim($m[3] ?? '', '0');
        if ($frac !== '') {
            $grouped .= ',' . str_pad($frac, 2, '0');
        }
        $neg = $m[1] === '-' && ($int !== '0' || $frac !== '');
        $out = ($neg ? '-' : '') . $grouped;
        return $format === 'rupiah' ? ($neg ? '-Rp ' . $grouped : 'Rp ' . $grouped) : $out;
    }

    /**
     * @param array<string,mixed> $field
     * @param array<int,string> $labels id => label untuk relasi
     */
    public static function cell(array $field, mixed $v, array $labels = []): string
    {
        if ($v === null || $v === '') {
            return '-';
        }
        $format = is_string($field['format'] ?? null) ? $field['format'] : '';
        $type = is_string($field['type'] ?? null) ? $field['type'] : 'string';
        if (is_array($v) || is_object($v)) {
            return '-';
        }
        if (is_array($field['upload'] ?? null)) {
            return 'Berkas terlampir'; // fid tidak ditampilkan
        }
        return match ($type) {
            'boolean' => (int) $v === 1 ? 'Ya' : 'Tidak',
            'decimal', 'integer' => self::number(is_int($v) ? $v : (string) $v, $format),
            'relasi' => $labels[(int) $v] ?? '(tidak ditemukan)',
            'date' => self::date((string) $v, 'd-m-Y'),
            'datetime' => self::date((string) $v, 'd-m-Y H:i'),
            default => (string) $v,
        };
    }

    private static function date(string $v, string $fmt): string
    {
        try {
            return (new \DateTimeImmutable($v))->format($fmt);
        } catch (\Exception) {
            return $v;
        }
    }
}
