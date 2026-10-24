<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

use JsonException;
use RuntimeException;

final class Json
{
    /**
     * File tidak ada menghasilkan []. JSON rusak melempar JsonException.
     *
     * @return array<mixed>
     */
    public static function read(string $file): array
    {
        if (!is_file($file)) {
            return [];
        }
        $raw = file_get_contents($file);
        if ($raw === false) {
            throw new RuntimeException('File tidak dapat dibaca');
        }
        $d = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($d)) {
            throw new JsonException('Root JSON harus objek atau array');
        }
        return $d;
    }

    /**
     * Deterministik (BLD-03): urutan key sesuai input, indentasi 2 spasi, tanpa escape, newline akhir.
     *
     * @param array<mixed> $data
     */
    public static function pretty(array $data): string
    {
        $s = json_encode(
            $data,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR
        );
        // PHP memakai 4 spasi; ubah ke 2. Aman: newline di dalam string selalu di-escape.
        $s = (string) preg_replace_callback(
            '/^( +)/m',
            static fn(array $m): string => str_repeat(' ', intdiv(strlen($m[1]), 2)),
            $s
        );
        return $s . "\n";
    }
}
