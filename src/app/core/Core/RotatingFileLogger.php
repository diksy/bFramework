<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Logger;
use InvalidArgumentException;
use Throwable;

/**
 * Logger berkas JSON-per-baris dengan rotasi ukuran (SEC-LOG-01). Berkas `app.log` di `$dir`
 * (sebaiknya `app/storage/logs`, di luar docroot). Semua konteks dan pesan melewati Redactor.
 * Kegagalan menulis ditelan agar tidak menggagalkan request.
 */
final class RotatingFileLogger implements Logger
{
    private const FILE = 'app.log';
    private const LOCK = '.lock';
    private const MAX_LINE = 4000;
    private const MIN_BYTES = 4096;
    private const MAX_KEEP = 20;

    private readonly string $dir;

    public function __construct(string $dir, private readonly int $maxBytes, private readonly int $keep)
    {
        if ($maxBytes < self::MIN_BYTES || $keep < 1 || $keep > self::MAX_KEEP) {
            throw new InvalidArgumentException('Parameter rotasi log tidak valid');
        }
        $this->dir = rtrim($dir, '/\\');
    }

    /** @param array<string,scalar> $ctx */
    public function error(string $msg, array $ctx = []): void
    {
        $this->write('error', $msg, $ctx);
    }

    /** @param array<string,scalar> $ctx */
    public function warning(string $msg, array $ctx = []): void
    {
        $this->write('warning', $msg, $ctx);
    }

    /** @param array<string,scalar> $ctx */
    public function info(string $msg, array $ctx = []): void
    {
        $this->write('info', $msg, $ctx);
    }

    /** @param array<string,scalar> $ctx */
    private function write(string $level, string $msg, array $ctx): void
    {
        try {
            $this->append($this->line($level, $msg, $ctx));
        } catch (Throwable) {
            // Sengaja ditelan: logging tidak boleh menggagalkan respons.
        }
    }

    /** @param array<string,scalar> $ctx */
    private function line(string $level, string $msg, array $ctx): string
    {
        $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE;
        $time = gmdate('Y-m-d\TH:i:s\Z');
        $json = json_encode([
            't' => $time,
            'lvl' => $level,
            'msg' => Redactor::message($msg),
            'ctx' => Redactor::clean($ctx),
        ], $flags);
        if ($json === false || strlen($json) > self::MAX_LINE) {
            $json = json_encode(['t' => $time, 'lvl' => $level, 'msg' => '(catatan terlalu panjang, dipotong)'], $flags) ?: '{}';
        }
        return $json . "\n";
    }

    private function append(string $line): void
    {
        if (!is_dir($this->dir) && !@mkdir($this->dir, 0750, true) && !is_dir($this->dir)) {
            return;
        }
        $lock = @fopen($this->dir . '/' . self::LOCK, 'c');
        if ($lock === false) {
            return;
        }
        try {
            if (!flock($lock, LOCK_EX)) {
                return;
            }
            $path = $this->dir . '/' . self::FILE;
            clearstatcache(true, $path);
            $size = is_file($path) ? (int) filesize($path) : 0;
            if ($size > 0 && $size + strlen($line) > $this->maxBytes) {
                $this->rotate($path);
            }
            $isNew = !is_file($path);
            if (file_put_contents($path, $line, FILE_APPEND) !== false && $isNew) {
                @chmod($path, 0640);
            }
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /** app.log -> app.log.1 -> ... -> app.log.<keep> (yang lebih tua dibuang). */
    private function rotate(string $path): void
    {
        for ($i = $this->keep - 1; $i >= 1; $i--) {
            $from = $path . '.' . $i;
            if (is_file($from)) {
                rename($from, $path . '.' . ($i + 1));
            }
        }
        rename($path, $path . '.1');
    }
}
