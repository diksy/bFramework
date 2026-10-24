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
    private const RATE_FILE = '.rate';
    private const RATE_WINDOW = 60;
    private const RATE_MAX_KEYS = 200;
    private const LOCK = '.lock';
    private const MAX_LINE = 4000;
    private const MIN_BYTES = 4096;
    private const MAX_KEEP = 20;
    private const SKIP_SUFFIX = '.skip';
    private const NOTE_WINDOW = 60;
    private const RECOVER_TRIES = 25;
    private const RECOVER_SLEEP_US = 20000;

    private readonly string $dir;
    /** @var array<string,bool> Flag re-entrancy (S8b) per direktori: warning dari rename() gagal -> ErrorHandler -> logger mana pun tidak boleh flock .lock yang sama. */
    private static array $busy = [];
    /** @var array<string,resource> Handle .lock yang sedang dipegang per kunci direktori; dilepas oleh recoverAfterFatal(). */
    private static array $held = [];
    /** @var array<string,int> Cadangan pembatas laju catatan kegagalan rotasi bila berkas status tak dapat ditulis. */
    private static array $lastNote = [];
    /** Setelah fatal: flock non-blocking dengan batas percobaan (handle lama mungkin masih memegang kunci). */
    private static bool $afterFatal = false;
    private ?string $realDir = null;

    /**
     * @param string $file nama berkas log (kanal terpisah, mis. audit.log, berkas dan kuota rotasi sendiri)
     * @param int|null $maxPerMinute batas catatan per pesan per menit (null = tanpa batas); batas total = 10x (S8a)
     */
    public function __construct(
        string $dir,
        private readonly int $maxBytes,
        private readonly int $keep,
        private readonly string $file = self::FILE,
        private readonly ?int $maxPerMinute = null,
        private readonly bool $truncateOnRotateFail = true,
    ) {
        if (preg_match('/^[A-Za-z0-9_-]{1,40}\.log$/D', $file) !== 1 || ($maxPerMinute !== null && $maxPerMinute < 1)) {
            throw new InvalidArgumentException('Parameter log tidak valid');
        }
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
        $raw = $this->dir;
        if (self::$busy[$raw] ?? false) {
            return; // re-entrant (mis. warning dari rename() gagal, juga dari instance lain): jangan flock lagi.
        }
        self::$busy[$raw] = true;
        $key = null;
        try {
            if (!is_dir($this->dir) && !@mkdir($this->dir, 0750, true) && !is_dir($this->dir)) {
                return;
            }
            // Kunci kanonik (realpath) agar path berbeda ke direktori yang sama tetap terdeteksi.
            $key = $this->realDir ??= (realpath($this->dir) ?: null);
            if ($key !== null && $key !== $raw) {
                if (self::$busy[$key] ?? false) {
                    $key = null;
                    return;
                }
                self::$busy[$key] = true;
            }
            $this->append($this->line($level, $msg, $ctx), $level . '|' . $msg, $key ?? $raw);
        } catch (Throwable) {
            // Sengaja ditelan: logging tidak boleh menggagalkan respons.
        } finally {
            unset(self::$busy[$raw]);
            if ($key !== null) {
                unset(self::$busy[$key]);
            }
        }
    }

    /**
     * Dipanggil handler shutdown setelah fatal (S8b): fatal di tengah write() melewati finally sehingga
     * flag re-entrancy dan flock .lock masih dipegang proses ini. Lepas keduanya agar fatal bisa dicatat;
     * flock berikutnya non-blocking dengan batas percobaan sehingga tidak pernah menggantung.
     */
    public static function recoverAfterFatal(): void
    {
        foreach (self::$held as $h) {
            @flock($h, LOCK_UN);
            @fclose($h);
        }
        self::$held = [];
        self::$busy = [];
        self::$afterFatal = true;
    }

    /** @param resource $lock */
    private static function acquire($lock): bool
    {
        if (!self::$afterFatal) {
            return flock($lock, LOCK_EX);
        }
        for ($i = 0; $i < self::RECOVER_TRIES; $i++) {
            if (flock($lock, LOCK_EX | LOCK_NB)) {
                return true;
            }
            usleep(self::RECOVER_SLEEP_US);
        }
        return false;
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

    private function append(string $line, string $key, string $dirKey): void
    {
        $lock = @fopen($this->dir . '/' . self::LOCK, 'c');
        if ($lock === false) {
            return;
        }
        $locked = false;
        try {
            if (!self::acquire($lock)) {
                if (self::$afterFatal) {
                    error_log('bFramework: log ' . $this->file . ' tidak dapat dikunci setelah fatal: ' . rtrim($line));
                }
                return;
            }
            $locked = true;
            self::$held[$dirKey] = $lock;
            if ($this->maxPerMinute !== null) {
                $summary = '';
                if (!$this->allow($key, $summary)) {
                    return;
                }
                $line = $summary . $line;
            }
            $skipFile = $this->dir . '/.' . $this->file . self::SKIP_SUFFIX;
            $skipped = 0;
            if (!$this->truncateOnRotateFail && is_file($skipFile)) {
                $skipped = $this->readSkip($skipFile)['n'];
                if ($skipped > 0) {
                    $line = $this->line('warning', 'Entri log terlewat karena rotasi gagal', ['kanal' => $this->file, 'terlewat' => $skipped]) . $line;
                }
            }
            $path = $this->dir . '/' . $this->file;
            clearstatcache(true, $path);
            $size = is_file($path) ? (int) filesize($path) : 0;
            if ($size > 0 && $size + strlen($line) > $this->maxBytes) {
                if (!$this->rotate($path)) {
                    $this->recordSkip(); // rotasi gagal dan tidak boleh memotong: lewati tulis (kuota keras), tapi tidak diam-diam
                    return;
                }
            }
            $isNew = !is_file($path);
            $ok = @file_put_contents($path, $line, FILE_APPEND) !== false;
            if ($ok && $isNew) {
                @chmod($path, 0640);
            }
            if ($ok && $skipped > 0) {
                @unlink($skipFile);
            }
        } finally {
            unset(self::$held[$dirKey]);
            if ($locked) {
                flock($lock, LOCK_UN);
            }
            fclose($lock);
        }
    }

    /** @return array{n:int,w:int} */
    private function readSkip(string $file): array
    {
        $raw = @file_get_contents($file);
        $st = is_string($raw) ? json_decode($raw, true) : null;
        return [
            'n' => is_array($st) && is_int($st['n'] ?? null) && $st['n'] >= 0 ? $st['n'] : 0,
            'w' => is_array($st) && is_int($st['w'] ?? null) ? $st['w'] : 0,
        ];
    }

    /**
     * S8b: entri dilewati karena rotasi gagal. Dipanggil di bawah flock .lock: hitung entri terlewat dan,
     * maksimal sekali per jendela, tulis satu baris kegagalan langsung ke app.log (tanpa ErrorHandler,
     * tanpa isi entri, tanpa path), dengan cadangan error_log() bila app.log tak bisa ditulis.
     */
    private function recordSkip(): void
    {
        $file = $this->dir . '/.' . $this->file . self::SKIP_SUFFIX;
        $st = $this->readSkip($file);
        $st['n']++;
        $now = time();
        $mem = $this->dir . '|' . $this->file;
        // Cadangan per proses hanya bila berkas status tidak tersimpan (mis. tak dapat ditulis).
        $last = is_file($file) ? $st['w'] : max($st['w'], self::$lastNote[$mem] ?? 0);
        $note = $now - $last >= self::NOTE_WINDOW || $now < $last;
        if ($note) {
            $st['w'] = $now;
            self::$lastNote[$mem] = $now;
        }
        @file_put_contents($file, json_encode($st) ?: '{}');
        if (!$note) {
            return;
        }
        $line = $this->line('error', 'Rotasi log gagal; entri dilewati', ['kanal' => $this->file, 'penyebab' => 'rename gagal', 'terlewat' => $st['n']]);
        $written = $this->file !== self::FILE && @file_put_contents($this->dir . '/' . self::FILE, $line, FILE_APPEND) !== false;
        if (!$written) {
            error_log('bFramework: ' . rtrim($line));
        }
    }

    /**
     * Batas laju per pesan (+ batas total) per jendela 60 detik; dipanggil di bawah flock. Saat jendela
     * berganti dan ada yang ditekan, satu baris ringkasan disisipkan agar banjir tetap terlihat.
     */
    private function allow(string $key, string &$summary): bool
    {
        $file = $this->dir . '/' . self::RATE_FILE;
        $raw = @file_get_contents($file);
        $st = is_string($raw) ? json_decode($raw, true) : null;
        $now = time();
        if (!is_array($st) || !is_int($st['w'] ?? null) || !is_array($st['k'] ?? null) || $now - $st['w'] >= self::RATE_WINDOW || $now < $st['w']) {
            $dropped = is_array($st) && is_int($st['s'] ?? null) ? $st['s'] : 0;
            if ($dropped > 0) {
                $summary = $this->line('warning', 'Log dibatasi (banjir)', ['ditekan' => $dropped]);
            }
            $st = ['w' => $now, 'k' => [], 's' => 0, 't' => 0];
        }
        $h = substr(hash('sha256', $key), 0, 16);
        $n = is_int($st['k'][$h] ?? null) ? $st['k'][$h] : 0;
        $total = is_int($st['t'] ?? null) ? $st['t'] : 0;
        $known = isset($st['k'][$h]);
        $ok = $n < (int) $this->maxPerMinute && $total < (int) $this->maxPerMinute * 10 && ($known || count($st['k']) < self::RATE_MAX_KEYS);
        if ($ok) {
            $st['k'][$h] = $n + 1;
            $st['t'] = $total + 1;
        } else {
            $st['s'] = (is_int($st['s'] ?? null) ? $st['s'] : 0) + 1;
        }
        @file_put_contents($file, json_encode($st) ?: '{}');
        return $ok;
    }

    /** app.log -> app.log.1 -> ... -> app.log.<keep> (yang lebih tua dibuang). Gagal rename: potong berkas (ukuran tetap terbatas). */
    private function rotate(string $path): bool
    {
        for ($i = $this->keep - 1; $i >= 1; $i--) {
            $from = $path . '.' . $i;
            if (is_file($from)) {
                @rename($from, $path . '.' . ($i + 1));
            }
        }
        if (!@rename($path, $path . '.1')) {
            if (!$this->truncateOnRotateFail) {
                return false; // jejak audit tidak pernah dipotong
            }
            @file_put_contents($path, '');
        }
        return true;
    }
}
