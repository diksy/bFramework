<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Clock;
use bFramework\Contracts\SessionStore;
use InvalidArgumentException;
use RuntimeException;

/**
 * Sesi berbasis file di storage aplikasi (SEC-SESS-01), bukan session_save_path bersama /tmp.
 * - ID: 32 byte acak (hex 64); ID dari klien yang tak dikenal tidak pernah diadopsi (anti-fixation).
 * - Isi file JSON (tanpa serialize/unserialize); nilai objek ditolak.
 * - Cookie: HttpOnly, SameSite=Lax, Secure + prefix __Host- bila HTTPS (SEC-SESS-03).
 * - Timeout idle dan absolut; sesi kedaluwarsa dihapus. File 0600, direktori 0700.
 * start() idempoten. Tulis-langsung per mutasi (last-writer-wins untuk request paralel).
 */
final class FileSessionStore implements SessionStore
{
    public const COOKIE = 'bf_sid';
    private const ID_RE = '/^[a-f0-9]{64}$/D';
    private const FLASH = '_flash';

    private bool $started = false;
    private string $id = '';
    /** @var array<string,mixed> */
    private array $data = [];
    private int $created = 0;
    /** @var callable(string,string,array<string,mixed>):void */
    private $emit;

    /**
     * @param array<string,mixed>|null $cookies default $_COOKIE
     * @param (callable(string,string,array<string,mixed>):void)|null $emit penerima Set-Cookie; default setcookie()
     */
    public function __construct(
        private readonly string $dir,
        private readonly bool $https = false,
        private readonly int $idleTtl = 1800,
        private readonly int $absoluteTtl = 28800,
        private readonly ?array $cookies = null,
        ?callable $emit = null,
        private readonly ?Clock $clock = null,
    ) {
        if ($idleTtl < 1 || $absoluteTtl < 1) {
            throw new InvalidArgumentException('TTL harus positif');
        }
        $this->emit = $emit ?? static function (string $n, string $v, array $o): void {
            if (PHP_SAPI !== 'cli' && !headers_sent()) {
                setcookie($n, $v, $o);
            }
        };
    }

    public function cookieName(): string
    {
        return $this->https ? '__Host-' . self::COOKIE : self::COOKIE;
    }

    public function start(): void
    {
        if ($this->started) {
            return;
        }
        $this->ensureDir();
        $this->started = true;
        $given = ($this->cookies ?? $_COOKIE)[$this->cookieName()] ?? null;
        if (is_string($given) && preg_match(self::ID_RE, $given) === 1) {
            $rec = $this->load($given);
            if ($rec !== null) {
                $this->id = $given;
                $this->created = $rec['c'];
                $this->data = $rec['d'];
                $this->save();
                return;
            }
        }
        $this->fresh();
    }

    public function id(): string
    {
        return $this->id;
    }

    public function get(string $k, mixed $d = null): mixed
    {
        $this->start();
        return $this->data[$k] ?? $d;
    }

    public function set(string $k, mixed $v): void
    {
        $this->start();
        self::assertPlain($v);
        $this->data[$k] = $v;
        $this->save();
    }

    public function forget(string $k): void
    {
        $this->start();
        unset($this->data[$k]);
        $this->save();
    }

    /** SEC-SESS-02: ID baru, data dipindah, file lama dihapus, token CSRF dibuang. */
    public function regenerate(): void
    {
        $this->start();
        $old = $this->id;
        unset($this->data[Csrf::KEY]);
        if (!is_file($this->path($old))) {
            // Sesi sudah dihancurkan request lain: jangan hidupkan datanya.
            $this->data = [];
            $this->created = $this->now();
        }
        $this->id = self::newId();
        $this->create();
        $this->unlink($old);
        $this->sendCookie($this->id);
    }

    public function destroy(): void
    {
        $this->start();
        $this->unlink($this->id);
        $this->data = [];
        $this->id = '';
        $this->started = false;
        ($this->emit)($this->cookieName(), '', $this->cookieOptions(max(1, $this->now() - 86400)));
    }

    public function flash(string $type, string $msg): void
    {
        $this->start();
        $f = $this->data[self::FLASH] ?? [];
        $f = is_array($f) ? $f : [];
        $f[] = ['type' => $type, 'msg' => $msg];
        $this->data[self::FLASH] = $f;
        $this->save();
    }

    public function pullFlash(): array
    {
        $this->start();
        $f = $this->data[self::FLASH] ?? [];
        unset($this->data[self::FLASH]);
        $this->save();
        $out = [];
        if (is_array($f)) {
            foreach ($f as $m) {
                if (is_array($m) && is_string($m['type'] ?? null) && is_string($m['msg'] ?? null)) {
                    $out[] = ['type' => $m['type'], 'msg' => $m['msg']];
                }
            }
        }
        return $out;
    }

    /** Hapus file sesi yang sudah lewat idle/absolut. Kembalikan jumlah terhapus. */
    public function gc(): int
    {
        $this->ensureDir();
        $n = 0;
        foreach (glob($this->dir . '/sess_*') ?: [] as $f) {
            $base = basename($f);
            $id = substr($base, 5);
            if (preg_match(self::ID_RE, $id) !== 1) {
                continue;
            }
            if ($this->load($id) === null) {
                $this->unlink($id);
                $n++;
            }
        }
        return $n;
    }

    private function fresh(): void
    {
        $this->id = self::newId();
        $this->data = [];
        $this->created = $this->now();
        $this->create();
        $this->sendCookie($this->id);
    }

    private static function newId(): string
    {
        return bin2hex(random_bytes(32));
    }

    private function now(): int
    {
        return $this->clock !== null ? $this->clock->now()->getTimestamp() : time();
    }

    private function path(string $id): string
    {
        if (preg_match(self::ID_RE, $id) !== 1) {
            throw new InvalidArgumentException('ID sesi tidak valid');
        }
        return $this->dir . '/sess_' . $id;
    }

    /** @return array{c:int,a:int,d:array<string,mixed>}|null null bila tidak ada/rusak/kedaluwarsa (file kedaluwarsa dihapus). */
    private function load(string $id): ?array
    {
        $p = $this->path($id);
        if (!is_file($p)) {
            return null;
        }
        $fh = @fopen($p, 'rb');
        if ($fh === false) {
            return null;
        }
        $raw = flock($fh, LOCK_SH) ? stream_get_contents($fh) : false;
        fclose($fh);
        $j = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($j) || !is_int($j['c'] ?? null) || !is_int($j['a'] ?? null) || !is_array($j['d'] ?? null)) {
            $this->unlink($id);
            return null;
        }
        $now = $this->now();
        if ($now - $j['a'] > $this->idleTtl || $now - $j['c'] > $this->absoluteTtl) {
            $this->unlink($id);
            return null;
        }
        /** @var array<string,mixed> $d */
        $d = $j['d'];
        return ['c' => $j['c'], 'a' => $j['a'], 'd' => $d];
    }

    private function payload(): string
    {
        return json_encode(
            ['c' => $this->created, 'a' => $this->now(), 'd' => $this->data],
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
        );
    }

    /** Buat file sesi baru (ID baru), izin 0600 sejak awal. */
    private function create(): void
    {
        $json = $this->payload();
        $old = umask(0177);
        try {
            $fh = @fopen($this->path($this->id), 'xb');
        } finally {
            umask($old);
        }
        if ($fh === false) {
            throw new RuntimeException('Gagal menulis sesi');
        }
        $ok = flock($fh, LOCK_EX) && fwrite($fh, $json) === strlen($json);
        fclose($fh);
        if (!$ok) {
            $this->unlink($this->id);
            throw new RuntimeException('Gagal menulis sesi');
        }
    }

    /**
     * Tulis ulang sesi yang sudah ada, di bawah flock. Bila file sudah tidak ada (destroy/regenerate
     * oleh request lain) tidak ditulis: sesi mati tidak boleh hidup lagi.
     */
    private function save(): void
    {
        if ($this->id === '') {
            return;
        }
        $json = $this->payload();
        $p = $this->path($this->id);
        $fh = @fopen($p, 'r+b');
        if ($fh === false) {
            return;
        }
        try {
            if (!flock($fh, LOCK_EX)) {
                throw new RuntimeException('Gagal menulis sesi');
            }
            clearstatcache(true, $p);
            $a = fstat($fh);
            $b = @stat($p);
            if ($a === false || $b === false || $a['ino'] !== $b['ino']) {
                return; // sudah dihapus/diganti saat menunggu lock
            }
            if (!ftruncate($fh, 0) || fseek($fh, 0) !== 0 || fwrite($fh, $json) !== strlen($json)) {
                throw new RuntimeException('Gagal menulis sesi');
            }
            fflush($fh);
        } finally {
            fclose($fh);
        }
    }

    private function unlink(string $id): void
    {
        if (preg_match(self::ID_RE, $id) === 1) {
            @unlink($this->path($id));
        }
    }

    private function ensureDir(): void
    {
        if (!is_dir($this->dir) && !@mkdir($this->dir, 0700, true) && !is_dir($this->dir)) {
            throw new RuntimeException('Direktori sesi tidak dapat dibuat');
        }
        @chmod($this->dir, 0700);
    }

    /** @return array<string,mixed> */
    private function cookieOptions(int $expires): array
    {
        return [
            'expires' => $expires,
            'path' => '/',
            'secure' => $this->https,
            'httponly' => true,
            'samesite' => 'Lax',
        ];
    }

    private function sendCookie(string $id): void
    {
        // Cookie sesi (tanpa expires): hilang saat browser ditutup; batas sebenarnya di sisi server.
        $o = $this->cookieOptions(0);
        ($this->emit)($this->cookieName(), $id, $o);
    }

    private static function assertPlain(mixed $v, int $depth = 0): void
    {
        if ($depth > 8) {
            throw new InvalidArgumentException('Nilai sesi terlalu dalam');
        }
        if (is_array($v)) {
            foreach ($v as $x) {
                self::assertPlain($x, $depth + 1);
            }
            return;
        }
        if ($v !== null && !is_scalar($v)) {
            throw new InvalidArgumentException('Nilai sesi hanya boleh skalar/array');
        }
        if (is_float($v) && !is_finite($v)) {
            throw new InvalidArgumentException('Nilai sesi tidak valid');
        }
    }
}
