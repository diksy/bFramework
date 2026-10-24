<?php

declare(strict_types=1);

namespace bFramework\Tests\Fixtures;

/**
 * Stream wrapper `stuckpc://` untuk tes CACHE-13: folder `stuckpc://root/_pc` berisi `a.html` yang tidak dapat
 * dihapus (unlink selalu gagal), tidak bergantung izin sistem berkas sehingga tetap berlaku saat tes berjalan
 * sebagai root. rename dicatat agar karantina dapat diperiksa.
 */
final class StuckPcWrapper
{
    public const DIR = 'stuckpc://root/_pc';

    /** @var list<array{0:string,1:string}> */
    public static array $renames = [];
    public static bool $renameOk = false;

    /** @var resource|null */
    public $context;
    private int $pos = 0;

    public static function register(): void
    {
        if (!in_array('stuckpc', stream_get_wrappers(), true)) {
            stream_wrapper_register('stuckpc', self::class);
        }
        self::$renames = [];
        self::$renameOk = false;
    }

    /** @return array<int|string,int>|false */
    public function url_stat(string $path, int $flags): array|false
    {
        if ($path === self::DIR) {
            return ['mode' => 0040755, 'size' => 0];
        }
        if ($path === self::DIR . '/a.html') {
            return ['mode' => 0100644, 'size' => 1];
        }
        return false;
    }

    public function dir_opendir(string $path, int $options): bool
    {
        $this->pos = 0;
        return $path === self::DIR;
    }

    public function dir_readdir(): string|false
    {
        return $this->pos++ === 0 ? 'a.html' : false;
    }

    public function dir_rewinddir(): bool
    {
        $this->pos = 0;
        return true;
    }

    public function dir_closedir(): bool
    {
        return true;
    }

    public function unlink(string $path): bool
    {
        return false;
    }

    public function rename(string $from, string $to): bool
    {
        self::$renames[] = [$from, $to];
        return self::$renameOk;
    }

    public function mkdir(string $path, int $mode, int $options): bool
    {
        return false;
    }
}
