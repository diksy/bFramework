<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

/**
 * Menjalankan hook "Kelas::method" dari extensions/. Regex compile (M8) hanya penyaring awal;
 * di sini diverifikasi ulang: file di dalam extDir (realpath, bukan symlink), kelas global,
 * method public static, hasil list<string>. Gagal = HookError (tidak pernah dilewati).
 */
final class HookRunner
{
    private readonly string $extReal;

    public function __construct(string $extDir)
    {
        $r = realpath($extDir);
        $this->extReal = $r === false ? '' : $r;
    }

    /**
     * @param array<string,mixed> $def model ter-compile
     * @param array<string,mixed> $data
     * @return list<string> pesan error (kosong = lolos); event tanpa hook = []
     */
    public function run(array $def, string $event, array $data): array
    {
        $hooks = $def['hooks'] ?? [];
        $h = is_array($hooks) ? ($hooks[$event] ?? null) : null;
        if ($h === null) {
            return [];
        }
        if (!is_array($h) || !is_string($h['class'] ?? null) || !is_string($h['method'] ?? null)) {
            throw new HookError('Definisi hook rusak');
        }
        $class = $h['class'];
        $method = $h['method'];
        $id = '/^[A-Za-z_][A-Za-z0-9_]{0,60}$/D';
        if (preg_match($id, $class) !== 1 || preg_match($id, $method) !== 1) {
            throw new HookError('Nama hook tidak valid');
        }
        $file = $this->verifiedFile($class);
        if (!class_exists($class, false)) {
            self::load($file);
        }
        if (!class_exists($class, false)) {
            throw new HookError('Kelas hook tidak ditemukan setelah dimuat');
        }
        $rc = new \ReflectionClass($class);
        if ($rc->getName() !== $class || $rc->getNamespaceName() !== '' || $rc->getFileName() !== $file) {
            throw new HookError('Kelas hook harus global dan berasal dari berkas ekstensi');
        }
        if (!$rc->hasMethod($method)) {
            throw new HookError('Method hook tidak ditemukan');
        }
        $rm = $rc->getMethod($method);
        if (!$rm->isPublic() || !$rm->isStatic() || $rm->isAbstract() || $rm->getDeclaringClass()->getName() !== $class) {
            throw new HookError('Method hook harus public static');
        }
        try {
            $res = $rm->invoke(null, $data);
        } catch (\Throwable $e) {
            throw new HookError('Hook melempar ' . $e::class, 0, $e);
        }
        if (!is_array($res) || !array_is_list($res)) {
            throw new HookError('Hasil hook harus list<string>');
        }
        foreach ($res as $m) {
            if (!is_string($m)) {
                throw new HookError('Hasil hook harus list<string>');
            }
        }
        /** @var list<string> $res */
        return $res;
    }

    private function verifiedFile(string $class): string
    {
        if ($this->extReal === '') {
            throw new HookError('Folder ekstensi tidak ditemukan');
        }
        $path = $this->extReal . '/' . $class . '.php';
        $real = realpath($path);
        if ($real === false || is_link($path) || $real !== $path || !is_file($real)) {
            throw new HookError('Berkas hook tidak sah');
        }
        return $real;
    }

    private static function load(string $file): void
    {
        (static function () use ($file): void {
            require_once $file;
        })();
    }
}
