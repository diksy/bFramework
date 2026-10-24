<?php

declare(strict_types=1);

namespace bFramework\Upload;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Action;
use bFramework\Contracts\Identity;
use bFramework\Contracts\Logger;
use bFramework\Core\RouteOpts;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\Router;
use bFramework\Runtime\Authorizer;
use bFramework\Runtime\CurrentIdentity;
use bFramework\Runtime\Query;
use bFramework\Runtime\Where;

/**
 * Penyaji file (SEC-FILE-01). Hak akses: file berelasi (model+ref_id) mengikuti Authorizer model tsb
 * (can + constrain pada baris yang mereferensikan); file lepas hanya untuk pengunggah atau peran admin.
 * Semua kegagalan (id rusak, tak ada, anonim, tak berhak) menghasilkan 404 identik (tanpa bocor eksistensi).
 */
final class FileController
{
    private const INLINE = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];

    /**
     * @param \Closure(string):(array<string,mixed>|null) $models resolver definisi model ter-compile
     * @param Query $modelQuery Query yang allowlist-nya memuat model yang direferensikan
     * @param list<string> $adminRoles
     */
    public function __construct(
        private readonly UploadService $uploads,
        private readonly CurrentIdentity $identity,
        private readonly Authorizer $authz,
        private readonly \Closure $models,
        private readonly Query $modelQuery,
        private readonly array $adminRoles = ['admin'],
        private readonly ?Logger $logger = null,
    ) {
    }

    public function registerRoutes(Router $router): void
    {
        $router->add('GET', '/files/{id}', fn(Request $q, array $p = []): Response => $this->serve(is_string($p['id'] ?? null) ? $p['id'] : ''), new RouteOpts(csrf: false));
        // CSRF aktif (default RouteOpts): token `_csrf` dari form; gagal = 419 oleh middleware.
        $router->add('POST', '/files', fn(Request $q, array $p = []): Response => $this->upload($q));
    }

    /**
     * Langkah 1 alur dua langkah: unggah berkas ke field file sebuah model. Policy HANYA dari definisi ter-compile.
     * Anonim 403; tanpa hak Create/Update model 403; model/field bukan field file 404.
     */
    public function upload(Request $q): Response
    {
        $who = $this->identity->get();
        if ($who === null) {
            return self::json(['error' => 'Akses ditolak'], 403);
        }
        $model = $q->post['model'] ?? null;
        $field = $q->post['field'] ?? null;
        $def = is_string($model) && preg_match('/^[a-z][a-z0-9_]{0,63}$/D', $model) === 1 ? ($this->models)($model) : null;
        if ($def === null) {
            return self::json(['error' => 'Tidak ditemukan'], 404);
        }
        if (!$this->authz->can($def, Action::Create, $who) && !$this->authz->can($def, Action::Update, $who)) {
            return self::json(['error' => 'Akses ditolak'], 403);
        }
        $f = is_string($field) && is_array($def['fields'] ?? null) ? ($def['fields'][$field] ?? null) : null;
        $up = is_array($f) && is_array($f['upload'] ?? null) && ($f['guarded'] ?? false) !== true ? $f['upload'] : null;
        if ($up === null) {
            return self::json(['error' => 'Tidak ditemukan'], 404);
        }
        try {
            $policy = new UploadPolicy(array_values(array_map('strval', (array) ($up['mimes'] ?? []))), is_int($up['maxBytes'] ?? null) ? $up['maxBytes'] : 0);
        } catch (\InvalidArgumentException) {
            $this->logger?->error('upload: policy definisi tidak valid', ['model' => $model]);
            return self::json(['error' => 'Konfigurasi upload tidak valid'], 500);
        }
        try {
            $file = UploadedFile::fromFiles($q->files, 'file');
            $stored = $this->uploads->store($file, $policy, $who->userId);
        } catch (UploadRejected $e) {
            return self::json(['error' => $e->getMessage(), 'code' => $e->reason], $e->getCode());
        }
        return self::json(['id' => $stored->id, 'mime' => $stored->mime, 'size' => $stored->size, 'name' => UploadService::cleanName($file->name)], 201);
    }

    /** @param array<string,mixed> $data */
    private static function json(array $data, int $status): Response
    {
        return Response::json($data, $status)->withHeader('Cache-Control', 'no-store')->withHeader('X-Content-Type-Options', 'nosniff');
    }

    public function serve(string $id): Response
    {
        $who = $this->identity->get();
        $meta = $who === null ? null : $this->uploads->find($id);
        if ($who === null || $meta === null || !$this->allowed($meta, $who)) {
            return self::notFound();
        }
        $path = $this->uploads->path($id);
        $len = is_file($path) ? @filesize($path) : false;
        if ($len === false) {
            $this->logger?->error('upload: berkas hilang di storage', ['fid' => $id]);
            return self::notFound();
        }
        $mime = (string) $meta['mime'];
        $inline = in_array($mime, self::INLINE, true);
        $disp = $inline ? 'inline' : 'attachment; filename="' . self::downloadName((string) ($meta['orig_name'] ?? ''), $mime) . '"';
        return Response::file($path, $mime)
            ->withHeader('X-Content-Type-Options', 'nosniff')
            ->withHeader('Content-Disposition', $disp)
            ->withHeader('Content-Security-Policy', "default-src 'none'; sandbox")
            ->withHeader('Cache-Control', 'private, no-store')
            ->withHeader('Content-Length', (string) $len);
    }

    /** @param array<string,mixed> $meta */
    private function allowed(array $meta, Identity $who): bool
    {
        $model = $meta['model'] ?? null;
        $ref = $meta['ref_id'] ?? null;
        if (is_string($model) && is_int($ref)) {
            $def = ($this->models)($model);
            if ($def === null || !$this->authz->can($def, Action::Read, $who)) {
                return false;
            }
            try {
                $w = $this->authz->constrain($def, Action::Read, $who, new Where([['id', '=', $ref]]));
                return $this->modelQuery->select($model, ['id'], $w, null, 1, 0) !== [];
            } catch (\Throwable $e) {
                $this->logger?->warning('upload: cek izin model gagal', ['ex' => $e::class]);
                return false;
            }
        }
        return (is_int($meta['owner_id'] ?? null) && $meta['owner_id'] === $who->userId)
            || in_array($who->activeRole, $this->adminRoles, true);
    }

    private static function notFound(): Response
    {
        return Response::html('Tidak ditemukan', 404)
            ->withHeader('X-Content-Type-Options', 'nosniff')
            ->withHeader('Cache-Control', 'no-store');
    }

    /** Hanya [A-Za-z0-9_-]; tanpa CR/LF/kutip/null/titik; ekstensi selalu dari mime di DB, bukan dari klien (double extension dinetralkan). */
    public static function downloadName(string $orig, string $mime): string
    {
        $n = preg_replace('/[^A-Za-z0-9_-]+/', '_', UploadService::cleanName($orig)) ?? '';
        $n = trim(substr($n, 0, 100), '_-');
        return ($n === '' ? 'file' : $n) . self::extFor($mime);
    }

    private static function extFor(string $mime): string
    {
        return match ($mime) {
            'application/pdf' => '.pdf', 'text/plain' => '.txt', 'text/csv' => '.csv',
            'image/jpeg' => '.jpg', 'image/png' => '.png', 'image/gif' => '.gif', 'image/webp' => '.webp',
            default => '.bin',
        };
    }
}
