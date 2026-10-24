<?php

declare(strict_types=1);

namespace bFramework\Builder;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\HttpException;
use bFramework\Contracts\Identity;
use bFramework\Contracts\Logger;
use bFramework\Contracts\NotFound;
use bFramework\Core\Csrf;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\Router;
use bFramework\Core\SafeHtml;
use bFramework\Core\Template;
use bFramework\Runtime\Connection;
use bFramework\Runtime\DefinitionSchema;
use bFramework\Runtime\Migrator;
use Closure;
use Throwable;

/**
 * UI builder `/_builder` (F15, BLD-01). Semua handler lewat BuilderGate. Halaman dirender dengan Template
 * (auto-escape + CSP nonce); API JSON memakai CSRF header (middleware) dan hanya menyentuh DefinitionWriter.
 */
final class BuilderController
{
    private const MAX_BODY = 300000;
    private const HASH_RE = '/^(?:[a-f0-9]{64})?$/D';

    /**
     * @param Closure(string):?array<string,mixed> $activeModel model ter-compile aktif (null bila belum ada)
     * @param Closure():list<string> $roles nama peran yang ada
     * @param Closure(Identity):list<array<string,mixed>> $nav menu samping
     */
    public function __construct(
        private readonly BuilderGate $gate,
        private readonly DefinitionWriter $writer,
        private readonly HookScanner $hooks,
        private readonly AuditLog $audit,
        private readonly Connection $conn,
        private readonly Csrf $csrf,
        private readonly Template $views,
        private readonly Template $layout,
        private readonly Closure $activeModel,
        private readonly Closure $roles,
        private readonly Closure $nav,
        private readonly ?Logger $logger = null,
    ) {
    }

    public function registerRoutes(Router $router): void
    {
        if (!$this->gate->enabled()) {
            return; // produksi default: rute tidak ada sama sekali (404 dari Router)
        }
        $router->add('GET', '/_builder', fn(Request $r, array $p = []): Response => $this->page($r));
        $router->add('GET', '/_builder/login', fn(Request $r, array $p = []): Response => $this->loginForm($r));
        $router->add('POST', '/_builder/login', fn(Request $r, array $p = []): Response => $this->login($r));
        $router->add('POST', '/_builder/logout', fn(Request $r, array $p = []): Response => $this->logout($r));
        $router->add('GET', '/_builder/api/state', fn(Request $r, array $p = []): Response => $this->api($r, fn(Identity $w): Response => $this->state()));
        $router->add('GET', '/_builder/api/etag', fn(Request $r, array $p = []): Response => $this->api($r, fn(Identity $w): Response => $this->json(['etag' => $this->etag()])));
        $router->add('GET', '/_builder/api/sample', fn(Request $r, array $p = []): Response => $this->api($r, fn(Identity $w): Response => $this->sample($r)));
        $router->add('POST', '/_builder/api/migration', fn(Request $r, array $p = []): Response => $this->api($r, fn(Identity $w): Response => $this->migration($r)));
        $router->add('POST', '/_builder/api/save', fn(Request $r, array $p = []): Response => $this->api($r, fn(Identity $w): Response => $this->save($r, $w)));
        $router->add('POST', '/_builder/api/delete', fn(Request $r, array $p = []): Response => $this->api($r, fn(Identity $w): Response => $this->delete($r, $w)));
    }

    // ---------- halaman ----------

    private function page(Request $r): Response
    {
        $who = $this->gate->authorize($r, false);
        if ($who instanceof Response) {
            return $who;
        }
        if (!$this->gate->isDev()) {
            $this->audit->record($who->userId, 'builder.open', null, $r->remoteAddr);
        }
        $content = $this->views->render('builder', ['dev' => $this->gate->isDev(), 'prod' => !$this->gate->isDev(), 'csrf' => $this->csrf->token()]);
        return $this->shell('Builder', $content, $who, ['/assets/builder.js']);
    }

    private function loginForm(Request $r, ?string $error = null, int $status = 200): Response
    {
        if ($this->gate->isDev()) {
            throw new NotFound();
        }
        $who = $this->gate->authorize($r, false, false);
        if ($who instanceof Response) {
            return $who;
        }
        $content = $this->views->render('login', ['csrf' => $this->csrf->token(), 'error' => $error ?? '']);
        return $this->shell('Login Builder', $content, $who, [], $status);
    }

    private function login(Request $r): Response
    {
        if ($this->gate->isDev()) {
            throw new NotFound();
        }
        $who = $this->gate->authorize($r, false, false);
        if ($who instanceof Response) {
            return $who;
        }
        $pw = $r->post['password'] ?? '';
        $pw = is_string($pw) && strlen($pw) <= 1024 ? $pw : '';
        if (!$this->gate->attemptLogin($r, $who, $pw)) {
            $this->audit->record($who->userId, 'builder.login_failed', null, $r->remoteAddr);
            return $this->loginForm($r, 'Kata sandi builder salah.', 401);
        }
        $this->audit->record($who->userId, 'builder.login', null, $r->remoteAddr);
        return Response::redirect('/_builder');
    }

    private function logout(Request $r): Response
    {
        $who = $this->gate->authorize($r, false, false);
        if ($who instanceof Response) {
            return $who;
        }
        $this->gate->logout();
        $this->audit->record($who->userId, 'builder.logout', null, $r->remoteAddr);
        return Response::redirect('/login');
    }

    /** @param list<string> $scripts */
    private function shell(string $title, SafeHtml $content, Identity $who, array $scripts, int $status = 200): Response
    {
        $nav = [];
        try {
            $nav = ($this->nav)($who);
        } catch (Throwable) {
            $this->logger?->warning('Menu builder tidak terbaca');
        }
        $nav[] = ['group' => 'Developer', 'items' => [['key' => 'builder', 'label' => 'Builder', 'icon' => '🛠', 'href' => '/_builder']]];
        $html = $this->layout->render('layout', [
            'title' => $title,
            'csrf' => $this->csrf->token(),
            'user' => ['name' => $who->activeRole, 'switch' => count($who->roles) > 1, 'roleOptions' => array_map(
                static fn(string $n): array => ['name' => $n, 'on' => $n === $who->activeRole],
                $who->roles,
            )],
            'nav' => $nav,
            'active' => 'builder',
            'flash' => [],
            'scripts' => $scripts,
            'bodyClass' => 'builder',
            'content' => $content,
        ]);
        return Response::html($html->toString(), $status)->withHeader('Cache-Control', 'no-store');
    }

    // ---------- API ----------

    /** @param Closure(Identity):Response $fn */
    private function api(Request $r, Closure $fn): Response
    {
        try {
            $who = $this->gate->authorize($r, true);
            if ($who instanceof Response) {
                return $who;
            }
            if (strlen($r->body) > self::MAX_BODY) {
                return $this->json(['error' => 'Permintaan terlalu besar.'], 413);
            }
            return $fn($who);
        } catch (NotFound $e) {
            throw $e;
        } catch (HttpException $e) {
            return $this->json(['error' => $e->status === 400 ? 'Permintaan tidak valid.' : 'Permintaan ditolak.'], $e->status);
        }
    }

    /** @param array<mixed> $d */
    private function json(array $d, int $status = 200): Response
    {
        return Response::json($d, $status)->withHeader('Cache-Control', 'no-store');
    }

    private function state(): Response
    {
        $broken = [];
        $out = ['models' => [], 'pages' => []];
        foreach (['model' => 'models', 'page' => 'pages'] as $kind => $key) {
            foreach ($this->writer->names($kind) as $n) {
                [$data, $hash] = $this->writer->read((string) $this->writer->path($kind, $n));
                if ($data === null) {
                    $broken[] = $key . '/' . $n . '.json';
                    continue;
                }
                $out[$key][$n] = ['data' => $data === [] ? new \stdClass() : $data, 'hash' => $hash];
            }
        }
        [$auth, $authHash] = $this->writer->read((string) $this->writer->path('auth', 'auth'));
        $out['auth'] = ['data' => $auth ?? ['driver' => 'local'], 'hash' => $authHash];
        $out['broken'] = $broken;
        $out['roles'] = array_map(static fn(string $n): array => ['role' => $n], ($this->roles)());
        $out['hooks'] = $this->hooks->scan();
        $out['urls'] = ['callback' => '/auth/sso/callback', 'postLogout' => '/auth/sso/signed-out', 'backchannel' => '/auth/sso/backchannel'];
        $out['dev'] = $this->gate->isDev();
        $out['etag'] = $this->etag();
        return $this->json($out);
    }

    private function etag(): string
    {
        $h = hash_init('sha256');
        foreach (['model', 'page'] as $kind) {
            foreach ($this->writer->names($kind) as $n) {
                hash_update($h, $kind . '/' . $n . ':' . $this->writer->hashOf((string) $this->writer->path($kind, $n)) . ';');
            }
        }
        hash_update($h, 'auth:' . $this->writer->hashOf((string) $this->writer->path('auth', 'auth')));
        return hash_final($h);
    }

    private function sample(Request $r): Response
    {
        if (!$this->gate->isDev()) {
            return $this->json(['error' => 'Tidak tersedia.'], 404);
        }
        $m = $r->query['model'] ?? '';
        $file = is_string($m) ? $this->writer->path('model', $m) : null;
        if ($file === null) {
            return $this->json(['error' => 'Model tidak ditemukan.'], 404);
        }
        [$data] = $this->writer->read($file);
        $schema = new DefinitionSchema();
        $model = $data === null ? null : $schema->model((string) $m, $data);
        if ($model === null || $schema->errors() !== []) {
            return $this->json(['error' => 'Model tidak ditemukan.'], 404);
        }
        return $this->json(Sampler::seed($model, 8, true));
    }

    /** @return array{0:string,1:string,2:array<mixed>,3:string,4:bool}|Response [kind,name,data,baseHash,confirm] */
    private function input(Request $r): array|Response
    {
        $in = $r->json();
        $kind = $in['kind'] ?? null;
        $name = $in['name'] ?? null;
        $data = $in['data'] ?? [];
        $hash = $in['baseHash'] ?? '';
        if (!is_string($kind) || !is_string($name) || !is_array($data) || !is_string($hash) || preg_match(self::HASH_RE, $hash) !== 1
            || !in_array($kind, ['model', 'page', 'auth'], true)) {
            return $this->json(['error' => 'Permintaan tidak valid.'], 422);
        }
        if ($this->writer->path($kind, $name) === null) {
            return $this->json(['error' => 'Jenis atau nama definisi tidak valid.'], 422);
        }
        return [$kind, $kind === 'auth' ? 'auth' : $name, $data, $hash, ($in['confirmLoss'] ?? false) === true];
    }

    private function migration(Request $r): Response
    {
        $in = $this->input($r);
        if ($in instanceof Response) {
            return $in;
        }
        [$kind, $name, $data] = $in;
        if ($kind !== 'model') {
            return $this->json(['sql' => [], 'lossWarnings' => []]);
        }
        [$clean, $err] = $this->writer->normalize($kind, $data, $name);
        if ($clean === null) {
            return $this->json(['error' => $err], 422);
        }
        $plan = $this->plan($name, $clean);
        return $this->json(['sql' => $plan->sql, 'lossWarnings' => $plan->lossWarnings]);
    }

    /** @param array<mixed> $clean */
    private function plan(string $name, array $clean): \bFramework\Runtime\MigrationPlan
    {
        $schema = new DefinitionSchema();
        $compiled = $schema->model($name, $clean);
        if ($compiled === null) {
            throw new \RuntimeException('Model tidak valid');
        }
        return MigrationPreview::for(($this->activeModel)($name), $compiled, $this->conn->grammar());
    }

    private function save(Request $r, Identity $who): Response
    {
        $in = $this->input($r);
        if ($in instanceof Response) {
            return $in;
        }
        [$kind, $name, $data, $base, $confirm] = $in;
        $file = (string) $this->writer->path($kind, $name);
        [$clean, $err] = $this->writer->normalize($kind, $data, $name);
        if ($clean === null) {
            return $this->json(['error' => $err], 422);
        }
        if ($kind === 'model') {
            foreach ((array) ($clean['hooks'] ?? []) as $ref) {
                [$cls, $method] = array_pad(explode('::', (string) $ref, 2), 2, '');
                if (!$this->hooks->isUsable($cls, $method)) {
                    return $this->json(['error' => 'Hook tidak tersedia atau ditandai berbahaya: ' . mb_substr((string) preg_replace('/[^A-Za-z0-9_:]/', '?', (string) $ref), 0, 80)], 422);
                }
            }
        }
        $plan = null;
        if ($kind === 'model') {
            $plan = $this->plan($name, $clean);
            if ($plan->lossWarnings !== [] && !$confirm) {
                return $this->json(['error' => 'Perubahan berpotensi menghilangkan data; konfirmasi diperlukan.', 'code' => 'confirm_loss',
                    'sql' => $plan->sql, 'lossWarnings' => $plan->lossWarnings], 409);
            }
        }
        $prev = $this->writer->raw($file);
        try {
            $hash = $this->writer->write($file, $clean, $base);
        } catch (WriteConflict $e) {
            return $this->json(['error' => 'Berkas diubah di luar builder.', 'code' => 'conflict', 'disk' => $e->disk, 'diskHash' => $e->diskHash], 409);
        } catch (WriteRejected $e) {
            return $this->json(['error' => $e->getMessage(), 'errors' => $e->errors], $e->status);
        }
        if ($plan !== null && $plan->sql !== []) {
            try {
                (new Migrator($this->conn, $this->conn->grammar(), $this->logger))->apply($plan, $confirm);
            } catch (Throwable $e) {
                $this->logger?->error('Migrasi builder gagal', ['class' => $e::class]);
                try {
                    $this->writer->rollback($file, $prev);
                } catch (Throwable) {
                    $this->logger?->error('Rollback definisi builder gagal');
                }
                $this->audit->record($who->userId, 'builder.migrate_failed', $this->rel($kind, $name), $r->remoteAddr);
                return $this->json(['error' => 'Migrasi database gagal; definisi dikembalikan.'], 500);
            }
        }
        $this->audit->record($who->userId, 'builder.save', $this->rel($kind, $name), $r->remoteAddr);
        return $this->json(['ok' => true, 'hash' => $hash, 'data' => $clean]);
    }

    private function delete(Request $r, Identity $who): Response
    {
        $in = $this->input($r);
        if ($in instanceof Response) {
            return $in;
        }
        [$kind, $name, , $base] = $in;
        if ($kind === 'auth') {
            return $this->json(['error' => 'auth.json tidak dapat dihapus.'], 422);
        }
        try {
            $this->writer->delete((string) $this->writer->path($kind, $name), $base);
        } catch (WriteConflict $e) {
            return $this->json(['error' => 'Berkas diubah di luar builder.', 'code' => 'conflict', 'disk' => $e->disk, 'diskHash' => $e->diskHash], 409);
        } catch (WriteRejected $e) {
            return $this->json(['error' => $e->getMessage(), 'errors' => $e->errors], $e->status);
        }
        $this->audit->record($who->userId, 'builder.delete', $this->rel($kind, $name), $r->remoteAddr);
        return $this->json(['ok' => true]);
    }

    private function rel(string $kind, string $name): string
    {
        return $kind === 'auth' ? 'auth.json' : ($kind === 'model' ? 'models' : 'pages') . '/' . $name . '.json';
    }
}
