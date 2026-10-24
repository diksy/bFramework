<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Action;
use bFramework\Contracts\Forbidden;
use bFramework\Contracts\Identity;
use bFramework\Contracts\NotFound;
use bFramework\Contracts\SessionStore;
use bFramework\Core\Csrf;
use bFramework\Core\Nonce;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\SafeHtml;
use bFramework\Core\Template;

/**
 * Handler rute halaman (index|form|save|delete). Statis karena rute ter-compile berupa "Kelas::metode";
 * dependensi dipasang sekali oleh bootstrap.php lewat configure(). Nama halaman HANYA dari argumen ke-3
 * (kunci `page` tabel rute), bukan dari path/input pengguna.
 */
final class PageController
{
    private static ?self $ctx = null;

    private function __construct(
        private readonly Definitions $defs,
        private readonly Query $query,
        private readonly Authorizer $authz,
        private readonly HookRunner $hooks,
        private readonly Template $views,
        private readonly Template $layout,
        private readonly SessionStore $session,
        private readonly CurrentIdentity $identity,
        private readonly Csrf $csrf,
        private readonly bool $devMode = false,
        private readonly ?\bFramework\Contracts\Logger $logger = null,
        private readonly ?FileRefs $files = null,
        private readonly ?PageCacheSink $cache = null,
    ) {
    }

    public static function configure(
        Definitions $defs,
        Query $query,
        Authorizer $authz,
        HookRunner $hooks,
        Template $views,
        Template $layout,
        SessionStore $session,
        CurrentIdentity $identity,
        Csrf $csrf,
        bool $devMode = false,
        ?\bFramework\Contracts\Logger $logger = null,
        ?FileRefs $files = null,
        ?PageCacheSink $cache = null,
    ): void {
        self::$ctx = new self($defs, $query, $authz, $hooks, $views, $layout, $session, $identity, $csrf, $devMode, $logger, $files, $cache);
    }

    /** @param array<string,string> $params */
    public static function index(Request $r, array $params, string $page): Response
    {
        return self::ctx()->doIndex($r, $page);
    }

    /** @param array<string,string> $params */
    public static function form(Request $r, array $params, string $page): Response
    {
        return self::ctx()->doForm($page, self::id($params), null, [], [], 200);
    }

    /** @param array<string,string> $params */
    public static function save(Request $r, array $params, string $page): Response
    {
        return self::ctx()->doSave($r, $page, self::id($params));
    }

    /** @param array<string,string> $params */
    public static function delete(Request $r, array $params, string $page): Response
    {
        $id = self::id($params) ?? throw new NotFound();
        return self::ctx()->doDelete($page, $id);
    }

    // ---------- implementasi ----------

    private static function ctx(): self
    {
        return self::$ctx ?? throw new \LogicException('PageController belum dikonfigurasi');
    }

    /** @param array<string,string> $params */
    private static function id(array $params): ?int
    {
        if (!array_key_exists('id', $params)) {
            return null;
        }
        $id = $params['id'];
        if (preg_match('/^[1-9][0-9]{0,17}$/D', $id) !== 1) {
            throw new NotFound();
        }
        return (int) $id;
    }

    /**
     * @return array{0:array<string,mixed>,1:?Identity}|Response halaman + identitas, atau respons penolakan
     */
    private function gate(string $name, bool $anon = false): array|Response
    {
        $page = preg_match(DefinitionSchema::PAGE_RE, $name) === 1 ? $this->defs->page($name) : null;
        if ($page === null) {
            throw new NotFound();
        }
        $who = $anon ? null : $this->identity->get(); // anon: tanpa cookie sesi, sesi tidak dimulai (F8)
        if (!Navigation::allows($page, $who)) {
            if ($who === null) {
                return Response::redirect('/login');
            }
            throw new Forbidden('Akses ditolak');
        }
        return [$page, $who];
    }

    /**
     * Model yang dikelola halaman: sumber komponen table/form pertama.
     *
     * @param array<string,mixed> $page
     * @return array{0:array<string,mixed>,1:?array<string,mixed>}|null [model, komponen]
     */
    private function modelOf(array $page): ?array
    {
        foreach ((array) ($page['layout'] ?? []) as $c) {
            if (is_array($c) && in_array($c['component'] ?? '', ['table', 'form'], true)
                && is_array($c['source'] ?? null) && is_string($c['source']['model'] ?? null)) {
                $m = $this->defs->model($c['source']['model']);
                if ($m !== null) {
                    return [$m, $c];
                }
            }
        }
        return null;
    }

    private function targetResolver(): \Closure
    {
        return fn(string $m): ?array => $this->defs->model($m);
    }

    /** @param array<string,mixed> $def */
    private function repo(array $def, ?Identity $who): ModelRepository
    {
        return new ModelRepository($def, $this->query, $this->authz, $who, $this->hooks, null, $this->targetResolver(), $this->devMode, $this->logger, $this->files, $this->cache);
    }

    private function doIndex(Request $r, string $name): Response
    {
        // F8: request anonim tanpa cookie sesi ke halaman ber-cache. Middleware sesi dilewati (SkipMiddleware), jadi
        // tidak ada sesi/token CSRF/flash/nonce yang boleh ikut ke HTML.
        $anon = $this->cache !== null && $this->cache->eligible($r);
        $g = $this->gate($name, $anon);
        if ($g instanceof Response) {
            return $g;
        }
        [$page, $who] = $g;
        // CACHE-14 (runtime): hanya halaman cache:true + access '*' + tanpa identitas.
        $cacheable = $anon && $who === null && ($page['cache'] ?? false) === true
            && ($page['access'] ?? null) === '*' && ($page['route'] ?? null) === $r->path;
        $tags = $cacheable ? $this->cacheTags($page) : [];
        $snap = $cacheable && $this->cache !== null ? $this->cache->snapshot($tags) : null; // sebelum data dibaca
        $rend = new ComponentRenderer(
            $this->defs, $this->query, $this->authz, $this->hooks, $this->views, $who, $page, $r->query, $anon ? '' : $this->csrf->token(),
        );
        $body = '';
        foreach ((array) ($page['layout'] ?? []) as $c) {
            if (is_array($c)) {
                $body .= $rend->render($c)->toString();
            }
        }
        if ($anon && str_contains($body, '_csrf')) {
            $cacheable = false; // form ber-token tidak boleh masuk cache; dilayani tanpa cache (token kosong = ditolak 419)
            $this->logger?->warning('Halaman cache memuat form ber-token; tidak di-cache', ['page' => $name]);
        }
        $title = is_string($page['title'] ?? null) ? $page['title'] : $name;
        $content = $this->views->render('page', ['title' => $title, 'body' => SafeHtml::fromTrusted($body)]);
        $res = $this->layoutResponse($title, $content, $name, $who, 200, false, $anon);
        if ($cacheable && $this->cache !== null) {
            $this->cache->store((string) $page['route'], SafeHtml::fromTrusted($res->body), $tags, $snap);
        }
        return $res;
    }

    /**
     * Tag cache halaman: model sumber komponen + model target relasi field-nya (label relasi ikut tampil).
     *
     * @param array<string,mixed> $page
     * @return list<string>
     */
    private function cacheTags(array $page): array
    {
        $tags = [];
        foreach ((array) ($page['layout'] ?? []) as $c) {
            if (!is_array($c) || !is_array($c['source'] ?? null) || !is_string($c['source']['model'] ?? null)) {
                continue;
            }
            $tags[$c['source']['model']] = true;
            $def = $this->defs->model($c['source']['model']);
            foreach ((array) ($def['fields'] ?? []) as $f) {
                if (is_array($f) && ($f['type'] ?? '') === 'relasi' && is_string($f['target'] ?? null)) {
                    $tags[$f['target']] = true;
                }
            }
        }
        return array_map('strval', array_keys($tags));
    }

    /**
     * @param array<string,mixed>|null $values
     * @param array<string,list<string>> $errors
     * @param list<string> $formErrors
     */
    private function doForm(string $name, ?int $id, ?array $values, array $errors, array $formErrors, int $status): Response
    {
        $g = $this->gate($name);
        if ($g instanceof Response) {
            return $g;
        }
        [$page, $who] = $g;
        $mc = $this->modelOf($page);
        if ($mc === null) {
            throw new NotFound();
        }
        [$def, $comp] = $mc;
        $repo = $this->repo($def, $who);
        if (!$repo->can($id === null ? Action::Create : Action::Update)) {
            throw new Forbidden('Akses ditolak');
        }
        if ($id !== null && $values === null) {
            $values = $repo->find($id); // di luar scope = NotFound
        }
        $fields = $this->formFields($def, $comp);
        $vm = [];
        foreach ($fields as $n => $f) {
            $vm[] = $this->fieldView((string) $def['model'], $n, $f, $values[$n] ?? ($f['default'] ?? ''), $errors[$n] ?? [], $who);
        }
        $route = (string) $page['route'];
        $label = ucfirst((string) $def['model']);
        $content = $this->views->render('form', [
            'heading' => ($id === null ? 'Tambah ' : 'Ubah ') . $label,
            'action' => $id === null ? $route : "$route/$id",
            'back' => $route, 'fields' => $vm, 'formErrors' => $formErrors, 'csrf' => $this->csrf->token(),
        ]);
        $hasUpload = array_filter($vm, static fn(array $v): bool => $v['isFile'] === true) !== [];
        return $this->layoutResponse('Form ' . $label, $content, $name, $who, $status, $hasUpload);
    }

    /**
     * Field yang tampil/divalidasi: daftar `fields` komponen form bila ada, selain itu semua field; guarded tak pernah.
     *
     * @param array<string,mixed> $def
     * @param array<string,mixed>|null $comp
     * @return array<string,array<string,mixed>>
     */
    private function formFields(array $def, ?array $comp): array
    {
        $all = is_array($def['fields'] ?? null) ? $def['fields'] : [];
        $names = $comp !== null && ($comp['component'] ?? '') === 'form' && is_array($comp['fields'] ?? null)
            ? array_map('strval', $comp['fields']) : array_map('strval', array_keys($all));
        $out = [];
        foreach ($names as $n) {
            if (isset($all[$n]) && is_array($all[$n]) && ($all[$n]['guarded'] ?? false) !== true) {
                $out[$n] = $all[$n];
            }
        }
        return $out;
    }

    /**
     * @param array<string,mixed> $f
     * @param list<string> $errors
     * @return array<string,mixed>
     */
    private function fieldView(string $model, string $n, array $f, mixed $v, array $errors, ?Identity $who): array
    {
        $t = (string) ($f['type'] ?? 'string');
        $val = is_scalar($v) ? (string) $v : '';
        $options = [];
        if ($t === 'relasi' && is_string($f['target'] ?? null)) {
            $td = $this->defs->model($f['target']);
            if ($td !== null) {
                try {
                    foreach ($this->repo($td, $who)->labels() as $id => $lbl) {
                        $options[] = ['value' => (string) $id, 'label' => $lbl, 'sel' => (string) $id === $val];
                    }
                } catch (Forbidden) {
                    $options = [];
                }
            }
        }
        $file = is_array($f['upload'] ?? null) ? $f['upload'] : null;
        $fid = $file !== null && preg_match('/^[a-f0-9]{32}$/D', $val) === 1 ? $val : '';
        if ($file !== null) {
            $val = $fid; // nilai selain fid tidak pernah dicetak kembali
        }
        $inputType = ['integer' => 'number', 'date' => 'date', 'datetime' => 'datetime-local'][$t] ?? 'text';
        if ($t === 'datetime' && $val !== '') {
            $val = str_replace(' ', 'T', $val);
        }
        return [
            'name' => $n, 'label' => is_string($f['label'] ?? null) ? $f['label'] : $n,
            'required' => ($f['required'] ?? false) === true, 'value' => $val, 'inputType' => $inputType,
            'isBool' => $t === 'boolean', 'checked' => $val === '1' || $v === true,
            'isTextarea' => $t === 'text' || $t === 'json', 'isSelect' => $t === 'relasi', 'options' => $options,
            'errors' => $errors, 'hasErr' => $errors !== [],
            'isFile' => $file !== null, 'fileModel' => $model, 'fileHref' => $fid === '' ? '' : '/files/' . $fid, 'hasFile' => $fid !== '',
            'accept' => $file === null ? '' : implode(',', array_map('strval', (array) ($file['mimes'] ?? []))),
        ];
    }

    private function doSave(Request $r, string $name, ?int $id): Response
    {
        $g = $this->gate($name);
        if ($g instanceof Response) {
            return $g;
        }
        [$page, $who] = $g;
        $mc = $this->modelOf($page);
        if ($mc === null) {
            throw new NotFound();
        }
        [$def, $comp] = $mc;
        // Hanya field yang tampil di form yang boleh diisi (mass assignment, SEC-DATA-02).
        $repo = new ModelRepository($def, $this->query, $this->authz, $who, $this->hooks, array_map('strval', array_keys($this->formFields($def, $comp))), $this->targetResolver(), $this->devMode, $this->logger, $this->files, $this->cache);
        $res = $id === null ? $repo->create($r->post) : $repo->update($id, $r->post);
        if (!$res->ok()) {
            return $this->doForm($name, $id, $r->post + $res->values, $res->errors, $res->formErrors, 422);
        }
        $this->session->flash('ok', $id === null ? 'Data berhasil ditambahkan.' : 'Data berhasil diperbarui.');
        return Response::redirect((string) $page['route']);
    }

    private function doDelete(string $name, int $id): Response
    {
        $g = $this->gate($name);
        if ($g instanceof Response) {
            return $g;
        }
        [$page, $who] = $g;
        $mc = $this->modelOf($page);
        if ($mc === null) {
            throw new NotFound();
        }
        try {
            $this->repo($mc[0], $who)->delete($id);
            $this->session->flash('ok', 'Data dihapus.');
        } catch (HookRejected $e) {
            $this->session->flash('err', implode(' ', $e->messages));
        }
        return Response::redirect((string) $page['route']);
    }

    private function layoutResponse(string $title, SafeHtml $content, string $active, ?Identity $who, int $status, bool $upload = false, bool $anon = false): Response
    {
        $html = $this->layout->render('layout', [
            'title' => $title,
            'csrf' => $anon ? '' : $this->csrf->token(),
            'user' => $who === null ? null : [
                'name' => $who->activeRole,
                'switch' => count($who->roles) > 1,
                'roleOptions' => array_map(static fn(string $n): array => ['name' => $n, 'on' => $n === $who->activeRole], $who->roles),
            ],
            'nav' => Navigation::build($this->defs->pages(), $who),
            'active' => $active,
            'flash' => $anon ? [] : $this->session->pullFlash(),
            'scripts' => $upload ? ['/assets/app.js', '/assets/upload.js'] : ['/assets/app.js'],
            'bodyClass' => '',
            'content' => $content,
        ]);
        $out = $html->toString();
        if ($anon) {
            // Halaman anonim dilayani sama persis dengan versi cache: tanpa atribut nonce (script-src 'self' cukup untuk /assets/).
            $out = str_replace(' nonce="' . Nonce::current() . '"', '', $out);
        }
        return Response::html($out, $status);
    }
}
