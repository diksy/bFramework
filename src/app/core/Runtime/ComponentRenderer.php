<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Action;
use bFramework\Contracts\Forbidden;
use bFramework\Contracts\Identity;
use bFramework\Core\SafeHtml;
use bFramework\Core\Template;

/**
 * Merender komponen halaman ter-compile menjadi SafeHtml lewat Template (auto-escape, SEC-OUT-01/02).
 * Data hanya lewat ModelRepository (Authorizer + constrain); tanpa string HTML dari input.
 */
final class ComponentRenderer
{
    /**
     * @param array<string,mixed> $page halaman ter-compile (route dipakai untuk tautan)
     * @param array<string,mixed> $query query string request (sort, hal)
     */
    public function __construct(
        private readonly Definitions $defs,
        private readonly Query $dataQuery,
        private readonly Authorizer $authz,
        private readonly HookRunner $hooks,
        private readonly Template $views,
        private readonly ?Identity $who,
        private readonly array $page,
        private readonly array $query,
        private readonly string $csrf,
    ) {
    }

    /** @param array<string,mixed> $component */
    public function render(array $component): SafeHtml
    {
        $span = is_int($component['span'] ?? null) ? max(1, min(12, $component['span'])) : 12;
        $inner = match ($component['component'] ?? '') {
            'table' => $this->table($component),
            'stat' => $this->stat($component),
            'card', 'text' => $this->view('card', ['title' => $component['title'] ?? '', 'text' => $component['text'] ?? '']),
            'chart' => $this->chart($component),
            'image' => $this->image($component),
            'form' => $this->formLink($component),
            default => $this->notice('Komponen tidak dikenal.'),
        };
        return SafeHtml::fromTrusted('<div class="span-' . $span . '">' . $inner->toString() . '</div>');
    }

    /** @param array<string,mixed> $c */
    private function repo(array $c): ?ModelRepository
    {
        $src = $c['source'] ?? null;
        $name = is_array($src) && is_string($src['model'] ?? null) ? $src['model'] : '';
        return $name === '' ? null : $this->repoFor($name);
    }

    private function repoFor(string $model): ?ModelRepository
    {
        $def = $this->defs->model($model);
        return $def === null ? null : new ModelRepository($def, $this->dataQuery, $this->authz, $this->who, $this->hooks);
    }

    /**
     * @param array<string,mixed> $vars
     */
    private function view(string $name, array $vars): SafeHtml
    {
        return $this->views->render($name, $vars);
    }

    private function notice(string $m): SafeHtml
    {
        return $this->view('notice', ['message' => $m]);
    }

    /** @param array<string,mixed> $c */
    private function table(array $c): SafeHtml
    {
        $repo = $this->repo($c);
        if ($repo === null || !$repo->can(Action::Read)) {
            return $this->notice('Anda tidak berhak melihat data ini.');
        }
        $def = $this->defs->model((string) ((array) $c['source'])['model']) ?? [];
        /** @var array<string,array<string,mixed>> $fields */
        $fields = is_array($def['fields'] ?? null) ? $def['fields'] : [];
        $src = (array) $c['source'];
        $defSort = is_string($src['sort'] ?? null) ? $src['sort'] : null;
        $sort = $defSort;
        $qs = $this->query['sort'] ?? null;
        if (is_string($qs) && $qs !== '') {
            try {
                $repo->normalizeSort($qs);
                $sort = $qs;
            } catch (\InvalidArgumentException) {
                // sort tak sah dari query diabaikan; pakai bawaan definisi
            }
        }
        $perPage = is_int($src['perPage'] ?? null) ? $src['perPage'] : 20;
        $perPage = max(1, min(100, $perPage));
        $hal = $this->query['hal'] ?? 1;
        $pageNo = is_string($hal) && ctype_digit($hal) && strlen($hal) <= 6 ? max(1, (int) $hal) : 1;
        $filters = is_array($src['filter'] ?? null) ? $src['filter'] : [];
        try {
            $res = $repo->paginate($sort, $pageNo, $perPage, $filters);
        } catch (\InvalidArgumentException) {
            return $this->notice('Definisi tabel tidak valid.');
        }

        $cols = array_values(array_filter(
            array_map('strval', is_array($c['columns'] ?? null) ? $c['columns'] : array_keys($fields)),
            static fn(string $n): bool => isset($fields[$n]) && ($fields[$n]['guarded'] ?? false) !== true,
        ));
        $labels = [];
        foreach ($cols as $n) {
            if (($fields[$n]['type'] ?? '') === 'relasi' && is_string($fields[$n]['target'] ?? null)) {
                $t = $this->repoFor($fields[$n]['target']);
                try {
                    $labels[$n] = $t === null ? [] : $t->labels();
                } catch (Forbidden) {
                    $labels[$n] = [];
                }
            }
        }
        $route = (string) $this->page['route'];
        $acts = is_array($c['actions'] ?? null) ? $c['actions'] : [];
        $canEdit = in_array('edit', $acts, true) && $repo->can(Action::Update);
        $canDelete = in_array('hapus', $acts, true) && $repo->can(Action::Delete);
        $canCreate = $repo->can(Action::Create) && (in_array('baru', $acts, true) || $acts === [] || $canEdit || $canDelete);
        $cur = $sort ?? '';
        $heads = [];
        foreach ($cols as $n) {
            $asc = $cur === $n;
            $heads[] = [
                'label' => is_string($fields[$n]['label'] ?? null) ? $fields[$n]['label'] : $n,
                'href' => $route . '?sort=' . rawurlencode($asc ? '-' . $n : $n),
                'asc' => $asc, 'desc' => $cur === '-' . $n,
            ];
        }
        $rows = [];
        foreach ($res['rows'] as $r) {
            $cells = [];
            foreach ($cols as $n) {
                $t = (string) ($fields[$n]['type'] ?? 'string');
                $cells[] = [
                    'text' => Format::cell($fields[$n], $r[$n] ?? null, $labels[$n] ?? []),
                    'cls' => in_array($t, ['integer', 'decimal'], true) ? 'num' : '',
                ];
            }
            $id = (int) ($r['id'] ?? 0);
            $rows[] = ['cells' => $cells, 'editHref' => "$route/$id/ubah", 'deleteHref' => "$route/$id/hapus"];
        }
        $pages = max(1, (int) ceil($res['total'] / $perPage));
        $current = min($pageNo, $pages);
        $base = $route . '?' . ($sort !== null ? 'sort=' . rawurlencode($sort) . '&' : '');
        $pager = [];
        for ($i = max(1, $current - 5); $i <= min($pages, $current + 5); $i++) {
            $pager[] = ['n' => $i, 'on' => $i === $current, 'href' => $base . 'hal=' . $i];
        }
        $hasActions = $canEdit || $canDelete;
        return $this->view('table', [
            'title' => is_string($c['title'] ?? null) ? $c['title'] : ucfirst((string) ($def['model'] ?? '')),
            'heads' => $heads, 'rows' => $rows, 'total' => $res['total'], 'empty' => $res['rows'] === [],
            'colspan' => count($cols) + ($hasActions ? 1 : 0), 'hasActions' => $hasActions,
            'canEdit' => $canEdit, 'canDelete' => $canDelete, 'canCreate' => $canCreate,
            'createHref' => $route . '/baru', 'csrf' => $this->csrf,
            'page' => $current, 'pages' => $pages, 'pager' => $pager,
        ]);
    }

    /** @param array<string,mixed> $c */
    private function stat(array $c): SafeHtml
    {
        $repo = $this->repo($c);
        $val = '-';
        if ($repo !== null && $repo->can(Action::Read)) {
            $f = is_string($c['field'] ?? null) && $c['field'] !== '' ? $c['field'] : null;
            $def = $this->defs->model((string) ((array) $c['source'])['model']) ?? [];
            $format = $f !== null && is_array($def['fields'][$f] ?? null) && is_string($def['fields'][$f]['format'] ?? null) ? $def['fields'][$f]['format'] : '';
            try {
                $v = $repo->aggregate(is_string($c['agg'] ?? null) ? $c['agg'] : 'count', $f);
                $val = $v === null ? '-' : Format::number($v, $format);
            } catch (Forbidden | \InvalidArgumentException) {
                $val = '-';
            }
        }
        return $this->view('stat', ['label' => is_string($c['label'] ?? null) ? $c['label'] : 'Statistik', 'value' => $val]);
    }

    /** @param array<string,mixed> $c */
    private function image(array $c): SafeHtml
    {
        $src = is_string($c['src'] ?? null) ? $c['src'] : '';
        $local = preg_match('#^/(?!/)[\w./%-]+$#D', $src) === 1 && !str_contains($src, '..');
        if (!$local && preg_match('#^https://[\w.-]+(:\d+)?(/[\w./%+-]*)?$#Di', $src) !== 1) {
            return $this->view('notice', ['message' => 'Gambar (belum dipilih)']);
        }
        return $this->view('image', ['src' => $src, 'alt' => is_string($c['alt'] ?? null) ? $c['alt'] : '']);
    }

    /** @param array<string,mixed> $c */
    private function chart(array $c): SafeHtml
    {
        $repo = $this->repo($c);
        $field = is_string($c['field'] ?? null) ? $c['field'] : '';
        if ($repo === null || $field === '' || !$repo->can(Action::Read)) {
            return $this->notice('Tidak ada akses.');
        }
        $def = $this->defs->model((string) ((array) $c['source'])['model']) ?? [];
        $label = null;
        foreach ((array) ($def['fields'] ?? []) as $n => $f) {
            if (is_array($f) && $f['type'] === 'string' && ($f['guarded'] ?? false) !== true) {
                $label = (string) $n;
                break;
            }
        }
        $limit = is_int(((array) $c['source'])['perPage'] ?? null) ? ((array) $c['source'])['perPage'] : 6;
        try {
            $rows = $repo->paginate('-' . $field, 1, $limit, is_array(((array) $c['source'])['filter'] ?? null) ? ((array) $c['source'])['filter'] : [])['rows'];
            $max = $repo->aggregate('max', $field) ?? '0';
        } catch (Forbidden | \InvalidArgumentException) {
            return $this->notice('Tidak ada akses.');
        }
        $bars = [];
        foreach ($rows as $r) {
            $v = $r[$field] ?? 0;
            $bars[] = ['label' => $label === null ? '' : (string) ($r[$label] ?? ''), 'value' => (string) $v, 'text' => Format::number(is_int($v) ? $v : (string) $v)];
        }
        return $this->view('chart', [
            'title' => is_string($c['title'] ?? null) ? $c['title'] : 'Grafik',
            'bars' => $bars, 'max' => preg_match('/^-?\d+(\.\d+)?$/D', $max) === 1 && $max !== '0' ? $max : '1',
        ]);
    }

    /** @param array<string,mixed> $c */
    private function formLink(array $c): SafeHtml
    {
        $repo = $this->repo($c);
        if ($repo === null || !$repo->can(Action::Create)) {
            return $this->notice('Form tidak tersedia untuk peran Anda.');
        }
        return $this->view('formlink', [
            'title' => is_string($c['title'] ?? null) ? $c['title'] : 'Form',
            'href' => (string) $this->page['route'] . '/baru',
        ]);
    }
}
