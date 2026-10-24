<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Identity;

/** Menu samping dari definisi halaman: hanya item yang boleh diakses Identity; grup "Admin" selalu terakhir. */
final class Navigation
{
    /** @param array<string,mixed> $page halaman ter-compile */
    public static function allows(array $page, ?Identity $who): bool
    {
        $acc = $page['access'] ?? [];
        if ($acc === '*') {
            return true;
        }
        return $who !== null && is_array($acc) && in_array($who->activeRole, $acc, true);
    }

    /**
     * @param array<string,array<string,mixed>> $pages nama => halaman ter-compile
     * @return list<array{group:string,items:list<array{key:string,label:string,icon:string,href:string}>}>
     */
    public static function build(array $pages, ?Identity $who): array
    {
        if ($who === null) {
            return [];
        }
        /** @var array<string,array{min:int,items:list<array{0:int,1:array{key:string,label:string,icon:string,href:string}}>}> $groups */
        $groups = [];
        foreach ($pages as $name => $p) {
            $route = $p['route'] ?? '';
            if (!is_string($route) || $route === '' || !self::allows($p, $who)) {
                continue;
            }
            $title = is_string($p['title'] ?? null) && trim($p['title']) !== '' ? trim($p['title']) : ucfirst(str_replace(['-', '_'], ' ', (string) $name));
            $icon = is_string($p['icon'] ?? null) && $p['icon'] !== '' ? mb_substr($p['icon'], 0, 4) : '▫';
            $g = is_string($p['group'] ?? null) ? trim($p['group']) : '';
            if ($g === '' || mb_strtolower($g) === 'admin') { // "Admin" dicadangkan (tak bisa dari definisi)
                $g = 'Aplikasi';
            }
            $order = is_int($p['order'] ?? null) ? $p['order'] : PHP_INT_MAX;
            $groups[$g]['items'][] = [$order, ['key' => (string) $name, 'label' => $title, 'icon' => $icon, 'href' => $route]];
            $groups[$g]['min'] = min($groups[$g]['min'] ?? PHP_INT_MAX, $order);
        }
        uksort($groups, static fn(string $a, string $b): int => [$groups[$a]['min'], $a] <=> [$groups[$b]['min'], $b]);
        $out = [];
        foreach ($groups as $g => $info) {
            usort($info['items'], static fn(array $x, array $y): int => [$x[0], $x[1]['label']] <=> [$y[0], $y[1]['label']]);
            $out[] = ['group' => (string) $g, 'items' => array_map(static fn(array $i): array => $i[1], $info['items'])];
        }
        if ($who->activeRole === 'admin') {
            $out[] = ['group' => 'Admin', 'items' => [
                ['key' => 'pengguna', 'label' => 'Pengguna', 'icon' => '👥', 'href' => '/admin/pengguna'],
                ['key' => 'peran', 'label' => 'Peran', 'icon' => '🔑', 'href' => '/admin/peran'],
            ]];
        }
        return $out;
    }
}
