<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Identity;
use bFramework\Contracts\NotFound;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\Router;
use InvalidArgumentException;

/**
 * GET /: anonim -> /login; pengguna login -> item menu pertama yang boleh diakses peran aktifnya
 * (Navigation; halaman admin bila admin dan tak ada halaman aplikasi). Tujuan hanya path internal dari
 * definisi ter-compile / daftar menu bawaan (bukan input pengguna), jadi tidak ada open redirect.
 * Bukan halaman cache: '/' tidak pernah ada di tabel rute cache (rute definisi minimal satu segmen).
 */
final class HomeRedirect
{
    /**
     * @param \Closure():?Identity $identity
     * @param \Closure():array<string,array<string,mixed>> $pages
     */
    public function __construct(private readonly \Closure $identity, private readonly \Closure $pages)
    {
    }

    public function registerRoutes(Router $router): void
    {
        $router->add('GET', '/', fn(Request $r, array $p = []): Response => $this->go());
    }

    private function go(): Response
    {
        $who = ($this->identity)();
        if ($who === null) {
            return Response::redirect('/login');
        }
        try {
            $pages = ($this->pages)();
        } catch (\Throwable) {
            $pages = []; // cache belum dibangun: hanya menu bawaan
        }
        foreach (Navigation::build($pages, $who) as $group) {
            foreach ($group['items'] as $item) {
                try {
                    return Response::redirect($item['href']);
                } catch (InvalidArgumentException) {
                    continue; // tujuan tak aman dilewati
                }
            }
        }
        throw new NotFound();
    }
}
