<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use bFramework\Core\CsrfMiddleware;
use bFramework\Core\FileSessionStore;
use bFramework\Core\Csrf;
use bFramework\Core\Middleware;
use bFramework\Core\Router;
use bFramework\Core\SecurityHeaders;
use bFramework\Core\HostGuard;
use bFramework\Core\Nonce;

/** Hasil perakitan autentikasi oleh bootstrap.php: sesi, driver, antrean tunda, dan rantai middleware. */
final readonly class AuthKit
{
    public function __construct(
        public FileSessionStore $session,
        public CookieJar $jar,
        public Csrf $csrf,
        public AuthManager $manager,
        public RememberMe $remember,
        public AuthDriver $driver,
        public Deferred $deferred,
        public ?AdminController $admin = null,
    ) {
    }

    /**
     * Urutan (terluar dulu): header keamanan, HostGuard, sesi+cookie (+gc), pemulihan ingat-saya dan
     * validasi identitas, CSRF. Router harus sudah berisi semua rute (termasuk rute driver).
     *
     * @param list<string> $allowedHosts
     * SEC-REQ-03 fail-closed: daftar kosong menolak semua host (400) kecuali $devMode.
     *
     * @return list<Middleware>
     */
    public function middleware(Router $router, array $allowedHosts = [], bool $devMode = false): array
    {
        $chain = [new SecurityHeaders(Nonce::current(...))];
        if ($allowedHosts !== [] || !$devMode) {
            $chain[] = new HostGuard($allowedHosts);
        }
        $chain[] = new SessionMiddleware($this->session, $this->jar, $this->session->gc(...));
        $chain[] = new AuthMiddleware($this->manager, $this->remember);
        $chain[] = new CsrfMiddleware($router, $this->csrf, $this->session);
        return $chain;
    }
}
