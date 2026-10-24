<?php

declare(strict_types=1);

namespace bFramework\Update;

defined('APP_BOOTED') || exit;

use bFramework\Auth\AuthManager;
use bFramework\Auth\StepUp;
use bFramework\Contracts\Action;
use bFramework\Contracts\Forbidden;
use bFramework\Contracts\Identity;
use bFramework\Contracts\Logger;
use bFramework\Contracts\SessionStore;
use bFramework\Contracts\TooManyRequests;
use bFramework\Core\Csrf;
use bFramework\Core\RateLimiter;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\Router;
use bFramework\Core\Template;
use bFramework\Runtime\Authorizer;
use bFramework\Runtime\Navigation;

/**
 * GET /admin/pembaruan: status baca-saja (versi, kesiapan kunci penandatangan, diff MANIFEST, mode pemeliharaan).
 * Hanya peran admin (Authorizer), rate limit per pengguna, tanpa isi file. Penerapan paket HANYA lewat CLI
 * (php app/cli/update.php): unggahan web yang mengeksekusi kode dihindari untuk memperkecil permukaan serangan.
 */
final class UpdateController
{
    private const ACCESS = ['access' => ['read' => ['admin'], 'write' => ['admin']]];

    /** @param \Closure():array<string,array<string,mixed>> $pages */
    public function __construct(
        private readonly AuthManager $auth,
        private readonly Authorizer $authz,
        private readonly Csrf $csrf,
        private readonly SessionStore $session,
        private readonly Template $views,
        private readonly Template $layout,
        private readonly RateLimiter $limiter,
        private readonly CoreManifest $manifest,
        private readonly UpdatePackage $package,
        private readonly \Closure $pages,
        private readonly StepUp $stepUp,
        private readonly ?Logger $logger = null,
    ) {
    }

    public function registerRoutes(Router $router): void
    {
        $router->add('GET', '/admin/pembaruan', fn(Request $r, array $p = []): Response => $this->status($r));
    }

    private function status(Request $r): Response
    {
        $who = $this->auth->current();
        if ($who === null) {
            return Response::redirect('/login');
        }
        if (!$this->authz->can(self::ACCESS, Action::Read, $who)) {
            throw new Forbidden('Akses ditolak');
        }
        if (!$this->stepUp->satisfied($who)) {
            return $this->stepUp->redirect($r);
        }
        if (!$this->limiter->hit('update-status:' . $who->userId, 30, 300)) {
            throw new TooManyRequests();
        }
        $diff = $this->manifest->diff();
        $this->logger?->info('Halaman pembaruan dibuka', ['user_id' => $who->userId, 'bersih' => $diff->clean()]);
        return $this->render($who, [
            'version' => $this->package->installedVersion(),
            'keyReady' => $this->package->keyReady(),
            'noKey' => !$this->package->keyReady(),
            'hasManifest' => $diff->available,
            'noManifest' => !$diff->available,
            'clean' => $diff->clean(),
            'dirty' => $diff->available && !$diff->clean(),
            'changed' => $diff->changed,
            'missing' => $diff->missing,
            'extra' => $diff->extra,
            'maintenance' => is_file(dirname(__DIR__, 2) . '/storage/maintenance'),
        ]);
    }

    /** @param array<string,mixed> $vars */
    private function render(Identity $who, array $vars): Response
    {
        $content = $this->views->render('status', $vars);
        $pages = [];
        try {
            $pages = ($this->pages)();
        } catch (\Throwable) {
            $this->logger?->warning('Definisi halaman tidak terbaca untuk menu');
        }
        $html = $this->layout->render('layout', [
            'title' => 'Pembaruan',
            'csrf' => $this->csrf->token(),
            'user' => ['name' => $who->activeRole, 'switch' => count($who->roles) > 1, 'roleOptions' => array_map(
                static fn(string $n): array => ['name' => $n, 'on' => $n === $who->activeRole],
                $who->roles,
            )],
            'nav' => Navigation::build($pages, $who),
            'active' => '/admin/pembaruan',
            'flash' => $this->session->pullFlash(),
            'scripts' => ['/assets/app.js'],
            'bodyClass' => '',
            'content' => $content,
        ]);
        return Response::html($html->toString())->withHeader('Cache-Control', 'no-store');
    }
}
