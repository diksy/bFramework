<?php

declare(strict_types=1);

namespace bFramework\Install;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Logger;
use bFramework\Contracts\NotFound;
use bFramework\Contracts\TooManyRequests;
use bFramework\Core\Csrf;
use bFramework\Core\RateLimiter;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\Router;
use bFramework\Core\TransportPolicy;
use bFramework\Core\Template;

/** GET|POST /install (CSRF aktif lewat middleware, rate limit per IP). Setelah terpasang: 404. */
final class InstallController
{
    public function __construct(
        private readonly Installer $installer,
        private readonly Csrf $csrf,
        private readonly Template $views,
        private readonly Template $layout,
        private readonly RateLimiter $limiter,
        private readonly ?Logger $logger = null,
        private readonly int $rateMax = 10,
        private readonly int $rateWindow = 900,
    ) {
    }

    private const TLS_WARNING = 'APP_URL berskema https tetapi permintaan ini tampak HTTP (TLS diputus di proxy/CDN?). Cookie sesi tetap dipaksa Secure/__Host- dan HSTS dikirim; atur TRUSTED_PROXIES bila perlu.';

    public function registerRoutes(Router $router): void
    {
        $router->add('GET', '/install', fn(Request $r, array $p = []): Response => $this->show($r));
        $router->add('POST', '/install', fn(Request $r, array $p = []): Response => $this->submit($r));
        $router->add('POST', '/install/canary', fn(Request $r, array $p = []): Response => $this->canary($r));
    }

    private function show(Request $r): Response
    {
        if ($this->installer->isInstalled()) {
            throw new NotFound();
        }
        // Mode cadangan: kanari dibuat dulu; token baru dibuat setelah browser membuktikan kanari tidak terunduh (S1)
        $this->installer->ensureToken();
        $scheme = $r->isHttps ? 'https' : 'http';
        $host = strtolower($r->header('host') ?? '');
        return $this->form(['app_url' => HostPolicy::validHost($host) ? $scheme . '://' . $host : '', 'db_driver' => 'sqlite',
            'db_file' => 'app.sqlite', 'db_host' => 'localhost', 'db_port' => '3306', 'smtp_port' => '587', 'smtp_secure' => 'starttls'], [], 200);
    }

    /** Laporan uji kanari dari browser (CSRF aktif lewat middleware). Hasil: JSON {ok:bool}. */
    private function canary(Request $r): Response
    {
        if ($this->installer->isInstalled()) {
            throw new NotFound();
        }
        if (!$this->limiter->hit('install:' . $r->remoteAddr, $this->rateMax * 3, $this->rateWindow)) {
            throw new TooManyRequests();
        }
        $ok = $this->installer->reportCanary(($r->post['blocked'] ?? '') === '1');
        if ($ok) {
            $this->installer->ensureToken();
        } else {
            $this->logger?->warning('Uji kanari installer tidak lulus');
        }
        return Response::json(['ok' => $ok], $ok ? 200 : 422)->withHeader('Cache-Control', 'no-store');
    }

    private function submit(Request $r): Response
    {
        if ($this->installer->isInstalled()) {
            throw new NotFound();
        }
        if (!$this->limiter->hit('install:' . $r->remoteAddr, $this->rateMax, $this->rateWindow)) {
            $this->logger?->warning('Installer kena rate limit');
            throw new TooManyRequests();
        }
        $f = [];
        foreach (['app_url', 'admin_email', 'admin_name', 'db_driver', 'db_file', 'db_host', 'db_port', 'db_name', 'db_user',
            'mail_from', 'smtp_host', 'smtp_port', 'smtp_secure', 'smtp_user', 'allowed_hosts'] as $k) {
            $v = $r->post[$k] ?? '';
            $f[$k] = is_string($v) ? trim($v) : '';
        }
        $secret = static fn(string $k): string => is_string($r->post[$k] ?? null) ? $r->post[$k] : '';
        $hosts = array_values(array_filter(array_map('trim', preg_split('/[\s,]+/', strtolower($f['allowed_hosts'])) ?: []), static fn(string $h): bool => $h !== ''));

        $url = HostPolicy::parse($f['app_url']);
        $reqHost = strtolower($r->header('host') ?? '');
        if ($url !== null && $url['authority'] !== $reqHost) {
            return $this->form($f, ['APP_URL harus sama dengan alamat yang sedang dipakai membuka installer.'], 422);
        }
        // S9: APP_URL https tetapi permintaan ini tampak HTTP (TLS diputus di proxy/CDN, atau akses tanpa TLS).
        $tlsWarn = TransportPolicy::isHttpsUrl($f['app_url']) && !$r->isHttps;
        $in = new InstallInput(
            appUrl: rtrim($f['app_url'], '/'),
            adminEmail: $f['admin_email'],
            adminName: $f['admin_name'],
            dbDriver: $f['db_driver'],
            dbFile: $f['db_file'],
            dbHost: $f['db_host'],
            dbPort: (int) $f['db_port'],
            dbName: $f['db_name'],
            dbUser: $f['db_user'],
            dbPassword: $secret('db_password'),
            mailFrom: $f['mail_from'],
            smtpHost: $f['smtp_host'],
            smtpPort: (int) $f['smtp_port'],
            smtpSecure: $f['smtp_secure'],
            smtpUser: $f['smtp_user'],
            smtpPassword: $secret('smtp_password'),
            allowedHosts: $hosts,
            registration: ($r->post['registration'] ?? '') === '1',
            installToken: trim($secret('install_token')),
        );
        try {
            $res = $this->installer->install($in);
        } catch (InstallRejected $e) {
            if ($e->status === 404) {
                throw new NotFound();
            }
            return $this->form($f, array_merge([$e->getMessage()], $e->errors), $e->status, $tlsWarn);
        }
        // Rahasia (tautan reset) hanya tampil di respons ini; jangan di-cache.
        return $this->page('done', 'Instalasi selesai', ['resetUrl' => $res->resetUrl, 'tlsWarn' => $tlsWarn], 200);
    }

    /**
     * @param array<string,string> $values nilai non-rahasia untuk diisi ulang
     * @param list<string> $errors
     */
    private function form(array $values, array $errors, int $status, bool $tlsWarn = false): Response
    {
        $values += ['smtp_secure' => 'starttls', 'db_driver' => 'sqlite'];
        $canary = $this->installer->ensureCanary();
        return $this->page('install', 'Instalasi', [
            'canaryUrl' => $canary['url'] ?? '',
            'canaryContent' => $canary['content'] ?? '',
            'v' => $values,
            'sel' => ['sqlite' => $values['db_driver'] !== 'mysql', 'mysql' => $values['db_driver'] === 'mysql',
                'starttls' => $values['smtp_secure'] !== 'tls', 'tls' => $values['smtp_secure'] === 'tls'],
            'errors' => $errors,
            'checks' => array_merge(
                array_map(static fn(Check $c): array => ['ok' => $c->ok, 'warn' => !$c->ok && !$c->fatal, 'msg' => $c->msg], $this->installer->checks()),
                $tlsWarn ? [['ok' => false, 'warn' => true, 'msg' => self::TLS_WARNING]] : [],
            ),
            'tokenFile' => 'app/storage/' . Installer::TOKEN_FILE . '<kode-acak>',
            'blocked' => $this->installer->canaryRequired() && !$this->installer->canaryProven(),
        ], $status);
    }

    /** @param array<string,mixed> $vars */
    private function page(string $view, string $title, array $vars, int $status): Response
    {
        $csrf = $this->csrf->token();
        $content = $this->views->render($view, $vars + ['csrf' => $csrf]);
        $html = $this->layout->render('layout', [
            'title' => $title, 'csrf' => $csrf, 'user' => null, 'nav' => [], 'active' => '', 'flash' => [],
            'scripts' => ($vars['canaryUrl'] ?? '') !== '' ? ['/assets/install-canary.js'] : [], 'bodyClass' => 'auth', 'content' => $content,
        ]);
        return Response::html($html->toString(), $status)->withHeader('Cache-Control', 'no-store');
    }
}
