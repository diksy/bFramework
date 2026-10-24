<?php

declare(strict_types=1);

namespace bFramework\Tests\Fixtures;

use bFramework\Auth\AuthKit;
use bFramework\Auth\AuthManager;
use bFramework\Auth\CookieJar;
use bFramework\Auth\LocalDriver;
use bFramework\Auth\Mailer;
use bFramework\Auth\SecretVault;
use bFramework\Core\Csrf;
use bFramework\Core\FileSessionStore;
use bFramework\Core\Kernel;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\Router;
use bFramework\Core\Template;
use bFramework\Runtime\CurrentIdentity;
use bFramework\Sso\BackchannelHandler;
use bFramework\Sso\ClaimsValidator;
use bFramework\Sso\FileCache;
use bFramework\Sso\FirebaseJwtVerifier;
use bFramework\Sso\JtiStore;
use bFramework\Sso\OidcClient;
use bFramework\Sso\RefreshVault;
use bFramework\Sso\SidMap;
use bFramework\Sso\SsoConfig;
use bFramework\Sso\SsoDriver;
use bFramework\Sso\SsoTables;

/** Perakitan SSO lengkap dengan IdP palsu. Mode: bikinin_sso | hybrid. Hanya data dummy. */
final class SsoHarness
{
    public AuthHarness $a;
    public FakeIdp $idp;
    public string $mode;
    /** @var array<string,mixed> */
    public array $sso = [];
    public ?SsoDriver $driver = null;
    public ?Router $router = null;

    public function __construct(string $mode = 'bikinin_sso')
    {
        $this->mode = $mode;
        $this->a = new AuthHarness();
        SsoTables::install($this->a->conn);
        $this->idp = new FakeIdp($this->a->clock);
    }

    public function config(): SsoConfig
    {
        $c = SsoConfig::from(array_replace([
            'issuer' => FakeIdp::ISSUER, 'client_id' => FakeIdp::CLIENT_ID, 'client_secret' => FakeIdp::SECRET,
            'provisioning' => 'jit', 'default_role' => 'staf', 'offline_access' => false, 'session_check_minutes' => 5,
        ], $this->sso), 'https://app.contoh.test');
        if ($c === null) {
            throw new \RuntimeException('config tes tidak sah');
        }
        return $c;
    }

    public function sids(): SidMap
    {
        return new SidMap($this->a->conn, $this->a->clock, $this->a->logger);
    }

    public function vault(): RefreshVault
    {
        return new RefreshVault($this->a->conn, new SecretVault(AuthHarness::APP_KEY), $this->a->clock, $this->a->dir . '/locks', $this->a->logger);
    }

    public function oidc(): OidcClient
    {
        return new OidcClient($this->idp->http(), new FileCache($this->a->dir . '/sso', $this->a->clock), $this->a->clock, $this->config(), new FirebaseJwtVerifier(), $this->a->logger);
    }

    /**
     * @param array<string,string> $cookies
     * @return array{0:Kernel,1:Router}
     */
    public function wire(array $cookies): array
    {
        $a = $this->a;
        $jar = new CookieJar();
        $session = new FileSessionStore($a->dir . '/sessions', false, 1800, 28800, $cookies, $jar->add(...), $a->clock);
        $csrf = new Csrf($session);
        $manager = new AuthManager($session, new CurrentIdentity($session), $csrf, $a->accounts, $a->clock);
        $views = new Template(dirname(__DIR__, 2) . '/app/core/Auth/views', $a->dir . '/views');
        $layout = new Template(dirname(__DIR__, 2) . '/app/core/Core/views', $a->dir . '/views');
        $local = null;
        if ($this->mode === 'hybrid') {
            $local = new LocalDriver(
                $manager, $a->accounts, $a->hasher, $a->throttle(), $a->remember(), $a->tokens(), $a->twofa(),
                new Mailer($a->mail, $a->logger), $a->deferred, $session, $csrf, $views, $layout, $a->clock,
                ['appUrl' => 'https://app.contoh.test', 'from' => 'noreply@contoh.test', 'breakGlass' => true],
                $a->logger,
            );
        }
        $cfg = $this->config();
        $oidc = $this->oidc();
        $claims = new ClaimsValidator($cfg->issuer, $cfg->clientId);
        $sids = $this->sids();
        $vault = $this->vault();
        $bc = new BackchannelHandler($oidc, $claims, new JtiStore($a->dir . '/jti', $a->clock), $sids, $vault, $a->clock, $a->logger, new \bFramework\Core\RateLimiter($a->dir . '/ratelimit', $a->clock));
        $driver = new SsoDriver(
            $this->mode, $cfg, $oidc, $bc, $claims, $manager, $a->users(), $a->accounts, $sids, $vault, $a->hasher, $a->throttle(),
            $session, $csrf, $views, $layout, $a->clock, $local, $a->logger,
        );
        $this->driver = $driver;
        $kit = new AuthKit($session, $jar, $csrf, $manager, $a->remember(), $driver, $a->deferred, null);
        $router = new Router();
        $driver->registerRoutes($router);
        $this->router = $router;
        return [new Kernel($router, $kit->middleware($router, [], true), $a->logger), $router];
    }

    /** @param array<string,string> $cookies */
    public function dispatch(Request $r, array $cookies): Response
    {
        [$kernel] = $this->wire($cookies);
        return $kernel->handle($r);
    }

    public function browser(string $ip = '203.0.113.7'): SsoBrowser
    {
        return new SsoBrowser($this, $ip);
    }
}
