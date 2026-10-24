<?php

declare(strict_types=1);

namespace bFramework\Tests\Fixtures;

use bFramework\Auth\AccountStore;
use bFramework\Auth\AdminController;
use bFramework\Auth\AuthKit;
use bFramework\Auth\DbUserStore;
use bFramework\Auth\RoleStore;
use bFramework\Runtime\Authorizer;
use bFramework\Auth\AuthManager;
use bFramework\Auth\AuthSchema;
use bFramework\Auth\CookieJar;
use bFramework\Auth\Deferred;
use bFramework\Auth\LocalDriver;
use bFramework\Auth\LoginThrottle;
use bFramework\Auth\Mailer;
use bFramework\Auth\OneTimeToken;
use bFramework\Auth\RememberMe;
use bFramework\Auth\SecretVault;
use bFramework\Auth\TwoFactor;
use bFramework\Core\Csrf;
use bFramework\Core\FileSessionStore;
use bFramework\Core\Kernel;
use bFramework\Core\RateLimiter;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\Router;
use bFramework\Core\Template;
use bFramework\Runtime\Connection;
use bFramework\Runtime\CurrentIdentity;

/** Perakitan lengkap (SQLite memori, jam palsu, sesi file) yang meniru satu siklus request PHP. Hanya data dummy. */
final class AuthHarness
{
    public const APP_KEY = 'kunci-dummy-untuk-tes-0123456789abcdef-0123456789';
    public const PASSWORD = 'kata sandi dummy panjang 42';

    public Connection $conn;
    public FakeClock $clock;
    public CaptureTransport $mail;
    public CaptureLogger $logger;
    public SpyHasher $hasher;
    public Deferred $deferred;
    public AccountStore $accounts;
    public string $dir;
    public bool $registration = false;
    /** @var ?\Closure(Router, AuthKit):void rute tambahan modul lain (mis. M17) */
    public ?\Closure $extraRoutes = null;

    public function __construct()
    {
        $this->dir = sys_get_temp_dir() . '/auth_' . bin2hex(random_bytes(6));
        mkdir($this->dir . '/views', 0700, true);
        $this->conn = Connection::sqlite(':memory:');
        AuthSchema::install($this->conn);
        $this->clock = new FakeClock();
        $this->mail = new CaptureTransport();
        $this->logger = new CaptureLogger();
        $this->hasher = new SpyHasher(64, 1, 1, 4);
        $this->deferred = new Deferred($this->logger);
        $this->accounts = new AccountStore($this->conn, $this->clock, $this->logger);
        $this->conn->pdo()->exec("INSERT INTO roles (name) VALUES ('admin'), ('staf')");
    }

    public function __destruct()
    {
        self::rm($this->dir);
    }

    private static function rm(string $d): void
    {
        foreach (glob($d . '/{,.}*', GLOB_BRACE) ?: [] as $f) {
            if (basename($f) === '.' || basename($f) === '..') {
                continue;
            }
            is_dir($f) ? self::rm($f) : @unlink($f);
        }
        @rmdir($d);
    }

    /** @param list<string> $roles */
    public function user(string $email, string $password = self::PASSWORD, array $roles = ['staf'], string $status = 'active'): int
    {
        $id = $this->accounts->create($email, 'Pengguna Dummy', $this->hasher->hash($password), $status);
        if ($id === null) {
            throw new \RuntimeException('email ganda');
        }
        foreach ($roles as $r) {
            $this->accounts->assignRole($id, $r);
        }
        return $id;
    }

    public function users(): DbUserStore
    {
        return new DbUserStore($this->conn, $this->clock, $this->accounts, $this->logger);
    }

    public function vault(): SecretVault
    {
        return new SecretVault(self::APP_KEY);
    }

    public function twofa(): TwoFactor
    {
        return new TwoFactor($this->accounts, $this->vault(), $this->clock);
    }

    public function remember(): RememberMe
    {
        return new RememberMe($this->conn, $this->clock, $this->logger);
    }

    public function tokens(): OneTimeToken
    {
        return new OneTimeToken($this->conn, $this->clock);
    }

    public function throttle(): LoginThrottle
    {
        return new LoginThrottle(new RateLimiter($this->dir . '/rl', $this->clock));
    }

    /**
     * Merakit seluruh lapisan untuk satu request.
     *
     * @param array<string,string> $cookies
     * @return array{0:Kernel,1:AuthKit,2:CookieJar}
     */
    public function wire(array $cookies): array
    {
        $jar = new CookieJar();
        $session = new FileSessionStore($this->dir . '/sessions', false, 1800, 28800, $cookies, $jar->add(...), $this->clock);
        $csrf = new Csrf($session);
        $manager = new AuthManager($session, new CurrentIdentity($session), $csrf, $this->accounts, $this->clock);
        $remember = $this->remember();
        $driver = new LocalDriver(
            $manager, $this->accounts, $this->hasher, $this->throttle(), $remember, $this->tokens(), $this->twofa(),
            new Mailer($this->mail, $this->logger), $this->deferred, $session, $csrf,
            new Template(dirname(__DIR__, 2) . '/app/core/Auth/views', $this->dir . '/views'),
            new Template(dirname(__DIR__, 2) . '/app/core/Core/views', $this->dir . '/views'),
            $this->clock,
            ['appUrl' => 'https://app.contoh.test', 'registration' => $this->registration, 'defaultRole' => 'staf', 'from' => 'noreply@contoh.test'],
            $this->logger,
        );
        $views = new Template(dirname(__DIR__, 2) . '/app/core/Auth/views', $this->dir . '/views');
        $admin = new AdminController(
            $manager, $this->users(), new RoleStore($this->conn), $this->tokens(), new Mailer($this->mail, $this->logger),
            $this->deferred, $session, $csrf, $views,
            new Template(dirname(__DIR__, 2) . '/app/core/Core/views', $this->dir . '/views'),
            new Authorizer(), static fn(): array => [],
            ['appUrl' => 'https://app.contoh.test', 'from' => 'noreply@contoh.test'], $this->logger,
        );
        $kit = new AuthKit($session, $jar, $csrf, $manager, $remember, $driver, $this->deferred, $admin);
        $router = new Router();
        $driver->registerRoutes($router);
        $admin->registerRoutes($router);
        if ($this->extraRoutes !== null) {
            ($this->extraRoutes)($router, $kit);
        }
        return [new Kernel($router, $kit->middleware($router, [], true), $this->logger), $kit, $jar];
    }

    public function browser(string $ip = '203.0.113.7'): AuthBrowser
    {
        return new AuthBrowser($this, $ip);
    }

    public function dispatch(Request $r, array $cookies): Response
    {
        [$kernel] = $this->wire($cookies);
        return $kernel->handle($r);
    }
}
