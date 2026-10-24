<?php

declare(strict_types=1);

namespace bFramework\Builder;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Clock;
use bFramework\Contracts\Forbidden;
use bFramework\Contracts\Identity;
use bFramework\Contracts\Logger;
use bFramework\Contracts\NotFound;
use bFramework\Contracts\SessionStore;
use bFramework\Contracts\TooManyRequests;
use bFramework\Core\RateLimiter;
use bFramework\Core\Request;
use bFramework\Core\Response;
use Closure;

/**
 * SEC-BLD-01: gerbang `/_builder`. Mode dev (satu sumber: Config::devMode() dari pemanggil) = terbuka bagi admin
 * login. Produksi = 404 kecuali `unsafeBuilderInProduction` DAN whitelist IP DAN hash kata sandi builder terisi;
 * lalu wajib: IP di whitelist, Identity admin, dan login builder terpisah (kata sandi sendiri, terikat ke user,
 * kedaluwarsa). Selain itu selalu 404 (tidak membocorkan keberadaan). Tanpa Identity admin tidak ada akses.
 */
final class BuilderGate
{
    public const SESSION_KEY = '_builder_auth';

    /**
     * @param array{unsafeBuilderInProduction?:bool,allowedIps?:list<string>,passwordHash?:string,loginTtl?:int,rateMax?:int,rateWindow?:int} $opts
     * @param Closure():?Identity $identity
     */
    public function __construct(
        private readonly bool $devMode,
        private readonly array $opts,
        private readonly SessionStore $session,
        private readonly Closure $identity,
        private readonly RateLimiter $limiter,
        private readonly Clock $clock,
        private readonly ?Logger $logger = null,
    ) {
    }

    public function isDev(): bool
    {
        return $this->devMode;
    }

    /** Boleh dipasang rutenya? Produksi default = false. */
    public function enabled(): bool
    {
        if ($this->devMode) {
            return true;
        }
        $hash = $this->opts['passwordHash'] ?? '';
        return ($this->opts['unsafeBuilderInProduction'] ?? false) === true
            && $this->ips() !== []
            && is_string($hash) && $hash !== '' && (password_get_info($hash)['algo'] ?? null) !== null;
    }

    /**
     * @param bool $needLogin false untuk halaman/aksi login builder itu sendiri
     * @return Identity|Response Response = alihkan/401 (belum login); pengecualian = 404/403
     */
    public function authorize(Request $r, bool $api, bool $needLogin = true): Identity|Response
    {
        if (!$this->enabled()) {
            throw new NotFound();
        }
        if (!$this->devMode && !$this->ipAllowed($r->remoteAddr)) {
            $this->logger?->warning('Builder produksi: IP di luar whitelist');
            throw new NotFound();
        }
        $who = ($this->identity)();
        if ($who === null) {
            if (!$this->devMode) {
                throw new NotFound();
            }
            return $api ? self::deny(401, 'Belum masuk.', 'login') : Response::redirect('/login');
        }
        if ($who->activeRole !== 'admin') {
            if (!$this->devMode) {
                throw new NotFound();
            }
            throw new Forbidden('Builder hanya untuk peran admin');
        }
        if (!$this->devMode && $needLogin && !$this->loggedIn($who)) {
            return $api ? self::deny(401, 'Login builder diperlukan.', 'builder_login') : Response::redirect('/_builder/login');
        }
        return $who;
    }

    public function loggedIn(Identity $who): bool
    {
        if ($this->devMode) {
            return true;
        }
        $s = $this->session->get(self::SESSION_KEY);
        return is_array($s) && ($s['uid'] ?? null) === $who->userId && is_int($s['until'] ?? null)
            && $s['until'] > $this->clock->now()->getTimestamp();
    }

    /** Login builder terpisah (produksi). Benar -> sesi dirotasi dan ditandai; salah -> false. */
    public function attemptLogin(Request $r, Identity $who, #[\SensitiveParameter] string $password): bool
    {
        if ($this->devMode) {
            return true;
        }
        $max = max(1, (int) ($this->opts['rateMax'] ?? 5));
        if (!$this->limiter->hit('builderlogin:' . $r->remoteAddr, $max, max(60, (int) ($this->opts['rateWindow'] ?? 900)))) {
            throw new TooManyRequests();
        }
        $hash = $this->opts['passwordHash'] ?? '';
        $ok = is_string($hash) && $hash !== '' && $password !== '' && password_verify($password, $hash);
        if (!$ok) {
            return false;
        }
        $this->session->regenerate();
        $ttl = max(60, min(3600, (int) ($this->opts['loginTtl'] ?? 900)));
        $this->session->set(self::SESSION_KEY, ['uid' => $who->userId, 'until' => $this->clock->now()->getTimestamp() + $ttl]);
        return true;
    }

    public function logout(): void
    {
        $this->session->forget(self::SESSION_KEY);
    }

    public function ipAllowed(string $ip): bool
    {
        $bin = $ip === '' ? false : @inet_pton($ip);
        if ($bin === false) {
            return false;
        }
        foreach ($this->ips() as $entry) {
            [$net, $len] = str_contains($entry, '/') ? explode('/', $entry, 2) + [1 => ''] : [$entry, ''];
            $nb = @inet_pton($net);
            if ($nb === false || strlen($nb) !== strlen($bin)) {
                continue;
            }
            $bits = $len === '' ? strlen($nb) * 8 : (ctype_digit($len) ? (int) $len : -1);
            if ($bits < 0 || $bits > strlen($nb) * 8) {
                continue;
            }
            $full = intdiv($bits, 8);
            if (substr($nb, 0, $full) !== substr($bin, 0, $full)) {
                continue;
            }
            $rest = $bits % 8;
            if ($rest === 0 || ((ord($nb[$full]) ^ ord($bin[$full])) & (0xFF << (8 - $rest)) & 0xFF) === 0) {
                return true;
            }
        }
        return false;
    }

    /** @return list<string> */
    private function ips(): array
    {
        return array_values(array_filter($this->opts['allowedIps'] ?? [], 'is_string'));
    }

    private static function deny(int $status, string $msg, string $code): Response
    {
        return Response::json(['error' => $msg, 'code' => $code], $status)->withHeader('Cache-Control', 'no-store');
    }
}
