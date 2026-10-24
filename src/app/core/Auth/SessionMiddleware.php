<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\SessionStore;
use bFramework\Core\Middleware;
use bFramework\Core\Request;
use bFramework\Core\Response;

/**
 * Memulai sesi, memasang cookie sesi ke Response (SEC-SESS-03), dan memicu gc() secara probabilistik
 * (default 1%). Cookie dikirim juga pada respons error/redirect karena dipasang setelah rantai kembali.
 */
final class SessionMiddleware implements Middleware
{
    /** @var (callable():mixed)|null */
    private $gc;
    /** @var callable():int */
    private $dice;

    /**
     * @param (callable():mixed)|null $gc mis. FileSessionStore::gc(...)
     * @param (callable():int)|null $dice mengembalikan 1..$gcOdds; gc dijalankan bila hasil = 1 (disuntik untuk tes)
     */
    public function __construct(
        private readonly SessionStore $session,
        private readonly CookieJar $jar,
        ?callable $gc = null,
        int $gcOdds = 100,
        ?callable $dice = null,
    ) {
        $this->gc = $gc;
        $odds = max(1, $gcOdds);
        $this->dice = $dice ?? static fn(): int => random_int(1, $odds);
    }

    public function process(Request $r, callable $next): Response
    {
        $this->session->start();
        $res = $next($r);
        $res = $this->jar->applyTo($res);
        if ($this->gc !== null && ($this->dice)() === 1) {
            ($this->gc)();
        }
        return $res;
    }
}
