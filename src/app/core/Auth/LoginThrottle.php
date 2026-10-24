<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\TooManyRequests;
use bFramework\Core\RateLimiter;

/**
 * SEC-REQ-02: rate limit + lockout bertahap lewat RateLimiter (M2). Tangga per akun: 5/15 menit,
 * 10/jam, 20/hari (semakin banyak percobaan, semakin lama terkunci) dan per IP. Kunci memakai email
 * yang DIKIRIM (ada atau tidak) sehingga perilakunya identik untuk akun nyata dan palsu. Percobaan
 * yang ditolak tidak dicatat, jadi penyerang tidak bisa memperpanjang kunci.
 */
final class LoginThrottle
{
    private const ACCOUNT = [[5, 900], [10, 3600], [20, 86400]];
    private const IP = [[30, 900], [100, 86400]];

    public function __construct(private readonly RateLimiter $limiter)
    {
    }

    /** @throws TooManyRequests */
    public function login(string $emailInput, string $ip): void
    {
        $this->run('login:acct:' . mb_strtolower(trim($emailInput)), self::ACCOUNT);
        $this->run('login:ip:' . $ip, self::IP);
    }

    /** @throws TooManyRequests */
    public function otp(int $userId, string $ip): void
    {
        $this->run('otp:user:' . $userId, [[5, 900], [10, 3600]]);
        $this->run('otp:ip:' . $ip, self::IP);
    }

    /** @throws TooManyRequests */
    public function mail(string $kind, string $emailInput, string $ip): void
    {
        $this->run($kind . ':acct:' . mb_strtolower(trim($emailInput)), [[3, 3600], [6, 86400]]);
        $this->run($kind . ':ip:' . $ip, [[10, 3600], [30, 86400]]);
    }

    /** @throws TooManyRequests */
    public function token(string $ip): void
    {
        $this->run('token:ip:' . $ip, [[10, 900], [40, 86400]]);
    }

    /** @param list<array{0:int,1:int}> $tiers */
    private function run(string $key, array $tiers): void
    {
        foreach ($tiers as $i => [$max, $window]) {
            if (!$this->limiter->hit($key . '#' . $i, $max, $window)) {
                throw new TooManyRequests('Terlalu banyak percobaan');
            }
        }
    }
}
