<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\SessionStore;

/** SEC-REQ-01: token CSRF per sesi, dibandingkan dengan hash_equals. */
final class Csrf
{
    private const KEY = '_csrf';

    public function __construct(private readonly SessionStore $session)
    {
    }

    public function token(): string
    {
        $t = $this->session->get(self::KEY);
        if (!is_string($t) || $t === '') {
            $t = bin2hex(random_bytes(32));
            $this->session->set(self::KEY, $t);
        }
        return $t;
    }

    public function verify(?string $given): bool
    {
        $t = $this->session->get(self::KEY);
        return is_string($t) && $t !== '' && $given !== null && $given !== '' && hash_equals($t, $given);
    }
}
