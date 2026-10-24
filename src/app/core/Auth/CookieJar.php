<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use bFramework\Core\Response;

/** Menampung Set-Cookie dari FileSessionStore (emit) untuk dipasang ke Response oleh SessionMiddleware. */
final class CookieJar
{
    /** @var array<string,array{value:string,options:array<string,mixed>}> */
    private array $items = [];

    /** @param array<string,mixed> $options */
    public function add(string $name, string $value, array $options): void
    {
        $this->items[$name] = ['value' => $value, 'options' => $options];
    }

    public function applyTo(Response $res): Response
    {
        foreach ($this->items as $name => $c) {
            $res = $res->withCookie($name, $c['value'], $c['options']);
        }
        $this->items = [];
        return $res;
    }
}
