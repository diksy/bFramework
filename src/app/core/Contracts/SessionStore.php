<?php

declare(strict_types=1);

namespace bFramework\Contracts;

defined('APP_BOOTED') || exit;

interface SessionStore
{
    public function start(): void;

    public function id(): string;

    public function get(string $k, mixed $d = null): mixed;

    public function set(string $k, mixed $v): void;

    public function forget(string $k): void;

    public function regenerate(): void;

    public function destroy(): void;

    public function flash(string $type, string $msg): void;

    /** @return list<array{type:string,msg:string}> */
    public function pullFlash(): array;
}
