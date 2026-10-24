<?php

declare(strict_types=1);

namespace bFramework\Tests\Fixtures;

use bFramework\Contracts\SessionStore;

/** Fake in-memory sampai FileSessionStore (M7) siap. */
final class ArraySessionStore implements SessionStore
{
    /** @var array<string,mixed> */
    private array $data = [];
    /** @var list<array{type:string,msg:string}> */
    private array $flash = [];
    private string $id = '';

    public function start(): void
    {
        if ($this->id === '') {
            $this->id = bin2hex(random_bytes(16));
        }
    }

    public function id(): string
    {
        return $this->id;
    }

    public function get(string $k, mixed $d = null): mixed
    {
        return $this->data[$k] ?? $d;
    }

    public function set(string $k, mixed $v): void
    {
        $this->data[$k] = $v;
    }

    public function forget(string $k): void
    {
        unset($this->data[$k]);
    }

    public function regenerate(): void
    {
        $this->id = bin2hex(random_bytes(16));
    }

    public function destroy(): void
    {
        $this->data = [];
        $this->flash = [];
        $this->id = '';
    }

    public function flash(string $type, string $msg): void
    {
        $this->flash[] = ['type' => $type, 'msg' => $msg];
    }

    public function pullFlash(): array
    {
        $f = $this->flash;
        $this->flash = [];
        return $f;
    }
}
