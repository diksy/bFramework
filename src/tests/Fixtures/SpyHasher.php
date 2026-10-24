<?php

declare(strict_types=1);

namespace bFramework\Tests\Fixtures;

use bFramework\Auth\PasswordHasher;

final class SpyHasher extends PasswordHasher
{
    public int $verifies = 0;

    public function verify(string $password, string $hash): bool
    {
        $this->verifies++;
        return parent::verify($password, $hash);
    }
}
