<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

final readonly class Sort
{
    public bool $desc;

    public function __construct(public string $column, string $dir = 'asc')
    {
        $d = strtolower($dir);
        if ($d !== 'asc' && $d !== 'desc') {
            throw new \InvalidArgumentException('Arah urut harus asc/desc');
        }
        $this->desc = $d === 'desc';
    }
}
