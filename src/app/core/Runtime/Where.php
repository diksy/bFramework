<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

/** Kumpulan kondisi AND: [kolom, operator, nilai]. Operator dari whitelist; nilai hanya via binding. */
final readonly class Where
{
    public const OPS = ['=', '!=', '<', '<=', '>', '>=', 'like', 'in', 'null', 'notnull'];

    /** @param list<array{0:string,1:string,2?:mixed}> $conds */
    public function __construct(public array $conds = [])
    {
        foreach ($conds as $c) {
            if (!in_array($c[1], self::OPS, true)) {
                throw new \InvalidArgumentException('Operator tidak diizinkan');
            }
        }
    }

    public static function none(): self
    {
        return new self();
    }

    public function isEmpty(): bool
    {
        return $this->conds === [];
    }
}
