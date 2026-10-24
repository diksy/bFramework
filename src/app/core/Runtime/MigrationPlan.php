<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

final readonly class MigrationPlan
{
    /**
     * @param list<string> $sql
     * @param list<string> $lossWarnings
     */
    public function __construct(public array $sql, public array $lossWarnings = [])
    {
    }
}
