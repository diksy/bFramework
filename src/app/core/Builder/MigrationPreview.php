<?php

declare(strict_types=1);

namespace bFramework\Builder;

defined('APP_BOOTED') || exit;

use bFramework\Runtime\Definitions;
use bFramework\Runtime\Grammar;
use bFramework\Runtime\MigrationPlan;

/** Pratinjau migrasi (BLD-08) dari Grammar M3: SQL + lossWarnings. Tidak menyentuh database. */
final class MigrationPreview
{
    /**
     * @param ?array<string,mixed> $oldModel model ter-compile yang aktif (null = model baru -> CREATE)
     * @param array<string,mixed> $newModel hasil DefinitionSchema::model()
     */
    public static function for(?array $oldModel, array $newModel, Grammar $g): MigrationPlan
    {
        $new = Definitions::tableSpec($newModel);
        if ($oldModel === null) {
            return new MigrationPlan($g->createTable($new));
        }
        $old = Definitions::tableSpec($oldModel);
        return new MigrationPlan($g->alter($old, $new), $g->lossWarnings($old, $new));
    }
}
