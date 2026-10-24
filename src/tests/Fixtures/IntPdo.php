<?php

declare(strict_types=1);

namespace bFramework\Tests\Fixtures;

/** PDO untuk pemeriksaan DB tes integrasi: query() selalu mengembalikan statement (error mode exception). */
final class IntPdo extends \PDO
{
    #[\ReturnTypeWillChange]
    public function query(string $query, ?int $fetchMode = null, mixed ...$fetchModeArgs): \PDOStatement
    {
        $st = $fetchMode === null ? parent::query($query) : parent::query($query, $fetchMode, ...$fetchModeArgs);
        if ($st === false) {
            throw new \RuntimeException('query gagal');
        }
        return $st;
    }
}
