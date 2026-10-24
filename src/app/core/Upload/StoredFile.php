<?php

declare(strict_types=1);

namespace bFramework\Upload;

defined('APP_BOOTED') || exit;

final readonly class StoredFile
{
    /** @param string $id 32 hex acak */
    public function __construct(public string $id, public string $mime, public int $size)
    {
    }
}
