<?php

declare(strict_types=1);

namespace bFramework\Contracts;

defined('APP_BOOTED') || exit;

enum Dialect: string
{
    case MySql = 'mysql';
    case Sqlite = 'sqlite';
}
