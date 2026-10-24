<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

/** Parser header Cookie (Request tidak menyimpan cookie). Nama ganda: yang pertama menang. */
final class Cookies
{
    /** @return array<string,string> */
    public static function parse(string $header): array
    {
        $out = [];
        foreach (explode(';', $header) as $pair) {
            $pair = trim($pair);
            $eq = strpos($pair, '=');
            if ($eq === false || $eq === 0) {
                continue;
            }
            $name = substr($pair, 0, $eq);
            if (preg_match('/^[A-Za-z0-9_.-]{1,64}$/D', $name) !== 1 || isset($out[$name])) {
                continue;
            }
            $out[$name] = substr($pair, $eq + 1, 512);
        }
        return $out;
    }
}
