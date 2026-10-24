<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

/**
 * Penyamaran rahasia sebelum masuk log (SEC-LOG-02): nilai pada kunci sensitif
 * (password, token, secret, kode, cookie, Authorization, kunci) dan pola token di dalam string.
 */
final class Redactor
{
    public const MASK = '[REDAKSI]';

    private const MAX_STRING = 1000;

    private const KEY_PATTERN = '/pass|pwd|secret|token|cookie|authori[sz]|api[_-]?key|app[_-]?key|private|kunci|otp|csrf|session|sid$|(^|[_-])key$|(^|[_-])code$|signature/i';

    /** @var list<array{0:string,1:string}> pola => pengganti */
    private const VALUE_RULES = [
        ['/\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+\/=-]+/i', '$1 [REDAKSI]'],
        ['/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/', '[REDAKSI]'],
        ['/(\w*(?:pass|pwd|secret|token|code|kunci|key|cookie|session|sid|authorization)\w*\s*[=:]\s*)[^\s&;,"\'<>]+/i', '$1[REDAKSI]'],
        ['/\b[A-Fa-f0-9]{40,}\b/', '[REDAKSI]'],
    ];

    /**
     * @param array<array-key,mixed> $data
     * @return array<array-key,mixed>
     */
    public static function clean(array $data): array
    {
        $out = [];
        foreach ($data as $k => $v) {
            if (is_string($k) && preg_match(self::KEY_PATTERN, $k) === 1) {
                $out[$k] = self::MASK;
                continue;
            }
            if (is_array($v)) {
                $out[$k] = self::clean($v);
            } elseif (is_string($v)) {
                $out[$k] = self::message($v);
            } elseif (is_int($v) || is_float($v) || is_bool($v) || $v === null) {
                $out[$k] = $v;
            }
            // Objek dan resource tidak dicatat.
        }
        return $out;
    }

    /** Menyamarkan pola token dalam teks lalu memotong panjangnya. */
    public static function message(string $text): string
    {
        $out = $text;
        foreach (self::VALUE_RULES as [$pattern, $replace]) {
            $result = preg_replace($pattern, $replace, $out);
            if ($result === null) {
                return self::MASK;
            }
            $out = $result;
        }
        if (strlen($out) > self::MAX_STRING) {
            $out = substr($out, 0, self::MAX_STRING) . '...';
        }
        return $out;
    }
}
