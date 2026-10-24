<?php

declare(strict_types=1);

namespace bFramework\Upload;

defined('APP_BOOTED') || exit;

/** Whitelist mime + batas ukuran. Mime aktif/berbahaya (SVG, HTML, XML, skrip) ditolak saat konstruksi (SEC-FILE-02). */
final readonly class UploadPolicy
{
    private const FORBIDDEN = [
        'image/svg+xml', 'text/html', 'application/xhtml+xml', 'text/xml', 'application/xml',
        'application/x-httpd-php', 'text/x-php', 'application/x-php', 'application/javascript',
        'text/javascript', 'application/x-sh', 'application/x-msdownload', 'application/x-executable',
    ];

    /** @param list<string> $mimes */
    public function __construct(public array $mimes, public int $maxBytes)
    {
        if ($mimes === [] || $maxBytes < 1 || $maxBytes > 104857600) {
            throw new \InvalidArgumentException('Kebijakan upload tidak valid');
        }
        foreach ($mimes as $m) {
            if (!is_string($m) || preg_match('#^[a-z0-9.+-]+/[a-z0-9.+-]+$#D', $m) !== 1) {
                throw new \InvalidArgumentException('Mime tidak valid');
            }
            if (in_array($m, self::FORBIDDEN, true) || str_contains($m, 'svg') || str_contains($m, 'php')) {
                throw new \InvalidArgumentException('Mime tidak diizinkan: ' . $m);
            }
        }
    }
}
