<?php

declare(strict_types=1);

namespace bFramework\Install;

defined('APP_BOOTED') || exit;

/** Input instalasi. Rahasia tidak pernah muncul di var_dump/log; tidak pernah ditampilkan ulang di form. */
final class InstallInput
{
    /** @var list<string> */
    public readonly array $allowedHosts;

    /** @param list<string> $allowedHosts kosong = host dari appUrl */
    public function __construct(
        public readonly string $appUrl,
        public readonly string $adminEmail,
        public readonly string $adminName,
        public readonly string $dbDriver = 'sqlite',
        public readonly string $dbFile = 'app.sqlite',
        public readonly string $dbHost = 'localhost',
        public readonly int $dbPort = 3306,
        public readonly string $dbName = '',
        public readonly string $dbUser = '',
        #[\SensitiveParameter] public readonly string $dbPassword = '',
        public readonly string $mailFrom = '',
        public readonly string $smtpHost = '',
        public readonly int $smtpPort = 587,
        public readonly string $smtpSecure = 'starttls',
        public readonly string $smtpUser = '',
        #[\SensitiveParameter] public readonly string $smtpPassword = '',
        array $allowedHosts = [],
        public readonly bool $registration = false,
        #[\SensitiveParameter] public readonly string $installToken = '',
    ) {
        if ($allowedHosts === []) {
            $p = HostPolicy::parse($appUrl);
            $allowedHosts = $p === null ? [] : [$p['authority']];
        }
        $this->allowedHosts = array_values($allowedHosts);
    }

    public function __debugInfo(): array
    {
        return ['appUrl' => $this->appUrl, 'adminEmail' => $this->adminEmail, 'dbDriver' => $this->dbDriver, 'secrets' => '[disembunyikan]'];
    }
}
