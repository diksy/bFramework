<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use InvalidArgumentException;

/**
 * AUTH-03: Argon2id (parameter OWASP minimum: m=19 MiB, t=2, p=1); fallback bcrypt hanya bila
 * PHP tidak dibangun dengan Argon2id. Hash lama dengan parameter/algoritma berbeda ditandai needsRehash().
 */
class PasswordHasher
{
    /** Hash palsu (password acak yang dibuang) untuk menyamakan waktu saat akun tidak ada. */
    private const DUMMY_ARGON = '$argon2id$v=19$m=19456,t=2,p=1$/bTZpnz2fk7Lq25ZLgSpUA$mocEWDLPAFIU5CCgm/rgl11O4oXCUzDtmJ6jAjKCY1o';
    private const DUMMY_BCRYPT = '$2y$12$YeCRWhgz69YN.B9vChZCP./pimD.f8TBWL79PdZjbgAOIguFLIJhK';
    /** Input lebih panjang dari ini tidak pernah di-hash (cegah DoS lewat password raksasa). */
    private const HARD_MAX_BYTES = 1024;

    /** @var array<string,string> */
    private static array $dummyCache = [];
    private readonly bool $argon;

    public function __construct(
        private readonly int $memoryKib = 19456,
        private readonly int $timeCost = 2,
        private readonly int $threads = 1,
        private readonly int $bcryptCost = 12,
        ?bool $useArgon = null,
    ) {
        if ($memoryKib < 8 || $timeCost < 1 || $threads < 1 || $bcryptCost < 4 || $bcryptCost > 31) {
            throw new InvalidArgumentException('Parameter hash tidak valid');
        }
        $has = defined('PASSWORD_ARGON2ID');
        $this->argon = $useArgon === null ? $has : ($useArgon && $has);
    }

    public function algorithm(): string
    {
        return $this->argon ? 'argon2id' : 'bcrypt';
    }

    /** Batas byte password: bcrypt memotong di 72 byte, jadi ditolak lebih awal. */
    public function maxBytes(): int
    {
        return $this->argon ? 256 : 72;
    }

    public function hash(string $password): string
    {
        if (strlen($password) > self::HARD_MAX_BYTES || str_contains($password, "\0")) {
            throw new InvalidArgumentException('Password tidak valid');
        }
        $h = $this->argon
            ? password_hash($password, PASSWORD_ARGON2ID, $this->argonOptions())
            : password_hash($password, PASSWORD_BCRYPT, ['cost' => $this->bcryptCost]);
        if (!is_string($h)) {
            throw new \RuntimeException('Hash password gagal');
        }
        return $h;
    }

    public function verify(string $password, string $hash): bool
    {
        if (strlen($password) > self::HARD_MAX_BYTES || str_contains($password, "\0") || $hash === '') {
            return false;
        }
        return password_verify($password, $hash);
    }

    public function needsRehash(string $hash): bool
    {
        return $this->argon
            ? password_needs_rehash($hash, PASSWORD_ARGON2ID, $this->argonOptions())
            : password_needs_rehash($hash, PASSWORD_BCRYPT, ['cost' => $this->bcryptCost]);
    }

    /** Hash palsu dengan parameter setara konfigurasi ini (konstanta bila parameter bawaan). */
    public function dummyHash(): string
    {
        if ($this->argon && $this->memoryKib === 19456 && $this->timeCost === 2 && $this->threads === 1) {
            return self::DUMMY_ARGON;
        }
        if (!$this->argon && $this->bcryptCost === 12) {
            return self::DUMMY_BCRYPT;
        }
        $k = $this->algorithm() . '|' . $this->memoryKib . '|' . $this->timeCost . '|' . $this->threads . '|' . $this->bcryptCost;
        return self::$dummyCache[$k] ??= $this->hash(bin2hex(random_bytes(16)));
    }

    /** @return array{memory_cost:int,time_cost:int,threads:int} */
    private function argonOptions(): array
    {
        return ['memory_cost' => $this->memoryKib, 'time_cost' => $this->timeCost, 'threads' => $this->threads];
    }
}
