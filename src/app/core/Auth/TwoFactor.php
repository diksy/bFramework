<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Clock;

/**
 * Pendaftaran dan verifikasi TOTP + kode pemulihan. Secret terenkripsi (SecretVault, kunci turunan
 * APP_KEY); kode pemulihan hanya disimpan sebagai HMAC. Anti replay: langkah TOTP yang sudah
 * dipakai tidak bisa dipakai lagi (UPDATE atomik totp_last_step < langkah).
 */
final class TwoFactor
{
    private const CTX_SECRET = 'totp-secret';
    private const CTX_RECOVERY = 'totp-recovery';
    public const RECOVERY_COUNT = 10;

    public function __construct(
        private readonly AccountStore $accounts,
        private readonly SecretVault $vault,
        private readonly Clock $clock,
    ) {
    }

    /** Mulai pendaftaran (belum aktif sampai dikonfirmasi). @return string secret base32 untuk ditampilkan sekali */
    public function begin(int $userId): string
    {
        $secret = Totp::generateSecret();
        $this->accounts->updateTotp($userId, [
            'totp_secret' => $this->vault->seal($secret, self::CTX_SECRET),
            'totp_enabled' => 0,
            'totp_last_step' => 0,
            'recovery_codes' => null,
        ]);
        return $secret;
    }

    /** @return list<string>|null kode pemulihan (tampil sekali) bila kode TOTP benar */
    public function confirm(int $userId, string $code): ?array
    {
        $acc = $this->accounts->find($userId);
        $secret = $acc === null || $acc->totpSealed === null ? null : $this->vault->open($acc->totpSealed, self::CTX_SECRET);
        if ($acc === null || $secret === null || $acc->totpEnabled) {
            return null;
        }
        $step = Totp::matchStep($secret, $code, $this->now(), $acc->totpLastStep);
        if ($step === null) {
            return null;
        }
        $plain = [];
        $hashes = [];
        for ($i = 0; $i < self::RECOVERY_COUNT; $i++) {
            $raw = strtolower(substr(Totp::base32Encode(random_bytes(7)), 0, 10));
            $plain[] = substr($raw, 0, 5) . '-' . substr($raw, 5);
            $hashes[] = $this->recoveryHash($raw);
        }
        $this->accounts->updateTotp($userId, [
            'totp_enabled' => 1,
            'totp_last_step' => $step,
            'recovery_codes' => json_encode($hashes, JSON_THROW_ON_ERROR),
        ]);
        return $plain;
    }

    public function disable(int $userId): void
    {
        $this->accounts->updateTotp($userId, ['totp_enabled' => 0, 'totp_secret' => null, 'totp_last_step' => null, 'recovery_codes' => null]);
    }

    /** Kode 6 digit TOTP atau kode pemulihan. true bila sah (dan langsung terpakai). */
    public function verifyLogin(Account $acc, string $input): bool
    {
        if (!$acc->totpEnabled || $acc->totpSealed === null) {
            return false;
        }
        $compact = str_replace([' ', '-'], '', $input);
        if (preg_match('/^[0-9]{6}$/D', $compact) === 1) {
            $secret = $this->vault->open($acc->totpSealed, self::CTX_SECRET);
            if ($secret === null) {
                return false;
            }
            $step = Totp::matchStep($secret, $compact, $this->now(), $acc->totpLastStep);
            return $step !== null && $this->accounts->advanceTotpStep($acc->id, $step);
        }
        return $this->useRecovery($acc, $compact);
    }

    private function useRecovery(Account $acc, string $compact): bool
    {
        $norm = strtolower($compact);
        if (preg_match('/^[a-z2-7]{10}$/D', $norm) !== 1) {
            return false;
        }
        $given = $this->recoveryHash($norm);
        $hit = null;
        foreach ($acc->recoveryHashes as $i => $h) {
            if (hash_equals($h, $given)) {
                $hit = $i;
            }
        }
        if ($hit === null) {
            return false;
        }
        $left = $acc->recoveryHashes;
        unset($left[$hit]);
        $old = json_encode($acc->recoveryHashes, JSON_THROW_ON_ERROR);
        return $this->accounts->swapRecovery($acc->id, $old, json_encode(array_values($left), JSON_THROW_ON_ERROR));
    }

    /** Secret polos untuk menampilkan ulang saat pendaftaran belum selesai. */
    public function pendingSecret(Account $acc): ?string
    {
        return $acc->totpEnabled || $acc->totpSealed === null ? null : $this->vault->open($acc->totpSealed, self::CTX_SECRET);
    }

    private function recoveryHash(string $normalized): string
    {
        return $this->vault->mac($normalized, self::CTX_RECOVERY);
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }
}
