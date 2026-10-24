<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

use bFramework\Auth\SecretVault;
use bFramework\Contracts\Clock;
use bFramework\Contracts\Logger;
use bFramework\Runtime\Connection;
use bFramework\Runtime\Query;
use bFramework\Runtime\Where;
use RuntimeException;

/**
 * Penyimpanan refresh token (SSO-12/13). Disimpan terenkripsi (sodium secretbox; kunci diturunkan HKDF dari
 * APP_KEY per konteks `sso-refresh|<user>`, nonce acak unik per penyimpanan). Rotasi dikunci per user dengan
 * flock: rotasi BikininSSO mencabut seluruh sesi bila token lama dipakai ulang, jadi request paralel yang kalah
 * balapan TIDAK boleh mengirim refresh kedua.
 */
final class RefreshVault
{
    private readonly Query $q;

    public function __construct(
        Connection $conn,
        private readonly SecretVault $vault,
        private readonly Clock $clock,
        private readonly string $lockDir,
        ?Logger $logger = null,
    ) {
        $this->q = new Query($conn, $conn->grammar(), SsoTables::allowlist(), $logger);
    }

    public function store(int $userId, #[\SensitiveParameter] string $token): void
    {
        $sealed = $this->vault->seal($token, $this->ctx($userId));
        $now = $this->clock->now()->getTimestamp();
        $row = $this->row($userId);
        if ($row === null) {
            try {
                $this->q->insert(SsoTables::REFRESH, ['user_id' => $userId, 'token_sealed' => $sealed, 'version' => 1, 'updated_at' => $now]);
                return;
            } catch (\bFramework\Runtime\DatabaseError) {
                $row = $this->row($userId); // balapan insert: lanjut sebagai update
            }
        }
        $this->q->update(SsoTables::REFRESH, [
            'token_sealed' => $sealed, 'version' => (int) ($row['version'] ?? 0) + 1, 'updated_at' => $now,
        ], new Where([['user_id', '=', $userId]]));
    }

    /** Versi saat ini (untuk refreshOnce); null bila user tidak punya refresh token. */
    public function version(int $userId): ?int
    {
        $r = $this->row($userId);
        return $r === null ? null : (int) $r['version'];
    }

    public function get(int $userId): ?string
    {
        $r = $this->row($userId);
        return $r === null ? null : $this->vault->open((string) $r['token_sealed'], $this->ctx($userId));
    }

    public function delete(int $userId): void
    {
        $this->q->delete(SsoTables::REFRESH, new Where([['user_id', '=', $userId]]));
    }

    /**
     * Jalankan $do(refreshToken) tepat sekali per versi. Di bawah flock per user: bila versi sudah berubah sejak
     * $seenVersion dibaca (request lain sudah merotasi), $do TIDAK dipanggil dan hasilnya null.
     * invalid_grant dari $do menghapus token (sudah mati) dan dilempar ulang tanpa retry.
     *
     * @param callable(string):array<string,mixed> $do harus mengembalikan respons token endpoint
     * @return array<string,mixed>|null
     * @throws InvalidGrant
     */
    public function refreshOnce(int $userId, int $seenVersion, callable $do): ?array
    {
        if (!is_dir($this->lockDir) && !@mkdir($this->lockDir, 0700, true) && !is_dir($this->lockDir)) {
            throw new RuntimeException('Direktori kunci SSO tidak dapat dibuat');
        }
        $fh = fopen($this->lockDir . '/refresh_' . $userId . '.lock', 'c');
        if ($fh === false || !flock($fh, LOCK_EX)) {
            throw new RuntimeException('Kunci refresh SSO gagal');
        }
        try {
            $r = $this->row($userId);
            if ($r === null || (int) $r['version'] !== $seenVersion) {
                return null; // sudah dirotasi request lain (atau dicabut)
            }
            $token = $this->vault->open((string) $r['token_sealed'], $this->ctx($userId));
            if ($token === null) {
                $this->delete($userId);
                return null;
            }
            try {
                $res = $do($token);
            } catch (InvalidGrant $e) {
                $this->delete($userId);
                throw $e;
            }
            $new = $res['refresh_token'] ?? null;
            $this->store($userId, is_string($new) && $new !== '' ? $new : $token);
            return $res;
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }

    /** @return array<string,mixed>|null */
    private function row(int $userId): ?array
    {
        $rows = $this->q->select(SsoTables::REFRESH, ['token_sealed', 'version'], new Where([['user_id', '=', $userId]]), null, 1, 0);
        return $rows[0] ?? null;
    }

    private function ctx(int $userId): string
    {
        return 'sso-refresh|' . $userId;
    }
}
