<?php

declare(strict_types=1);

namespace bFramework\Tests\Sso;

use bFramework\Auth\SecretVault;
use bFramework\Sso\InvalidGrant;
use bFramework\Tests\Fixtures\AuthHarness;
use bFramework\Tests\Fixtures\SsoHarness;
use PHPUnit\Framework\TestCase;

final class RefreshSessionTest extends TestCase
{
    private SsoHarness $h;

    protected function setUp(): void
    {
        $this->h = new SsoHarness();
        $this->h->sso['offline_access'] = true;
    }

    private function sealedOf(int $uid): string
    {
        $st = $this->h->a->conn->pdo()->prepare('SELECT token_sealed FROM sso_refresh_tokens WHERE user_id = ?');
        $st->execute([$uid]);
        return (string) $st->fetchColumn();
    }

    private function uid(): int
    {
        return (int) $this->h->a->users()->findBySsoSub('sub-001')?->id;
    }

    public function test_SSO_13_refresh_token_terenkripsi_dan_nonce_unik(): void
    {
        $b = $this->h->browser();
        $b->login([], ['refresh_token' => 'rt-rahasia-1']);
        $uid = $this->uid();
        $sealed = $this->sealedOf($uid);
        self::assertNotSame('rt-rahasia-1', $sealed);
        self::assertStringNotContainsString('rt-rahasia-1', $sealed);
        self::assertStringStartsWith('v1.', $sealed);
        self::assertSame('rt-rahasia-1', $this->h->vault()->get($uid));
        // Nonce unik: plaintext sama dua kali menghasilkan ciphertext berbeda.
        $v = new SecretVault(AuthHarness::APP_KEY);
        self::assertNotSame($v->seal('x', 'k'), $v->seal('x', 'k'));
        $this->h->vault()->store($uid, 'rt-rahasia-1');
        self::assertNotSame($sealed, $this->sealedOf($uid));
    }

    public function test_SSO_13_kunci_diturunkan_bukan_APP_KEY_mentah_dan_terikat_user(): void
    {
        $b = $this->h->browser();
        $b->login([], ['refresh_token' => 'rt-1']);
        $uid = $this->uid();
        $raw = base64_decode(strtr(substr($this->sealedOf($uid), 3), '-_', '+/'), true);
        self::assertIsString($raw);
        $n = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $box = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $rawKey = substr(hash('sha256', AuthHarness::APP_KEY, true), 0, 32);
        self::assertFalse(sodium_crypto_secretbox_open($box, $n, $rawKey), 'bukan APP_KEY (atau hash polosnya) sebagai kunci');
        // Menyalin ciphertext user lain ke baris user ini tidak bisa dibuka (konteks terikat user).
        $pdo = $this->h->a->conn->pdo();
        $pdo->exec("INSERT INTO sso_refresh_tokens (user_id, token_sealed, version, updated_at) SELECT 9999, token_sealed, 1, 0 FROM sso_refresh_tokens WHERE user_id = $uid");
        self::assertNull($this->h->vault()->get(9999));
    }

    public function test_SSO_11_tanpa_offline_access_refresh_token_tidak_disimpan(): void
    {
        $h = new SsoHarness();
        $h->browser()->login([], ['refresh_token' => 'rt-1']);
        $uid = (int) $h->a->users()->findBySsoSub('sub-001')?->id;
        self::assertNull($h->vault()->get($uid));
    }

    public function test_SSO_12_refresh_paralel_hanya_satu_request(): void
    {
        $b = $this->h->browser();
        $b->login([], ['refresh_token' => 'rt-1']);
        $uid = $this->uid();
        $vault = $this->h->vault();
        $seen = $vault->version($uid);
        self::assertNotNull($seen);
        $calls = 0;
        $do = function (string $t) use (&$calls): array {
            $calls++;
            self::assertSame('rt-1', $t);
            return ['access_token' => 'at-2', 'refresh_token' => 'rt-2'];
        };
        // Dua "request paralel" membaca versi yang sama sebelum salah satunya merotasi.
        $r1 = $vault->refreshOnce($uid, $seen, $do);
        $r2 = $this->h->vault()->refreshOnce($uid, $seen, $do);
        self::assertSame('at-2', $r1['access_token'] ?? null);
        self::assertNull($r2, 'yang kalah balapan tidak mengirim refresh kedua');
        self::assertSame(1, $calls);
        self::assertSame('rt-2', $vault->get($uid), 'rotasi tersimpan');
        self::assertNotSame($seen, $vault->version($uid));
    }

    public function test_SSO_12_invalid_grant_menghapus_token_dan_tidak_diulang(): void
    {
        $b = $this->h->browser();
        $b->login([], ['refresh_token' => 'rt-1']);
        $uid = $this->uid();
        $vault = $this->h->vault();
        $calls = 0;
        try {
            $vault->refreshOnce($uid, (int) $vault->version($uid), function () use (&$calls): array {
                $calls++;
                throw new InvalidGrant('invalid_grant');
            });
            self::fail('harus melempar');
        } catch (InvalidGrant) {
        }
        self::assertSame(1, $calls);
        self::assertNull($vault->get($uid));
    }

    public function test_SSO_12_sesi_end_to_end_refresh_saat_access_token_habis_sekali_saja(): void
    {
        $b = $this->h->browser();
        $b->login([], ['refresh_token' => 'rt-1', 'expires_in' => 60]);
        $this->h->idp->clock->advance(6 * 60); // lewat session_check_minutes dan access token sudah habis
        $this->h->idp->tokenQueue[] = [200, ['access_token' => 'at-2', 'expires_in' => 600, 'refresh_token' => 'rt-2']];
        $before = $this->h->idp->hits['token'];
        self::assertTrue($b->loggedIn());
        self::assertTrue($b->loggedIn(), 'request berikutnya tidak memicu refresh lagi (chk diperbarui)');
        self::assertSame($before + 1, $this->h->idp->hits['token']);
        self::assertSame('rt-2', $this->h->vault()->get($this->uid()));
    }

    public function test_SSO_20_refresh_invalid_grant_mengakhiri_sesi_tanpa_retry(): void
    {
        $b = $this->h->browser();
        $b->login([], ['refresh_token' => 'rt-1', 'expires_in' => 60]);
        $this->h->idp->clock->advance(6 * 60);
        $this->h->idp->tokenQueue[] = [400, ['error' => 'invalid_grant']];
        $before = $this->h->idp->hits['token'];
        self::assertFalse($b->loggedIn());
        self::assertSame($before + 1, $this->h->idp->hits['token']);
        self::assertNull($this->h->vault()->get($this->uid()));
        self::assertFalse($b->loggedIn());
        self::assertSame($before + 1, $this->h->idp->hits['token'], 'tanpa retry otomatis');
    }

    public function test_SSO_18_introspeksi_berkala_mengakhiri_sesi_yang_dicabut_di_SSO(): void
    {
        $b = $this->h->browser();
        $b->login([], ['expires_in' => 3600]);
        self::assertTrue($b->loggedIn());
        self::assertSame(0, $this->h->idp->hits['introspect'], 'belum waktunya');
        $this->h->idp->clock->advance(4 * 60);
        self::assertTrue($b->loggedIn());
        self::assertSame(0, $this->h->idp->hits['introspect']);
        $this->h->idp->clock->advance(2 * 60); // total 6 menit > 5
        $this->h->idp->introspectActive = false;
        self::assertFalse($b->loggedIn(), 'dicabut di SSO -> berakhir di aplikasi');
        self::assertSame(1, $this->h->idp->hits['introspect']);
    }

    public function test_SSO_18_introspeksi_aktif_mempertahankan_sesi_dan_error_jaringan_tidak_mengusir(): void
    {
        $b = $this->h->browser();
        $b->login([], ['expires_in' => 3600]);
        $this->h->idp->clock->advance(6 * 60);
        self::assertTrue($b->loggedIn());
        self::assertSame(1, $this->h->idp->hits['introspect']);
        $this->h->idp->ip = '10.0.0.9'; // IdP tak terjangkau (diblokir SSRF): fail-open, dicatat
        $this->h->idp->clock->advance(6 * 60);
        self::assertTrue($b->loggedIn());
    }
}
