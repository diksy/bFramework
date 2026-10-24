<?php

declare(strict_types=1);

namespace bFramework\Tests\Sso;

use bFramework\Sso\JwtInvalid;
use bFramework\Sso\JwtLibrary;
use bFramework\Sso\UnknownKid;
use bFramework\Tests\Fixtures\FakeIdp;
use bFramework\Tests\Fixtures\SsoBrowser;
use bFramework\Tests\Fixtures\SsoHarness;
use PHPUnit\Framework\TestCase;

final class TokenSecurityTest extends TestCase
{
    private SsoHarness $h;

    protected function setUp(): void
    {
        $this->h = new SsoHarness();
    }

    /** Callback dengan id_token buatan; kembalikan status callback. */
    private function callbackWith(callable $mk, ?SsoBrowser $b = null): int
    {
        $b ??= $this->h->browser();
        $p = $b->start()['params'];
        $this->h->idp->tokenQueue[] = [200, ['access_token' => 'a', 'expires_in' => 60, 'id_token' => $mk($p['nonce'])]];
        $res = $b->get('/auth/sso/callback?code=k&state=' . $p['state']);
        self::assertFalse($b->loggedIn() && $res->status >= 400, 'tidak boleh login saat token ditolak');
        return $res->status;
    }

    public function test_SSO_05_library_di_vendor_proyek_tanpa_composer(): void
    {
        JwtLibrary::load();
        $f = (new \ReflectionClass(\Firebase\JWT\JWT::class))->getFileName();
        self::assertNotFalse($f);
        self::assertStringContainsString('/app/core/vendor/firebase-php-jwt/', $f);
        self::assertStringNotContainsString('/vendor/firebase/', $f);
        self::assertFileExists(JwtLibrary::dir() . '/LICENSE');
    }

    public function test_SSO_06_token_valid_diterima_sebagai_pembanding(): void
    {
        self::assertSame(302, $this->callbackWith(fn(string $n): string => $this->h->idp->idToken($n)));
    }

    public function test_SSO_06_alg_none_ditolak(): void
    {
        $idp = $this->h->idp;
        self::assertSame(400, $this->callbackWith(fn(string $n): string => $idp->forge('none', $idp->claims(['nonce' => $n]))));
        self::assertSame(0, (int) $this->h->a->conn->pdo()->query('SELECT COUNT(*) FROM users')->fetchColumn());
    }

    public function test_SSO_06_HS256_dan_algorithm_confusion_ditolak(): void
    {
        $idp = $this->h->idp;
        // Penyerang menandatangani HS256 memakai kunci PUBLIK RSA sebagai secret HMAC.
        self::assertSame(400, $this->callbackWith(fn(string $n): string => $idp->forge('HS256', $idp->claims(['nonce' => $n]), $idp->publicPem())));
        self::assertSame(400, $this->callbackWith(fn(string $n): string => $idp->forge('HS256', $idp->claims(['nonce' => $n]), 'secret'), $this->h->browser('198.51.100.2')));
        self::assertSame(400, $this->callbackWith(fn(string $n): string => $idp->forge('RS384', $idp->claims(['nonce' => $n])), $this->h->browser('198.51.100.3')));
    }

    public function test_SSO_06_tanda_tangan_dari_kunci_lain_ditolak(): void
    {
        $idp = $this->h->idp;
        $idp->addKey('kid-penyerang');
        // kid sama dengan kunci sah, tetapi ditandatangani kunci penyerang.
        $forged = fn(string $n): string => \Firebase\JWT\JWT::encode(
            $idp->claims(['nonce' => $n]),
            (string) (function () {
                $r = openssl_pkey_new(['private_key_bits' => 2048]);
                openssl_pkey_export($r, $pem);
                return $pem;
            })(),
            'RS256',
            'kid-1',
        );
        self::assertSame(400, $this->callbackWith($forged));
    }

    public function test_SSO_04_iss_dan_aud_salah_ditolak(): void
    {
        $idp = $this->h->idp;
        foreach ([
            ['iss' => 'https://sso-jahat.test'], ['iss' => FakeIdp::ISSUER . '/'], ['aud' => 'app-orang-lain'],
            ['aud' => [FakeIdp::CLIENT_ID, 'lain']], ['azp' => 'lain'],
        ] as $i => $over) {
            self::assertSame(400, $this->callbackWith(fn(string $n): string => $idp->idToken($n, $over), $this->h->browser('198.51.100.' . $i)), json_encode($over) ?: '');
        }
        // aud ganda dengan azp yang benar diperbolehkan.
        self::assertSame(302, $this->callbackWith(fn(string $n): string => $idp->idToken($n, ['aud' => [FakeIdp::CLIENT_ID, 'lain'], 'azp' => FakeIdp::CLIENT_ID]), $this->h->browser('198.51.100.50')));
    }

    public function test_SSO_06_token_kedaluwarsa_belum_berlaku_dan_iat_masa_depan_ditolak(): void
    {
        $idp = $this->h->idp;
        $t = $idp->clock->t;
        foreach ([
            'exp lampau' => ['exp' => $t - 600],
            'exp tepat batas skew' => ['exp' => $t - 60],
            'nbf masa depan' => ['nbf' => $t + 600],
            'iat masa depan' => ['iat' => $t + 600],
            'tanpa exp' => ['exp' => null],
            'tanpa sub' => ['sub' => null],
            'tanpa nonce' => ['nonce' => null],
        ] as $name => $over) {
            $ip = '198.51.100.' . (10 + count(explode(' ', $name)) + strlen($name));
            self::assertSame(400, $this->callbackWith(fn(string $n): string => $idp->sign($idp->claims(array_replace(['nonce' => $n], $over))), $this->h->browser($ip)), $name);
        }
        // Dalam skew kecil masih diterima.
        self::assertSame(302, $this->callbackWith(fn(string $n): string => $idp->idToken($n, ['exp' => $t - 30]), $this->h->browser('198.51.100.200')));
    }

    public function test_SSO_07_kid_asing_berulang_hanya_satu_fetch_jwks(): void
    {
        $idp = $this->h->idp;
        $oidc = $this->h->oidc();
        $idp->addKey('kid-asing');
        $tok = $idp->sign($idp->claims(), 'kid-asing'); // kid tidak dipublikasikan di JWKS
        $oidc->verifyToken($idp->sign($idp->claims())); // mengisi cache JWKS (1 fetch)
        self::assertSame(1, $idp->hits['jwks']);
        for ($i = 0; $i < 100; $i++) {
            try {
                $oidc->verifyToken($tok);
                self::fail('harus ditolak');
            } catch (UnknownKid) {
            }
        }
        self::assertSame(2, $idp->hits['jwks'], 'seratus token kid asing hanya memicu satu fetch tambahan');
        // Setelah semenit, satu fetch lagi diizinkan; bila kini kid dipublikasikan, token diterima.
        $idp->clock->advance(61);
        $idp->published[] = 'kid-asing';
        $idp->cacheControl = 'max-age=3600';
        self::assertSame('sub-001', $this->h->oidc()->verifyToken($idp->sign($idp->claims(['iat' => $idp->clock->t, 'exp' => $idp->clock->t + 300]), 'kid-asing'))['sub']);
        self::assertSame(3, $idp->hits['jwks']);
    }

    public function test_SSO_07_cache_discovery_dan_jwks_mengikuti_cache_control(): void
    {
        $idp = $this->h->idp;
        $idp->cacheControl = 'public, max-age=120';
        $oidc = $this->h->oidc();
        $oidc->verifyToken($idp->sign($idp->claims()));
        $oidc->authorizationUrl('s', 'n', 'c');
        $idp->clock->advance(100);
        $c2 = $idp->claims(['iat' => $idp->clock->t, 'exp' => $idp->clock->t + 300]);
        $this->h->oidc()->verifyToken($idp->sign($c2));
        self::assertSame(1, $idp->hits['jwks']);
        self::assertSame(1, $idp->hits['discovery']);
        $idp->clock->advance(30); // total 130 dt > 120
        $c3 = $idp->claims(['iat' => $idp->clock->t, 'exp' => $idp->clock->t + 300]);
        $this->h->oidc()->verifyToken($idp->sign($c3));
        self::assertSame(2, $idp->hits['jwks']);
        self::assertSame(2, $idp->hits['discovery']);
    }

    public function test_SSO_07_no_store_selalu_fetch_ulang_dan_cache_bukan_php(): void
    {
        $idp = $this->h->idp;
        $idp->cacheControl = 'no-store';
        $this->h->oidc()->verifyToken($idp->sign($idp->claims()));
        $this->h->oidc()->verifyToken($idp->sign($idp->claims()));
        self::assertSame(2, $idp->hits['jwks']);
        foreach (glob($this->h->a->dir . '/sso/*') ?: [] as $f) {
            self::assertStringEndsNotWith('.php', $f);
            self::assertSame(0600, fileperms($f) & 0777, $f);
        }
    }

    public function test_SSO_06_verifier_menolak_tanpa_kid_dan_token_terlalu_besar(): void
    {
        $v = new \bFramework\Sso\FirebaseJwtVerifier();
        $jwks = ['keys' => []];
        $b = static fn(string $x): string => rtrim(strtr(base64_encode($x), '+/', '-_'), '=');
        $noKid = $b('{"alg":"RS256"}') . '.' . $b('{}') . '.' . $b('x');
        foreach ([$noKid, str_repeat('a', 20000)] as $bad) {
            try {
                $v->verify($bad, $jwks, 1, 0);
                self::fail('harus ditolak');
            } catch (JwtInvalid $e) {
                self::assertNotInstanceOf(UnknownKid::class, $e);
            }
        }
    }

    public function test_SSO_06_jwks_hanya_kunci_rsa_sig_yang_dipakai(): void
    {
        $idp = $this->h->idp;
        $idp->discoveryOverride = [];
        $rows = ['keys' => [
            ['kty' => 'oct', 'kid' => 'x', 'k' => 'AAAA'], ['kty' => 'RSA', 'kid' => 'y', 'alg' => 'RS384', 'n' => 'AQAB', 'e' => 'AQAB'],
            ['kty' => 'RSA', 'kid' => 'z', 'use' => 'enc', 'n' => 'AQAB', 'e' => 'AQAB'],
        ]];
        $v = new \bFramework\Sso\FirebaseJwtVerifier();
        $b = static fn(string $x): string => rtrim(strtr(base64_encode($x), '+/', '-_'), '=');
        foreach (['x', 'y', 'z'] as $kid) {
            $tok = $b((string) json_encode(['alg' => 'RS256', 'kid' => $kid])) . '.' . $b('{}') . '.' . $b('s');
            try {
                $v->verify($tok, $rows, 1, 0);
                self::fail('harus ditolak');
            } catch (JwtInvalid $e) {
                self::assertNotInstanceOf(UnknownKid::class, $e, $kid);
            }
        }
    }
}
