<?php

declare(strict_types=1);

namespace bFramework\Tests\Fixtures;

use bFramework\Core\HttpClient;
use bFramework\Core\HttpResponse;
use bFramework\Core\Transport;
use bFramework\Sso\JwtLibrary;
use Firebase\JWT\JWT;

/**
 * IdP palsu untuk tes SSO: Transport pengganti jaringan (discovery, JWKS, token, introspect) + penanda tangan
 * token dengan kunci RSA uji yang dibangkitkan saat tes. Hanya data dummy; tidak ada koneksi nyata.
 */
final class FakeIdp implements Transport
{
    public const ISSUER = 'https://sso.contoh.test';
    public const CLIENT_ID = 'app-contoh';
    public const SECRET = 'rahasia-klien-dummy-untuk-tes';

    /** @var array<string,array{pem:string,jwk:array<string,string>}> */
    private array $keys = [];
    public string $activeKid = 'kid-1';
    /** @var list<string> kid yang dipublikasikan di JWKS */
    public array $published = ['kid-1'];
    /** @var array<string,int> */
    public array $hits = ['discovery' => 0, 'jwks' => 0, 'token' => 0, 'introspect' => 0];
    /** @var list<array{method:string,path:string,headers:array<string,string>,body:?string}> */
    public array $calls = [];
    /** @var list<array{int,array<string,mixed>}> antrean jawaban token endpoint */
    public array $tokenQueue = [];
    public bool $introspectActive = true;
    public string $cacheControl = 'max-age=3600';
    /** @var array<string,mixed> */
    public array $discoveryOverride = [];
    public string $ip = '93.184.216.34';

    public function __construct(public \bFramework\Tests\Fixtures\FakeClock $clock)
    {
        JwtLibrary::load();
        $this->addKey('kid-1');
    }

    public function addKey(string $kid): void
    {
        $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        if ($res === false) {
            throw new \RuntimeException('openssl gagal');
        }
        openssl_pkey_export($res, $pem);
        $d = openssl_pkey_get_details($res);
        if ($d === false) {
            throw new \RuntimeException('openssl gagal');
        }
        $b = static fn(string $x): string => rtrim(strtr(base64_encode($x), '+/', '-_'), '=');
        $this->keys[$kid] = ['pem' => (string) $pem, 'pub' => $d['key'], 'jwk' => [
            'kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256', 'n' => $b($d['rsa']['n']), 'e' => $b($d['rsa']['e']),
        ]];
    }

    public function publicPem(string $kid = 'kid-1'): string
    {
        return $this->keys[$kid]['pub'];
    }

    public function http(): HttpClient
    {
        $ip = $this->ip;
        return new HttpClient(null, $this, 1048576, [], [443], static fn(string $h): array => [$ip]);
    }

    /** @return array<string,mixed> */
    public function discoveryDoc(): array
    {
        return $this->discoveryOverride + [
            'issuer' => self::ISSUER,
            'authorization_endpoint' => self::ISSUER . '/oauth2/auth',
            'token_endpoint' => self::ISSUER . '/oauth2/tok',
            'jwks_uri' => self::ISSUER . '/keys/set.json',
            'end_session_endpoint' => self::ISSUER . '/oauth2/bye',
            'introspection_endpoint' => self::ISSUER . '/oauth2/check',
            'id_token_signing_alg_values_supported' => ['RS256'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic'],
        ];
    }

    public function send(string $method, string $host, int $port, string $ip, string $pathAndQuery, array $headers, ?string $body, int $timeout, int $maxBytes): HttpResponse
    {
        $path = strtok($pathAndQuery, '?') ?: '/';
        $this->calls[] = ['method' => $method, 'path' => $path, 'headers' => $headers, 'body' => $body];
        $h = ['content-type' => 'application/json', 'cache-control' => $this->cacheControl];
        switch ($path) {
            case '/.well-known/openid-configuration':
                $this->hits['discovery']++;
                return new HttpResponse(200, $h, json_encode($this->discoveryDoc(), JSON_THROW_ON_ERROR));
            case '/keys/set.json':
                $this->hits['jwks']++;
                $keys = array_map(fn(string $k): array => $this->keys[$k]['jwk'], $this->published);
                return new HttpResponse(200, $h, json_encode(['keys' => $keys], JSON_THROW_ON_ERROR));
            case '/oauth2/tok':
                $this->hits['token']++;
                [$st, $j] = array_shift($this->tokenQueue) ?? [400, ['error' => 'invalid_grant']];
                return new HttpResponse($st, $h, json_encode($j, JSON_THROW_ON_ERROR));
            case '/oauth2/check':
                $this->hits['introspect']++;
                return new HttpResponse(200, $h, json_encode(['active' => $this->introspectActive], JSON_THROW_ON_ERROR));
        }
        return new HttpResponse(404, $h, '{}');
    }

    /**
     * @param array<string,mixed> $over claim yang menimpa/ditambah; nilai null = hapus claim
     * @return array<string,mixed>
     */
    public function claims(array $over = []): array
    {
        $now = $this->clock->t;
        $c = array_replace([
            'iss' => self::ISSUER, 'aud' => self::CLIENT_ID, 'sub' => 'sub-001', 'sid' => 'sid-001',
            'iat' => $now, 'exp' => $now + 300, 'email' => 'budi@contoh.test', 'email_verified' => true, 'name' => 'Budi Dummy',
        ], $over);
        return array_filter($c, static fn($v): bool => $v !== null);
    }

    /** @param array<string,mixed> $claims */
    public function sign(array $claims, ?string $kid = null): string
    {
        $kid ??= $this->activeKid;
        return JWT::encode($claims, $this->keys[$kid]['pem'], 'RS256', $kid);
    }

    /** @param array<string,mixed> $over */
    public function idToken(string $nonce, array $over = []): string
    {
        return $this->sign($this->claims(['nonce' => $nonce] + $over));
    }

    /** @param array<string,mixed> $over */
    public function logoutToken(array $over = []): string
    {
        $now = $this->clock->t;
        $base = [
            'iss' => self::ISSUER, 'aud' => self::CLIENT_ID, 'sub' => 'sub-001', 'sid' => 'sid-001', 'iat' => $now,
            'jti' => bin2hex(random_bytes(8)), 'events' => ['http://schemas.openid.net/event/backchannel-logout' => new \stdClass()],
        ];
        $c = array_filter(array_replace($base, $over), static fn($v): bool => $v !== null);
        return $this->sign($c);
    }

    /** Token palsu: header dikendalikan penuh (alg none / HS256 / RS384 dst). */
    public function forge(string $alg, array $claims, string $secret = ''): string
    {
        $b = static fn(string $x): string => rtrim(strtr(base64_encode($x), '+/', '-_'), '=');
        $head = $b((string) json_encode(['alg' => $alg, 'typ' => 'JWT', 'kid' => $this->activeKid]));
        $body = $b((string) json_encode($claims));
        if ($alg === 'none') {
            return $head . '.' . $body . '.';
        }
        if ($alg === 'HS256') {
            return $head . '.' . $body . '.' . $b(hash_hmac('sha256', $head . '.' . $body, $secret, true));
        }
        return $head . '.' . $body . '.' . $b('sigpalsu');
    }
}
