<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Clock;
use bFramework\Contracts\Logger;
use bFramework\Core\HttpClient;
use bFramework\Core\HttpError;
use bFramework\Core\HttpResponse;

/**
 * Klien OIDC confidential (SSO-02/03/04/07). Semua endpoint berasal dari discovery; semua request lewat
 * HttpClient (TLS wajib, SSRF: IP privat ditolak untuk discovery, JWKS, dan token endpoint). client_secret
 * tidak pernah dicatat/di-cache.
 */
final class OidcClient
{
    private const DISCOVERY = 'discovery';
    private const JWKS = 'jwks';
    private const DEFAULT_TTL = 3600;
    private const MAX_TTL = 86400;
    /** S2: TTL minimum (clamp no-cache/no-store/max-age=0) agar fetch keluar tidak bisa dipicu tiap request. */
    public const MIN_TTL = 60;
    /** S2: negative cache bila fetch gagal. */
    private const NEGATIVE_TTL = 30;
    private const STALE_GRACE = 86400;
    /** SSO-07: refetch JWKS karena kid asing maksimal sekali per menit. */
    private const KID_REFETCH_INTERVAL = 60;
    private const TIMEOUT = 5;

    public function __construct(
        private readonly HttpClient $http,
        private readonly FileCache $cache,
        private readonly Clock $clock,
        private readonly SsoConfig $cfg,
        private readonly JwtVerifier $verifier,
        private readonly ?Logger $logger = null,
    ) {
    }

    // ---------- discovery & JWKS ----------

    /**
     * @return array<string,mixed> dokumen discovery tervalidasi (issuer persis sama, endpoint https)
     * @throws OidcException
     */
    public function discovery(): array
    {
        $c = $this->cache->get(self::DISCOVERY);
        $now = $this->now();
        if ($c !== null && is_array($c['doc'] ?? null) && is_int($c['exp'] ?? null) && $c['exp'] > $now
            && ($c['issuer'] ?? null) === $this->cfg->issuer) {
            /** @var array<string,mixed> $doc */
            $doc = $c['doc'];
            return $doc;
        }
        try {
            $this->assertNotBackedOff(self::DISCOVERY);
            [$doc, $ttl] = self::fetchDiscovery($this->http, $this->cfg->issuer);
        } catch (OidcException $e) {
            $this->markFailed(self::DISCOVERY, $e);
            $stale = $c['doc'] ?? null;
            if (is_array($stale) && is_int($c['exp'] ?? null) && $c['exp'] + self::STALE_GRACE > $now
                && ($c['issuer'] ?? null) === $this->cfg->issuer) {
                $this->logger?->warning('Discovery SSO gagal diambil; memakai cache lama');
                /** @var array<string,mixed> $stale */
                return $stale;
            }
            throw $e;
        }
        $this->cache->put(self::DISCOVERY, ['issuer' => $this->cfg->issuer, 'doc' => $doc, 'exp' => $now + $ttl]);
        return $doc;
    }

    /** @return array<string,mixed> */
    private function jwks(bool $force = false): array
    {
        $c = $this->cache->get(self::JWKS);
        $now = $this->now();
        if (!$force && $c !== null && is_array($c['doc'] ?? null) && is_int($c['exp'] ?? null) && $c['exp'] > $now
            && ($c['issuer'] ?? null) === $this->cfg->issuer) {
            /** @var array<string,mixed> $doc */
            $doc = $c['doc'];
            return $doc;
        }
        $uri = $this->endpoint('jwks_uri');
        try {
            $this->assertNotBackedOff(self::JWKS);
            [$doc, $ttl] = self::fetchJwks($this->http, $uri);
        } catch (OidcException $e) {
            $this->markFailed(self::JWKS, $e);
            $stale = $c['doc'] ?? null;
            if (is_array($stale) && is_int($c['exp'] ?? null) && $c['exp'] + self::STALE_GRACE > $now
                && ($c['issuer'] ?? null) === $this->cfg->issuer) {
                $this->logger?->warning('JWKS SSO gagal diambil; memakai cache lama');
                /** @var array<string,mixed> $stale */
                return $stale;
            }
            throw $e;
        }
        $this->cache->put(self::JWKS, ['issuer' => $this->cfg->issuer, 'doc' => $doc, 'exp' => $now + $ttl]);
        return $doc;
    }

    /** S2: setelah fetch gagal, jangan mencoba lagi selama NEGATIVE_TTL detik. */
    private function assertNotBackedOff(string $what): void
    {
        $n = $this->cache->get('neg_' . $what);
        if ($n !== null && is_int($n['exp'] ?? null) && $n['exp'] > $this->now()) {
            throw new BackedOff('Pengambilan ' . $what . ' ditunda sementara setelah kegagalan.');
        }
    }

    private function markFailed(string $what, OidcException $e): void
    {
        if (!$e instanceof BackedOff) {
            $this->cache->put('neg_' . $what, ['exp' => $this->now() + self::NEGATIVE_TTL]);
        }
    }

    /**
     * Verifikasi tanda tangan + waktu. kid asing memicu satu refetch JWKS (maks. sekali per menit, SSO-07).
     *
     * @return array<string,mixed>
     * @throws JwtInvalid|OidcException
     */
    public function verifyToken(string $jwt): array
    {
        $now = $this->now();
        try {
            return $this->verifier->verify($jwt, $this->jwks(), $now, SsoConfig::SKEW);
        } catch (UnknownKid $e) {
            if (!$this->cache->claim('jwks_kid_refetch', self::KID_REFETCH_INTERVAL)) {
                throw $e;
            }
            return $this->verifier->verify($jwt, $this->jwks(true), $now, SsoConfig::SKEW);
        }
    }

    // ---------- authorize / token ----------

    public function authorizationUrl(string $state, string $nonce, string $codeChallenge): string
    {
        $ep = $this->endpoint('authorization_endpoint');
        $q = http_build_query([
            'response_type' => 'code',
            'client_id' => $this->cfg->clientId,
            'redirect_uri' => $this->cfg->callbackUri,
            'scope' => implode(' ', $this->cfg->scopes),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ], '', '&', PHP_QUERY_RFC3986);
        return $ep . (str_contains($ep, '?') ? '&' : '?') . $q;
    }

    /**
     * @return array<string,mixed> respons token endpoint
     * @throws InvalidGrant|OidcException
     */
    public function exchangeCode(string $code, string $codeVerifier): array
    {
        return $this->tokenRequest([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->cfg->callbackUri,
            'code_verifier' => $codeVerifier,
        ]);
    }

    /**
     * @return array<string,mixed>
     * @throws InvalidGrant|OidcException
     */
    public function refresh(#[\SensitiveParameter] string $refreshToken): array
    {
        return $this->tokenRequest(['grant_type' => 'refresh_token', 'refresh_token' => $refreshToken]);
    }

    /**
     * SSO-18. Null bila IdP tidak punya endpoint introspeksi.
     *
     * @throws OidcException
     */
    public function introspect(#[\SensitiveParameter] string $token, string $hint = 'access_token'): ?bool
    {
        $doc = $this->discovery();
        $ep = $doc['introspection_endpoint'] ?? null;
        if (!is_string($ep)) {
            return null;
        }
        $res = $this->post($ep, ['token' => $token, 'token_type_hint' => $hint]);
        if ($res->status !== 200) {
            throw new OidcException('Introspeksi gagal (HTTP ' . $res->status . ')');
        }
        $j = json_decode($res->body, true);
        if (!is_array($j) || !is_bool($j['active'] ?? null)) {
            throw new OidcException('Respons introspeksi tidak valid');
        }
        return $j['active'];
    }

    /** URL logout SSO (SSO-14) atau null bila IdP tidak punya end_session_endpoint. */
    public function endSessionUrl(?string $idTokenHint): ?string
    {
        $ep = $this->discovery()['end_session_endpoint'] ?? null;
        if (!is_string($ep)) {
            return null;
        }
        $p = ['post_logout_redirect_uri' => $this->cfg->postLogoutUri, 'client_id' => $this->cfg->clientId];
        if ($idTokenHint !== null && $idTokenHint !== '') {
            $p = ['id_token_hint' => $idTokenHint] + $p;
        }
        return $ep . (str_contains($ep, '?') ? '&' : '?') . http_build_query($p, '', '&', PHP_QUERY_RFC3986);
    }

    // ---------- Tes koneksi (SSO-21) ----------

    /**
     * Memeriksa discovery + JWKS untuk issuer tertentu. Tanpa client_secret; semua request lewat HttpClient
     * (SSRF-safe). Pesan error spesifik tetapi tidak memuat URL penuh, header, maupun isi respons.
     *
     * @return array{ok:bool,steps:list<array{name:string,ok:bool,msg:string}>}
     */
    public static function probe(HttpClient $http, string $issuer): array
    {
        $steps = [];
        $ok = true;
        $jwksUri = null;
        if (preg_match('#^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$#D', $issuer) !== 1) {
            return ['ok' => false, 'steps' => [['name' => 'issuer', 'ok' => false, 'msg' => 'Issuer harus berbentuk https://host (tanpa path).']]];
        }
        try {
            [$doc] = self::fetchDiscovery($http, $issuer);
            $steps[] = ['name' => 'discovery', 'ok' => true, 'msg' => 'Discovery valid; issuer cocok persis.'];
            $jwksUri = $doc['jwks_uri'];
        } catch (OidcException $e) {
            $ok = false;
            $steps[] = ['name' => 'discovery', 'ok' => false, 'msg' => $e->getMessage()];
        }
        if (is_string($jwksUri)) {
            try {
                [$jwks] = self::fetchJwks($http, $jwksUri);
                $steps[] = ['name' => 'jwks', 'ok' => true, 'msg' => 'JWKS terbaca (' . count($jwks['keys']) . ' kunci RSA).'];
            } catch (OidcException $e) {
                $ok = false;
                $steps[] = ['name' => 'jwks', 'ok' => false, 'msg' => $e->getMessage()];
            }
        }
        return ['ok' => $ok, 'steps' => $steps];
    }

    // ---------- internal ----------

    /**
     * @return array{0:array<string,mixed>,1:int}
     * @throws OidcException
     */
    private static function fetchDiscovery(HttpClient $http, string $issuer): array
    {
        [$doc, $ttl] = self::getJson($http, $issuer . '/.well-known/openid-configuration', 'Discovery');
        // SSO-04: issuer persis sama dengan config (tidak dinormalisasi: tanpa trailing slash, huruf berbeda ditolak).
        if (($doc['issuer'] ?? null) !== $issuer) {
            throw new OidcException('Issuer pada discovery tidak sama persis dengan issuer di konfigurasi.');
        }
        foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $k) {
            if (!is_string($doc[$k] ?? null) || !self::httpsUrl($doc[$k])) {
                throw new OidcException('Discovery tidak memuat ' . $k . ' https yang sah.');
            }
        }
        foreach (['end_session_endpoint', 'introspection_endpoint'] as $k) {
            if (isset($doc[$k]) && (!is_string($doc[$k]) || !self::httpsUrl($doc[$k]))) {
                throw new OidcException('Discovery memuat ' . $k . ' yang tidak sah.');
            }
        }
        self::supports($doc, 'id_token_signing_alg_values_supported', 'RS256', 'IdP tidak mendukung RS256.');
        self::supports($doc, 'code_challenge_methods_supported', 'S256', 'IdP tidak mendukung PKCE S256.');
        self::supports($doc, 'token_endpoint_auth_methods_supported', 'client_secret_basic', 'IdP tidak mendukung client_secret_basic.');
        $keep = [];
        foreach (['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'end_session_endpoint', 'introspection_endpoint'] as $k) {
            if (isset($doc[$k])) {
                $keep[$k] = $doc[$k];
            }
        }
        return [$keep, $ttl];
    }

    /**
     * @return array{0:array{keys:list<array<string,mixed>>},1:int}
     * @throws OidcException
     */
    private static function fetchJwks(HttpClient $http, string $uri): array
    {
        [$doc, $ttl] = self::getJson($http, $uri, 'JWKS');
        $keys = [];
        foreach (is_array($doc['keys'] ?? null) ? $doc['keys'] : [] as $k) {
            // Hanya RSA publik untuk penandatanganan RS256; kunci lain/privat diabaikan.
            if (is_array($k) && ($k['kty'] ?? null) === 'RSA' && is_string($k['kid'] ?? null) && !isset($k['d'])
                && is_string($k['n'] ?? null) && is_string($k['e'] ?? null)
                && (!isset($k['use']) || $k['use'] === 'sig') && (!isset($k['alg']) || $k['alg'] === 'RS256')) {
                /** @var array<string,mixed> $k */
                $keys[] = $k;
            }
        }
        if ($keys === []) {
            throw new OidcException('JWKS tidak memuat kunci RSA untuk RS256.');
        }
        return [['keys' => $keys], $ttl];
    }

    /**
     * @return array{0:array<string,mixed>,1:int}
     * @throws OidcException
     */
    private static function getJson(HttpClient $http, string $url, string $what): array
    {
        try {
            $res = $http->request('GET', $url, ['Accept' => 'application/json'], null, self::TIMEOUT);
        } catch (HttpError $e) {
            throw new OidcException($what . ' tidak dapat diambil: ' . $e->getMessage());
        }
        if ($res->status !== 200) {
            throw new OidcException($what . ' menjawab HTTP ' . $res->status . '.');
        }
        $j = json_decode($res->body, true);
        if (!is_array($j)) {
            throw new OidcException($what . ' bukan JSON yang sah.');
        }
        /** @var array<string,mixed> $j */
        return [$j, self::ttl($res)];
    }

    private static function ttl(HttpResponse $res): int
    {
        $cc = strtolower($res->headers['cache-control'] ?? '');
        if ($cc === '') {
            return self::DEFAULT_TTL;
        }
        if (preg_match('/\b(no-store|no-cache)\b/', $cc) === 1) {
            return self::MIN_TTL;
        }
        if (preg_match('/\bmax-age\s*=\s*(\d{1,9})\b/', $cc, $m) === 1) {
            return max(self::MIN_TTL, min((int) $m[1], self::MAX_TTL));
        }
        return self::DEFAULT_TTL;
    }

    /** @param array<string,mixed> $doc */
    private static function supports(array $doc, string $key, string $value, string $msg): void
    {
        if (isset($doc[$key]) && (!is_array($doc[$key]) || !in_array($value, $doc[$key], true))) {
            throw new OidcException($msg);
        }
    }

    private static function httpsUrl(string $u): bool
    {
        $p = parse_url($u);
        return $p !== false && ($p['scheme'] ?? '') === 'https' && isset($p['host']) && !isset($p['user'], $p['pass'])
            && !isset($p['fragment']) && preg_match('/[\x00-\x20\x7f\\\\]/', $u) !== 1;
    }

    private function endpoint(string $key): string
    {
        $v = $this->discovery()[$key] ?? null;
        if (!is_string($v)) {
            throw new OidcException('Endpoint ' . $key . ' tidak tersedia.');
        }
        return $v;
    }

    /**
     * @param array<string,string> $params
     * @return array<string,mixed>
     */
    private function tokenRequest(array $params): array
    {
        $res = $this->post($this->endpoint('token_endpoint'), $params);
        $j = json_decode($res->body, true);
        if ($res->status !== 200) {
            $err = is_array($j) && is_string($j['error'] ?? null) ? $j['error'] : '';
            if ($err === 'invalid_grant') {
                throw new InvalidGrant('invalid_grant');
            }
            // Hanya kode error baku yang dicatat, tidak seluruh body.
            $this->logger?->warning('Token endpoint menolak permintaan', ['status' => $res->status, 'error' => preg_match('/^[a-z_]{1,40}$/D', $err) === 1 ? $err : '']);
            throw new OidcException('Token endpoint menjawab HTTP ' . $res->status);
        }
        if (!is_array($j) || !is_string($j['access_token'] ?? null)) {
            throw new OidcException('Respons token tidak valid');
        }
        /** @var array<string,mixed> $j */
        return $j;
    }

    /** @param array<string,string> $params */
    private function post(string $url, array $params): HttpResponse
    {
        try {
            return $this->http->request('POST', $url, [
                'Authorization' => $this->cfg->basicAuth(),
                'Content-Type' => 'application/x-www-form-urlencoded',
                'Accept' => 'application/json',
            ], http_build_query($params, '', '&', PHP_QUERY_RFC3986), self::TIMEOUT);
        } catch (HttpError $e) {
            throw new OidcException('Server SSO tidak dapat dihubungi: ' . $e->getMessage());
        }
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }
}
