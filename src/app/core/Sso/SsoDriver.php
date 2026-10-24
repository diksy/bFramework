<?php

declare(strict_types=1);

namespace bFramework\Sso;

defined('APP_BOOTED') || exit;

use bFramework\Auth\AccountStore;
use bFramework\Auth\AuthDriver;
use bFramework\Auth\AuthManager;
use bFramework\Auth\AuthResult;
use bFramework\Auth\LoginThrottle;
use bFramework\Auth\NewUser;
use bFramework\Auth\NoRoles;
use bFramework\Auth\PasswordHasher;
use bFramework\Auth\UserStore;
use bFramework\Contracts\Clock;
use bFramework\Contracts\Identity;
use bFramework\Contracts\Logger;
use bFramework\Contracts\SessionStore;
use bFramework\Core\Csrf;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\RouteOpts;
use bFramework\Core\Router;
use bFramework\Core\Template;
use Throwable;

/**
 * Driver `bikinin_sso` / `hybrid` (F13, SSO-01..20). Authorization Code + PKCE S256 + state + nonce; akun
 * ditautkan lewat `sub` (bukan email, SSO-09). Provisioning jit/pre_registered (SSO-10). Rute /auth/sso/* hanya
 * ada bila driver ini yang dipasang (SSO-19). Hanya /auth/sso/backchannel yang tanpa CSRF (SSO-16).
 */
final class SsoDriver implements AuthDriver
{
    private const FLOW = '_sso_flow';
    private const LINK = '_sso_link';
    private const STATE = '_sso';
    private const FLOW_TTL = 600;

    /**
     * @param 'bikinin_sso'|'hybrid' $mode
     * @param ?AuthDriver $local driver lokal mode break-glass (hanya hybrid)
     */
    public function __construct(
        private readonly string $mode,
        private readonly ?SsoConfig $cfg,
        private readonly ?OidcClient $oidc,
        private readonly ?BackchannelHandler $backchannel,
        private readonly ?ClaimsValidator $claims,
        private readonly AuthManager $auth,
        private readonly UserStore $users,
        private readonly AccountStore $accounts,
        private readonly SidMap $sids,
        private readonly ?RefreshVault $refresh,
        private readonly PasswordHasher $hasher,
        private readonly LoginThrottle $throttle,
        private readonly SessionStore $session,
        private readonly Csrf $csrf,
        private readonly Template $views,
        private readonly Template $layout,
        private readonly Clock $clock,
        private readonly ?AuthDriver $local = null,
        private readonly ?Logger $logger = null,
    ) {
        $this->auth->useGuard($this->guard(...));
    }

    public function name(): string
    {
        return $this->mode;
    }

    public function registerRoutes(Router $router): void
    {
        $h = fn(string $m): \Closure => fn(Request $r, array $p = []): Response => $this->$m($r);
        $router->add('GET', '/login', $h('landing'));
        $router->add('POST', '/logout', $h('logoutPost'));
        $router->add('GET', '/auth/sso/login', $h('start'));
        $router->add('GET', '/auth/sso/callback', $h('callback'));
        $router->add('GET', '/auth/sso/signed-out', $h('signedOut'));
        $router->add('POST', '/auth/sso/link', $h('linkPost'));
        if ($this->backchannel !== null) {
            // SSO-16: satu-satunya pengecualian CSRF, eksplisit per route (autentikasi lewat tanda tangan logout token).
            $router->add('POST', '/auth/sso/backchannel', fn(Request $r, array $p = []): Response => $this->backchannel->handle($r), new RouteOpts(csrf: false));
        }
        $this->local?->registerRoutes($router);
    }

    // ---------- AuthDriver ----------

    /** Menyelesaikan callback (state, code, token, claims, penentuan akun) tanpa membuat sesi. */
    public function authenticate(Request $request): AuthResult
    {
        $o = $this->verifyCallback($request);
        return $o instanceof Response ? AuthResult::fail('Login SSO gagal.') : AuthResult::success($o['userId'], ['sso']);
    }

    public function logout(Request $request, Identity $identity): Response
    {
        if (!in_array('sso', $identity->amr, true) || $identity->ssoSid === null) {
            if ($this->local !== null) {
                return $this->local->logout($request, $identity);
            }
            $this->auth->logout();
            return Response::redirect('/login');
        }
        $s = $this->session->get(self::STATE);
        $hint = is_array($s) && is_string($s['idt'] ?? null) ? $s['idt'] : null;
        $this->sids->revoke($identity->ssoSid, null);
        $this->refresh?->delete($identity->userId);
        $this->auth->logout(); // sesi lokal hilang lebih dulu (SSO-14)
        $url = null;
        try {
            $url = $this->oidc?->endSessionUrl($hint);
        } catch (OidcException $e) {
            $this->logger?->warning('Endpoint logout SSO tidak tersedia');
        }
        if ($url !== null && self::externalOk($url)) {
            // CSP `form-action 'self'` (SecurityHeaders) membuat Chrome memblokir 302 lintas-origin dari POST /logout.
            // Karena itu: 200 + header Refresh (navigasi baru, bukan lanjutan pengiriman form) + tautan cadangan.
            return $this->panel('Keluar', 200, [
                'paragraphs' => ['Anda sudah keluar dari aplikasi. Mengalihkan ke SSO untuk mengakhiri sesi di sana.'],
                'links' => [['href' => $url, 'label' => 'Lanjut ke SSO']],
            ])->withHeader('Refresh', '0; url=' . $url);
        }
        return Response::redirect('/auth/sso/signed-out');
    }

    // ---------- guard sesi (SSO-01, 17, 18) ----------

    /** Dipasang ke AuthManager: false = sesi tidak sah dan akan diakhiri. Tidak pernah melempar. */
    public function guard(Identity $id): bool
    {
        if (in_array('sso', $id->amr, true)) {
            if ($id->ssoSid === null || !$this->sids->isActive($id->ssoSid, $id->userId)) {
                return false;
            }
            return $this->periodicCheck($id);
        }
        if ($this->mode !== 'hybrid') {
            return false; // bikinin_sso murni: sesi lokal (mis. sisa ingat-saya) tidak berlaku
        }
        // hybrid: hanya login darurat (SSO-01) oleh akun break_glass dengan bukti password; ingat-saya tidak cukup.
        $u = $this->users->find($id->userId);
        return $u !== null && $u->breakGlass && in_array('pwd', $id->amr, true);
    }

    private function periodicCheck(Identity $id): bool
    {
        $s = $this->session->get(self::STATE);
        if ($this->cfg === null || $this->oidc === null || !is_array($s) || !is_int($s['chk'] ?? null)) {
            return true;
        }
        $now = $this->now();
        if ($now - $s['chk'] < $this->cfg->sessionCheckMinutes * 60) {
            return true;
        }
        $s['chk'] = $now; // dicatat dulu agar request paralel tidak memicu pemeriksaan ganda
        $this->session->set(self::STATE, $s);
        try {
            $at = $s['at'] ?? null;
            if (is_string($at) && is_int($s['atx'] ?? null) && $s['atx'] > $now) {
                $active = $this->oidc->introspect($at);
                if ($active === false) {
                    return $this->kill($id);
                }
                if ($active === true) {
                    return true;
                }
            }
            $ver = $this->refresh?->version($id->userId);
            if ($this->refresh !== null && $ver !== null) {
                $oidc = $this->oidc;
                $res = $this->refresh->refreshOnce($id->userId, $ver, static fn(string $t): array => $oidc->refresh($t));
                if (is_array($res) && is_string($res['access_token'] ?? null)) {
                    $exp = is_int($res['expires_in'] ?? null) ? $res['expires_in'] : 300;
                    $this->session->set(self::STATE, ['at' => $res['access_token'], 'atx' => $now + max(0, $exp)] + $s);
                }
            }
        } catch (InvalidGrant) {
            return $this->kill($id); // SSO-20: tanpa retry otomatis
        } catch (Throwable $e) {
            $this->logger?->warning('Pemeriksaan sesi SSO gagal; sesi dipertahankan', ['error' => $e::class]);
        }
        return true;
    }

    private static function externalOk(string $url): bool
    {
        return preg_match('#^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/[^\s\x00-\x1F\x7F\\"<>]*$#D', $url) === 1;
    }

    private function kill(Identity $id): bool
    {
        if ($id->ssoSid !== null) {
            $this->sids->revoke($id->ssoSid, null);
        }
        $this->refresh?->delete($id->userId);
        return false;
    }

    // ---------- alur login ----------

    private function landing(Request $r): Response
    {
        if ($this->auth->current() !== null) {
            return Response::redirect('/');
        }
        $next = self::safeNext($r->query['next'] ?? null);
        $href = '/auth/sso/login' . ($next === '/' ? '' : '?next=' . rawurlencode($next));
        return $this->panel('Masuk', 200, [
            'paragraphs' => ['Aplikasi ini memakai BikininSSO untuk masuk.'],
            'links' => [['href' => $href, 'label' => 'Masuk dengan BikininSSO']],
        ]);
    }

    private function start(Request $r): Response
    {
        if ($this->oidc === null) {
            return $this->unavailable();
        }
        $next = self::safeNext($r->query['next'] ?? null);
        if ($this->auth->current() !== null) {
            return Response::redirect($next);
        }
        $state = self::b64(random_bytes(32));
        $nonce = self::b64(random_bytes(32));
        $verifier = self::b64(random_bytes(48)); // 64 karakter
        $challenge = self::b64(hash('sha256', $verifier, true));
        try {
            $url = $this->oidc->authorizationUrl($state, $nonce, $challenge);
        } catch (OidcException $e) {
            $this->logger?->error('Discovery SSO gagal saat memulai login', ['error' => $e->getMessage()]);
            return $this->unavailable();
        }
        $this->session->start();
        $this->session->set(self::FLOW, ['state' => $state, 'nonce' => $nonce, 'cv' => $verifier, 'exp' => $this->now() + self::FLOW_TTL, 'next' => $next]);
        $host = parse_url($url, PHP_URL_HOST);
        try {
            return Response::redirect($url, 302, [is_string($host) ? strtolower($host) : ''])->withHeader('Cache-Control', 'no-store');
        } catch (\InvalidArgumentException) {
            $this->logger?->error('URL otorisasi SSO ditolak');
            return $this->unavailable();
        }
    }

    private function callback(Request $r): Response
    {
        $o = $this->verifyCallback($r);
        if ($o instanceof Response) {
            return $o;
        }
        return $this->finish($o['userId'], $o['claims'], $o['tokens'], $o['next'], true);
    }

    /**
     * @return Response|array{userId:int,claims:array{sub:string,sid:?string,email:?string,emailVerified:?bool,name:?string},tokens:array<string,mixed>,next:string}
     */
    private function verifyCallback(Request $r): Response|array
    {
        if ($this->oidc === null || $this->cfg === null || $this->claims === null) {
            return $this->unavailable();
        }
        $flow = $this->session->get(self::FLOW);
        $this->session->forget(self::FLOW); // sekali pakai: callback ulang/replay tidak punya flow lagi
        $q = $r->query;
        $state = $q['state'] ?? null;
        if (!is_array($flow) || !is_string($flow['state'] ?? null) || !is_string($flow['nonce'] ?? null) || !is_string($flow['cv'] ?? null)
            || !is_int($flow['exp'] ?? null) || $flow['exp'] < $this->now() || !is_string($state)
            || !hash_equals($flow['state'], $state)) { // SSO-08
            return $this->failPage('Permintaan login tidak valid', 'Permintaan login tidak valid atau sudah kedaluwarsa. Silakan coba lagi.', 400);
        }
        $next = is_string($flow['next'] ?? null) ? self::safeNext($flow['next']) : '/';
        if (isset($q['error'])) {
            $denied = ($q['error']) === 'access_denied';
            return $this->failPage($denied ? 'Login dibatalkan' : 'Login SSO gagal', $denied ? 'Anda membatalkan login.' : 'Server SSO menolak permintaan login.', 400);
        }
        $code = $q['code'] ?? null;
        if (!is_string($code) || $code === '' || strlen($code) > 2048) {
            return $this->failPage('Permintaan login tidak valid', 'Permintaan login tidak valid. Silakan coba lagi.', 400);
        }
        try {
            $tokens = $this->oidc->exchangeCode($code, $flow['cv']);
        } catch (InvalidGrant) {
            // SSO-20: halaman ramah, tanpa retry otomatis.
            return $this->failPage('Sesi login kedaluwarsa', 'Kode login sudah kedaluwarsa atau sudah dipakai. Silakan login ulang.', 400);
        } catch (OidcException $e) {
            $this->logger?->error('Pertukaran code SSO gagal', ['error' => $e->getMessage()]);
            return $this->unavailable();
        }
        $idt = $tokens['id_token'] ?? null;
        if (!is_string($idt) || $idt === '') {
            return $this->failPage('Login SSO gagal', 'Respons SSO tidak lengkap. Silakan coba lagi.', 400);
        }
        try {
            $v = $this->claims->idToken($this->oidc->verifyToken($idt), $flow['nonce'], $this->now());
        } catch (JwtInvalid | ClaimsInvalid $e) {
            $this->logger?->warning('ID token SSO ditolak', ['alasan' => $e->getMessage()]);
            return $this->failPage('Login SSO gagal', 'Token dari server SSO tidak dapat diverifikasi. Silakan coba lagi.', 400);
        } catch (OidcException $e) {
            $this->logger?->error('Verifikasi ID token SSO gagal', ['error' => $e->getMessage()]);
            return $this->unavailable();
        }
        $tokens['id_token'] = $idt;
        $userId = $this->resolveUser($v, $tokens, $next);
        return $userId instanceof Response ? $userId : ['userId' => $userId, 'claims' => $v, 'tokens' => $tokens, 'next' => $next];
    }

    /**
     * SSO-09/10: akun ditemukan lewat `sub`. Email TIDAK dipakai untuk menemukan akun yang sudah ada; bentrok email
     * dengan akun lokal berujung pada tautan yang membuktikan kepemilikan (password), bukan takeover.
     *
     * @param array{sub:string,sid:?string,email:?string,emailVerified:?bool,name:?string} $v
     * @param array<string,mixed> $tokens
     */
    private function resolveUser(array $v, array $tokens, string $next): int|Response
    {
        $cfg = $this->cfg;
        if ($cfg === null) {
            return $this->unavailable();
        }
        $user = $this->users->findBySsoSub($v['sub']);
        if ($user !== null) {
            return $user->isActive() ? $user->id : $this->denied();
        }
        if ($cfg->provisioning === 'pre_registered') {
            $this->logger?->warning('Login SSO ditolak: sub belum terdaftar (pre_registered)');
            return $this->failPage('Akun belum terdaftar', 'Akun Anda belum didaftarkan di aplikasi ini. Hubungi administrator.', 403);
        }
        $email = $v['email'] === null ? null : AccountStore::normalizeEmail($v['email']);
        if ($email === null || $v['emailVerified'] === false) {
            return $this->failPage('Akun tidak dapat dibuat', 'Server SSO tidak mengirim alamat email yang terverifikasi.', 403);
        }
        $name = self::cleanName($v['name'], $email);
        if ($this->users->findByEmail($email) !== null) {
            $this->session->set(self::LINK, [
                'sub' => $v['sub'], 'sid' => $v['sid'], 'email' => $email, 'name' => $name, 'exp' => $this->now() + 600,
                'idt' => $tokens['id_token'], 'at' => $tokens['access_token'] ?? null,
                'atx' => $this->now() + (is_int($tokens['expires_in'] ?? null) ? $tokens['expires_in'] : 0), 'next' => $next,
            ]);
            return $this->linkPage([], $email, $name, 200);
        }
        try {
            $created = $this->users->create(new NewUser($email, $name, null, 'active', $v['sub'], [$cfg->defaultRole]));
        } catch (\InvalidArgumentException) {
            $again = $this->users->findBySsoSub($v['sub']); // balapan login pertama
            if ($again === null || !$again->isActive()) {
                return $this->failPage('Akun tidak dapat dibuat', 'Akun tidak dapat dibuat. Hubungi administrator.', 403);
            }
            return $again->id;
        }
        if ($v['emailVerified'] === true) {
            $this->accounts->markVerified($created->id);
        }
        return $created->id;
    }

    /**
     * @param array{sub:string,sid:?string,email:?string,emailVerified:?bool,name:?string} $v
     * @param array<string,mixed> $tokens
     */
    private function finish(int $userId, array $v, array $tokens, string $next, bool $withRefresh): Response
    {
        $sid = $v['sid'] ?? 'l-' . bin2hex(random_bytes(16));
        // Baris sid harus ada sebelum login() karena guard memeriksanya.
        $this->sids->record($sid, $userId, $v['sub']);
        try {
            $this->auth->login($userId, ['sso'], $sid);
        } catch (NoRoles) {
            $this->sids->revoke($sid, null);
            return $this->failPage('Akun belum dapat digunakan', 'Akun belum memiliki peran. Hubungi administrator.', 403);
        } catch (\InvalidArgumentException) {
            $this->sids->revoke($sid, null);
            return $this->denied();
        }
        $now = $this->now();
        $exp = is_int($tokens['expires_in'] ?? null) ? $tokens['expires_in'] : 0;
        $at = $tokens['access_token'] ?? null;
        $this->session->set(self::STATE, [
            'idt' => is_string($tokens['id_token'] ?? null) ? $tokens['id_token'] : '',
            'at' => is_string($at) ? $at : null, 'atx' => $now + max(0, $exp), 'chk' => $now,
        ]);
        $rt = $tokens['refresh_token'] ?? null;
        // SSO-11/13: refresh token hanya bila offline_access diaktifkan; selalu terenkripsi.
        if ($withRefresh && $this->cfg?->offlineAccess === true && $this->refresh !== null && is_string($rt) && $rt !== '') {
            $this->refresh->store($userId, $rt);
        }
        if (random_int(1, 50) === 1) {
            $this->sids->purge(86400);
        }
        return Response::redirect(self::safeNext($next))->withHeader('Cache-Control', 'no-store');
    }

    private function linkPost(Request $r): Response
    {
        $p = $this->session->get(self::LINK);
        if (!is_array($p) || !is_string($p['sub'] ?? null) || !is_string($p['email'] ?? null) || !is_string($p['name'] ?? null)
            || !is_int($p['exp'] ?? null) || $p['exp'] < $this->now()) {
            $this->session->forget(self::LINK);
            return Response::redirect('/login');
        }
        $this->throttle->login($p['email'], $r->remoteAddr);
        $pw = $r->post['password'] ?? null;
        $pw = is_string($pw) && strlen($pw) <= 1024 ? $pw : '';
        $acc = $this->accounts->findByEmail($p['email']);
        $valid = $this->hasher->verify($pw, $acc?->passwordHash ?? $this->hasher->dummyHash()); // waktu setara
        if ($acc === null || $acc->passwordHash === null || !$valid || !$acc->isActive() || $acc->ssoSub !== null) {
            return $this->linkPage(['Password salah.'], $p['email'], $p['name'], 401);
        }
        try {
            $this->users->update($acc->id, ['sso_sub' => $p['sub']]);
        } catch (\InvalidArgumentException) {
            return $this->linkPage(['Akun tidak dapat ditautkan.'], $p['email'], $p['name'], 409);
        }
        $this->session->forget(self::LINK);
        $sid = is_string($p['sid'] ?? null) ? $p['sid'] : null;
        $tokens = ['id_token' => $p['idt'] ?? '', 'access_token' => $p['at'] ?? null, 'expires_in' => max(0, (is_int($p['atx'] ?? null) ? $p['atx'] : 0) - $this->now())];
        // Refresh token sengaja tidak dibawa lewat sesi; tersimpan pada login SSO berikutnya.
        return $this->finish($acc->id, ['sub' => $p['sub'], 'sid' => $sid, 'email' => $p['email'], 'emailVerified' => null, 'name' => $p['name']], $tokens, is_string($p['next'] ?? null) ? $p['next'] : '/', false);
    }

    private function logoutPost(Request $r): Response
    {
        $id = $this->auth->current();
        return $id === null ? Response::redirect('/login') : $this->logout($r, $id);
    }

    private function signedOut(Request $r): Response
    {
        return $this->panel('Anda sudah keluar', 200, [
            'paragraphs' => ['Sesi Anda sudah diakhiri.'],
            'links' => [['href' => '/login', 'label' => 'Masuk lagi']],
        ]);
    }

    // ---------- tampilan ----------

    /** @param list<string> $errors */
    private function linkPage(array $errors, string $email, string $name, int $status): Response
    {
        return $this->panel('Tautkan akun', $status, [
            'errors' => $errors,
            'paragraphs' => [
                'Email ' . $email . ' (' . $name . ') sudah dipakai akun lokal. Masukkan password akun lokal tersebut untuk menautkannya ke akun SSO ini.',
            ],
            'forms' => [['id' => 'k', 'action' => '/auth/sso/link', 'submit' => 'Tautkan dan masuk', 'fields' => [
                ['name' => 'password', 'label' => 'Password akun lokal', 'type' => 'password', 'autocomplete' => 'current-password', 'value' => '', 'isCheck' => false],
            ]]],
        ]);
    }

    private function failPage(string $title, string $msg, int $status): Response
    {
        return $this->panel($title, $status, [
            'paragraphs' => [$msg],
            'links' => [['href' => '/auth/sso/login', 'label' => 'Login ulang']],
        ]);
    }

    private function denied(): Response
    {
        return $this->failPage('Akses ditolak', 'Akun Anda tidak dapat masuk. Hubungi administrator.', 403);
    }

    private function unavailable(): Response
    {
        return $this->panel('SSO tidak tersedia', 503, [
            'paragraphs' => ['Layanan SSO belum dapat dipakai saat ini. Coba lagi nanti atau hubungi administrator.'],
        ]);
    }

    /** @param array<string,mixed> $vars */
    private function panel(string $title, int $status, array $vars): Response
    {
        $vars += ['errors' => [], 'paragraphs' => [], 'codes' => [], 'forms' => [], 'links' => []];
        $content = $this->views->render('panel', $vars + ['heading' => $title, 'csrf' => $this->csrf->token()]);
        $html = $this->layout->render('layout', [
            'title' => $title, 'csrf' => $this->csrf->token(), 'user' => null, 'nav' => [], 'active' => '',
            'flash' => $this->session->pullFlash(), 'scripts' => [], 'bodyClass' => 'auth', 'content' => $content,
        ]);
        return Response::html($html->toString(), $status)->withHeader('Cache-Control', 'no-store');
    }

    // ---------- util ----------

    /** Tujuan setelah login: hanya path lokal (cegah open redirect); selain itu "/". */
    public static function safeNext(mixed $v): string
    {
        if (!is_string($v) || $v === '' || strlen($v) > 512 || preg_match('#^/(?![/\\\\])[^\s\x00-\x1F\x7F\\\\]*$#D', $v) !== 1
            || str_starts_with($v, '/auth/sso/') || str_starts_with($v, '/login')) {
            return '/';
        }
        return $v;
    }

    private static function cleanName(?string $name, string $email): string
    {
        $n = trim(preg_replace('/[\x00-\x1F\x7F]/u', '', (string) $name) ?? '');
        $n = mb_substr($n, 0, 120);
        return $n !== '' ? $n : mb_substr((string) strstr($email, '@', true), 0, 120);
    }

    private static function b64(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }
}
