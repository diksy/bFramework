<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Clock;
use bFramework\Contracts\Identity;
use bFramework\Contracts\Logger;
use bFramework\Contracts\NotFound;
use bFramework\Contracts\SessionStore;
use bFramework\Core\Csrf;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\Router;
use bFramework\Core\Template;

/**
 * Driver `local` (AUTH-01..08). Pesan gagal login selalu sama dan waktu verifikasi dibuat setara
 * (hash palsu) sehingga akun ada/tidak tidak bisa dibedakan. Rute: /login, /logout, /auth/*.
 * Pendaftaran publik (AUTH-08) tidak diregistrasi kecuali opts['registration'] === true.
 */
final class LocalDriver implements AuthDriver
{
    public const GENERIC_FAIL = 'Email atau password salah.';
    private const PENDING_2FA = '_pending_2fa';
    private const RESET_KEY = '_reset_token';
    private const VERIFY_KEY = '_verify_token';

    /** @var array{appUrl:string,registration:bool,defaultRole:string,resetTtl:int,verifyTtl:int,issuer:string,from:string,fromName:string,breakGlass:bool,loginPath:string} */
    private array $opts;

    /**
     * @param array<string,mixed> $opts appUrl (wajib, https kecuali allowHttp), registration, defaultRole,
     *     resetTtl/verifyTtl (detik, maks 3600), issuer, from, fromName, allowHttp, breakGlass (SSO-01: mode hybrid, hanya
     *     akun break_glass lewat loginPath terpisah; rute lain tidak didaftarkan), loginPath
     */
    public function __construct(
        private readonly AuthManager $auth,
        private readonly AccountStore $accounts,
        private readonly PasswordHasher $hasher,
        private readonly LoginThrottle $throttle,
        private readonly RememberMe $remember,
        private readonly OneTimeToken $tokens,
        private readonly ?TwoFactor $twofa,
        private readonly Mailer $mailer,
        private readonly Deferred $deferred,
        private readonly SessionStore $session,
        private readonly Csrf $csrf,
        private readonly Template $views,
        private readonly Template $layout,
        private readonly Clock $clock,
        array $opts,
        private readonly ?Logger $logger = null,
    ) {
        $url = rtrim(is_string($opts['appUrl'] ?? null) ? $opts['appUrl'] : '', '/');
        $allowHttp = ($opts['allowHttp'] ?? false) === true;
        $ok = preg_match('#^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$#D', $url) === 1
            || ($allowHttp && preg_match('#^http://[A-Za-z0-9.-]+(:[0-9]{1,5})?$#D', $url) === 1);
        if (!$ok) {
            throw new \InvalidArgumentException('APP_URL harus https://host (http hanya mode dev)');
        }
        $ttl = static fn(mixed $v): int => is_int($v) && $v >= 60 && $v <= OneTimeToken::MAX_TTL ? $v : 1800;
        $str = static fn(mixed $v, string $d): string => is_string($v) && $v !== '' ? $v : $d;
        $loginPath = $opts['loginPath'] ?? '/auth/break-glass';
        if (!is_string($loginPath) || preg_match('#^/[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+){0,3}$#D', $loginPath) !== 1
            || str_starts_with($loginPath, '/auth/sso') || $loginPath === '/login') {
            throw new \InvalidArgumentException('loginPath break-glass tidak valid');
        }
        $this->opts = [
            'appUrl' => $url,
            'registration' => ($opts['registration'] ?? false) === true,
            'defaultRole' => $str($opts['defaultRole'] ?? null, 'staf'),
            'resetTtl' => $ttl($opts['resetTtl'] ?? null),
            'verifyTtl' => $ttl($opts['verifyTtl'] ?? null),
            'issuer' => $str($opts['issuer'] ?? null, 'BikininFramework'),
            'from' => $str($opts['from'] ?? null, 'noreply@example.invalid'),
            'fromName' => $str($opts['fromName'] ?? null, 'BikininFramework'),
            'breakGlass' => ($opts['breakGlass'] ?? false) === true,
            'loginPath' => $loginPath,
        ];
    }

    public function name(): string
    {
        return 'local';
    }

    public function registerRoutes(Router $router): void
    {
        $h = fn(string $m): \Closure => fn(Request $r, array $p = []): Response => $this->$m($r, $p);
        if ($this->opts['breakGlass']) {
            // SSO-01: hanya login darurat, di URL terpisah yang tidak ditautkan dari halaman login mana pun.
            $router->add('GET', $this->opts['loginPath'], $h('loginForm'));
            $router->add('POST', $this->opts['loginPath'], $h('loginPost'));
            $router->add('GET', '/auth/otp', $h('otpForm'));
            $router->add('POST', '/auth/otp', $h('otpPost'));
            return;
        }
        $router->add('GET', '/login', $h('loginForm'));
        $router->add('POST', '/login', $h('loginPost'));
        $router->add('POST', '/logout', $h('logoutPost'));
        $router->add('GET', StepUp::PATH, $h('stepUpForm'));
        $router->add('POST', StepUp::PATH, $h('stepUpPost'));
        $router->add('GET', '/auth/otp', $h('otpForm'));
        $router->add('POST', '/auth/otp', $h('otpPost'));
        $router->add('GET', '/auth/forgot', $h('forgotForm'));
        $router->add('POST', '/auth/forgot', $h('forgotPost'));
        $router->add('GET', '/auth/reset/{token}', $h('resetLink'));
        $router->add('GET', '/auth/reset', $h('resetForm'));
        $router->add('POST', '/auth/reset', $h('resetPost'));
        $router->add('GET', '/auth/verify/{token}', $h('verifyLink'));
        $router->add('GET', '/auth/verify', $h('verifyForm'));
        $router->add('POST', '/auth/verify', $h('verifyPost'));
        $router->add('POST', '/auth/verify/resend', $h('verifyResend'));
        if ($this->twofa !== null) {
            $router->add('GET', '/auth/2fa', $h('twofaForm'));
            $router->add('POST', '/auth/2fa/begin', $h('twofaBegin'));
            $router->add('POST', '/auth/2fa/confirm', $h('twofaConfirm'));
            $router->add('POST', '/auth/2fa/disable', $h('twofaDisable'));
        }
        if ($this->opts['registration']) {
            $router->add('GET', '/auth/register', $h('registerForm'));
            $router->add('POST', '/auth/register', $h('registerPost'));
        }
    }

    // ---------- AuthDriver ----------

    /** Verifikasi email+password saja (tanpa membuat sesi). Melempar TooManyRequests bila melewati batas. */
    public function authenticate(Request $request): AuthResult
    {
        $email = self::str($request->post['email'] ?? null);
        $password = self::str($request->post['password'] ?? null);
        $this->throttle->login($email, $request->remoteAddr);

        $acc = AccountStore::normalizeEmail($email) === null ? null : $this->accounts->findByEmail($email);
        $hash = $acc?->passwordHash ?? $this->hasher->dummyHash();
        $valid = $this->hasher->verify($password, $hash); // selalu satu verifikasi, ada/tidaknya akun
        if ($acc === null || $acc->passwordHash === null || !$valid || !$acc->isActive()
            || ($this->opts['breakGlass'] && !$acc->breakGlass)) {
            return AuthResult::fail(self::GENERIC_FAIL);
        }
        if ($this->hasher->needsRehash($acc->passwordHash)) {
            $this->accounts->updateHash($acc->id, $this->hasher->hash($password));
        }
        return AuthResult::success($acc->id, ['pwd']);
    }

    public function logout(Request $request, Identity $identity): Response
    {
        $name = AuthMiddleware::cookieName($request->isHttps);
        $token = Cookies::parse($request->header('cookie') ?? '')[$name] ?? null;
        if ($token !== null) {
            $this->remember->revoke($token);
        }
        $this->auth->logout();
        $this->session->flash('ok', 'Anda sudah keluar.');
        return Response::redirect('/login')->withCookie($name, '', AuthMiddleware::cookieOptions($request->isHttps, 1));
    }

    // ---------- login / logout ----------

    /** @param array<string,string> $p */
    private function loginForm(Request $r, array $p): Response
    {
        if ($this->auth->current() !== null) {
            return Response::redirect('/');
        }
        return $this->loginPage([], '', 200);
    }

    /** @param array<string,string> $p */
    private function loginPost(Request $r, array $p): Response
    {
        $res = $this->authenticate($r);
        if (!$res->ok || $res->userId === null) {
            return $this->loginPage([$res->error ?? self::GENERIC_FAIL], self::str($r->post['email'] ?? null), 401);
        }
        $acc = $this->accounts->find($res->userId);
        if ($acc === null) {
            return $this->loginPage([self::GENERIC_FAIL], '', 401);
        }
        $remember = !$this->opts['breakGlass'] && ($r->post['remember'] ?? null) === '1'; // login darurat: tanpa ingat-saya
        if ($acc->totpEnabled) {
            if ($this->twofa === null) {
                $this->logger?->error('Akun memakai 2FA tetapi APP_KEY tidak tersedia; login ditolak');
                return $this->loginPage([self::GENERIC_FAIL], '', 401);
            }
            $this->session->regenerate();
            $this->csrf->rotate();
            $this->session->set(self::PENDING_2FA, ['uid' => $acc->id, 'exp' => $this->now() + 300, 'remember' => $remember]);
            return Response::redirect('/auth/otp');
        }
        return $this->finishLogin($r, $acc->id, $res->amr, $remember);
    }

    /** @param list<string> $amr */
    private function finishLogin(Request $r, int $uid, array $amr, bool $remember): Response
    {
        try {
            $this->auth->login($uid, $amr);
        } catch (NoRoles) {
            return $this->loginPage(['Akun belum dapat digunakan. Hubungi administrator.'], '', 403);
        }
        $this->session->forget(self::PENDING_2FA);
        $res = Response::redirect('/');
        if ($remember) {
            $res = $res->withCookie(
                AuthMiddleware::cookieName($r->isHttps),
                $this->remember->issue($uid),
                AuthMiddleware::cookieOptions($r->isHttps, time() + $this->remember->ttl()),
            );
        }
        return $res;
    }

    /** @param array<string,string> $p */
    private function logoutPost(Request $r, array $p): Response
    {
        $id = $this->auth->current();
        return $id === null ? Response::redirect('/login') : $this->logout($r, $id);
    }

    // ---------- 2FA saat login ----------

    /** @return array{uid:int,remember:bool}|null */
    private function pending(): ?array
    {
        $d = $this->session->get(self::PENDING_2FA);
        if (!is_array($d) || !is_int($d['uid'] ?? null) || !is_int($d['exp'] ?? null) || $d['exp'] < $this->now()) {
            $this->session->forget(self::PENDING_2FA);
            return null;
        }
        return ['uid' => $d['uid'], 'remember' => ($d['remember'] ?? false) === true];
    }

    /** @param array<string,string> $p */
    private function otpForm(Request $r, array $p): Response
    {
        return $this->pending() === null ? Response::redirect('/login') : $this->otpPage([], 200);
    }

    /** @param array<string,string> $p */
    private function otpPost(Request $r, array $p): Response
    {
        $pend = $this->pending();
        if ($pend === null) {
            return Response::redirect('/login');
        }
        $this->throttle->otp($pend['uid'], $r->remoteAddr);
        $acc = $this->accounts->find($pend['uid']);
        if ($acc === null || !$acc->isActive() || $this->twofa === null
            || !$this->twofa->verifyLogin($acc, self::str($r->post['code'] ?? null))) {
            return $this->otpPage(['Kode salah atau sudah dipakai.'], 401);
        }
        return $this->finishLogin($r, $acc->id, ['pwd', 'otp'], $pend['remember']);
    }

    // ---------- lupa / reset password ----------

    /** @param array<string,string> $p */
    private function forgotForm(Request $r, array $p): Response
    {
        return $this->forgotPage([], 200);
    }

    /** @param array<string,string> $p */
    private function forgotPost(Request $r, array $p): Response
    {
        $email = self::str($r->post['email'] ?? null);
        $this->throttle->mail('forgot', $email, $r->remoteAddr);
        // Seluruh pekerjaan khusus-akun-ada (cari, terbitkan token, kirim email) dijalankan setelah respons dikirim.
        $this->deferred->push(function () use ($email): void {
            $acc = AccountStore::normalizeEmail($email) === null ? null : $this->accounts->findByEmail($email);
            if ($acc === null || !$acc->isActive()) {
                return;
            }
            $this->mailResetLink($acc->id, $acc->email);
        });
        // Respons identik untuk email terdaftar maupun tidak.
        return $this->panel('Lupa password', 200, [
            'paragraphs' => ['Jika email terdaftar, tautan pengaturan ulang password telah dikirim.'],
            'links' => [['href' => '/login', 'label' => 'Kembali ke login']],
        ]);
    }

    private function mailResetLink(int $uid, string $email): void
    {
        $token = $this->tokens->issue($uid, OneTimeToken::RESET, $this->opts['resetTtl']);
        $this->queueMail($email, 'Atur ulang password',
            "Halo,\n\nAda permintaan mengatur ulang password akun Anda. Buka tautan berikut (berlaku "
            . intdiv($this->opts['resetTtl'], 60) . " menit, sekali pakai):\n\n"
            . $this->opts['appUrl'] . '/auth/reset/' . $token
            . "\n\nAbaikan email ini bila Anda tidak memintanya.\n");
    }

    /** @param array<string,string> $p */
    private function resetLink(Request $r, array $p): Response
    {
        $this->throttle->token($r->remoteAddr);
        $token = $p['token'] ?? '';
        if (!OneTimeToken::wellFormed($token)) {
            return $this->invalidLink();
        }
        // Token dipindah ke sesi lalu URL dibersihkan (tidak tertinggal di riwayat/Referer).
        $this->session->set(self::RESET_KEY, $token);
        return Response::redirect('/auth/reset');
    }

    /** @param array<string,string> $p */
    private function resetForm(Request $r, array $p): Response
    {
        return is_string($this->session->get(self::RESET_KEY)) ? $this->resetPage([], 200) : $this->invalidLink();
    }

    /** @param array<string,string> $p */
    private function resetPost(Request $r, array $p): Response
    {
        $this->throttle->token($r->remoteAddr);
        $token = $this->session->get(self::RESET_KEY);
        if (!is_string($token)) {
            return $this->invalidLink();
        }
        $pw = self::str($r->post['password'] ?? null);
        if (!hash_equals($pw, self::str($r->post['password2'] ?? null))) {
            return $this->resetPage(['Konfirmasi password tidak sama.'], 422);
        }
        $errors = PasswordPolicy::check($pw, '', $this->hasher->maxBytes());
        if ($errors !== []) {
            return $this->resetPage($errors, 422); // token belum dikonsumsi
        }
        $uid = $this->tokens->consume($token, OneTimeToken::RESET);
        $acc = $uid === null ? null : $this->accounts->find($uid);
        if ($acc === null || !in_array($acc->status, ['active', 'pending'], true)) {
            $this->session->forget(self::RESET_KEY);
            return $this->invalidLink();
        }
        if (PasswordPolicy::check($pw, $acc->email, $this->hasher->maxBytes()) !== []) {
            // Gagal karena mengandung email: terbitkan token baru agar pengguna tak perlu minta ulang.
            $this->session->set(self::RESET_KEY, $this->tokens->issue($acc->id, OneTimeToken::RESET, $this->opts['resetTtl']));
            return $this->resetPage(PasswordPolicy::check($pw, $acc->email, $this->hasher->maxBytes()), 422);
        }
        $this->accounts->setPassword($acc->id, $this->hasher->hash($pw));
        $this->tokens->revokeAll($acc->id);   // semua token reset/verifikasi lain batal
        $this->remember->revokeAll($acc->id); // perangkat lain harus login ulang
        $this->accounts->markVerified($acc->id);
        $this->session->forget(self::RESET_KEY);
        $this->session->regenerate();
        $this->csrf->rotate();
        $this->session->flash('ok', 'Password diperbarui. Silakan login.');
        return Response::redirect('/login');
    }

    // ---------- verifikasi email ----------

    /** @param array<string,string> $p */
    private function verifyLink(Request $r, array $p): Response
    {
        $this->throttle->token($r->remoteAddr);
        $token = $p['token'] ?? '';
        if (!OneTimeToken::wellFormed($token)) {
            return $this->invalidLink();
        }
        $this->session->set(self::VERIFY_KEY, $token);
        return Response::redirect('/auth/verify');
    }

    /** @param array<string,string> $p */
    private function verifyForm(Request $r, array $p): Response
    {
        if (!is_string($this->session->get(self::VERIFY_KEY))) {
            return $this->invalidLink();
        }
        // Konfirmasi lewat POST agar pemindai tautan email tidak menghanguskan token.
        return $this->panel('Verifikasi email', 200, ['forms' => [[
            'id' => 'v', 'action' => '/auth/verify', 'submit' => 'Verifikasi email saya', 'fields' => [],
        ]]]);
    }

    /** @param array<string,string> $p */
    private function verifyPost(Request $r, array $p): Response
    {
        $this->throttle->token($r->remoteAddr);
        $token = $this->session->get(self::VERIFY_KEY);
        $uid = is_string($token) ? $this->tokens->consume($token, OneTimeToken::VERIFY_EMAIL) : null;
        $this->session->forget(self::VERIFY_KEY);
        if ($uid === null) {
            return $this->invalidLink();
        }
        $this->accounts->markVerified($uid);
        $this->session->flash('ok', 'Email terverifikasi.');
        return Response::redirect('/login');
    }

    /** @param array<string,string> $p */
    private function verifyResend(Request $r, array $p): Response
    {
        $id = $this->auth->current();
        if ($id === null) {
            return Response::redirect('/login');
        }
        $acc = $this->accounts->find($id->userId);
        if ($acc !== null && $acc->emailVerifiedAt === null) {
            $this->throttle->mail('verify', $acc->email, $r->remoteAddr);
            $this->sendVerification($acc->id, $acc->email);
        }
        $this->session->flash('ok', 'Jika email belum terverifikasi, tautan verifikasi dikirim.');
        return Response::redirect('/');
    }

    private function sendVerification(int $uid, string $email): void
    {
        $token = $this->tokens->issue($uid, OneTimeToken::VERIFY_EMAIL, $this->opts['verifyTtl']);
        $this->queueMail($email, 'Verifikasi email',
            "Halo,\n\nBuka tautan berikut untuk memverifikasi email Anda (berlaku "
            . intdiv($this->opts['verifyTtl'], 60) . " menit, sekali pakai):\n\n"
            . $this->opts['appUrl'] . '/auth/verify/' . $token . "\n");
    }

    // ---------- registrasi (opsional, AUTH-08) ----------

    /** @param array<string,string> $p */
    private function registerForm(Request $r, array $p): Response
    {
        return $this->registerPage([], '', '', 200);
    }

    /** @param array<string,string> $p */
    private function registerPost(Request $r, array $p): Response
    {
        $email = self::str($r->post['email'] ?? null);
        $name = self::str($r->post['name'] ?? null);
        $this->throttle->mail('register', $email, $r->remoteAddr);
        $norm = AccountStore::normalizeEmail($email);
        $errors = [];
        if ($norm === null) {
            $errors[] = 'Email tidak valid.';
        }
        if (trim($name) === '' || mb_strlen(trim($name)) > 120) {
            $errors[] = 'Nama wajib diisi (maks. 120 karakter).';
        }
        if ($errors !== []) {
            return $this->registerPage($errors, $name, $email, 422);
        }
        // Password pendaftar TIDAK disimpan: akun pending tanpa password usable. Pemilik email menetapkan password
        // lewat tautan sekali pakai (alur reset) sehingga pra-registrasi tidak dapat membajak akun.
        // Semua pekerjaan khusus-akun dijalankan setelah respons dikirim (respons identik, waktu setara).
        $this->deferred->push(function () use ($norm, $name): void {
            $uid = $this->accounts->create((string) $norm, $name, null, 'pending');
            if ($uid !== null) {
                try {
                    $this->accounts->assignRole($uid, $this->opts['defaultRole']);
                } catch (\InvalidArgumentException) {
                    $this->logger?->error('Peran bawaan registrasi tidak ada');
                }
                $this->mailResetLink($uid, (string) $norm);
                return;
            }
            $existing = $this->accounts->findByEmail((string) $norm);
            if ($existing !== null && $existing->status === 'pending' && $existing->passwordHash === null) {
                $this->mailResetLink($existing->id, $existing->email); // kirim ulang ke pemilik email; tidak menimpa data
            }
        });
        // Respons sama untuk email baru maupun yang sudah terdaftar.
        return $this->panel('Pendaftaran', 200, [
            'paragraphs' => ['Jika data valid, email berisi tautan penetapan password telah dikirim. Akun aktif setelah Anda menetapkan password lewat tautan di email.'],
            'links' => [['href' => '/login', 'label' => 'Ke halaman login']],
        ]);
    }

    // ---------- step-up admin (S3) ----------

    /** @param array<string,string> $p */
    private function stepUpForm(Request $r, array $p): Response
    {
        $acc = $this->requireAccount();
        if ($acc instanceof Response) {
            return $acc;
        }
        $next = StepUp::safeNext($r->query['next'] ?? null);
        if ($next !== null) {
            $this->session->set(StepUp::NEXT_KEY, $next);
        }
        return $this->stepUpPage($acc, [], 200);
    }

    /** @param array<string,string> $p */
    private function stepUpPost(Request $r, array $p): Response
    {
        $acc = $this->requireAccount();
        if ($acc instanceof Response) {
            return $acc;
        }
        $this->throttle->login($acc->email, $r->remoteAddr); // batas yang sama dengan login
        $ok = $this->verifyPassword($acc, self::str($r->post['password'] ?? null));
        if ($ok && $acc->totpEnabled) {
            $this->throttle->otp($acc->id, $r->remoteAddr);
            $ok = $this->twofa !== null && $this->twofa->verifyLogin($acc, self::str($r->post['code'] ?? null));
        }
        if (!$ok) {
            $this->logger?->warning('Step-up admin gagal', ['user_id' => $acc->id]);
            return $this->stepUpPage($acc, ['Password atau kode salah.'], 401);
        }
        $this->auth->markStepUp();
        $next = StepUp::safeNext($this->session->get(StepUp::NEXT_KEY)) ?? '/admin/pengguna';
        $this->session->forget(StepUp::NEXT_KEY);
        return Response::redirect($next);
    }

    /** @param list<string> $errors */
    private function stepUpPage(Account $acc, array $errors, int $status): Response
    {
        $fields = [self::field('password', 'Password', 'password', 'current-password')];
        if ($acc->totpEnabled) {
            $fields[] = self::field('code', 'Kode 2FA', 'text', 'one-time-code');
        }
        return $this->panel('Konfirmasi identitas', $status, [
            'errors' => $errors,
            'paragraphs' => ['Halaman administrasi memerlukan login ulang. Masukkan password' . ($acc->totpEnabled ? ' dan kode 2FA' : '') . ' Anda.'],
            'forms' => [['id' => 's', 'action' => StepUp::PATH, 'submit' => 'Lanjutkan', 'fields' => $fields]],
        ], true);
    }

    // ---------- pengaturan 2FA ----------

    private function verifyPassword(Account $acc, string $pw): bool
    {
        $valid = $this->hasher->verify($pw, $acc->passwordHash ?? $this->hasher->dummyHash());
        return $valid && $acc->passwordHash !== null;
    }

    /** @return list<array<string,mixed>> */
    private function pwFields(): array
    {
        return [self::field('password', 'Password', 'password', 'current-password')];
    }

    /** @return array<string,mixed> */
    private function disableForm(): array
    {
        return ['id' => 'd', 'action' => '/auth/2fa/disable', 'submit' => 'Nonaktifkan 2FA', 'fields' => [
            self::field('password', 'Password', 'password', 'current-password'),
            self::field('code', 'Kode 2FA atau kode pemulihan', 'text', 'one-time-code'),
        ]];
    }

    /** Perubahan 2FA: cabut ingat-saya dan sesi lain, lalu beri tahu pemilik lewat email (antrean tunda). */
    private function twofaChanged(Account $acc, string $what): void
    {
        $this->remember->revokeAll($acc->id);
        $this->auth->revokeOtherSessions($acc->id);
        $this->queueMail($acc->email, 'Perubahan autentikasi dua langkah',
            "Halo,\n\n2FA pada akun Anda baru saja {$what}. Semua perangkat lain dikeluarkan.\n\n"
            . "Jika ini bukan Anda, segera atur ulang password Anda dan hubungi administrator.\n");
        $this->logger?->info('2FA berubah', ['user_id' => $acc->id, 'aksi' => $what]);
    }

    /** @param array<string,string> $p */
    private function twofaForm(Request $r, array $p): Response
    {
        $acc = $this->requireAccount();
        if ($acc instanceof Response) {
            return $acc;
        }
        if ($acc->totpEnabled) {
            return $this->panel('Autentikasi dua langkah', 200, [
                'paragraphs' => ['2FA aktif. Untuk menonaktifkan, masukkan password dan kode 2FA (atau kode pemulihan) Anda.'],
                'forms' => [$this->disableForm()],
            ], true);
        }
        return $this->panel('Autentikasi dua langkah', 200, [
            'paragraphs' => ['2FA belum aktif. Masukkan password Anda untuk memulai.'],
            'forms' => [['id' => 'b', 'action' => '/auth/2fa/begin', 'submit' => 'Mulai aktifkan 2FA', 'fields' => $this->pwFields()]],
        ], true);
    }

    /** @param array<string,string> $p */
    private function twofaBegin(Request $r, array $p): Response
    {
        $acc = $this->requireAccount();
        if ($acc instanceof Response || $this->twofa === null) {
            return $acc instanceof Response ? $acc : Response::redirect('/');
        }
        if ($acc->totpEnabled) {
            return Response::redirect('/auth/2fa');
        }
        $this->throttle->login('2fa-setup:' . $acc->id, $r->remoteAddr);
        if (!$this->verifyPassword($acc, self::str($r->post['password'] ?? null))) {
            return $this->panel('Autentikasi dua langkah', 401, [
                'errors' => ['Password salah.'],
                'forms' => [['id' => 'b', 'action' => '/auth/2fa/begin', 'submit' => 'Mulai aktifkan 2FA', 'fields' => $this->pwFields()]],
            ], true);
        }
        $secret = $this->twofa->begin($acc->id);
        return $this->confirmPage($secret, $acc->email, [], 200);
    }

    /** @param array<string,string> $p */
    private function twofaConfirm(Request $r, array $p): Response
    {
        $acc = $this->requireAccount();
        if ($acc instanceof Response || $this->twofa === null) {
            return $acc instanceof Response ? $acc : Response::redirect('/');
        }
        $this->throttle->otp($acc->id, $r->remoteAddr);
        $secret = $this->twofa->pendingSecret($acc);
        if ($secret === null) {
            return Response::redirect('/auth/2fa');
        }
        if (!$this->verifyPassword($acc, self::str($r->post['password'] ?? null))) {
            // S4: secret tertunda hanya ditampilkan setelah password valid.
            return $this->panel('Aktifkan 2FA', 401, [
                'errors' => ['Password salah.'],
                'forms' => [['id' => 'c', 'action' => '/auth/2fa/confirm', 'submit' => 'Konfirmasi', 'fields' => $this->confirmFields()]],
            ], true);
        }
        $codes = $this->twofa->confirm($acc->id, self::str($r->post['code'] ?? null));
        if ($codes === null) {
            return $this->confirmPage($secret, $acc->email, ['Kode salah.'], 422);
        }
        $this->twofaChanged($acc, 'diaktifkan');
        return $this->panel('2FA aktif', 200, [
            'paragraphs' => ['Simpan kode pemulihan ini di tempat aman. Setiap kode hanya berlaku sekali dan tidak akan ditampilkan lagi.'],
            'codes' => $codes,
        ], true);
    }

    /** @param array<string,string> $p */
    private function twofaDisable(Request $r, array $p): Response
    {
        $acc = $this->requireAccount();
        if ($acc instanceof Response || $this->twofa === null) {
            return $acc instanceof Response ? $acc : Response::redirect('/');
        }
        $this->throttle->login('2fa-disable:' . $acc->id, $r->remoteAddr);
        $ok = $this->verifyPassword($acc, self::str($r->post['password'] ?? null));
        if ($ok && $acc->totpEnabled) {
            $this->throttle->otp($acc->id, $r->remoteAddr);
            $ok = $this->twofa->verifyLogin($acc, self::str($r->post['code'] ?? null)); // OTP lama wajib
        }
        if (!$ok) {
            return $this->panel('Autentikasi dua langkah', 401, [
                'errors' => ['Password atau kode salah.'],
                'forms' => [$this->disableForm()],
            ], true);
        }
        $this->twofa->disable($acc->id);
        $this->twofaChanged($acc, 'dinonaktifkan');
        $this->session->flash('ok', '2FA dinonaktifkan.');
        return Response::redirect('/auth/2fa');
    }

    private function requireAccount(): Account|Response
    {
        $id = $this->auth->current();
        $acc = $id === null ? null : $this->accounts->find($id->userId);
        return $acc ?? Response::redirect('/login');
    }

    // ---------- tampilan ----------

    /** @param list<string> $errors */
    private function loginPage(array $errors, string $email, int $status): Response
    {
        $bg = $this->opts['breakGlass'];
        $fields = [
            self::field('email', 'Email', 'email', 'username', $email),
            self::field('password', 'Password', 'password', 'current-password'),
        ];
        if (!$bg) {
            $fields[] = ['name' => 'remember', 'label' => 'Ingat saya', 'isCheck' => true, 'type' => '', 'value' => '', 'autocomplete' => ''];
        }
        return $this->panel($bg ? 'Login darurat' : 'Masuk', $status, [
            'errors' => $errors,
            'forms' => [['id' => 'l', 'action' => $bg ? $this->opts['loginPath'] : '/login', 'submit' => 'Masuk', 'fields' => $fields]],
            'links' => $bg ? [] : [['href' => '/auth/forgot', 'label' => 'Lupa password?']],
        ]);
    }

    /** @param list<string> $errors */
    private function otpPage(array $errors, int $status): Response
    {
        return $this->panel('Verifikasi dua langkah', $status, [
            'errors' => $errors,
            'paragraphs' => ['Masukkan kode 6 digit dari aplikasi autentikator, atau salah satu kode pemulihan.'],
            'forms' => [['id' => 'o', 'action' => '/auth/otp', 'submit' => 'Verifikasi',
                'fields' => [self::field('code', 'Kode', 'text', 'one-time-code')]]],
        ]);
    }

    /** @param list<string> $errors */
    private function forgotPage(array $errors, int $status): Response
    {
        return $this->panel('Lupa password', $status, [
            'errors' => $errors,
            'forms' => [['id' => 'f', 'action' => '/auth/forgot', 'submit' => 'Kirim tautan',
                'fields' => [self::field('email', 'Email', 'email', 'username')]]],
            'links' => [['href' => '/login', 'label' => 'Kembali ke login']],
        ]);
    }

    /** @param list<string> $errors */
    private function resetPage(array $errors, int $status): Response
    {
        return $this->panel('Atur ulang password', $status, [
            'errors' => $errors,
            'paragraphs' => ['Minimal ' . PasswordPolicy::MIN_LENGTH . ' karakter; kalimat sandi yang panjang lebih baik.'],
            'forms' => [['id' => 'r', 'action' => '/auth/reset', 'submit' => 'Simpan password', 'fields' => [
                self::field('password', 'Password baru', 'password', 'new-password'),
                self::field('password2', 'Ulangi password', 'password', 'new-password'),
            ]]],
        ]);
    }

    /** @param list<string> $errors */
    private function registerPage(array $errors, string $name, string $email, int $status): Response
    {
        return $this->panel('Daftar', $status, [
            'errors' => $errors,
            'forms' => [['id' => 'g', 'action' => '/auth/register', 'submit' => 'Daftar', 'fields' => [
                self::field('name', 'Nama', 'text', 'name', $name),
                self::field('email', 'Email', 'email', 'username', $email),
            ]]],
            'links' => [['href' => '/login', 'label' => 'Sudah punya akun?']],
        ]);
    }

    /** @param list<string> $errors */
    private function confirmPage(string $secret, string $email, array $errors, int $status): Response
    {
        return $this->panel('Aktifkan 2FA', $status, [
            'errors' => $errors,
            'paragraphs' => [
                'Tambahkan akun ke aplikasi autentikator dengan kunci berikut (jenis: berbasis waktu, 6 digit):',
                'Kunci: ' . $secret,
                'URI: ' . Totp::uri($secret, $email, $this->opts['issuer']),
                'Lalu masukkan kode 6 digit yang ditampilkan untuk konfirmasi.',
            ],
            'forms' => [['id' => 'c', 'action' => '/auth/2fa/confirm', 'submit' => 'Konfirmasi',
                'fields' => $this->confirmFields()]],
        ], true);
    }

    /** @return list<array<string,mixed>> */
    private function confirmFields(): array
    {
        return [self::field('password', 'Password', 'password', 'current-password'), self::field('code', 'Kode', 'text', 'one-time-code')];
    }

    private function invalidLink(): Response
    {
        return $this->panel('Tautan tidak valid', 400, [
            'paragraphs' => ['Tautan tidak valid atau sudah kedaluwarsa. Minta tautan baru.'],
            'links' => [['href' => '/auth/forgot', 'label' => 'Lupa password'], ['href' => '/login', 'label' => 'Login']],
        ]);
    }

    /**
     * @param array<string,mixed> $vars
     */
    private function panel(string $title, int $status, array $vars, bool $loggedIn = false): Response
    {
        $vars += ['errors' => [], 'paragraphs' => [], 'codes' => [], 'forms' => [], 'links' => []];
        $content = $this->views->render('panel', $vars + ['heading' => $title, 'csrf' => $this->csrf->token()]);
        $html = $this->layout->render('layout', [
            'title' => $title,
            'csrf' => $this->csrf->token(),
            'user' => null,
            'nav' => [],
            'active' => '',
            'flash' => $this->session->pullFlash(),
            'scripts' => [],
            'bodyClass' => $loggedIn ? '' : 'auth',
            'content' => $content,
        ]);
        return Response::html($html->toString(), $status)->withHeader('Cache-Control', 'no-store');
    }

    /** @return array<string,mixed> */
    private static function field(string $name, string $label, string $type, string $autocomplete, string $value = ''): array
    {
        return ['name' => $name, 'label' => $label, 'type' => $type, 'autocomplete' => $autocomplete, 'value' => $value, 'isCheck' => false];
    }

    private function queueMail(string $to, string $subject, string $body): void
    {
        $from = $this->opts['from'];
        $fromName = $this->opts['fromName'];
        $mailer = $this->mailer;
        $logger = $this->logger;
        $this->deferred->push(static function () use ($mailer, $to, $subject, $body, $from, $fromName, $logger): void {
            try {
                $mailer->send(new Message($to, $subject, $body, $from, $fromName));
            } catch (MailException) {
                $logger?->error('Email autentikasi gagal dikirim');
            }
        });
    }

    private static function str(mixed $v): string
    {
        return is_string($v) ? $v : '';
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }
}
