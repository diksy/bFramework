<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Action;
use bFramework\Contracts\Forbidden;
use bFramework\Contracts\Identity;
use bFramework\Contracts\Logger;
use bFramework\Contracts\NotFound;
use bFramework\Contracts\SessionStore;
use bFramework\Core\Csrf;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\Router;
use bFramework\Core\Template;
use bFramework\Runtime\Authorizer;
use bFramework\Runtime\Navigation;
use InvalidArgumentException;

/**
 * Halaman admin F16: /admin/pengguna, /admin/peran, dan POST /peran-aktif. Setiap rute admin melewati
 * Authorizer (hanya peran aktif "admin"; anonim diarahkan ke login, peran lain 403) dan CSRF (default Router).
 * Input form dibaca per kunci eksplisit (tanpa mass assignment): peran hanya dari daftar RoleStore, status
 * hanya active/disabled, hash/secret tidak pernah ada di form. Reset password hanya lewat tautan email
 * sekali pakai; password tidak pernah ditampilkan atau disetel admin. Audit perubahan ke log tanpa data sensitif.
 */
final class AdminController
{
    /** Definisi akses sintetis untuk Authorizer (SEC-AUTHZ-01). */
    private const ACCESS = ['access' => ['read' => ['admin'], 'write' => ['admin']]];
    private const PER_PAGE = 25;
    private const PENDING_MAX_AGE = 604800; // 7 hari

    /** @var array{appUrl:string,from:string,fromName:string,resetTtl:int} */
    private array $opts;

    /**
     * @param \Closure():array<string,array<string,mixed>> $pages halaman ter-compile untuk menu samping
     * @param StepUp $stepUp gerbang re-auth untuk sesi tanpa password segar
     * @param array<string,mixed> $opts appUrl (wajib), from, fromName, resetTtl
     */
    public function __construct(
        private readonly AuthManager $auth,
        private readonly DbUserStore $users,
        private readonly RoleStore $roles,
        private readonly OneTimeToken $tokens,
        private readonly Mailer $mailer,
        private readonly Deferred $deferred,
        private readonly SessionStore $session,
        private readonly Csrf $csrf,
        private readonly Template $views,
        private readonly Template $layout,
        private readonly Authorizer $authz,
        private readonly \Closure $pages,
        private readonly StepUp $stepUp,
        array $opts,
        private readonly ?Logger $logger = null,
    ) {
        $url = rtrim(is_string($opts['appUrl'] ?? null) ? $opts['appUrl'] : '', '/');
        if (preg_match('#^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$#D', $url) !== 1) {
            throw new InvalidArgumentException('APP_URL tidak valid');
        }
        $ttl = $opts['resetTtl'] ?? null;
        $this->opts = [
            'appUrl' => $url,
            'from' => is_string($opts['from'] ?? null) && $opts['from'] !== '' ? $opts['from'] : 'noreply@example.invalid',
            'fromName' => is_string($opts['fromName'] ?? null) && $opts['fromName'] !== '' ? $opts['fromName'] : 'BikininFramework',
            'resetTtl' => is_int($ttl) && $ttl >= 60 && $ttl <= OneTimeToken::MAX_TTL ? $ttl : 1800,
        ];
    }

    public function registerRoutes(Router $router): void
    {
        $r = static function (Router $router, string $method, string $path, \Closure $h): void {
            $router->add($method, $path, $h);
        };
        $read = fn(string $m): \Closure => fn(Request $q, array $p = []): Response => $this->guarded(Action::Read, $m, $q, $p);
        $write = fn(string $m): \Closure => fn(Request $q, array $p = []): Response => $this->guarded(Action::Update, $m, $q, $p);

        $r($router, 'GET', '/admin/pengguna', $read('usersList'));
        $r($router, 'GET', '/admin/pengguna/baru', $read('userNew'));
        $r($router, 'POST', '/admin/pengguna', $write('userCreate'));
        $r($router, 'POST', '/admin/pengguna/bersihkan', $write('usersCleanup'));
        $r($router, 'GET', '/admin/pengguna/{id}', $read('userEdit'));
        $r($router, 'POST', '/admin/pengguna/{id}', $write('userUpdate'));
        $r($router, 'POST', '/admin/pengguna/{id}/status', $write('userStatus'));
        $r($router, 'POST', '/admin/pengguna/{id}/reset', $write('userReset'));
        $r($router, 'POST', '/admin/pengguna/{id}/hapus', $write('userDelete'));
        $r($router, 'GET', '/admin/peran', $read('rolesList'));
        $r($router, 'POST', '/admin/peran', $write('roleCreate'));
        $r($router, 'POST', '/admin/peran/{id}/hapus', $write('roleDelete'));
        $router->add('POST', '/peran-aktif', fn(Request $q, array $p = []): Response => $this->switchRole($q));
    }

    /** @param array<string,string> $p */
    private function guarded(Action $action, string $method, Request $r, array $p): Response
    {
        $who = $this->auth->current();
        if ($who === null) {
            return Response::redirect('/login');
        }
        if (!$this->authz->can(self::ACCESS, $action, $who)) {
            throw new Forbidden('Akses ditolak');
        }
        if (!$this->stepUp->satisfied($who)) {
            return $this->stepUp->redirect($r); // sesi ingat-saya: wajib re-auth (S3)
        }
        /** @var Response */
        return $this->$method($r, $p, $who);
    }

    // ---------- ganti peran aktif ----------

    private function switchRole(Request $r): Response
    {
        $who = $this->auth->current();
        if ($who === null) {
            return Response::redirect('/login');
        }
        $role = $r->post['role'] ?? null;
        if (!is_string($role) || !in_array($role, $who->roles, true)) {
            $this->logger?->warning('Ganti peran ditolak: peran tidak dimiliki', ['user_id' => $who->userId]);
            throw new Forbidden('Peran tidak dimiliki');
        }
        $new = $this->auth->switchRole($role); // regenerate sesi + Csrf::rotate (SEC-SESS-02)
        $this->logger?->info('Peran aktif diganti', ['user_id' => $who->userId, 'from' => $who->activeRole, 'to' => $new->activeRole]);
        return Response::redirect('/');
    }

    // ---------- pengguna ----------

    /** @param array<string,string> $p */
    private function usersList(Request $r, array $p, Identity $who): Response
    {
        $total = $this->users->count();
        $pages = max(1, (int) ceil($total / self::PER_PAGE));
        $page = $this->intOr($r->query['page'] ?? null, 1, 1, $pages);
        $rows = [];
        foreach ($this->users->list(self::PER_PAGE, ($page - 1) * self::PER_PAGE) as $u) {
            $rows[] = [
                'id' => $u->id, 'name' => $u->name, 'email' => $u->email, 'status' => $u->status,
                'roles' => implode(', ', $u->roles), 'href' => '/admin/pengguna/' . $u->id,
            ];
        }
        $pager = [];
        for ($i = 1; $i <= $pages; $i++) {
            $pager[] = ['n' => $i, 'href' => '/admin/pengguna?page=' . $i, 'on' => $i === $page];
        }
        return $this->render('Pengguna', 'admin_users', [
            'rows' => $rows, 'empty' => $rows === [], 'total' => $total, 'pager' => $pager, 'multiPage' => $pages > 1,
            'csrf' => $this->csrf->token(),
        ], $who, 'pengguna');
    }

    /** @param array<string,string> $p */
    private function userNew(Request $r, array $p, Identity $who): Response
    {
        return $this->render('Pengguna baru', 'admin_user_form', [
            'isNew' => true, 'action' => '/admin/pengguna', 'csrf' => $this->csrf->token(),
            'u' => ['name' => '', 'email' => ''], 'roleOptions' => $this->roleOptions([]),
        ], $who, 'pengguna');
    }

    /** @param array<string,string> $p */
    private function userCreate(Request $r, array $p, Identity $who): Response
    {
        $email = $this->str($r->post['email'] ?? null);
        $name = $this->str($r->post['name'] ?? null);
        $roles = $this->postedRoles($r);
        if ($roles === []) {
            return $this->fail('/admin/pengguna/baru', 'Pilih minimal satu peran.');
        }
        try {
            // Akun dibuat tanpa password dan berstatus pending; pengguna menyetel sendiri lewat tautan email.
            $user = $this->users->create(new NewUser($email, $name, null, 'pending', null, $roles));
        } catch (InvalidArgumentException $e) {
            return $this->fail('/admin/pengguna/baru', $e->getMessage());
        }
        $this->audit('Pengguna dibuat', $who, $user->id, ['roles' => implode(',', $roles)]);
        $this->mailLink($user, 'Undangan akun', "Halo,\n\nAdministrator membuat akun untuk Anda. Buka tautan berikut untuk menyetel password sendiri (berlaku %d menit, sekali pakai):\n\n%s\n\nAbaikan email ini bila Anda tidak mengenalinya.\n");
        $this->session->flash('ok', 'Pengguna dibuat; tautan penyetelan password dikirim ke emailnya.');
        return Response::redirect('/admin/pengguna/' . $user->id);
    }

    /** @param array<string,string> $p */
    private function userEdit(Request $r, array $p, Identity $who): Response
    {
        $u = $this->target($p);
        return $this->render('Ubah pengguna', 'admin_user_form', [
            'isNew' => false, 'action' => '/admin/pengguna/' . $u->id, 'csrf' => $this->csrf->token(),
            'u' => ['id' => $u->id, 'name' => $u->name, 'email' => $u->email, 'status' => $u->status,
                'totp' => $u->totpEnabled, 'isSelf' => $u->id === $who->userId,
                'canDisable' => $u->status === 'active', 'canEnable' => $u->status === 'disabled',
                'resetAction' => '/admin/pengguna/' . $u->id . '/reset', 'statusAction' => '/admin/pengguna/' . $u->id . '/status',
                'deleteAction' => '/admin/pengguna/' . $u->id . '/hapus'],
            'roleOptions' => $this->roleOptions($u->roles),
        ], $who, 'pengguna');
    }

    /** @param array<string,string> $p */
    private function userUpdate(Request $r, array $p, Identity $who): Response
    {
        $u = $this->target($p);
        $back = '/admin/pengguna/' . $u->id;
        $roles = $this->postedRoles($r);
        if ($roles === []) {
            return $this->fail($back, 'Pilih minimal satu peran.');
        }
        try {
            // Hanya name yang diteruskan dari form; email/status/hash/sso tidak bisa diisi dari sini.
            $this->users->update($u->id, ['name' => $this->str($r->post['name'] ?? null)]);
            $before = $u->roles;
            $this->users->setRoles($u->id, $roles);
        } catch (RuleViolation | InvalidArgumentException $e) {
            return $this->fail($back, $e->getMessage());
        }
        $after = $this->users->roles($u->id);
        if ($before !== $after) {
            $this->audit('Peran pengguna diubah', $who, $u->id, [
                'added' => implode(',', array_values(array_diff($after, $before))),
                'removed' => implode(',', array_values(array_diff($before, $after))),
            ]);
        }
        $this->session->flash('ok', 'Pengguna diperbarui.');
        return Response::redirect($back);
    }

    /** @param array<string,string> $p */
    private function userStatus(Request $r, array $p, Identity $who): Response
    {
        $u = $this->target($p);
        $back = '/admin/pengguna/' . $u->id;
        $to = $r->post['status'] ?? null;
        if (!is_string($to) || !in_array($to, ['active', 'disabled'], true)) {
            return $this->fail($back, 'Status tidak valid.');
        }
        if ($to === 'disabled' && $u->id === $who->userId) {
            return $this->fail($back, 'Anda tidak dapat menonaktifkan akun sendiri.');
        }
        if ($to === 'active' && $u->status === 'pending') {
            return $this->fail($back, 'Akun pending diaktifkan oleh pemiliknya lewat tautan email.');
        }
        try {
            $this->users->update($u->id, ['status' => $to]);
        } catch (RuleViolation | InvalidArgumentException $e) {
            return $this->fail($back, $e->getMessage());
        }
        $this->audit('Status pengguna diubah', $who, $u->id, ['status' => $to]);
        $this->session->flash('ok', $to === 'disabled' ? 'Akun dinonaktifkan; semua sesi dan token pengguna dicabut.' : 'Akun diaktifkan.');
        return Response::redirect($back);
    }

    /** @param array<string,string> $p */
    private function userReset(Request $r, array $p, Identity $who): Response
    {
        $u = $this->target($p);
        $back = '/admin/pengguna/' . $u->id;
        if (!in_array($u->status, ['active', 'pending'], true)) {
            return $this->fail($back, 'Akun nonaktif tidak dapat direset.');
        }
        $this->mailLink($u, 'Atur ulang password', "Halo,\n\nAdministrator memulai pengaturan ulang password akun Anda. Buka tautan berikut (berlaku %d menit, sekali pakai):\n\n%s\n\nAbaikan email ini bila Anda tidak mengharapkannya.\n");
        $this->audit('Reset password dimulai admin', $who, $u->id, []);
        $this->session->flash('ok', 'Tautan reset dikirim ke email pengguna.');
        return Response::redirect($back);
    }

    /** @param array<string,string> $p */
    private function userDelete(Request $r, array $p, Identity $who): Response
    {
        $u = $this->target($p);
        if ($u->id === $who->userId) {
            return $this->fail('/admin/pengguna/' . $u->id, 'Anda tidak dapat menghapus akun sendiri.');
        }
        try {
            $this->users->delete($u->id);
        } catch (RuleViolation | InvalidArgumentException $e) {
            return $this->fail('/admin/pengguna/' . $u->id, $e->getMessage());
        }
        $this->audit('Pengguna dihapus', $who, $u->id, []);
        $this->session->flash('ok', 'Pengguna dihapus.');
        return Response::redirect('/admin/pengguna');
    }

    /** @param array<string,string> $p */
    private function usersCleanup(Request $r, array $p, Identity $who): Response
    {
        $n = $this->users->purgeExpiredPending(self::PENDING_MAX_AGE);
        $this->session->flash('ok', $n . ' akun pending kedaluwarsa dibersihkan.');
        return Response::redirect('/admin/pengguna');
    }

    // ---------- peran ----------

    /** @param array<string,string> $p */
    private function rolesList(Request $r, array $p, Identity $who): Response
    {
        $rows = [];
        foreach ($this->roles->all() as $role) {
            $rows[] = ['id' => $role->id, 'name' => $role->name, 'label' => $role->label ?? '', 'system' => $role->system,
                'count' => $role->userCount, 'canDelete' => !$role->system, 'action' => '/admin/peran/' . $role->id . '/hapus'];
        }
        return $this->render('Peran', 'admin_roles', ['rows' => $rows, 'csrf' => $this->csrf->token()], $who, 'peran');
    }

    /** @param array<string,string> $p */
    private function roleCreate(Request $r, array $p, Identity $who): Response
    {
        try {
            $role = $this->roles->create($this->str($r->post['name'] ?? null), $this->str($r->post['label'] ?? null));
        } catch (InvalidArgumentException $e) {
            return $this->fail('/admin/peran', $e->getMessage());
        }
        $this->audit('Peran dibuat', $who, 0, ['role' => $role->name]);
        $this->session->flash('ok', 'Peran dibuat.');
        return Response::redirect('/admin/peran');
    }

    /** @param array<string,string> $p */
    private function roleDelete(Request $r, array $p, Identity $who): Response
    {
        $id = $this->idParam($p);
        $role = $this->roles->find($id) ?? throw new NotFound();
        try {
            $this->roles->delete($id);
        } catch (RuleViolation $e) {
            return $this->fail('/admin/peran', $e->getMessage());
        }
        $this->audit('Peran dihapus', $who, 0, ['role' => $role->name]);
        $this->session->flash('ok', 'Peran dihapus.');
        return Response::redirect('/admin/peran');
    }

    // ---------- util ----------

    /** @param array<string,string> $p */
    private function idParam(array $p): int
    {
        $raw = $p['id'] ?? '';
        if (preg_match('/^[1-9][0-9]{0,17}$/D', $raw) !== 1) {
            throw new NotFound();
        }
        return (int) $raw;
    }

    /** @param array<string,string> $p */
    private function target(array $p): User
    {
        return $this->users->find($this->idParam($p)) ?? throw new NotFound();
    }

    /** @return list<string> hanya nama peran yang ada di RoleStore */
    private function postedRoles(Request $r): array
    {
        $in = $r->post['roles'] ?? [];
        if (!is_array($in)) {
            return [];
        }
        $known = $this->roles->names();
        $out = [];
        foreach ($in as $v) {
            if (is_string($v) && in_array($v, $known, true)) {
                $out[$v] = $v;
            }
        }
        return array_values($out);
    }

    /**
     * @param list<string> $have
     * @return list<array{name:string,label:string,on:bool}>
     */
    private function roleOptions(array $have): array
    {
        $out = [];
        foreach ($this->roles->all() as $role) {
            $out[] = ['name' => $role->name, 'label' => $role->label ?? $role->name, 'on' => in_array($role->name, $have, true)];
        }
        return $out;
    }

    private function mailLink(User $u, string $subject, string $template): void
    {
        $token = $this->tokens->issue($u->id, OneTimeToken::RESET, $this->opts['resetTtl']);
        $body = sprintf($template, intdiv($this->opts['resetTtl'], 60), $this->opts['appUrl'] . '/auth/reset/' . $token);
        $to = $u->email;
        $mailer = $this->mailer;
        $logger = $this->logger;
        $from = $this->opts['from'];
        $fromName = $this->opts['fromName'];
        $this->deferred->push(static function () use ($mailer, $to, $subject, $body, $from, $fromName, $logger): void {
            try {
                $mailer->send(new Message($to, $subject, $body, $from, $fromName));
            } catch (MailException) {
                $logger?->error('Email admin gagal dikirim');
            }
        });
    }

    /** @param array<string,scalar> $extra tanpa data sensitif (tanpa email/nama/hash) */
    private function audit(string $event, Identity $who, int $target, array $extra): void
    {
        $this->logger?->info('audit: ' . $event, ['actor_id' => $who->userId, 'actor_role' => $who->activeRole, 'target_id' => $target] + $extra);
    }

    private function fail(string $to, string $msg): Response
    {
        $this->session->flash('err', $msg);
        return Response::redirect($to);
    }

    private function str(mixed $v): string
    {
        return is_string($v) ? $v : '';
    }

    private function intOr(mixed $v, int $d, int $min, int $max): int
    {
        return is_string($v) && preg_match('/^[0-9]{1,6}$/D', $v) === 1 ? max($min, min($max, (int) $v)) : $d;
    }

    /** @param array<string,mixed> $vars */
    private function render(string $title, string $view, array $vars, Identity $who, string $active, int $status = 200): Response
    {
        $content = $this->views->render($view, $vars);
        $pages = [];
        try {
            $pages = ($this->pages)();
        } catch (\Throwable) {
            $this->logger?->warning('Definisi halaman tidak terbaca untuk menu');
        }
        $html = $this->layout->render('layout', [
            'title' => $title,
            'csrf' => $this->csrf->token(),
            'user' => ['name' => $who->activeRole, 'switch' => count($who->roles) > 1, 'roleOptions' => array_map(
                static fn(string $n): array => ['name' => $n, 'on' => $n === $who->activeRole],
                $who->roles,
            )],
            'nav' => Navigation::build($pages, $who),
            'active' => $active,
            'flash' => $this->session->pullFlash(),
            'scripts' => ['/assets/app.js'],
            'bodyClass' => '',
            'content' => $content,
        ]);
        return Response::html($html->toString(), $status)->withHeader('Cache-Control', 'no-store');
    }
}
