<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Identity;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\Router;

/** AUTH-01: semua driver (local, bikinin_sso) memakai antarmuka yang sama. Driver hanya menjawab "siapa user ini". */
interface AuthDriver
{
    public function name(): string;

    public function registerRoutes(Router $router): void;

    public function authenticate(Request $request): AuthResult;

    public function logout(Request $request, Identity $identity): Response;
}
