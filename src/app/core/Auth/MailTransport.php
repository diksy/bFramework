<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

interface MailTransport
{
    /** @throws MailException */
    public function send(Message $m): void;
}
