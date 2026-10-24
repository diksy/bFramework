<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Logger;
use bFramework\Core\Response;

/**
 * Pekerjaan yang dijalankan SETELAH respons dikirim (mis. kirim email), sehingga waktu respons
 * "lupa password"/registrasi tidak membedakan email terdaftar dan tidak.
 */
final class Deferred
{
    /** @var list<\Closure> */
    private array $jobs = [];

    public function __construct(private readonly ?Logger $logger = null)
    {
    }

    public function push(\Closure $job): void
    {
        $this->jobs[] = $job;
    }

    public function pending(): int
    {
        return count($this->jobs);
    }

    /**
     * Kirim respons, tutup koneksi ke klien, baru jalankan pekerjaan tunda. $emit/$close dapat diganti (tes).
     *
     * @param (\Closure():void)|null $emit
     * @param (\Closure():void)|null $close
     */
    public function respondThenRun(Response $response, ?\Closure $emit = null, ?\Closure $close = null): void
    {
        if ($this->jobs !== []) {
            if ($response->body !== '') {
                $response = $response->withHeader('Content-Length', (string) strlen($response->body));
            }
            $response = $response->withHeader('Connection', 'close');
        }
        ($emit ?? static function () use ($response): void {
            $response->send();
        })();
        if ($this->jobs !== []) {
            ($close ?? static function (): void {
                if (function_exists('fastcgi_finish_request')) {
                    fastcgi_finish_request();
                    return;
                }
                while (ob_get_level() > 0) {
                    ob_end_flush();
                }
                flush();
            })();
        }
        $this->run();
    }

    public function run(): void
    {
        // Pekerjaan boleh menambah pekerjaan baru (mis. kirim email); ulangi sampai antrean kosong.
        while ($this->jobs !== []) {
            $jobs = $this->jobs;
            $this->jobs = [];
            foreach ($jobs as $job) {
                try {
                    $job();
                } catch (\Throwable) {
                    $this->logger?->error('Pekerjaan tertunda gagal');
                }
            }
        }
    }
}
