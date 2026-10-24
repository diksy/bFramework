<?php

declare(strict_types=1);

namespace bFramework\Core;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Logger;
use Throwable;

/**
 * Penanganan error global (SEC-LOG-01): display_errors dimatikan, error tidak tertangkap dicatat
 * ke Logger, dan pengguna hanya melihat halaman generik tanpa pesan, trace, atau path.
 */
final class ErrorHandler
{
    private const TEMPLATE = 'error';
    private const MAX_PREVIOUS = 5;
    private const FALLBACK = '<!doctype html><html lang="id"><meta charset="utf-8"><title>Kesalahan</title>'
        . '<h1>Terjadi kesalahan</h1><p>Permintaan tidak dapat diproses. Silakan coba lagi nanti.</p>';

    public function __construct(
        private readonly bool $production,
        private readonly Logger $logger,
        private readonly Template $template,
    ) {
    }

    /** Membuat handler dan memasangnya sebagai handler global. */
    public static function register(bool $production, Logger $logger, Template $template): self
    {
        $handler = new self($production, $logger, $template);
        $handler->install();
        return $handler;
    }

    public function install(): void
    {
        ini_set('display_errors', '0');
        ini_set('log_errors', '0');
        error_reporting(E_ALL);
        set_error_handler(function (int $no, string $message, string $file, int $line): bool {
            return $this->onError($no, $message, $file, $line);
        });
        set_exception_handler(function (Throwable $e): void {
            $this->onException($e);
        });
        register_shutdown_function(function (): void {
            $this->onShutdown();
        });
    }

    public function onError(int $no, string $message, string $file, int $line): bool
    {
        if ((error_reporting() & $no) === 0) {
            return false;
        }
        $this->logger->warning('PHP error', [
            'errno' => $no,
            'file' => basename($file),
            'line' => $line,
            'pesan' => $message,
        ]);
        return true;
    }

    public function onException(Throwable $e): void
    {
        $this->logger->error('Exception tidak tertangkap', self::context($e));
        if (!headers_sent()) {
            $this->page(500)->send();
        }
    }

    public function onShutdown(): void
    {
        $err = error_get_last();
        if ($err === null || !in_array($err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
            return;
        }
        $this->logger->error('Fatal error', [
            'errno' => $err['type'],
            'file' => basename($err['file']),
            'line' => $err['line'],
            'pesan' => $err['message'],
        ]);
        if (!headers_sent()) {
            $this->page(500)->send();
        }
    }

    /** Halaman error generik untuk status HTTP tertentu (dipakai Kernel). Tidak pernah melempar. */
    public function page(int $status): Response
    {
        $status = ($status >= 400 && $status < 600) ? $status : 500;
        try {
            $html = $this->template->render(self::TEMPLATE, [
                'status' => $status,
                'message' => self::message($status),
                'hint' => $this->production ? '' : 'Detail teknis tersedia di storage/logs.',
            ])->toString();
        } catch (Throwable $e) {
            $this->logger->error('Template halaman error gagal', ['class' => $e::class]);
            $html = self::FALLBACK;
        }
        return Response::html($html, $status);
    }

    /**
     * Konteks log untuk exception: kelas, berkas, baris, pesan, dan rantai previous (datar, maks. 5 tingkat).
     * Dipakai bersama oleh onException dan Kernel agar detail selalu disamarkan lewat Redactor.
     *
     * @return array<string,scalar>
     */
    public static function context(Throwable $e): array
    {
        $ctx = [];
        $current = $e;
        for ($depth = 0; $current !== null && $depth <= self::MAX_PREVIOUS; $depth++) {
            $prefix = $depth === 0 ? '' : 'prev' . $depth . '_';
            $ctx[$prefix . 'class'] = $current::class;
            $ctx[$prefix . 'file'] = basename($current->getFile());
            $ctx[$prefix . 'line'] = $current->getLine();
            $ctx[$prefix . 'pesan'] = $current->getMessage();
            $current = $current->getPrevious();
        }
        /** @var array<string,scalar> $clean */
        $clean = Redactor::clean($ctx);
        return $clean;
    }

    private static function message(int $status): string
    {
        return match ($status) {
            400 => 'Permintaan tidak valid.',
            403 => 'Akses ditolak.',
            404 => 'Halaman tidak ditemukan.',
            405 => 'Metode tidak diizinkan.',
            419 => 'Sesi kedaluwarsa. Muat ulang halaman lalu coba lagi.',
            429 => 'Terlalu banyak permintaan. Coba lagi nanti.',
            default => $status >= 500 ? 'Terjadi kesalahan pada server.' : 'Permintaan gagal.',
        };
    }
}
