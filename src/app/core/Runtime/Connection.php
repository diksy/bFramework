<?php

declare(strict_types=1);

namespace bFramework\Runtime;

defined('APP_BOOTED') || exit;

use bFramework\Contracts\Dialect;
use PDO;
use PDOException;
use RuntimeException;

final class Connection
{
    private function __construct(private readonly PDO $pdo, private readonly Dialect $dialect)
    {
    }

    /** Path ':memory:' atau file; file harus dikelola pemanggil. */
    public static function sqlite(string $path): self
    {
        if ($path === '' || str_contains($path, "\0")) {
            throw new RuntimeException('Path database tidak valid');
        }
        try {
            $pdo = new PDO('sqlite:' . $path, null, null, self::options());
            $pdo->exec('PRAGMA foreign_keys = ON');
        } catch (PDOException) {
            throw new RuntimeException('Koneksi database gagal');
        }
        return new self($pdo, Dialect::Sqlite);
    }

    /** Kredensial berasal dari Config/env oleh pemanggil; pesan galat tidak memuat DSN/sandi. */
    public static function mysql(string $host, string $db, string $user, string $pass, int $port = 3306): self
    {
        if (preg_match('/^[A-Za-z0-9._-]{1,255}$/D', $host) !== 1 || preg_match('/^[A-Za-z0-9_]{1,64}$/D', $db) !== 1) {
            throw new RuntimeException('Host/nama database tidak valid');
        }
        try {
            $pdo = new PDO("mysql:host=$host;port=$port;dbname=$db;charset=utf8mb4", $user, $pass, self::options());
        } catch (PDOException) {
            throw new RuntimeException('Koneksi database gagal');
        }
        return new self($pdo, Dialect::MySql);
    }

    /** @return array<int,mixed> */
    private static function options(): array
    {
        return [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_STRINGIFY_FETCHES => false,
        ];
    }

    public function pdo(): PDO
    {
        return $this->pdo;
    }

    public function dialect(): Dialect
    {
        return $this->dialect;
    }

    public function grammar(): Grammar
    {
        return $this->dialect === Dialect::MySql ? new MySqlGrammar() : new SqliteGrammar();
    }
}
