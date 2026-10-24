<?php

declare(strict_types=1);

namespace bFramework\Tests\Core;

use bFramework\Core\Config;
use bFramework\Core\Json;
use PHPUnit\Framework\TestCase;

final class JsonConfigTest extends TestCase
{
    public function test_BLD_03_pretty_deterministik_dua_spasi(): void
    {
        $d = ['b' => ['x' => 1.0, 'y' => 'é/'], 'a' => [1, 2]];
        $s = Json::pretty($d);
        self::assertSame($s, Json::pretty($d));
        self::assertStringContainsString("\n  \"b\": {\n    \"x\": 1.0,", $s);
        self::assertStringEndsWith("}\n", $s);
        self::assertSame($d, json_decode($s, true));
    }

    public function test_BLD_03_roundtrip_byte_identik(): void
    {
        $f = tempnam(sys_get_temp_dir(), 'j');
        self::assertIsString($f);
        file_put_contents($f, Json::pretty(['k' => ['z' => 1, 'a' => null]]));
        $before = file_get_contents($f);
        file_put_contents($f, Json::pretty(Json::read($f)));
        self::assertSame($before, file_get_contents($f));
        unlink($f);
    }

    public function test_read_file_tidak_ada_dan_rusak(): void
    {
        self::assertSame([], Json::read('/nonexistent/x.json'));
        $f = tempnam(sys_get_temp_dir(), 'j');
        self::assertIsString($f);
        file_put_contents($f, '{bad');
        try {
            $this->expectException(\JsonException::class);
            Json::read($f);
        } finally {
            unlink($f);
        }
    }

    public function test_config_exportable_tanpa_rahasia(): void
    {
        Config::set(['APP_KEY' => 'k', 'DB_PASSWORD' => 'p', 'client_secret' => 's', 'app_name' => 'n',
            'smtp' => ['SMTP_PASSWORD' => 'x', 'host' => 'h']]);
        self::assertSame('n', Config::get('app_name'));
        self::assertSame('d', Config::get('none', 'd'));
        self::assertSame(['app_name' => 'n', 'smtp' => ['host' => 'h']], Config::exportable());
        Config::set([]);
    }
}
