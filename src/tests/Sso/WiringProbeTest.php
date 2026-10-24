<?php

declare(strict_types=1);

namespace bFramework\Tests\Sso;

use bFramework\Core\Request;
use bFramework\Sso\OidcClient;
use bFramework\Tests\Fixtures\AuthHarness;
use bFramework\Tests\Fixtures\FakeIdp;
use bFramework\Tests\Fixtures\FakeClock;
use PHPUnit\Framework\TestCase;

final class WiringProbeTest extends TestCase
{
    /** Menjalankan buildAuth di proses terpisah agar status "kelas dimuat" bersih. @return array<string,mixed> */
    private function boot(string $configPhp): array
    {
        $dir = sys_get_temp_dir() . '/ssowire_' . bin2hex(random_bytes(6));
        mkdir($dir . '/storage', 0700, true);
        symlink((string) realpath(__DIR__ . '/../../app/core'), $dir . '/core'); // view Template dicari relatif ke appDir/core
        $script = $dir . '/run.php';
        file_put_contents($script, '<?php
require ' . var_export(realpath(__DIR__ . '/../../app/bootstrap.php'), true) . ';
use bFramework\Core\Config;
Config::set(' . $configPhp . ');
$conn = bFramework\Runtime\Connection::sqlite(":memory:");
bFramework\Auth\AuthSchema::install($conn);
$kit = bFramework\buildAuth(' . var_export($dir, true) . ', $conn, false);
$router = new bFramework\Core\Router();
$kit->driver->registerRoutes($router);
$has = static fn(string $m, string $p): bool => $router->opts(new bFramework\Core\Request($m, $p)) !== null;
echo json_encode([
  "driver" => $kit->driver->name(),
  "ssoLoaded" => class_exists("bFramework\\\\Sso\\\\SsoDriver", false),
  "oidcLoaded" => class_exists("bFramework\\\\Sso\\\\OidcClient", false),
  "jwtLoaded" => class_exists("Firebase\\\\JWT\\\\JWT", false),
  "callback" => $has("GET", "/auth/sso/callback"),
  "backchannel" => $has("POST", "/auth/sso/backchannel"),
  "login" => $has("GET", "/login"),
  "forgot" => $has("GET", "/auth/forgot"),
  "breakGlass" => $has("GET", "/auth/break-glass"),
]);');
        $out = (string) shell_exec(escapeshellarg(PHP_BINARY) . ' -d display_errors=1 ' . escapeshellarg($script) . ' 2>&1');
        unlink($dir . '/core');
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) {
            $f->isDir() && !$f->isLink() ? rmdir($f->getPathname()) : unlink($f->getPathname());
        }
        rmdir($dir);
        $j = json_decode($out, true);
        self::assertIsArray($j, $out);
        return $j;
    }

    public function test_SSO_19_driver_local_callback_mengembalikan_404_lewat_kernel(): void
    {
        $b = (new AuthHarness())->browser();
        self::assertSame(404, $b->get('/auth/sso/callback?code=x&state=y')->status);
        self::assertSame(404, $b->get('/auth/sso/login')->status);
        self::assertSame(404, $b->post('/auth/sso/backchannel', ['logout_token' => 'x'], false)->status);
    }

    public function test_SSO_05_library_ikut_paket_rilis_tanpa_composer(): void
    {
        require_once __DIR__ . '/../../../tools/build-release.php';
        $files = releaseFiles(__DIR__ . '/../..');
        foreach (['JWT.php', 'JWK.php', 'Key.php', 'LICENSE'] as $f) {
            self::assertContains('app/core/vendor/firebase-php-jwt/' . $f, $files);
        }
        self::assertSame([], array_filter($files, static fn(string $f): bool => str_contains($f, 'vendor/autoload')));
    }

    private const BASE = "'APP_URL' => 'https://app.contoh.test', 'APP_KEY' => 'kunci-dummy-untuk-tes-0123456789abcdef-0123456789', 'APP_ENV' => 'production'";

    public function test_SSO_19_driver_local_tanpa_rute_sso_dan_tanpa_memuat_library(): void
    {
        $j = $this->boot('[' . self::BASE . ", 'auth' => ['driver' => 'local']]");
        self::assertSame('local', $j['driver']);
        self::assertFalse($j['callback'], '/auth/sso/callback = 404 pada driver local');
        self::assertFalse($j['backchannel']);
        self::assertFalse($j['ssoLoaded']);
        self::assertFalse($j['oidcLoaded']);
        self::assertFalse($j['jwtLoaded']);
        self::assertTrue($j['login']);
        self::assertTrue($j['forgot']);
        self::assertFalse($j['breakGlass']);
    }

    public function test_SSO_19_default_tanpa_blok_auth_adalah_local(): void
    {
        $j = $this->boot('[' . self::BASE . ']');
        self::assertSame('local', $j['driver']);
        self::assertFalse($j['ssoLoaded']);
        $j2 = $this->boot('[' . self::BASE . ", 'auth' => ['driver' => 'tidak-dikenal']]");
        self::assertSame('local', $j2['driver']);
    }

    public function test_SSO_19_hybrid_memasang_rute_sso_dan_library_dimuat_lazy(): void
    {
        $sso = "'sso' => ['issuer' => 'https://sso.contoh.test', 'client_id' => 'app-contoh', 'client_secret' => 'x-dummy']";
        $j = $this->boot('[' . self::BASE . ", 'auth' => ['driver' => 'hybrid', $sso]]");
        self::assertSame('hybrid', $j['driver']);
        self::assertTrue($j['callback']);
        self::assertTrue($j['backchannel']);
        self::assertTrue($j['breakGlass']);
        self::assertFalse($j['forgot'], 'hanya login darurat yang tersisa dari driver lokal');
        self::assertTrue($j['ssoLoaded']);
        self::assertFalse($j['jwtLoaded'], 'library JWT baru dimuat saat verifikasi pertama');
    }

    public function test_SSO_fail_closed_konfigurasi_tidak_lengkap_tidak_jatuh_ke_login_lokal(): void
    {
        $j = $this->boot('[' . self::BASE . ", 'auth' => ['driver' => 'bikinin_sso', 'sso' => ['issuer' => 'http://tidak-https']]]");
        self::assertSame('bikinin_sso', $j['driver']);
        self::assertTrue($j['callback']);
        self::assertFalse($j['forgot']);
        self::assertFalse($j['backchannel'], 'tanpa konfigurasi sah tidak ada endpoint yang bisa dipakai');
    }

    // ---------- SSO-21: Tes koneksi ----------

    private function idp(): FakeIdp
    {
        return new FakeIdp(new FakeClock());
    }

    public function test_SSO_21_koneksi_sehat(): void
    {
        $idp = $this->idp();
        $r = OidcClient::probe($idp->http(), FakeIdp::ISSUER);
        self::assertTrue($r['ok']);
        self::assertSame(['discovery', 'jwks'], array_column($r['steps'], 'name'));
        self::assertStringContainsString('1 kunci', $r['steps'][1]['msg']);
        foreach ($idp->calls as $c) {
            self::assertArrayNotHasKey('Authorization', $c['headers'], 'tanpa client_secret');
        }
    }

    public function test_SSO_21_issuer_salah_pesan_spesifik(): void
    {
        $idp = $this->idp();
        $idp->discoveryOverride = ['issuer' => 'https://sso-lain.test'];
        $r = OidcClient::probe($idp->http(), FakeIdp::ISSUER);
        self::assertFalse($r['ok']);
        self::assertStringContainsString('Issuer pada discovery tidak sama persis', $r['steps'][0]['msg']);
        self::assertCount(1, $r['steps'], 'JWKS tidak diambil dari discovery yang tidak tepercaya');
        self::assertSame(0, $idp->hits['jwks']);
    }

    public function test_SSO_21_ssrf_ip_privat_dan_format_issuer(): void
    {
        $idp = $this->idp();
        $idp->ip = '169.254.169.254';
        $r = OidcClient::probe($idp->http(), FakeIdp::ISSUER);
        self::assertFalse($r['ok']);
        self::assertStringContainsString('non-publik', $r['steps'][0]['msg']);
        self::assertSame([], $idp->calls);
        foreach (['http://sso.contoh.test', 'https://sso.contoh.test/path', 'ftp://x', "https://a.test\r\nX: y", 'https://user@sso.test'] as $bad) {
            $x = OidcClient::probe($this->idp()->http(), $bad);
            self::assertFalse($x['ok'], $bad);
            self::assertStringContainsString('https://host', $x['steps'][0]['msg']);
        }
    }

    public function test_SSO_21_discovery_cacat_dan_jwks_kosong(): void
    {
        $idp = $this->idp();
        $idp->discoveryOverride = ['token_endpoint' => 'http://sso.contoh.test/tok'];
        self::assertStringContainsString('token_endpoint', OidcClient::probe($idp->http(), FakeIdp::ISSUER)['steps'][0]['msg']);
        $idp = $this->idp();
        $idp->discoveryOverride = ['id_token_signing_alg_values_supported' => ['HS256']];
        self::assertStringContainsString('RS256', OidcClient::probe($idp->http(), FakeIdp::ISSUER)['steps'][0]['msg']);
        $idp = $this->idp();
        $idp->discoveryOverride = ['token_endpoint_auth_methods_supported' => ['client_secret_post']];
        self::assertStringContainsString('client_secret_basic', OidcClient::probe($idp->http(), FakeIdp::ISSUER)['steps'][0]['msg']);
        $idp = $this->idp();
        $idp->published = [];
        $r = OidcClient::probe($idp->http(), FakeIdp::ISSUER);
        self::assertTrue($r['steps'][0]['ok']);
        self::assertFalse($r['ok']);
        self::assertStringContainsString('JWKS tidak memuat kunci RSA', $r['steps'][1]['msg']);
    }
}
