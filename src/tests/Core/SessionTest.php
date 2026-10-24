<?php

declare(strict_types=1);

namespace bFramework\Tests\Core;

use bFramework\Contracts\Clock;
use bFramework\Core\Csrf;
use bFramework\Core\CsrfMiddleware;
use bFramework\Core\FileSessionStore;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\Router;
use DateTimeImmutable;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class SessionTest extends TestCase
{
    private string $dir;
    private int $t = 1_000_000;
    /** @var list<array{0:string,1:string,2:array<string,mixed>}> */
    private array $sent = [];

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/sess_' . bin2hex(random_bytes(6));
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            unlink($f);
        }
        if (is_dir($this->dir)) {
            rmdir($this->dir);
        }
    }

    /** @param array<string,mixed> $cookies */
    private function store(array $cookies = [], bool $https = false, int $idle = 100, int $abs = 1000): FileSessionStore
    {
        $clock = new class ($this) implements Clock {
            public function __construct(private SessionTest $t)
            {
            }

            public function now(): DateTimeImmutable
            {
                return (new DateTimeImmutable())->setTimestamp($this->t->time());
            }
        };
        return new FileSessionStore($this->dir, $https, $idle, $abs, $cookies, function (string $n, string $v, array $o): void {
            $this->sent[] = [$n, $v, $o];
        }, $clock);
    }

    public function time(): int
    {
        return $this->t;
    }

    public function test_SEC_SESS_01_file_di_direktori_sendiri_permission_ketat_dan_id_kuat(): void
    {
        $s = $this->store();
        $s->start();
        $s->set('a', 1);
        self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $s->id());
        $f = $this->dir . '/sess_' . $s->id();
        self::assertFileExists($f);
        self::assertSame('0600', substr(sprintf('%o', fileperms($f)), -4));
        self::assertSame('0700', substr(sprintf('%o', fileperms($this->dir)), -4));
        self::assertStringStartsWith($this->dir, $f);
    }

    public function test_SEC_SESS_01_start_idempoten_dan_data_bertahan_antar_request(): void
    {
        $s = $this->store();
        $s->start();
        $id = $s->id();
        $s->start();
        self::assertSame($id, $s->id());
        $s->set('k', ['x' => 'y']);
        $s2 = $this->store(['bf_sid' => $id]);
        self::assertSame(['x' => 'y'], $s2->get('k'));
        self::assertSame($id, $s2->id());
    }

    public function test_SEC_SESS_01_tanpa_serialisasi_objek(): void
    {
        $s = $this->store();
        $this->expectException(InvalidArgumentException::class);
        $s->set('o', new \stdClass());
    }

    public function test_SEC_SESS_01_file_berisi_php_serialisasi_ditolak(): void
    {
        $s = $this->store();
        $s->start();
        $id = bin2hex(random_bytes(32));
        file_put_contents($this->dir . '/sess_' . $id, 'O:8:"stdClass":0:{}');
        $s2 = $this->store(['bf_sid' => $id]);
        $s2->start();
        self::assertNotSame($id, $s2->id());
    }

    public function test_SEC_SESS_01_fixation_id_dari_klien_tak_dikenal_tidak_diadopsi(): void
    {
        $attacker = str_repeat('a', 64);
        $s = $this->store(['bf_sid' => $attacker]);
        $s->start();
        self::assertNotSame($attacker, $s->id());
        self::assertFileDoesNotExist($this->dir . '/sess_' . $attacker);
    }

    /** @return array<string,array{0:string}> */
    public static function badIds(): array
    {
        return [
            'traversal' => ['../../etc/passwd'],
            'traversal-hex' => ['../' . str_repeat('a', 61)],
            'pendek' => ['abc'],
            'nullbyte' => [str_repeat('a', 63) . "\0"],
            'huruf besar' => [str_repeat('A', 64)],
            'newline' => [str_repeat('a', 64) . "\n"],
            'panjang' => [str_repeat('a', 65)],
        ];
    }

    /** @dataProvider badIds */
    public function test_SEC_SESS_01_path_traversal_id_sesi_ditolak(string $bad): void
    {
        $victim = dirname($this->dir) . '/victim_' . bin2hex(random_bytes(3));
        file_put_contents($victim, '{"c":1000000,"a":1000000,"d":{"x":1}}');
        $s = $this->store(['bf_sid' => $bad]);
        $s->start();
        self::assertNull($s->get('x'));
        self::assertNotSame($bad, $s->id());
        self::assertFileExists($victim);
        unlink($victim);
    }

    public function test_SEC_SESS_02_regenerate_id_berubah_data_ikut_id_lama_mati_csrf_dirotasi(): void
    {
        $s = $this->store();
        $csrf = new Csrf($s);
        $s->start();
        $s->set('u', 5);
        $tok = $csrf->token();
        $old = $s->id();
        $s->regenerate();
        self::assertNotSame($old, $s->id());
        self::assertSame(5, $s->get('u'));
        self::assertFileDoesNotExist($this->dir . '/sess_' . $old);
        self::assertNotSame($tok, $csrf->token());
        self::assertFalse($csrf->verify($tok));
        // cookie baru terkirim
        self::assertSame($s->id(), end($this->sent)[1]);
        // penyerang dengan ID lama tidak mendapat sesi
        $atk = $this->store(['bf_sid' => $old]);
        self::assertNull($atk->get('u'));
    }

    public function test_SEC_SESS_02_save_dari_instance_lama_tidak_menghidupkan_sesi_setelah_destroy(): void
    {
        $a = $this->store();
        $a->start();
        $a->set('u', 5);
        $id = $a->id();
        $b = $this->store(['bf_sid' => $id]);
        $b->start();
        $a->destroy();
        $b->set('x', 1);
        $b->flash('ok', 'm');
        self::assertFileDoesNotExist($this->dir . '/sess_' . $id);
        self::assertNull($this->store(['bf_sid' => $id])->get('u'));
    }

    public function test_SEC_SESS_02_save_id_lama_setelah_regenerate_tidak_menghidupkan_lagi(): void
    {
        $a = $this->store();
        $a->start();
        $a->set('u', 5);
        $old = $a->id();
        $b = $this->store(['bf_sid' => $old]);
        $b->start();
        $a->regenerate();
        $b->set('u', 6);
        self::assertFileDoesNotExist($this->dir . '/sess_' . $old);
        // regenerate dari instance usang tidak membawa data sesi yang sudah mati
        $b->regenerate();
        self::assertNull($b->get('u'));
        self::assertSame(0600, fileperms($this->dir . '/sess_' . $b->id()) & 0777);
        self::assertSame([], glob($this->dir . '/tmp_*'));
    }

    public function test_SEC_SESS_02_csrf_rotate_membuang_token_lama(): void
    {
        $s = $this->store();
        $c = new Csrf($s);
        $a = $c->token();
        $b = $c->rotate();
        self::assertNotSame($a, $b);
        self::assertTrue($c->verify($b));
        self::assertFalse($c->verify($a));
    }

    public function test_SEC_SESS_03_atribut_cookie_http(): void
    {
        $s = $this->store();
        $s->start();
        [$n, $v, $o] = $this->sent[0];
        self::assertSame('bf_sid', $n);
        self::assertSame($s->id(), $v);
        self::assertTrue($o['httponly']);
        self::assertSame('Lax', $o['samesite']);
        self::assertSame('/', $o['path']);
        self::assertFalse($o['secure']);
    }

    public function test_SEC_SESS_03_https_memakai_host_prefix_dan_secure(): void
    {
        $s = $this->store([], true);
        $s->start();
        [$n, , $o] = $this->sent[0];
        self::assertSame('__Host-bf_sid', $n);
        self::assertTrue($o['secure']);
        self::assertTrue($o['httponly']);
        self::assertArrayNotHasKey('domain', $o);
        self::assertSame('/', $o['path']);
        // cookie tanpa prefix tidak diterima pada HTTPS (hijack lewat subdomain)
        $s->set('u', 1);
        $s2 = $this->store(['bf_sid' => $s->id()], true);
        self::assertNull($s2->get('u'));
        $s3 = $this->store(['__Host-bf_sid' => $s->id()], true);
        self::assertSame(1, $s3->get('u'));
    }

    public function test_SEC_SESS_idle_timeout(): void
    {
        $s = $this->store();
        $s->set('u', 1);
        $id = $s->id();
        $this->t += 101;
        $s2 = $this->store(['bf_sid' => $id]);
        self::assertNull($s2->get('u'));
        self::assertNotSame($id, $s2->id());
        self::assertFileDoesNotExist($this->dir . '/sess_' . $id);
    }

    public function test_SEC_SESS_idle_diperpanjang_tapi_absolut_tidak(): void
    {
        $s = $this->store();
        $s->set('u', 1);
        $id = $s->id();
        for ($i = 0; $i < 9; $i++) {
            $this->t += 90;
            $x = $this->store(['bf_sid' => $id]);
            self::assertSame(1, $x->get('u'), "iterasi $i");
        }
        $this->t += 90; // total 900 < 1000
        self::assertSame(1, $this->store(['bf_sid' => $id])->get('u'));
        $this->t += 90; // total 990
        self::assertSame(1, $this->store(['bf_sid' => $id])->get('u'));
        $this->t += 90; // 1080 > absolut
        self::assertNull($this->store(['bf_sid' => $id])->get('u'));
    }

    public function test_SEC_SESS_hijack_cookie_milik_sesi_lain_tidak_membuka_sesi_ketiga(): void
    {
        $a = $this->store();
        $a->set('u', 1);
        $b = $this->store();
        $b->set('u', 2);
        self::assertNotSame($a->id(), $b->id());
        self::assertSame(2, $this->store(['bf_sid' => $b->id()])->get('u'));
        self::assertSame(1, $this->store(['bf_sid' => $a->id()])->get('u'));
    }

    public function test_SEC_SESS_destroy_menghapus_file_dan_cookie(): void
    {
        $s = $this->store();
        $s->set('u', 1);
        $id = $s->id();
        $s->destroy();
        self::assertFileDoesNotExist($this->dir . '/sess_' . $id);
        $last = end($this->sent);
        self::assertSame('', $last[1]);
        self::assertLessThan($this->t, $last[2]['expires']);
        self::assertNull($this->store(['bf_sid' => $id])->get('u'));
    }

    public function test_SEC_SESS_gc_menghapus_hanya_yang_kedaluwarsa(): void
    {
        $a = $this->store();
        $a->set('u', 1);
        $this->t += 60;
        $b = $this->store();
        $b->set('u', 2);
        $this->t += 60; // a: 120 > idle 100; b: 60
        self::assertSame(1, $this->store()->gc());
        self::assertFileDoesNotExist($this->dir . '/sess_' . $a->id());
        self::assertFileExists($this->dir . '/sess_' . $b->id());
    }

    public function test_flash_sekali_baca(): void
    {
        $s = $this->store();
        $s->flash('ok', 'Tersimpan');
        self::assertSame([['type' => 'ok', 'msg' => 'Tersimpan']], $s->pullFlash());
        self::assertSame([], $s->pullFlash());
    }

    public function test_SEC_REQ_01_csrf_middleware_dengan_store_file_idempoten(): void
    {
        $s = $this->store();
        $csrf = new Csrf($s);
        $router = new Router();
        $router->add('POST', '/x', static fn(Request $r): Response => Response::html('ok'));
        $mw = new CsrfMiddleware($router, $csrf, $s);
        $s->start();
        $id = $s->id();
        $r = new Request('POST', '/x', [], ['_csrf' => $csrf->token()], [], '', [], false, '127.0.0.1');
        $res = $mw->process($r, static fn(Request $q): Response => Response::html('ok'));
        self::assertSame(200, $res->status);
        self::assertSame($id, $s->id());
    }
}
