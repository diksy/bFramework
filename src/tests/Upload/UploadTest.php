<?php

declare(strict_types=1);

namespace bFramework\Tests\Upload;

use bFramework\Contracts\FieldType as T;
use bFramework\Contracts\Identity;
use bFramework\Core\RateLimiter;
use bFramework\Runtime\Authorizer;
use bFramework\Runtime\ColumnSpec;
use bFramework\Runtime\Connection;
use bFramework\Runtime\CurrentIdentity;
use bFramework\Runtime\IdentifierAllowlist;
use bFramework\Runtime\Migrator;
use bFramework\Runtime\Query;
use bFramework\Runtime\SqliteGrammar;
use bFramework\Runtime\TableSpec;
use bFramework\Tests\Fixtures\ArraySessionStore;
use bFramework\Tests\Fixtures\CaptureLogger;
use bFramework\Upload\FileController;
use bFramework\Upload\FilesTable;
use bFramework\Upload\UploadedFile;
use bFramework\Upload\UploadPolicy;
use bFramework\Upload\UploadRejected;
use bFramework\Upload\UploadService;
use PHPUnit\Framework\TestCase;

final class UploadTest extends TestCase
{
    private string $root;
    private Connection $conn;
    private Query $q;
    private UploadService $svc;
    private FileController $ctl;
    private CurrentIdentity $cur;
    private CaptureLogger $log;
    private int $n = 0;

    /** @var array<string,mixed> */
    private array $catatan = ['model' => 'catatan', 'access' => ['read' => ['user', 'admin'], 'owner' => 'user_id', 'ownerExempt' => ['admin']]];

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/upl_' . bin2hex(random_bytes(6));
        mkdir($this->root . '/in', 0700, true);
        $this->conn = Connection::sqlite($this->root . '/db.sqlite');
        $cat = new TableSpec('catatan', ['user_id' => new ColumnSpec(T::Integer, false), 'isi' => new ColumnSpec(T::String, false)]);
        $m = new Migrator($this->conn, new SqliteGrammar());
        $m->apply($m->planCreate(FilesTable::spec()));
        $m->apply($m->planCreate($cat));
        $g = new SqliteGrammar();
        $this->q = new Query($this->conn, $g, FilesTable::allowlist());
        $mq = new Query($this->conn, $g, new IdentifierAllowlist([$cat]));
        $mq->insert('catatan', ['user_id' => 1, 'isi' => 'a']);
        $mq->insert('catatan', ['user_id' => 2, 'isi' => 'b']);
        $this->log = new CaptureLogger();
        $this->svc = new UploadService(
            $this->q,
            $this->root . '/storage/uploads',
            ['maxFilesPerOwner' => 5, 'rateMax' => 100],
            $this->root . '/public_html',
            new RateLimiter($this->root . '/rl'),
            $this->log,
            static fn(string $f): bool => is_file($f),
            static fn(string $a, string $b): bool => rename($a, $b),
        );
        $this->cur = new CurrentIdentity(new ArraySessionStore());
        $this->ctl = new FileController($this->svc, $this->cur, new Authorizer(), fn(string $n): ?array => $n === 'catatan' ? $this->catatan : null, $mq, ['admin'], $this->log);
    }

    protected function tearDown(): void
    {
        unset($this->conn, $this->q, $this->svc);
        $this->rm($this->root);
    }

    private function rm(string $p): void
    {
        if (is_dir($p) && !is_link($p)) {
            foreach (scandir($p) ?: [] as $e) {
                if ($e !== '.' && $e !== '..') {
                    $this->rm($p . '/' . $e);
                }
            }
            rmdir($p);
        } elseif (file_exists($p)) {
            unlink($p);
        }
    }

    private function tmp(string $content, string $name = 'x.bin'): UploadedFile
    {
        $f = $this->root . '/in/t' . (++$this->n);
        file_put_contents($f, $content);
        return new UploadedFile($name, $f, UPLOAD_ERR_OK, strlen($content));
    }

    private function png(): string
    {
        $im = imagecreatetruecolor(4, 4);
        ob_start();
        imagepng($im);
        return (string) ob_get_clean();
    }

    private function img(): UploadPolicy
    {
        return new UploadPolicy(['image/png', 'image/gif', 'image/jpeg'], 100000);
    }

    private function as(int $uid, string $role = 'user'): void
    {
        $this->cur->set(new Identity($uid, [$role], $role, ['pwd']));
    }

    private function rejects(UploadedFile $f, UploadPolicy $p, string $reason): void
    {
        try {
            $this->svc->store($f, $p, 1);
            self::fail('Harus ditolak: ' . $reason);
        } catch (UploadRejected $e) {
            self::assertSame($reason, $e->reason);
        }
        self::assertSame([], glob($this->root . '/storage/uploads/*[0-9a-f]') ?: []);
    }

    public function test_SEC_FILE_02_gambar_sah_disimpan_nama_acak_tanpa_ekstensi_luar_docroot(): void
    {
        $s = $this->svc->store($this->tmp($this->png(), 'foto.PNG'), $this->img(), 1);
        self::assertMatchesRegularExpression('/^[a-f0-9]{32}$/D', $s->id);
        self::assertSame('image/png', $s->mime);
        $p = $this->svc->path($s->id);
        self::assertStringStartsWith($this->root . '/storage/uploads/', $p);
        self::assertStringNotContainsString('.', basename($p));
        self::assertSame('0600', substr(sprintf('%o', fileperms($p)), -4));
        self::assertSame('0700', substr(sprintf('%o', fileperms(dirname($p))), -4));
    }

    public function test_SEC_FILE_01_direktori_di_dalam_docroot_ditolak(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        mkdir($this->root . '/public_html', 0700);
        new UploadService($this->q, $this->root . '/public_html/uploads', [], $this->root . '/public_html');
    }

    public function test_SEC_FILE_01_htaccess_penjaga_ditulis(): void
    {
        $h = (string) file_get_contents($this->root . '/storage/uploads/.htaccess');
        self::assertStringContainsString('Require all denied', $h);
        self::assertStringContainsString('engine off', $h);
    }

    public function test_SEC_FILE_02_webshell_php_disamarkan_jpg_ditolak(): void
    {
        $f = $this->tmp("<?php system(\$_GET['c']); ?>", 'shell.jpg');
        $this->rejects($f, $this->img(), 'mime');
    }

    public function test_SEC_FILE_02_polyglot_gif_plus_php_ditolak(): void
    {
        $f = $this->tmp("GIF89a\x01\x00\x01\x00\x00\x00\x00;<?php system(\$_GET['c']); ?>", 'a.gif');
        $this->rejects($f, $this->img(), 'polyglot');
        $p = $this->tmp($this->png() . '<?php echo 1;', 'a.png');
        $this->rejects($p, $this->img(), 'polyglot');
    }

    public function test_SEC_FILE_02_polyglot_pdf_dengan_tag_php_ditolak(): void
    {
        $f = $this->tmp("%PDF-1.4\n<?= system('id') ?>\n%%EOF", 'a.pdf');
        $this->rejects($f, new UploadPolicy(['application/pdf'], 100000), 'polyglot');
    }

    public function test_SEC_FILE_02_polyglot_png_dinetralkan_reencode(): void
    {
        // PNG sah ditambah data setelah IEND (tanpa tag terlarang) hilang setelah re-encode.
        $s = $this->svc->store($this->tmp($this->png() . 'TRAILING-DATA', 'a.png'), $this->img(), 1);
        self::assertStringNotContainsString('TRAILING-DATA', (string) file_get_contents($this->svc->path($s->id)));
    }

    public function test_SEC_FILE_02_svg_ditolak_di_policy_dan_isi(): void
    {
        try {
            new UploadPolicy(['image/svg+xml'], 1000);
            self::fail('SVG harus ditolak policy');
        } catch (\InvalidArgumentException) {
            self::assertTrue(true);
        }
        $svg = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>';
        $this->rejects($this->tmp($svg, 'x.svg'), $this->img(), 'mime');
        $this->rejects($this->tmp($svg, 'x.png'), new UploadPolicy(['text/plain', 'image/png'], 1000), 'mime');
    }

    public function test_SEC_FILE_02_mime_palsu_dari_klien_diabaikan(): void
    {
        // Ekstensi .png & nama klien tak berpengaruh: teks biasa bukan image/png.
        $this->rejects($this->tmp('halo dunia', 'x.png'), $this->img(), 'mime');
        $s = $this->svc->store($this->tmp('halo dunia', 'x.exe'), new UploadPolicy(['text/plain'], 1000), 1);
        self::assertSame('text/plain', $s->mime);
    }

    public function test_SEC_FILE_02_ukuran_melebihi_dan_error_upload(): void
    {
        $this->rejects($this->tmp($this->png()), new UploadPolicy(['image/png'], 10), 'too_large');
        foreach ([UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE] as $e) {
            $this->rejects(new UploadedFile('a', $this->tmp('x')->tmpName, $e, 1), $this->img(), 'too_large');
        }
        $this->rejects(new UploadedFile('', '', UPLOAD_ERR_NO_FILE), $this->img(), 'no_file');
        $this->rejects(new UploadedFile('a', $this->tmp('x')->tmpName, UPLOAD_ERR_PARTIAL), $this->img(), 'upload_error');
        $this->rejects($this->tmp(''), $this->img(), 'empty');
    }

    public function test_SEC_FILE_02_bukan_hasil_upload_http_ditolak(): void
    {
        $svc = new UploadService($this->q, $this->root . '/storage/uploads');
        $this->expectException(UploadRejected::class);
        $svc->store($this->tmp($this->png()), $this->img(), 1);
    }

    public function test_SEC_FILE_02_null_byte_di_tmp_dan_nama(): void
    {
        $this->rejects(new UploadedFile('a', "/etc/passwd\0.png", UPLOAD_ERR_OK, 5), $this->img(), 'not_uploaded');
        $s = $this->svc->store($this->tmp($this->png(), "a\0b/../../c.png"), $this->img(), 1);
        $meta = $this->svc->find($s->id);
        self::assertIsArray($meta);
        self::assertSame('ab....c.png', $meta['orig_name']);
    }

    public function test_SEC_FILE_01_path_traversal_pada_id(): void
    {
        foreach (['../../etc/passwd', '..%2f..%2fx', str_repeat('a', 31), str_repeat('A', 32), str_repeat('a', 32) . '/../x', "aaaa\0"] as $id) {
            self::assertNull($this->svc->find($id));
            try {
                $this->svc->path($id);
                self::fail('path harus menolak');
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
            $this->as(1, 'admin');
            self::assertSame(404, $this->ctl->serve($id)->status);
        }
    }

    public function test_SEC_FILE_01_serve_pemilik_ya_orang_lain_dan_anonim_404_seragam(): void
    {
        $s = $this->svc->store($this->tmp($this->png()), $this->img(), 1);
        $tak = $this->ctl->serve(str_repeat('0', 32));
        $anon = $this->ctl->serve($s->id);
        self::assertSame(404, $anon->status);
        $this->as(2);
        $lain = $this->ctl->serve($s->id);
        self::assertSame($tak->status, $lain->status);
        self::assertSame($tak->body, $lain->body);
        self::assertSame($tak->headers, $lain->headers);
        self::assertSame($tak->headers, $anon->headers);
        $this->as(1);
        self::assertSame(200, $this->ctl->serve($s->id)->status);
        $this->as(9, 'admin');
        self::assertSame(200, $this->ctl->serve($s->id)->status);
    }

    public function test_SEC_FILE_01_idor_file_berelasi_mengikuti_model_dan_pemilik_baris(): void
    {
        $a = $this->svc->store($this->tmp($this->png()), $this->img(), 1, 'catatan', 1);
        $b = $this->svc->store($this->tmp($this->png()), $this->img(), 2, 'catatan', 2);
        $this->as(1);
        self::assertSame(200, $this->ctl->serve($a->id)->status);
        self::assertSame(404, $this->ctl->serve($b->id)->status); // IDOR: baris milik user 2
        $this->as(7, 'admin');
        self::assertSame(200, $this->ctl->serve($b->id)->status); // ownerExempt
        $this->as(1, 'tamu'); // peran tanpa hak baca
        self::assertSame(404, $this->ctl->serve($a->id)->status);
        $c = $this->svc->store($this->tmp($this->png()), $this->img(), 1, 'tak_ada', 1); // model tak dikenal: fail-closed
        $this->as(1);
        self::assertSame(404, $this->ctl->serve($c->id)->status);
    }

    public function test_SEC_FILE_01_header_gambar_nosniff_dan_content_type_dari_db(): void
    {
        $s = $this->svc->store($this->tmp($this->png(), 'a.html'), $this->img(), 1);
        $this->as(1);
        $r = $this->ctl->serve($s->id);
        self::assertSame('image/png', $r->headers['Content-Type']);
        self::assertSame('nosniff', $r->headers['X-Content-Type-Options']);
        self::assertSame('inline', $r->headers['Content-Disposition']);
        self::assertStringContainsString('private', $r->headers['Cache-Control']);
        self::assertStringContainsString('sandbox', $r->headers['Content-Security-Policy']);
        // Isi file diganti di disk: Content-Type tetap dari DB.
        file_put_contents($this->svc->path($s->id), '<html><script>1</script>');
        self::assertSame('image/png', $this->ctl->serve($s->id)->headers['Content-Type']);
    }

    public function test_SEC_FILE_01_non_gambar_attachment_nama_crlf_dan_double_extension(): void
    {
        $nama = "evil\r\nSet-Cookie: x=1\";.php.txt";
        $s = $this->svc->store($this->tmp('isi teks', $nama), new UploadPolicy(['text/plain'], 1000), 1);
        $meta = $this->svc->find($s->id);
        self::assertIsArray($meta);
        self::assertDoesNotMatchRegularExpression('/[\r\n\x00]/', (string) $meta['orig_name']);
        $this->as(1);
        $r = $this->ctl->serve($s->id);
        $d = $r->headers['Content-Disposition'];
        self::assertStringStartsWith('attachment; filename="', $d);
        self::assertDoesNotMatchRegularExpression('/[\r\n\x00]/', $d);
        self::assertSame(1, substr_count($d, '"') / 2);
        self::assertStringEndsWith('.txt"', $d);
        self::assertSame('shell_php_jpg.txt', FileController::downloadName('shell.php.jpg', 'text/plain'));
        self::assertSame('file.bin', FileController::downloadName('../../..', 'application/zip'));
        self::assertSame('text/plain', $r->headers['Content-Type']);
        self::assertSame('nosniff', $r->headers['X-Content-Type-Options']);
    }

    public function test_SEC_FILE_01_hapus_menghapus_file_dan_metadata(): void
    {
        $a = $this->svc->store($this->tmp($this->png()), $this->img(), 1, 'catatan', 1);
        $b = $this->svc->store($this->tmp($this->png()), $this->img(), 1);
        self::assertSame(1, $this->svc->deleteForRef('catatan', 1));
        self::assertFileDoesNotExist($this->svc->path($a->id));
        self::assertNull($this->svc->find($a->id));
        $this->svc->delete($b->id);
        self::assertFileDoesNotExist($this->svc->path($b->id));
        $this->svc->delete('../x'); // id rusak: diabaikan
    }

    public function test_SEC_FILE_02_kuota_dan_rate_limit(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->svc->store($this->tmp($this->png()), $this->img(), 1);
        }
        $this->rejectsKeep($this->tmp($this->png()), 'quota');
        $svc = new UploadService($this->q, $this->root . '/storage/uploads', ['rateMax' => 1], null, new RateLimiter($this->root . '/rl2'));
        $svc2 = new UploadService($this->q, $this->root . '/storage/uploads', ['rateMax' => 1, 'maxFilesPerOwner' => 99], null, new RateLimiter($this->root . '/rl2'), null, static fn(string $f): bool => true, static fn(string $a, string $b): bool => rename($a, $b));
        $svc2->store($this->tmp($this->png()), $this->img(), 3);
        try {
            $svc2->store($this->tmp($this->png()), $this->img(), 3);
            self::fail('rate limit');
        } catch (UploadRejected $e) {
            self::assertSame('rate', $e->reason);
            self::assertSame(429, $e->getCode());
        }
        unset($svc);
    }

    private function rejectsKeep(UploadedFile $f, string $reason): void
    {
        try {
            $this->svc->store($f, $this->img(), 1);
            self::fail('Harus ditolak');
        } catch (UploadRejected $e) {
            self::assertSame($reason, $e->reason);
        }
    }

    public function test_SEC_FILE_02_log_tanpa_nama_asli_atau_path(): void
    {
        $this->svc->store($this->tmp($this->png(), 'rahasia-ktp.png'), $this->img(), 1);
        self::assertStringNotContainsString('rahasia', $this->log->all());
        self::assertStringNotContainsString($this->root, $this->log->all());
    }
}
