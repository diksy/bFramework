<?php

declare(strict_types=1);

namespace bFramework\Tests\Core;

use bFramework\Core\Nonce;
use bFramework\Core\Request;
use bFramework\Core\Response;
use bFramework\Core\SafeHtml;
use bFramework\Core\SecurityHeaders;
use bFramework\Core\Template;
use bFramework\Core\TemplateError;
use PHPUnit\Framework\TestCase;

final class TemplateTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/tpl_' . bin2hex(random_bytes(4));
        mkdir($this->dir . '/v/sub', 0700, true);
        mkdir($this->dir . '/c', 0700);
        Nonce::reset();
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/{c,v,v/sub}/*', GLOB_BRACE) ?: [] as $f) {
            is_file($f) && unlink($f);
        }
        @rmdir($this->dir . '/v/sub');
        @rmdir($this->dir . '/v');
        @rmdir($this->dir . '/c');
        @rmdir($this->dir);
    }

    /** @param array<string,mixed> $vars */
    private function r(string $tpl, array $vars = [], string $name = 'x'): string
    {
        file_put_contents($this->dir . "/v/$name.tpl", $tpl);
        return (new Template($this->dir . '/v', $this->dir . '/c'))->render($name, $vars)->toString();
    }

    private const XSS = '<script>alert(1)</script>"\'&';

    public function test_SEC_OUT_01_html_escape_default(): void
    {
        $o = $this->r('<p>{{ v }}</p>', ['v' => self::XSS]);
        self::assertStringNotContainsString('<script>', $o);
        self::assertStringContainsString('&lt;script&gt;', $o);
    }

    public function test_SEC_OUT_01_atribut_tidak_bisa_keluar_kutip(): void
    {
        $o = $this->r('<input value="{{ v }}" title=\'{{ v|attr }}\'>', ['v' => '" onfocus="alert(1)']);
        self::assertStringNotContainsString('" onfocus=', $o);
        self::assertStringContainsString('&quot; onfocus=&quot;', $o);
    }

    public function test_SEC_OUT_01_js_konteks_script_default(): void
    {
        $o = $this->r('<script nonce="{{ nonce }}">var a = {{ v }};</script>', ['v' => '</script><img src=x>\'"&']);
        self::assertSame(1, substr_count($o, '</script'));
        self::assertStringNotContainsString("'", explode('var a =', $o)[1]);
        self::assertStringContainsString('u003C', $o);
    }

    public function test_SEC_OUT_01_js_filter_eksplisit_di_html(): void
    {
        $o = $this->r('<div data-x="{{ v|js }}"></div>', ['v' => '"><script>']);
        self::assertStringNotContainsString('"><script>', $o);
    }

    /** @dataProvider urls */
    public function test_SEC_OUT_01_url_filter(string $in, string $out): void
    {
        self::assertSame("<a href=\"$out\">", $this->r('<a href="{{ v|url }}">', ['v' => $in]));
    }

    /** @return array<string,array{string,string}> */
    public static function urls(): array
    {
        return [
            'js' => ['javascript:alert(1)', '#'],
            'js spasi/kontrol' => ["  java\tscript:alert(1)", '#'],
            'js kapital' => ['JaVaScRiPt:alert(1)', '#'],
            'data' => ['data:text/html,<script>', '#'],
            'vbscript' => ['vbscript:x', '#'],
            'backslash' => ['\\\\evil.com', '#'],
            'http' => ['http://a.test/x', 'http://a.test/x'],
            'https' => ['https://a.test/?a=1&amp', 'https://a.test/?a=1&amp;amp'],
            'relatif' => ['/halaman?x=1', '/halaman?x=1'],
            'kutip' => ['/a"onclick="x', '/a&quot;onclick=&quot;x'],
        ];
    }

    public function test_SEC_OUT_01_raw_hanya_safehtml(): void
    {
        self::assertSame('<b>x</b>', $this->r('{!! v !!}', ['v' => SafeHtml::fromTrusted('<b>x</b>')]));
        $this->expectException(TemplateError::class);
        $this->r('{!! v !!}', ['v' => '<b>x</b>']);
    }

    public function test_SEC_OUT_01_safehtml_di_kurung_ganda_tetap_di_escape(): void
    {
        $o = $this->r('{{ v }}', ['v' => SafeHtml::fromTrusted('<b>')]);
        self::assertSame('&lt;b&gt;', $o);
    }

    public function test_SEC_OUT_01_nilai_array_ditolak_dan_properti_objek_tidak_dibaca(): void
    {
        $o = new \stdClass();
        $o->secret = 'rahasia';
        self::assertSame('', $this->r('{{ v.secret }}', ['v' => $o]));
        $this->expectException(TemplateError::class);
        $this->r('{{ v }}', ['v' => ['a']]);
    }

    public function test_SEC_OUT_01_output_tanpa_kutip_di_tag_ditolak(): void
    {
        $this->expectException(TemplateError::class);
        $this->r('<a {{ v }}>x</a>', ['v' => 'onclick=alert(1)']);
    }

    public function test_SEC_OUT_01_output_di_script_wajib_js_dan_di_style_ditolak(): void
    {
        try {
            $this->r('<script>{{ v|attr }}</script>', ['v' => 'x'], 'a');
            self::fail('harus ditolak');
        } catch (TemplateError) {
            self::assertTrue(true);
        }
        $this->expectException(TemplateError::class);
        $this->r('<style>a{color:{{ v }}}</style>', ['v' => 'red'], 'b');
    }

    public function test_SEC_OUT_02_atribut_on_statis_ditolak(): void
    {
        foreach (['<a onclick="x()">', '<img src=x onerror=alert(1)>', '<div class="a"onmouseover="x">'] as $i => $t) {
            try {
                $this->r($t, [], "o$i");
                self::fail("harus ditolak: $t");
            } catch (TemplateError) {
                self::assertTrue(true);
            }
        }
        // teks biasa yang memuat "onclick=" bukan atribut
        self::assertSame('<p>onclick=1</p>', $this->r('<p>onclick=1</p>'));
    }

    public function test_SEC_OUT_02_nonce_acak_per_request_dan_di_csp(): void
    {
        $a = Nonce::current();
        self::assertSame($a, Nonce::current());
        self::assertSame(32, strlen($a));
        Nonce::reset();
        self::assertNotSame($a, Nonce::current());

        $o = $this->r('<script nonce="{{ nonce }}"></script>', ['nonce' => 'palsu']);
        self::assertStringContainsString('nonce="' . Nonce::current() . '"', $o);

        $mw = new SecurityHeaders([Nonce::class, 'current']);
        $req = new Request('GET', '/');
        $res = $mw->process($req, static fn (Request $r): Response => Response::html('x'));
        self::assertStringContainsString("'nonce-" . Nonce::current() . "'", $res->headers['Content-Security-Policy']);
    }

    public function test_SEC_OUT_01_path_template_di_whitelist(): void
    {
        file_put_contents($this->dir . '/luar.tpl', 'rahasia');
        $t = new Template($this->dir . '/v', $this->dir . '/c');
        foreach (['../luar', '/etc/passwd', 'a/../../luar', 'x.tpl', 'A', "x\0", 'sub//a', ''] as $bad) {
            try {
                $t->render($bad, []);
                self::fail("harus ditolak: $bad");
            } catch (TemplateError) {
                self::assertTrue(true);
            }
        }
        unlink($this->dir . '/luar.tpl');
    }

    public function test_SEC_OUT_01_tanpa_eval_php_tidak_dijalankan(): void
    {
        $o = $this->r('<?php echo 1+1; ?>{{ v }}', ['v' => '<?php system("id"); ?>']);
        self::assertStringContainsString('<?php echo 1+1; ?>', $o);
        self::assertStringContainsString('&lt;?php system', $o);
    }

    public function test_layout_extends_block_include_if_for(): void
    {
        file_put_contents($this->dir . '/v/base.tpl', '<h1>{% block judul %}Default{% endblock %}</h1>{% block isi %}{% endblock %}');
        file_put_contents($this->dir . '/v/sub/part.tpl', '[{{ n }}]');
        $o = $this->r(
            "{% extends 'base' %}{% block judul %}{{ t }}{% endblock %}"
            . "{% block isi %}{% for n in list %}{% include 'sub/part' %}{% endfor %}"
            . '{% if ok %}Y{% else %}N{% endif %}{% if not ok %}!{% endif %}{% if a == b %}=={% endif %}{% endblock %}',
            ['t' => '<T>', 'list' => ['<1>', 2], 'ok' => false, 'a' => 'q', 'b' => 'q'],
            'anak'
        );
        self::assertSame('<h1>&lt;T&gt;</h1>[&lt;1&gt;][2]N!==', $o);
    }

    public function test_for_variabel_loop_masuk_scope_include(): void
    {
        file_put_contents($this->dir . '/v/p.tpl', '[{{ n }}]');
        $o = $this->r("{% for n in l %}{% include 'p' %}{% endfor %}", ['l' => ['<a>', 2]]);
        self::assertSame('[&lt;a&gt;][2]', $o);
    }

    public function test_cache_dipakai_dan_diperbarui_saat_file_berubah(): void
    {
        self::assertSame('a1', $this->r('a{{ v }}', ['v' => 1]));
        self::assertNotEmpty(glob($this->dir . '/c/tpl_*.json'));
        self::assertSame('a1', $this->r('a{{ v }}', ['v' => 1]));
        self::assertSame('bb1', $this->r('bb{{ v }}', ['v' => 1]));
    }

    public function test_komentar_tidak_menggeser_konteks(): void
    {
        $o = $this->r('<!-- {{ a }} {{ a }} --><!-- {{ a }} --><script>var x = {{ b }};</script><i title="{{ b }}"></i>', ['a' => 'A', 'b' => '</script>"x']);
        self::assertStringContainsString('var x = "\\u003C\\/script\\u003E\\u0022x";', str_replace('\\/', '\\/', $o));
        self::assertStringContainsString('title="&lt;/script&gt;&quot;x"', $o);
        self::assertSame(1, substr_count($o, '</script>'));
    }

    public function test_komentar_tak_tertutup_tetap_sejajar(): void
    {
        $o = $this->r('<p>{{ a }}</p><!-- {{ a }} {{ a }}', ['a' => '<b>']);
        self::assertStringContainsString('&lt;b&gt;', $o);
    }

    public function test_atribut_url_paksa_filter_url(): void
    {
        foreach (['href', 'SRC', 'action', 'formaction', 'poster', 'cite'] as $a) {
            $o = $this->r("<a $a=\"{{ u }}\">x</a>", ['u' => 'javascript:alert(1)'], "u1" . strtolower($a));
            self::assertStringContainsString("$a=\"#\"", $o);
        }
        $o = $this->r("<a href='{{ u }}'>x</a>", ['u' => ' JaVa\tScript:alert(1)'], 'u2');
        self::assertStringContainsString("href='#'", $o);
        self::assertStringContainsString('href="mailto:a@b.c"', $this->r('<a href="{{ u }}">', ['u' => 'mailto:a@b.c'], 'u3'));
        self::assertStringContainsString('href="/p?q=1"', $this->r('<a href="{{ u }}">', ['u' => '/p?q=1'], 'u4'));
        self::assertStringContainsString('title="javascript:x"', $this->r('<a title="{{ u }}">', ['u' => 'javascript:x'], 'u5'));
    }

    public function test_atribut_url_filter_attr_ditolak(): void
    {
        $this->expectException(TemplateError::class);
        $this->r('<a href="{{ u|attr }}">x</a>', ['u' => 'x']);
    }

    public function test_sintaks_salah_ditolak(): void
    {
        foreach (['{% endif %}', '{% if a %}', '{{ a.b|zzz }}', '{{ a b }}', '{% eval x %}', "{% include '../x' %}"] as $i => $t) {
            try {
                $this->r($t, [], "s$i");
                self::fail("harus ditolak: $t");
            } catch (TemplateError) {
                self::assertTrue(true);
            }
        }
    }

    public function test_layout_bawaan_escape_dan_tanpa_on_atribut(): void
    {
        $t = new Template(__DIR__ . '/../../app/core/Core/views', $this->dir . '/c');
        $o = $t->render('layout', [
            'csrf' => 't"1', 'title' => '<T>', 'bodyClass' => 'x', 'user' => ['name' => '<u>'],
            'nav' => [['group' => 'G', 'items' => [['href' => 'javascript:x', 'key' => 'a', 'label' => 'L', 'icon' => 'i']]]],
            'active' => 'a', 'flash' => [['type' => 'ok', 'msg' => '<m>']], 'scripts' => ['/a.js'],
            'content' => SafeHtml::fromTrusted('<p>isi</p>'),
        ])->toString();
        self::assertStringContainsString('<p>isi</p>', $o);
        self::assertStringNotContainsString('<u>', $o);
        self::assertStringContainsString('href="#"', $o);
        self::assertSame(0, preg_match('/<[^>]+\son[a-z]+\s*=/i', $o));
        self::assertStringContainsString('nonce="' . Nonce::current() . '"', $o);
    }
}
