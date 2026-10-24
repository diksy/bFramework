<?php

declare(strict_types=1);

namespace bFramework\Tests\Runtime;

use bFramework\Contracts\Action;
use bFramework\Contracts\FieldType as T;
use bFramework\Contracts\Forbidden;
use bFramework\Contracts\Identity;
use bFramework\Runtime\Authorizer;
use bFramework\Runtime\ColumnSpec;
use bFramework\Runtime\Connection;
use bFramework\Runtime\CurrentIdentity;
use bFramework\Runtime\IdentifierAllowlist;
use bFramework\Runtime\Migrator;
use bFramework\Runtime\Query;
use bFramework\Runtime\SqliteGrammar;
use bFramework\Runtime\TableSpec;
use bFramework\Runtime\Where;
use bFramework\Tests\Fixtures\ArraySessionStore;
use PHPUnit\Framework\TestCase;

final class AuthorizerTest extends TestCase
{
    private string $file;
    private Connection $conn;
    private Query $q;
    private Authorizer $az;

    /** @var array<string,mixed> */
    private array $def = [
        'model' => 'catatan',
        'access' => [
            'read' => ['user', 'admin'],
            'create' => ['user'],
            'update' => ['user'],
            'delete' => ['user', 'admin'],
            'owner' => 'user_id',
            'ownerExempt' => ['admin'],
        ],
    ];

    protected function setUp(): void
    {
        $this->file = sys_get_temp_dir() . '/authz_' . bin2hex(random_bytes(6)) . '.sqlite';
        $this->conn = Connection::sqlite($this->file);
        $spec = new TableSpec('catatan', [
            'user_id' => new ColumnSpec(T::Integer, false),
            'isi' => new ColumnSpec(T::String, false),
        ]);
        $m = new Migrator($this->conn, new SqliteGrammar());
        $m->apply($m->planCreate($spec));
        $this->q = new Query($this->conn, new SqliteGrammar(), new IdentifierAllowlist([$spec]));
        $this->az = new Authorizer();
        $this->q->insert('catatan', ['user_id' => 1, 'isi' => 'milik A']);
        $this->q->insert('catatan', ['user_id' => 2, 'isi' => 'milik B']);
    }

    protected function tearDown(): void
    {
        unset($this->conn, $this->q);
        foreach ([$this->file, $this->file . '-journal'] as $f) {
            if (is_file($f)) {
                unlink($f);
            }
        }
    }

    /** @param list<string> $amr */
    private function id(int $uid, string $role = 'user', array $amr = ['pwd']): Identity
    {
        return new Identity($uid, [$role], $role, $amr);
    }

    public function test_SEC_AUTHZ_01_tanpa_aturan_ditolak(): void
    {
        self::assertFalse($this->az->can(['model' => 'x'], Action::Read, $this->id(1)));
        self::assertFalse($this->az->can(['model' => 'x', 'access' => []], Action::Read, null));
        self::assertFalse($this->az->can(['access' => ['read' => ['user']]], Action::Delete, $this->id(1)));
        self::assertFalse($this->az->can(['access' => 'sembarang'], Action::Read, $this->id(1)));
    }

    public function test_SEC_AUTHZ_01_peran_dan_anonim(): void
    {
        $d = ['access' => ['read' => '*', 'write' => ['admin']]];
        self::assertTrue($this->az->can($d, Action::Read, null));
        self::assertFalse($this->az->can($d, Action::Create, null));
        self::assertFalse($this->az->can($d, Action::Update, $this->id(1, 'user')));
        self::assertTrue($this->az->can($d, Action::Delete, $this->id(1, 'admin')));
        self::assertFalse($this->az->can($this->def, Action::Read, null), 'model berpemilik tertutup untuk anonim');
    }

    public function test_SEC_AUTHZ_01_hanya_peran_aktif_dihitung(): void
    {
        $i = new Identity(1, ['user', 'admin'], 'user');
        self::assertFalse($this->az->can(['access' => ['create' => ['admin']]], Action::Create, $i));
    }

    public function test_SEC_AUTHZ_01_requireAmr(): void
    {
        $d = ['access' => ['read' => ['admin'], 'requireAmr' => ['otp']]];
        self::assertFalse($this->az->can($d, Action::Read, $this->id(1, 'admin', ['pwd'])));
        self::assertTrue($this->az->can($d, Action::Read, $this->id(1, 'admin', ['pwd', 'otp'])));
        $perAksi = ['access' => ['read' => ['admin'], 'delete' => ['admin'], 'requireAmr' => ['delete' => ['otp']]]];
        self::assertTrue($this->az->can($perAksi, Action::Read, $this->id(1, 'admin', ['pwd'])));
        self::assertFalse($this->az->can($perAksi, Action::Delete, $this->id(1, 'admin', ['pwd'])));
        $rusak = ['access' => ['read' => ['admin'], 'requireAmr' => 'otp']];
        self::assertFalse($this->az->can($rusak, Action::Read, $this->id(1, 'admin', ['otp'])));
    }

    public function test_SEC_AUTHZ_01_scope_tanpa_hak_melempar_403(): void
    {
        $this->expectException(Forbidden::class);
        $this->az->scope(['access' => ['read' => ['admin']]], Action::Read, $this->id(1, 'user'));
    }

    public function test_SEC_AUTHZ_02_scope_menyuntik_owner_dan_query_terfilter(): void
    {
        $a = $this->id(1);
        $w = $this->az->scope($this->def, Action::Read, $a);
        self::assertSame([['user_id', '=', 1]], $w->conds);
        $rows = $this->q->select('catatan', ['id', 'isi'], $w, null, 10, 0);
        self::assertCount(1, $rows);
        self::assertSame('milik A', $rows[0]['isi']);
        self::assertSame(1, $this->q->count('catatan', $w));
    }

    public function test_SEC_AUTHZ_02_IDOR_baca_ubah_hapus_baris_user_lain(): void
    {
        $a = $this->id(1);
        // id=2 milik B
        $byId = $this->az->constrain($this->def, Action::Read, $a, new Where([['id', '=', 2]]));
        self::assertSame([], $this->q->select('catatan', ['id'], $byId, null, 10, 0));
        $upd = $this->az->constrain($this->def, Action::Update, $a, new Where([['id', '=', 2]]));
        self::assertSame(0, $this->q->update('catatan', ['isi' => 'diretas'], $upd));
        $del = $this->az->constrain($this->def, Action::Delete, $a, new Where([['id', '=', 2]]));
        self::assertSame(0, $this->q->delete('catatan', $del));
        self::assertSame(2, $this->q->count('catatan', Where::none()));
        $row = $this->q->select('catatan', ['isi'], new Where([['id', '=', 2]]), null, 1, 0);
        self::assertSame('milik B', $row[0]['isi']);
    }

    public function test_SEC_AUTHZ_02_filter_pemanggil_tidak_bisa_menimpa_owner(): void
    {
        $w = $this->az->constrain($this->def, Action::Read, $this->id(1), new Where([['user_id', '=', 2]]));
        self::assertSame([], $this->q->select('catatan', ['id'], $w, null, 10, 0));
        $w2 = $this->az->constrain($this->def, Action::Read, $this->id(1), new Where([['user_id', 'in', [1, 2]]]));
        self::assertCount(1, $this->q->select('catatan', ['id'], $w2, null, 10, 0));
    }

    public function test_SEC_AUTHZ_02_mass_owner_create_dipaksa_dan_update_dibuang(): void
    {
        $a = $this->id(1);
        $in = $this->az->forceOwner($this->def, Action::Create, $a, ['isi' => 'x', 'user_id' => 2]);
        self::assertSame(1, $in['user_id']);
        $in = $this->az->forceOwner($this->def, Action::Create, $a, ['isi' => 'x']);
        self::assertSame(1, $in['user_id']);
        $up = $this->az->forceOwner($this->def, Action::Update, $a, ['isi' => 'x', 'user_id' => 2]);
        self::assertArrayNotHasKey('user_id', $up);
        $id = $this->q->insert('catatan', $in);
        self::assertSame(1, $this->q->count('catatan', new Where([['id', '=', $id], ['user_id', '=', 1]])));
    }

    public function test_SEC_AUTHZ_02_ownerExempt_melihat_semua_dan_model_tanpa_owner_tidak_difilter(): void
    {
        $admin = $this->id(9, 'admin');
        self::assertTrue($this->az->scope($this->def, Action::Read, $admin)->isEmpty());
        self::assertSame(2, $this->q->count('catatan', $this->az->scope($this->def, Action::Read, $admin)));
        $d = ['access' => ['read' => ['user']]];
        self::assertTrue($this->az->scope($d, Action::Read, $this->id(1))->isEmpty());
    }

    /** @return list<array{mixed}> */
    public static function badOwners(): array
    {
        return [[['user_id']], ['user id'], [123], [''], [null], ['a;b']];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('badOwners')]
    public function test_SEC_AUTHZ_02_owner_salah_bentuk_fail_closed(mixed $owner): void
    {
        $d = ['access' => ['read' => '*', 'update' => ['user'], 'owner' => $owner]];
        self::assertFalse($this->az->can($d, Action::Read, null));
        self::assertFalse($this->az->can($d, Action::Read, $this->id(1)));
        self::assertFalse($this->az->can($d, Action::Update, $this->id(1)));
        $this->expectException(Forbidden::class);
        $this->az->scope($d, Action::Read, $this->id(1));
    }

    public function test_SEC_AUTHZ_01_requireAmr_anonim_ditolak_dan_kombinasi_per_aksi(): void
    {
        $d = ['access' => ['read' => '*', 'requireAmr' => ['otp']]];
        self::assertFalse($this->az->can($d, Action::Read, null));
        self::assertFalse($this->az->can($d, Action::Read, $this->id(1, 'user', ['pwd'])));
        self::assertTrue($this->az->can($d, Action::Read, $this->id(1, 'user', ['otp'])));
        $p = ['access' => ['read' => '*', 'delete' => ['user'], 'requireAmr' => ['delete' => ['otp']]]];
        self::assertTrue($this->az->can($p, Action::Read, null));
        self::assertTrue($this->az->can($p, Action::Read, $this->id(1)));
        self::assertFalse($this->az->can($p, Action::Delete, $this->id(1)));
        self::assertTrue($this->az->can($p, Action::Delete, $this->id(1, 'user', ['otp'])));
        $q = ['access' => ['read' => '*', 'requireAmr' => ['read' => ['otp']]]];
        self::assertFalse($this->az->can($q, Action::Read, null));
    }

    public function test_SEC_AUTHZ_02_nama_kolom_owner_tak_valid_diabaikan_aman(): void
    {
        self::assertNull(Authorizer::ownerColumn(['access' => ['owner' => 'a; DROP TABLE x']]));
    }

    public function test_CurrentIdentity_roundtrip_dan_data_rusak(): void
    {
        $s = new ArraySessionStore();
        $ci = new CurrentIdentity($s);
        self::assertNull($ci->get());
        $i = new Identity(3, ['user', 'admin'], 'user', ['pwd', 'otp'], 'sid1');
        $ci->set($i);
        self::assertEquals($i, $ci->get());
        $s->set('_identity', ['userId' => '3', 'activeRole' => 'admin']);
        self::assertNull($ci->get());
        $ci->set($i);
        $ci->clear();
        self::assertNull($ci->get());
    }
}
