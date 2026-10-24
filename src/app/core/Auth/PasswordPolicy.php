<?php

declare(strict_types=1);

namespace bFramework\Auth;

defined('APP_BOOTED') || exit;

/** Kebijakan password gaya NIST: panjang minimum, tolak sandi umum; tanpa aturan komposisi huruf/angka/simbol. */
final class PasswordPolicy
{
    public const MIN_LENGTH = 10;
    public const MAX_LENGTH = 128;

    /** Daftar kecil sandi yang sangat umum (huruf kecil). */
    private const COMMON = [
        'password', 'password1', 'password123', 'passw0rd', 'p@ssw0rd', 'qwerty', 'qwertyuiop', 'qwerty123',
        'qwertyuiop123', 'asdfghjkl', 'asdfghjkl123', 'zxcvbnm', '1234567890', '12345678', '123456789',
        '1234567890123', '0123456789', '1q2w3e4r5t', '1qaz2wsx3edc', 'abcdefghij', 'abc1234567', 'iloveyou',
        'iloveyou123', 'welcome123', 'welcome1234', 'letmein123', 'letmeinplease', 'adminadmin', 'admin12345',
        'administrator', 'changeme123', 'changemenow', 'sayangkamu', 'sayang123', 'bismillah', 'bismillah123',
        'indonesia', 'indonesia123', 'indonesia1945', 'rahasia123', 'rahasiakita', 'katasandi', 'katasandi123',
        'passwordpassword', 'monkey1234', 'dragon1234', 'football123', 'baseball123', 'superman123', 'trustno1234',
        'master12345', 'shadow12345', 'sunshine123', 'princess123', 'starwars123', 'whatever123', 'freedom123',
        'default1234', 'test123456', 'testing123', 'user123456', 'login12345', 'secret1234', 'secret12345',
    ];

    /**
     * @return list<string> pesan galat (kosong = lolos)
     */
    public static function check(string $password, string $email = '', int $maxBytes = 256): array
    {
        $errors = [];
        if (str_contains($password, "\0") || preg_match('//u', $password) !== 1) {
            return ['Password mengandung karakter yang tidak diizinkan.'];
        }
        $len = mb_strlen($password);
        if ($len < self::MIN_LENGTH) {
            $errors[] = 'Password minimal ' . self::MIN_LENGTH . ' karakter.';
        }
        if ($len > self::MAX_LENGTH || strlen($password) > $maxBytes) {
            $errors[] = 'Password terlalu panjang.';
        }
        $norm = mb_strtolower($password);
        $stripped = rtrim($norm, '0123456789!@#$%^&*._-');
        if (in_array($norm, self::COMMON, true) || ($stripped !== '' && in_array($stripped, self::COMMON, true))) {
            $errors[] = 'Password terlalu umum; pilih yang lebih sulit ditebak.';
        }
        if (count(array_unique(mb_str_split($norm))) < 4) {
            $errors[] = 'Password terlalu sederhana.';
        }
        $local = strtolower(explode('@', $email)[0]);
        if (strlen($local) >= 4 && str_contains($norm, $local)) {
            $errors[] = 'Password tidak boleh memuat bagian email Anda.';
        }
        return $errors;
    }
}
