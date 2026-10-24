// S1: uji akses berkas kanari dari browser pemilik. URL kanari berasal dari server (atribut data), bukan input pengguna.
// Lulus bila isi kanari TIDAK terbaca (403/404/halaman lain, termasuk setelah redirect). Tanpa inline script (CSP nonce).
(function () {
  'use strict';

  // Keputusan murni (tanpa DOM): resolve true = TERBACA (gagal), false = aman (lulus); reject = galat fetch (tidak melapor).
  function isExposed(fetchFn, url, expected) {
    return fetchFn(url, { method: 'GET', credentials: 'omit', cache: 'no-store', redirect: 'follow' })
      .then(function (res) {
        // S21: redirect diikuti; yang dinilai HANYA isi respons akhir (redirect bukan tanda lulus).
        if (res.type === 'opaqueredirect') { return Promise.reject(new Error('redirect tidak dapat diikuti')); }
        if (res.status === 403 || res.status === 404) { return false; }
        return res.text().then(function (t) { return t.indexOf(expected) !== -1; });
      });
  }

  if (typeof module !== 'undefined' && module.exports) { module.exports = { isExposed: isExposed }; }
  if (typeof document === 'undefined') { return; }

  var box = document.getElementById('canary-box');
  var st = document.getElementById('canary-status');
  if (!box) { return; }
  var url = box.getAttribute('data-url') || '';
  var expected = box.getAttribute('data-content') || '';
  if (url.charAt(0) !== '/' || url.indexOf('//') === 0 || !expected) { return; }
  function say(t) { if (st) { st.textContent = t; } }
  function report(blocked) {
    var fd = new URLSearchParams();
    fd.append('_csrf', box.getAttribute('data-csrf') || '');
    fd.append('blocked', blocked ? '1' : '0');
    return fetch(box.getAttribute('data-report') || '/install/canary', { method: 'POST', body: fd, credentials: 'same-origin', cache: 'no-store' });
  }
  isExposed(fetch, url + '?t=' + Date.now(), expected)
    .then(function (exposed) {
      return report(!exposed).then(function () {
        if (exposed) {
          say('GAGAL: berkas di app/storage dapat diunduh lewat web. Pindahkan app/ ke luar docroot atau aktifkan .htaccess/blokir di server, lalu muat ulang.');
        } else {
          say('Lulus. Memuat ulang...');
          window.location.reload();
        }
      });
    })
    .catch(function () { say('Pemeriksaan gagal dijalankan; instal tetap ditolak. Muat ulang halaman untuk mencoba lagi.'); });
})();
