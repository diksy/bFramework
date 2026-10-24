'use strict';
// Konfirmasi hapus tanpa inline script (CSP).
document.addEventListener('submit', function (ev) {
  var msg = ev.target.getAttribute && ev.target.getAttribute('data-confirm');
  if (msg && !window.confirm(msg)) { ev.preventDefault(); }
});
// Installer: tampilkan kolom MySQL hanya bila dipilih.
(function () {
  var fs = document.querySelector('.db-mysql');
  if (!fs) { return; }
  function sync() {
    var r = document.querySelector('input[name="driver"]:checked');
    fs.hidden = !(r && r.value === 'mysql');
  }
  document.querySelectorAll('input[name="driver"]').forEach(function (i) { i.addEventListener('change', sync); });
  sync();
})();
