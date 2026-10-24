// Langkah 1 upload dua langkah: kirim berkas ke POST /files lalu isi hidden input dengan fid.
// Tanpa inline script (CSP nonce); semua nilai dari DOM/respons ditulis lewat textContent/value.
(function () {
  'use strict';
  document.querySelectorAll('input[type=file][data-upload]').forEach(function (inp) {
    inp.addEventListener('change', function () {
      var form = inp.form;
      var target = document.getElementById(inp.getAttribute('data-upload'));
      var status = document.querySelector('[data-upload-status="' + inp.getAttribute('data-upload') + '"]');
      var csrf = form ? form.querySelector('input[name=_csrf]') : null;
      if (!inp.files || !inp.files[0] || !target || !csrf) { return; }
      var fd = new FormData();
      fd.append('_csrf', csrf.value);
      fd.append('model', inp.getAttribute('data-model') || '');
      fd.append('field', inp.getAttribute('data-field') || '');
      fd.append('file', inp.files[0]);
      if (status) { status.textContent = 'Mengunggah...'; }
      fetch('/files', { method: 'POST', body: fd, credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
        .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
        .then(function (res) {
          if (res.ok && res.j && /^[a-f0-9]{32}$/.test(res.j.id)) {
            target.value = res.j.id;
            if (status) { status.textContent = 'Terunggah: ' + String(res.j.name || ''); }
          } else {
            target.value = '';
            if (status) { status.textContent = String((res.j && res.j.error) || 'Unggah gagal'); }
            inp.value = '';
          }
        })
        .catch(function () {
          if (status) { status.textContent = 'Unggah gagal'; }
          inp.value = '';
        });
    });
  });
})();
