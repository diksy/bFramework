'use strict';
/* BikininFramework Builder (F15) - vanilla JS tanpa build, tanpa handler inline, tanpa evaluasi string, data selalu lewat textContent. Hanya menyimpan JSON lewat /_builder/api/save. */
(function () {
  var TYPES = ['string', 'text', 'integer', 'decimal', 'boolean', 'date', 'datetime', 'json', 'relasi', 'file'];
  var DEFAULT_MIMES = ['image/png', 'image/jpeg', 'application/pdf'];
  var ACTIONS = ['read', 'create', 'update', 'delete'];
  var ACTION_LABEL = { read: 'Baca', create: 'Tambah', update: 'Ubah', delete: 'Hapus' };
  var EVENTS = ['beforeSave', 'afterCreate', 'afterUpdate', 'beforeDelete'];
  var TABS = [['model', 'Model designer'], ['page', 'Page designer'], ['access', 'Access designer'], ['hooks', 'Actions & hooks'], ['preview', 'Live preview'], ['auth', 'Autentikasi']];

  // Manifest komponen: panel properti dibuat otomatis dari skema ini (BLD-06).
  var MANIFEST = {
    table: { label: 'Tabel', def: { span: 12, source: { model: '', perPage: 20 }, columns: [], actions: ['edit', 'hapus'] }, props: [
      { k: 'source.model', t: 'model', l: 'Model' }, { k: 'title', t: 'text', l: 'Judul' }, { k: 'source.sort', t: 'text', l: 'Urutan (mis. -stok)' },
      { k: 'source.perPage', t: 'number', l: 'Baris per halaman' }, { k: 'columns', t: 'columns', l: 'Kolom' }, { k: 'actions', t: 'multi', l: 'Aksi baris', opts: ['edit', 'hapus'] }] },
    form: { label: 'Form', def: { span: 6, source: { model: '' }, title: 'Form' }, props: [{ k: 'source.model', t: 'model', l: 'Model' }, { k: 'title', t: 'text', l: 'Judul' }] },
    card: { label: 'Kartu', def: { span: 4, title: 'Judul kartu', text: '' }, props: [{ k: 'title', t: 'text', l: 'Judul' }, { k: 'text', t: 'textarea', l: 'Isi' }] },
    stat: { label: 'Statistik', def: { span: 4, label: 'Statistik', agg: 'count', source: { model: '' } }, props: [
      { k: 'label', t: 'text', l: 'Label' }, { k: 'source.model', t: 'model', l: 'Model' }, { k: 'agg', t: 'select', l: 'Agregat', opts: ['count', 'sum', 'avg'] }, { k: 'field', t: 'field', l: 'Field (sum/avg)' }] },
    chart: { label: 'Grafik', def: { span: 6, title: 'Grafik', source: { model: '' } }, props: [
      { k: 'title', t: 'text', l: 'Judul' }, { k: 'source.model', t: 'model', l: 'Model' }, { k: 'field', t: 'field', l: 'Field nilai' }] },
    text: { label: 'Teks', def: { span: 12, text: 'Teks contoh' }, props: [{ k: 'text', t: 'textarea', l: 'Teks' }] },
    image: { label: 'Gambar', def: { span: 4, src: '', alt: '' }, props: [{ k: 'src', t: 'text', l: 'Lokasi (/assets/...)' }, { k: 'alt', t: 'text', l: 'Teks alternatif' }] }
  };

  var S = null;                       // snapshot terakhir dari server
  var W = { models: {}, pages: {}, auth: null };   // salinan kerja
  var cur = { tab: 'model', model: null, page: null, comp: null, previewPage: null, device: 'desktop', testResult: null };
  var history = []; var future = []; var lastSnap = '';
  var $panel = document.getElementById('panel');
  var $status = document.getElementById('status');
  var $dlg = document.getElementById('dlg');
  var $dlgBody = document.getElementById('dlg-body');
  var csrf = document.querySelector('meta[name="csrf-token"]').content;

  /* ---------- util ---------- */
  function h(tag, attrs) {
    var el = document.createElement(tag);
    attrs = attrs || {};
    Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (k.indexOf('on') === 0 && typeof v === 'function') { el.addEventListener(k.slice(2), v); }
      else if (k === 'class') { el.className = v; }
      else if (k === 'style' || k.indexOf('on') === 0) { return; }   // CSP: tanpa atribut style/handler inline
      else if (k === 'value') { el.value = v; }
      else if (k === 'checked' || k === 'disabled' || k === 'selected' || k === 'draggable' || k === 'hidden') { if (v) { el[k] = true; } }
      else if (v !== null && v !== undefined) { el.setAttribute(k, v); }
    });
    for (var i = 2; i < arguments.length; i++) { add(el, arguments[i]); }
    return el;
  }
  function add(el, c) {
    if (c === null || c === undefined || c === false) { return; }
    if (Array.isArray(c)) { c.forEach(function (x) { add(el, x); }); return; }
    el.appendChild(typeof c === 'object' ? c : document.createTextNode(String(c)));
  }
  function clone(o) { return JSON.parse(JSON.stringify(o)); }
  function getPath(o, p) { return p.split('.').reduce(function (a, k) { return a == null ? a : a[k]; }, o); }
  function setPath(o, p, v) {
    var ks = p.split('.'); var last = ks.pop();
    ks.forEach(function (k) { if (typeof o[k] !== 'object' || o[k] === null) { o[k] = {}; } o = o[k]; });
    o[last] = v;
  }
  function say(msg, cls) { $status.textContent = msg; $status.className = cls || 'muted'; }
  function api(path, body) {
    var opt = { headers: { 'X-CSRF-Token': csrf, 'Accept': 'application/json' }, credentials: 'same-origin' };
    if (body !== undefined) { opt.method = 'POST'; opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    return fetch(path, opt).then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }); });
  }
  function openDlg(title, nodes) {
    $dlgBody.textContent = '';
    add($dlgBody, h('h3', {}, title));
    add($dlgBody, nodes);
    if (!$dlg.open) { $dlg.showModal(); }
  }
  function closeDlg() { if ($dlg.open) { $dlg.close(); } }
  function showJson(obj) { openDlg('Lihat JSON', h('pre', {}, JSON.stringify(obj, null, 2))); }
  function jsonBtn(getter) { return h('button', { class: 'btn', type: 'button', onclick: function () { showJson(getter()); } }, 'Lihat JSON'); }

  /* ---------- state ---------- */
  function adopt(snap) {
    S = snap; history = []; future = []; lastSnap = '';
    W.models = {}; W.pages = {};
    Object.keys(snap.models).forEach(function (n) { W.models[n] = { data: clone(snap.models[n].data), hash: snap.models[n].hash, orig: JSON.stringify(snap.models[n].data) }; });
    Object.keys(snap.pages).forEach(function (n) { W.pages[n] = { data: clone(snap.pages[n].data), hash: snap.pages[n].hash, orig: JSON.stringify(snap.pages[n].data) }; });
    W.auth = { data: clone(snap.auth.data), hash: snap.auth.hash, orig: JSON.stringify(snap.auth.data) };
    if (!cur.model || !W.models[cur.model]) { cur.model = Object.keys(W.models)[0] || null; }
    if (!cur.page || !W.pages[cur.page]) { cur.page = Object.keys(W.pages)[0] || null; cur.comp = null; }
    if (!cur.previewPage || !W.pages[cur.previewPage]) { cur.previewPage = cur.page; }
  }
  function isDirty(entry) { return !!entry && JSON.stringify(entry.data) !== entry.orig; }
  function anyDirty() {
    return Object.keys(W.models).some(function (n) { return isDirty(W.models[n]); }) ||
      Object.keys(W.pages).some(function (n) { return isDirty(W.pages[n]); }) || isDirty(W.auth);
  }
  function reload(msg) {
    return api('/_builder/api/state').then(function (r) {
      if (r.status !== 200) { say(r.body.error || 'Gagal memuat.', 'dirty'); return; }
      adopt(r.body); render(); say(msg || 'Definisi dimuat.');
    });
  }

  /* ---------- simpan ---------- */
  function entryFor(kind, name) { return kind === 'model' ? W.models[name] : kind === 'page' ? W.pages[name] : W.auth; }
  function fileOf(kind, name) { return kind === 'auth' ? 'auth.json' : kind + 's/' + name + '.json'; }
  function failDlg(msg, errors) {
    say(msg || 'Gagal menyimpan.', 'dirty');
    openDlg('Tidak dapat menyimpan', [h('p', {}, msg || 'Terjadi kesalahan.'), Array.isArray(errors) && errors.length ? h('ul', {}, errors.map(function (x) { return h('li', {}, String(x)); })) : null]);
  }
  function save(kind, name, confirmLoss) {
    var e = entryFor(kind, name);
    if (kind === 'page' && isReservedGroup(e.data.group)) { say(RESERVED_MSG, 'dirty'); openDlg('Tidak dapat menyimpan', h('p', {}, RESERVED_MSG)); return Promise.resolve(false); }
    return api('/_builder/api/save', { kind: kind, name: name, data: e.data, baseHash: e.hash, confirmLoss: !!confirmLoss }).then(function (r) {
      if (r.status === 200) {
        e.data = r.body.data; e.hash = r.body.hash; e.orig = JSON.stringify(r.body.data);
        say('Tersimpan: ' + fileOf(kind, name));
        return api('/_builder/api/etag').then(function (x) { if (x.body.etag) { S.etag = x.body.etag; } return true; });
      }
      if (r.status === 409 && r.body.code === 'conflict') { conflict(kind, name, r.body.disk, r.body.diskHash); return false; }
      if (r.status === 409 && r.body.code === 'confirm_loss') { return confirmLossDlg(kind, name, r.body); }
      if (r.status === 401) { say('Sesi berakhir; muat ulang halaman.', 'dirty'); return false; }
      failDlg(r.body.error, r.body.errors);
      return false;
    });
  }
  // BLD-05: berkas diubah di luar builder -> tampilkan kedua versi, jangan menimpa tanpa pilihan eksplisit.
  function conflict(kind, name, disk, diskHash) {
    var e = entryFor(kind, name);
    openDlg('Konflik: berkas diubah di luar builder', [
      h('p', {}, 'Isi di disk berbeda dari yang Anda muat. Bandingkan lalu pilih.'),
      h('div', { class: 'split' }, h('div', {}, h('b', {}, 'Di disk'), h('pre', {}, JSON.stringify(disk, null, 2))), h('div', {}, h('b', {}, 'Versi Anda'), h('pre', {}, JSON.stringify(e.data, null, 2)))),
      h('div', { class: 'row end' },
        h('button', { class: 'btn danger', type: 'button', onclick: function () { closeDlg(); e.hash = diskHash || ''; save(kind, name, false).then(render); } }, 'Timpa dengan versi saya'),
        h('button', { class: 'btn primary', type: 'button', onclick: function () { closeDlg(); reload('Memuat versi dari disk.'); } }, 'Muat versi dari disk'))
    ]);
  }
  // BLD-08: pratinjau migrasi (SQL + peringatan kehilangan data) dari server; menyimpan butuh konfirmasi eksplisit.
  function confirmLossDlg(kind, name, info) {
    return new Promise(function (resolve) {
      openDlg('Perubahan destruktif pada "' + name + '"', [
        h('div', { class: 'warnbox' }, 'Peringatan: perubahan ini dapat menghapus data.', h('ul', {}, (info.lossWarnings || []).map(function (x) { return h('li', {}, String(x)); })),
          h('b', {}, 'Pratinjau migrasi:'), h('pre', {}, (info.sql || []).join('\n'))),
        h('div', { class: 'row end' },
          h('button', { class: 'btn', type: 'button', onclick: function () { closeDlg(); resolve(false); } }, 'Batal'),
          h('button', { class: 'btn danger', type: 'button', onclick: function () { closeDlg(); save(kind, name, true).then(resolve); } }, 'Saya paham, simpan'))
      ]);
    });
  }
  function previewMigration(name) {
    var e = W.models[name];
    return api('/_builder/api/migration', { kind: 'model', name: name, data: e.data, baseHash: e.hash || '' }).then(function (r) {
      if (r.status !== 200) { failDlg(r.body.error); return; }
      openDlg('Pratinjau migrasi: ' + name, [
        (r.body.lossWarnings || []).length ? h('div', { class: 'warnbox' }, h('ul', {}, r.body.lossWarnings.map(function (x) { return h('li', {}, String(x)); }))) : null,
        h('pre', {}, (r.body.sql || []).join('\n') || '-- tidak ada perubahan skema')]);
    });
  }
  function saveModel(name) { return save('model', name).then(render); }
  function saveDirtyModels() {
    var names = Object.keys(W.models).filter(function (n) { return isDirty(W.models[n]); });
    return names.reduce(function (p, n) { return p.then(function () { return saveModel(n); }); }, Promise.resolve());
  }
  function removeDef(kind, name) {
    var e = entryFor(kind, name);
    if (!e.hash) { delete (kind === 'model' ? W.models : W.pages)[name]; render(); return; }
    if (!window.confirm('Hapus ' + fileOf(kind, name) + '? Tabel database tidak ikut dihapus.')) { return; }
    api('/_builder/api/delete', { kind: kind, name: name, baseHash: e.hash }).then(function (r) {
      if (r.status === 200) { reload('Dihapus: ' + fileOf(kind, name)); }
      else if (r.status === 409 && r.body.code === 'conflict') { conflict(kind, name, r.body.disk, r.body.diskHash); }
      else { failDlg(r.body.error, r.body.errors); }
    });
  }

  /* ---------- undo/redo (BLD-10) ---------- */
  function snapshot() {
    var o = { models: {}, pages: {}, auth: W.auth ? W.auth.data : null };
    Object.keys(W.models).forEach(function (n) { o.models[n] = W.models[n].data; });
    Object.keys(W.pages).forEach(function (n) { o.pages[n] = W.pages[n].data; });
    return JSON.stringify(o);
  }
  function track() {
    var cur2 = snapshot();
    if (lastSnap && cur2 !== lastSnap) { history.push(lastSnap); future = []; if (history.length > 50) { history.shift(); } }
    lastSnap = cur2;
  }
  function restore(str) {
    var o = JSON.parse(str);
    Object.keys(W.models).forEach(function (n) { if (o.models[n]) { W.models[n].data = o.models[n]; } });
    Object.keys(W.pages).forEach(function (n) { if (o.pages[n]) { W.pages[n].data = o.pages[n]; } });
    if (o.auth && W.auth) { W.auth.data = o.auth; }
    lastSnap = str;
  }
  function undo() { if (!history.length) { return; } future.push(snapshot()); restore(history.pop()); render(true); }
  function redo() { if (!future.length) { return; } history.push(snapshot()); restore(future.pop()); render(true); }

  /* ---------- tab ---------- */
  function renderTabs() {
    var box = document.getElementById('tabs'); box.textContent = '';
    TABS.forEach(function (t, i) {
      box.appendChild(h('button', { type: 'button', class: cur.tab === t[0] ? 'on' : '', onclick: function () { cur.tab = t[0]; render(); } }, (i + 1) + '. ' + t[1]));
    });
  }
  function render(skipTrack) {
    if (S && skipTrack !== true) { track(); }
    renderTabs(); $panel.textContent = '';
    if (!S) { return; }
    var fn = { model: panelModel, page: panelPage, access: panelAccess, hooks: panelHooks, preview: panelPreview, auth: panelAuth }[cur.tab];
    $panel.appendChild(fn());
  }
  function list(items, selected, onPick, onNew, newLabel) {
    var ul = h('ul', { class: 'list' });
    items.forEach(function (n) { ul.appendChild(h('li', {}, h('button', { type: 'button', class: n === selected ? 'on' : '', onclick: function () { onPick(n); } }, n))); });
    return h('div', { class: 'card' }, ul, h('button', { class: 'btn sm', type: 'button', onclick: onNew }, '+ ' + newLabel));
  }

  /* ---------- 1. model designer ---------- */
  function panelModel() {
    var names = Object.keys(W.models);
    var left = list(names, cur.model, function (n) { cur.model = n; render(); }, function () {
      var n = (window.prompt('Nama model baru (huruf kecil, angka, garis bawah):') || '').trim();
      if (!n) { return; }
      if (!/^[a-z][a-z0-9_]{0,40}$/.test(n) || W.models[n]) { say('Nama model tidak valid atau sudah ada.', 'dirty'); return; }
      W.models[n] = { data: { model: n, fields: { nama: { type: 'string', label: 'Nama', required: true, max: 100 } }, access: { read: ['admin'], write: ['admin'] } }, hash: '', orig: '' };
      cur.model = n; render();
    }, 'Model baru');
    var right = h('div', {});
    var m = cur.model && W.models[cur.model];
    if (m) {
      right.appendChild(h('div', { class: 'card' },
        h('div', { class: 'toolbar' },
          h('h3', { class: 'grow' }, 'Model: ' + cur.model, ' ', isDirty(m) ? h('small', { class: 'dirty' }, '(belum disimpan)') : ''),
          h('button', { class: 'btn', type: 'button', onclick: function () { var f = m.data.fields; var i = 1; while (f['field_' + i]) { i++; } f['field_' + i] = { type: 'string' }; render(); } }, '+ Field'),
          jsonBtn(function () { return m.data; }),
          h('button', { class: 'btn', type: 'button', onclick: function () { previewMigration(cur.model); } }, 'Pratinjau migrasi'),
          h('button', { class: 'btn danger', type: 'button', onclick: function () { removeDef('model', cur.model); } }, 'Hapus'),
          h('button', { class: 'btn primary', type: 'button', onclick: function () { saveModel(cur.model); } }, 'Simpan')),
        fieldTable(m)));
    }
    right.appendChild(h('div', { class: 'card' }, h('h3', {}, 'Diagram ERD'), erd()));
    return h('div', { class: 'split' }, left, right);
  }
  function fieldTable(m) {
    var f = m.data.fields;
    var tb = h('tbody', {});
    Object.keys(f).forEach(function (name) {
      var d = f[name];
      function upd(k, v) { if (v === '' || v === false || v === null) { delete d[k]; } else { d[k] = v; } }
      tb.appendChild(h('tr', {},
        h('td', {}, h('input', { value: name, 'aria-label': 'Nama field', onchange: function (ev) {
          var nn = ev.target.value.trim();
          if (!/^[a-z][a-z0-9_]{0,40}$/.test(nn) || (nn !== name && f[nn])) { say('Nama field tidak valid atau duplikat.', 'dirty'); render(); return; }
          var rebuilt = {}; Object.keys(f).forEach(function (k) { rebuilt[k === name ? nn : k] = f[k]; }); m.data.fields = rebuilt; render();
        } })),
        h('td', {}, h('select', { 'aria-label': 'Tipe', onchange: function (ev) {
          var t = ev.target.value;
          if (t === 'file') {   // field file = string + upload {mimes,maxBytes} (M12b); FieldType tidak bertambah
            d.type = 'string'; d.upload = d.upload || { mimes: DEFAULT_MIMES.slice(), maxBytes: 2097152 };
            ['min', 'max', 'default', 'unique'].forEach(function (k) { delete d[k]; });
          } else { d.type = t; delete d.upload; }
          if (d.type !== 'relasi') { delete d.target; } render();
        } }, TYPES.map(function (t) { return h('option', { value: t, selected: t === (d.upload ? 'file' : d.type) }, t); }))),
        h('td', {}, d.type === 'relasi'
          ? h('select', { 'aria-label': 'Model target', onchange: function (ev) { upd('target', ev.target.value); render(); } },
            [h('option', { value: '' }, '- target -')].concat(Object.keys(W.models).map(function (n) { return h('option', { value: n, selected: n === d.target }, n); })))
          : [h('input', { value: d.label || '', placeholder: 'Label', 'aria-label': 'Label', onchange: function (ev) { upd('label', ev.target.value.trim()); render(); } }),
            d.upload ? [
              h('input', { value: (d.upload.mimes || []).join(', '), placeholder: 'image/png, application/pdf', 'aria-label': 'MIME yang diizinkan', onchange: function (ev) {
                d.upload.mimes = ev.target.value.split(',').map(function (x) { return x.trim(); }).filter(function (x) { return x; }); render(); } }),
              h('input', { type: 'number', min: '1', value: d.upload.maxBytes, 'aria-label': 'Ukuran maks (byte)', onchange: function (ev) { d.upload.maxBytes = Number(ev.target.value); render(); } })] : null]),
        h('td', {}, h('input', { type: 'checkbox', checked: !!d.required, 'aria-label': 'Wajib', onchange: function (ev) { upd('required', ev.target.checked); render(); } })),
        h('td', {}, h('input', { type: 'number', disabled: !!d.upload, value: d.min !== undefined ? d.min : '', 'aria-label': 'Min', onchange: function (ev) { upd('min', ev.target.value === '' ? '' : Number(ev.target.value)); render(); } })),
        h('td', {}, h('input', { type: 'number', disabled: !!d.upload, value: d.max !== undefined ? d.max : '', 'aria-label': 'Maks', onchange: function (ev) { upd('max', ev.target.value === '' ? '' : Number(ev.target.value)); render(); } })),
        h('td', {}, h('button', { class: 'btn sm danger', type: 'button', onclick: function () { delete f[name]; render(); say('Field "' + name + '" dihapus dari salinan kerja; pratinjau migrasi muncul saat menyimpan.', 'dirty'); } }, 'Hapus'))));
    });
    return h('div', { class: 'scroll' }, h('table', { class: 'ftable' },
      h('thead', {}, h('tr', {}, ['Nama field', 'Tipe', 'Label / target', 'Wajib', 'Min', 'Maks', ''].map(function (x) { return h('th', {}, x); }))), tb));
  }
  function svg(tag, attrs, text) {
    var el = document.createElementNS('http://www.w3.org/2000/svg', tag);
    Object.keys(attrs || {}).forEach(function (k) { el.setAttribute(k, attrs[k]); });
    if (text !== undefined) { el.textContent = text; }
    return el;
  }
  function erd() {
    var names = Object.keys(W.models); var pos = {}; var x = 20; var maxH = 0;
    names.forEach(function (n) { var c = Object.keys(W.models[n].data.fields || {}).length; pos[n] = { x: x, y: 20, w: 200, h: 34 + c * 18 }; x += 240; maxH = Math.max(maxH, 34 + c * 18); });
    var s = svg('svg', { class: 'erd', viewBox: '0 0 ' + Math.max(x, 500) + ' ' + (maxH + 50), role: 'img', 'aria-label': 'Diagram ERD' });
    names.forEach(function (n) {
      var f = W.models[n].data.fields || {};
      Object.keys(f).forEach(function (fn) {
        var t = f[fn]; if (t.type === 'relasi' && pos[t.target]) {
          var a = pos[n]; var b = pos[t.target]; var self = n === t.target;
          var x1 = a.x + (b.x >= a.x ? a.w : 0); var x2 = b.x + (b.x >= a.x ? 0 : b.w);
          s.appendChild(svg('line', { x1: x1, y1: a.y + 17, x2: self ? x1 : x2, y2: self ? a.y + 40 : b.y + 17, stroke: '#2f5de0', 'stroke-width': 2 }));
          s.appendChild(svg('text', { x: (x1 + x2) / 2 - 20, y: a.y - 4, fill: '#2f5de0' }, '1 : N ' + fn));
        }
      });
    });
    names.forEach(function (n) {
      var p = pos[n]; var f = W.models[n].data.fields || {};
      s.appendChild(svg('rect', { x: p.x, y: p.y, width: p.w, height: p.h, rx: 6, fill: '#fff', stroke: '#9aa6c4' }));
      s.appendChild(svg('rect', { x: p.x, y: p.y, width: p.w, height: 26, rx: 6, fill: '#eaf0ff' }));
      s.appendChild(svg('text', { x: p.x + 8, y: p.y + 17, class: 't' }, n));
      Object.keys(f).forEach(function (fn, i) { s.appendChild(svg('text', { x: p.x + 8, y: p.y + 42 + i * 18, fill: '#1d2433' }, fn + ' : ' + f[fn].type)); });
    });
    return s;
  }

  /* ---------- 2. page designer ---------- */
  function newComp(key) {
    var c = clone(MANIFEST[key].def); c.component = key;
    var first = Object.keys(W.models)[0] || '';
    if (c.source && !c.source.model) { c.source.model = first; }
    if (key === 'table' && first) { c.columns = Object.keys(W.models[first].data.fields).slice(0, 4); }
    return c;
  }
  var RESERVED_MSG = 'Nama grup "Admin" dicadangkan untuk menu bawaan. Pilih nama grup lain.';
  function isReservedGroup(v) { return String(v || '').trim().toLowerCase() === 'admin'; }
  function groupList() {
    var seen = { 'Aplikasi': true };
    Object.keys(W.pages).forEach(function (n) { var g = (W.pages[n].data.group || '').trim(); if (g && !isReservedGroup(g)) { seen[g] = true; } });
    return h('datalist', { id: 'grup-list' }, Object.keys(seen).sort().map(function (g) { return h('option', { value: g }); }));
  }
  function panelPage() {
    var names = Object.keys(W.pages);
    var left = list(names, cur.page, function (n) { cur.page = n; cur.comp = null; render(); }, function () {
      var n = (window.prompt('Nama halaman baru (huruf kecil, angka, garis):') || '').trim();
      if (!/^[a-z][a-z0-9_-]{0,40}$/.test(n) || W.pages[n]) { say('Nama halaman tidak valid atau sudah ada.', 'dirty'); return; }
      W.pages[n] = { data: { page: n, route: '/' + n, access: ['admin'], layout: [] }, hash: '', orig: '' };
      cur.page = n; cur.comp = null; render();
    }, 'Halaman baru');
    var p = cur.page && W.pages[cur.page];
    if (!p) { return h('div', { class: 'split' }, left, h('div', { class: 'card' }, 'Belum ada halaman.')); }
    var d = p.data;

    var meta = h('div', { class: 'card' },
      h('div', { class: 'toolbar' },
        h('h3', { class: 'grow' }, 'Halaman: ' + cur.page + ' ', isDirty(p) ? h('small', { class: 'dirty' }, '(belum disimpan)') : ''),
        jsonBtn(function () { return d; }),
        h('button', { class: 'btn danger', type: 'button', onclick: function () { removeDef('page', cur.page); } }, 'Hapus'),
        h('button', { class: 'btn primary', type: 'button', onclick: function () { save('page', cur.page).then(render); } }, 'Simpan')),
      h('div', { class: 'row' },
        h('label', {}, 'Grup menu ', h('input', { value: d.group || '', list: 'grup-list', placeholder: 'Aplikasi', onchange: function (ev) {
          var v = ev.target.value.trim();
          if (isReservedGroup(v)) { ev.target.value = d.group || ''; say(RESERVED_MSG, 'dirty'); openDlg('Grup tidak diizinkan', h('p', {}, RESERVED_MSG)); return; }
          if (v === '') { delete d.group; } else { d.group = v; } render();
        } }), groupList()),
        h('label', {}, 'Urutan ', h('input', { type: 'number', step: '1', class: 'w5', value: d.order === undefined ? '' : d.order, onchange: function (ev) {
          var v = ev.target.value.trim();
          if (v === '' || isNaN(parseInt(v, 10))) { delete d.order; } else { d.order = parseInt(v, 10); } render();
        } }))),
      h('div', { class: 'row' },
        h('label', {}, 'Rute ', h('input', { value: d.route, style: null, onchange: function (ev) { d.route = ev.target.value.trim(); render(); } })),
        h('span', {}, 'Akses: '),
        (S.roles || []).map(function (r) {
          return h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: Array.isArray(d.access) && d.access.indexOf(r.role) >= 0, onchange: function (ev) {
            var a = Array.isArray(d.access) ? d.access.slice() : []; var i = a.indexOf(r.role);
            if (ev.target.checked && i < 0) { a.push(r.role); } if (!ev.target.checked && i >= 0) { a.splice(i, 1); } d.access = a; render();
          } }), r.role);
        })));

    var palette = h('div', { class: 'palette' }, h('span', { class: 'muted' }, 'Seret ke kanvas atau klik: '));
    Object.keys(MANIFEST).forEach(function (k) {
      palette.appendChild(h('span', { class: 'chip', draggable: true, tabindex: '0', ondragstart: function (ev) { ev.dataTransfer.setData('text/plain', 'new:' + k); },
        onclick: function () { d.layout.push(newComp(k)); cur.comp = d.layout.length - 1; render(); } }, '+ ' + MANIFEST[k].label));
    });

    var canvas = h('div', { class: 'canvas', ondragover: function (ev) { ev.preventDefault(); canvas.classList.add('over'); }, ondragleave: function () { canvas.classList.remove('over'); },
      ondrop: function (ev) { ev.preventDefault(); canvas.classList.remove('over'); drop(d, ev.dataTransfer.getData('text/plain'), d.layout.length); } });
    d.layout.forEach(function (c, i) {
      var man = MANIFEST[c.component] || { label: c.component };
      var blk = h('div', { class: 'blk' + (cur.comp === i ? ' sel' : ''), style: null, draggable: true, tabindex: '0',
        ondragstart: function (ev) { ev.dataTransfer.setData('text/plain', 'blk:' + i); },
        ondragover: function (ev) { ev.preventDefault(); },
        ondrop: function (ev) { ev.preventDefault(); ev.stopPropagation(); drop(d, ev.dataTransfer.getData('text/plain'), i); },
        onclick: function () { cur.comp = i; render(); } },
      h('b', {}, man.label), h('small', {}, (c.source && c.source.model ? c.source.model + ' - ' : '') + 'lebar ' + c.span + '/12'),
      h('div', { class: 'tools' },
        mini('◀', 'Lebih sempit', function () { c.span = Math.max(1, c.span - 1); }), mini('▶', 'Lebih lebar', function () { c.span = Math.min(12, c.span + 1); }),
        mini('▲', 'Naik', function () { move(d, i, i - 1); }), mini('▼', 'Turun', function () { move(d, i, i + 1); }),
        mini('✕', 'Hapus komponen', function () { d.layout.splice(i, 1); cur.comp = null; })));
      blk.style.gridColumn = 'span ' + Math.max(1, Math.min(12, c.span || 12));
      canvas.appendChild(blk);
    });
    if (!d.layout.length) { canvas.appendChild(h('div', { class: 'muted', style: null }, 'Kanvas kosong. Tambahkan komponen dari palet.')); canvas.lastChild.style.gridColumn = 'span 12'; }

    var props = h('div', { class: 'card' }, h('h3', {}, 'Properti'));
    var c = d.layout[cur.comp];
    if (!c) { props.appendChild(h('p', { class: 'muted' }, 'Pilih komponen di kanvas.')); }
    else { props.appendChild(propsPanel(c)); }
    return h('div', { class: 'split three' }, left, h('div', {}, meta, h('div', { class: 'card' }, palette, canvas)), props);
  }
  function mini(label, title, fn) {
    return h('button', { class: 'btn sm', type: 'button', title: title, 'aria-label': title, onclick: function (ev) { ev.stopPropagation(); fn(); render(); } }, label);
  }
  function move(d, from, to) {
    if (to < 0 || to >= d.layout.length) { return; }
    var x = d.layout.splice(from, 1)[0]; d.layout.splice(to, 0, x); cur.comp = to;
  }
  function drop(d, data, at) {
    if (data.indexOf('new:') === 0 && MANIFEST[data.slice(4)]) { d.layout.splice(at, 0, newComp(data.slice(4))); cur.comp = at; }
    else if (data.indexOf('blk:') === 0) { var from = parseInt(data.slice(4), 10); var x = d.layout.splice(from, 1)[0]; d.layout.splice(from < at ? at - 1 : at, 0, x); cur.comp = from < at ? at - 1 : at; }
    render();
  }
  function propsPanel(c) {
    var man = MANIFEST[c.component]; var box = h('div', {});
    function row(label, input) { return h('div', { class: 'field' }, h('label', {}, label), input); }
    box.appendChild(row('Lebar (kolom 1-12)', h('select', { onchange: function (ev) { c.span = Number(ev.target.value); render(); } },
      [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].map(function (n) { return h('option', { value: n, selected: n === c.span }, n); }))));
    man.props.forEach(function (p) {
      var val = getPath(c, p.k); var model = getPath(c, 'source.model'); var fields = model && W.models[model] ? Object.keys(W.models[model].data.fields) : [];
      var input;
      if (p.t === 'text' || p.t === 'number') {
        input = h('input', { type: p.t === 'number' ? 'number' : 'text', value: val === undefined ? '' : val, onchange: function (ev) { setPath(c, p.k, p.t === 'number' ? Number(ev.target.value) : ev.target.value); render(); } });
      } else if (p.t === 'textarea') {
        input = h('textarea', { rows: '3', onchange: function (ev) { setPath(c, p.k, ev.target.value); render(); } }, val || '');
      } else if (p.t === 'model') {
        input = h('select', { onchange: function (ev) { setPath(c, p.k, ev.target.value); if (c.component === 'table') { c.columns = Object.keys(W.models[ev.target.value].data.fields).slice(0, 4); } render(); } },
          Object.keys(W.models).map(function (n) { return h('option', { value: n, selected: n === val }, n); }));
      } else if (p.t === 'select' || p.t === 'field') {
        var opts = p.t === 'field' ? [''].concat(fields) : p.opts;
        input = h('select', { onchange: function (ev) { setPath(c, p.k, ev.target.value); render(); } }, opts.map(function (o) { return h('option', { value: o, selected: o === val }, o || '- tidak ada -'); }));
      } else if (p.t === 'columns' || p.t === 'multi') {
        var all = p.t === 'columns' ? fields : p.opts; var cur2 = Array.isArray(val) ? val : [];
        input = h('div', {}, all.map(function (o) {
          return h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: cur2.indexOf(o) >= 0, onchange: function (ev) {
            var next = all.filter(function (x) { return x === o ? ev.target.checked : cur2.indexOf(x) >= 0; }); setPath(c, p.k, next); render();
          } }), o);
        }));
      }
      box.appendChild(row(p.l, input));
    });
    return box;
  }

  /* ---------- 3. access designer ---------- */
  function allowed(acc, action, role) {
    acc = acc || {}; var rule = acc[action];
    if (rule === undefined && action !== 'read') { rule = acc.write; }
    return rule === '*' || (Array.isArray(rule) && rule.indexOf(role) >= 0);
  }
  function setAllowed(m, action, role, on) {
    var acc = m.data.access = m.data.access || {}; var roles = (S.roles || []).map(function (r) { return r.role; });
    ACTIONS.forEach(function (a) { acc[a] = roles.filter(function (r) { return allowed(m.data.access, a, r); }); });   // pecah "write" jadi aksi eksplisit
    delete acc.write;
    acc[action] = acc[action].filter(function (r) { return r !== role; });
    if (on) { acc[action].push(role); }
    if (action === 'read' && acc.read.length === roles.length) { acc.read = '*'; }
  }
  function panelAccess() {
    var roles = (S.roles || []).map(function (r) { return r.role; });
    var wrap = h('div', {});
    wrap.appendChild(h('div', { class: 'card toolbar' }, h('h3', { class: 'grow' }, 'Matriks peran x model x aksi'),
      jsonBtn(function () { var o = {}; Object.keys(W.models).forEach(function (n) { o[n] = W.models[n].data.access || {}; }); return o; }),
      h('button', { class: 'btn primary', type: 'button', onclick: function () { saveDirtyModels().then(render); } }, 'Simpan perubahan')));
    Object.keys(W.models).forEach(function (n) {
      var m = W.models[n]; var acc = m.data.access || {};
      var rows = roles.map(function (role) {
        var amr = acc.requireAmr && acc.requireAmr[role] && acc.requireAmr[role].indexOf('otp') >= 0;
        return h('tr', {}, h('td', {}, role),
          ACTIONS.map(function (a) { return h('td', {}, h('input', { type: 'checkbox', checked: allowed(m.data.access, a, role), 'aria-label': role + ' ' + a, onchange: function (ev) { setAllowed(m, a, role, ev.target.checked); render(); } })); }),
          h('td', {}, h('input', { type: 'checkbox', checked: !!amr, 'aria-label': role + ' butuh OTP', onchange: function (ev) {
            var a2 = m.data.access = m.data.access || {}; a2.requireAmr = a2.requireAmr || {};
            if (ev.target.checked) { a2.requireAmr[role] = ['otp']; } else { delete a2.requireAmr[role]; }
            if (!Object.keys(a2.requireAmr).length) { delete a2.requireAmr; } render();
          } })));
      });
      var flds = m.data.fields || {};
      var ownerCols = Object.keys(flds).filter(function (f) { return (flds[f].type === 'integer' || flds[f].type === 'relasi') && !flds[f].upload; });
      var exempt = Array.isArray(acc.ownerExempt) ? acc.ownerExempt : [];
      wrap.appendChild(h('div', { class: 'card' },
        h('h3', {}, n, ' ', isDirty(m) ? h('small', { class: 'dirty' }, '(belum disimpan)') : ''),
        h('div', { class: 'scroll' }, h('table', { class: 'table matrix' }, h('thead', {}, h('tr', {}, h('th', {}, 'Peran'), ACTIONS.map(function (a) { return h('th', {}, ACTION_LABEL[a]); }), h('th', {}, 'Butuh OTP'))), h('tbody', {}, rows))),
        h('div', { class: 'row' }, h('span', {}, 'Kolom pemilik baris: '),
          h('select', { 'aria-label': 'Kolom pemilik', onchange: function (ev) {
            var a3 = m.data.access = m.data.access || {};
            if (!ev.target.value) { delete a3.owner; delete a3.ownerExempt; } else { a3.owner = ev.target.value; } render();
          } }, [h('option', { value: '' }, '- tanpa pemilik -')].concat(ownerCols.map(function (f) { return h('option', { value: f, selected: f === acc.owner }, f); }))),
          acc.owner ? [h('span', {}, 'Peran dikecualikan (lihat semua baris): ')].concat(roles.map(function (r) {
            return h('label', {}, h('input', { type: 'checkbox', checked: exempt.indexOf(r) >= 0, 'aria-label': 'Kecualikan ' + r, onchange: function (ev) {
              var a4 = m.data.access; var cur = (Array.isArray(a4.ownerExempt) ? a4.ownerExempt : []).filter(function (x) { return x !== r; });
              if (ev.target.checked) { cur.push(r); }
              if (cur.length) { a4.ownerExempt = cur; } else { delete a4.ownerExempt; } render();
            } }), ' ', r);
          })) : null),
        h('p', { class: 'muted' }, 'Tanpa centang berarti akses ditolak. Pemilik baris: pengguna hanya melihat baris miliknya, kecuali peran yang dikecualikan.')));
    });
    return wrap;
  }

  /* ---------- 4. actions & hooks ---------- */
  function panelHooks() {
    var refs = []; (S.hooks || []).forEach(function (c) { c.methods.forEach(function (m) { refs.push(m); }); });
    var wrap = h('div', {});
    wrap.appendChild(h('div', { class: 'card toolbar' }, h('h3', { class: 'grow' }, 'Hubungkan event ke method di extensions/'),
      jsonBtn(function () { var o = {}; Object.keys(W.models).forEach(function (n) { o[n] = W.models[n].data.hooks || {}; }); return o; }),
      h('button', { class: 'btn primary', type: 'button', onclick: function () { saveDirtyModels().then(render); } }, 'Simpan perubahan')));
    var grid = h('div', { class: 'split' });
    var models = h('div', {});
    Object.keys(W.models).forEach(function (n) {
      var m = W.models[n]; var hooks = m.data.hooks || {};
      models.appendChild(h('div', { class: 'card' }, h('h3', {}, n, ' ', isDirty(m) ? h('small', { class: 'dirty' }, '(belum disimpan)') : ''),
        EVENTS.map(function (ev) {
          return h('div', { class: 'field' }, h('label', {}, ev), h('select', { onchange: function (e2) {
            m.data.hooks = m.data.hooks || {}; if (e2.target.value) { m.data.hooks[ev] = e2.target.value; } else { delete m.data.hooks[ev]; }
            if (!Object.keys(m.data.hooks).length) { delete m.data.hooks; } render();
          } }, [h('option', { value: '' }, '- tidak ada -')].concat(refs.map(function (r) { return h('option', { value: r.ref, selected: hooks[ev] === r.ref }, r.ref + (r.doc ? ' - ' + r.doc : '')); }))));
        })));
    });
    var avail = h('div', { class: 'card' }, h('h3', {}, 'Method tersedia (hasil Reflection)'));
    (S.hooks || []).forEach(function (c) {
      avail.appendChild(h('b', {}, c.class + '.php', c.blocked ? ' (DIBLOKIR: kode berbahaya)' : ''));
      if ((c.warnings || []).length) { avail.appendChild(h('ul', { class: 'muted' }, c.warnings.map(function (x) { return h('li', {}, String(x)); }))); }
      var ul = h('ul', {}); c.methods.forEach(function (m) { ul.appendChild(h('li', {}, h('code', {}, m.name + '()'), m.doc ? ' - ' + m.doc : '')); }); avail.appendChild(ul);
    });
    avail.appendChild(h('p', { class: 'muted' }, 'Builder tidak menulis PHP. Tambahkan class baru secara manual di app/extensions/.'));
    grid.style.gridTemplateColumns = '1fr 1fr';
    grid.appendChild(models); grid.appendChild(avail); wrap.appendChild(grid);
    return wrap;
  }

  /* ---------- 5. live preview ---------- */
  function panelPreview() {
    var names = Object.keys(W.pages); var p = cur.previewPage && W.pages[cur.previewPage];
    var out = h('div', { class: 'preview-wrap ' + cur.device });
    var wrap = h('div', {}, h('div', { class: 'card toolbar' },
      h('label', {}, 'Halaman: ', h('select', { onchange: function (ev) { cur.previewPage = ev.target.value; render(); } }, names.map(function (n) { return h('option', { value: n, selected: n === cur.previewPage }, n); }))),
      ['desktop', 'tablet', 'ponsel'].map(function (dv) { return h('button', { class: 'btn sm' + (cur.device === dv ? ' on' : ''), type: 'button', onclick: function () { cur.device = dv; render(); } }, dv); }),
      h('span', { class: 'muted grow' }, 'Data contoh dibuat dari tipe field model tersimpan (SQLite/dummy).'),
      p ? jsonBtn(function () { return p.data; }) : null), out);
    if (!p) { out.appendChild(h('div', { class: 'card' }, 'Belum ada halaman.')); return wrap; }
    var grid = h('div', { class: 'pgrid' }); out.appendChild(grid);
    var cache = {};
    function sample(model) {
      if (!model) { return Promise.resolve([]); }
      if (!cache[model]) { cache[model] = api('/_builder/api/sample?model=' + encodeURIComponent(model)).then(function (r) { return Array.isArray(r.body) ? r.body : []; }); }
      return cache[model];
    }
    p.data.layout.forEach(function (c) {
      var cell = h('div', {}); cell.style.gridColumn = 'span ' + Math.max(1, Math.min(12, c.span || 12)); grid.appendChild(cell);
      var model = getPath(c, 'source.model');
      sample(model).then(function (rows) { cell.appendChild(previewComp(c, rows)); });
    });
    return wrap;
  }
  function fmt(f, v) {
    if (f && f.type === 'boolean') { return Number(v) ? 'Ya' : 'Tidak'; }
    if (f && (f.type === 'decimal' || f.type === 'integer')) { var s = Number(v).toLocaleString('id-ID'); return f.format === 'rupiah' ? 'Rp ' + s : s; }
    return v === undefined || v === null ? '-' : String(v);
  }
  function previewComp(c, rows) {
    var model = getPath(c, 'source.model'); var def = model && W.models[model] ? W.models[model].data : { fields: {} }; var f = def.fields || {};
    var card = h('div', { class: 'card' });
    switch (c.component) {
      case 'table':
        var cols = (c.columns || []).filter(function (k) { return f[k]; });
        var sort = (c.source && c.source.sort) || ''; var key = sort.replace(/^-/, '');
        var data = rows.slice();
        if (key && f[key]) { data.sort(function (a, b) { return (a[key] > b[key] ? 1 : -1) * (sort[0] === '-' ? -1 : 1); }); }
        data = data.slice(0, Number(c.source && c.source.perPage) || 20);
        card.appendChild(h('h3', {}, c.title || model));
        card.appendChild(h('div', { class: 'scroll' }, h('table', { class: 'table' }, h('thead', {}, h('tr', {}, cols.map(function (k) { return h('th', {}, f[k].label || k); }), (c.actions || []).length ? h('th', {}, 'Aksi') : null)),
          h('tbody', {}, data.map(function (r) { return h('tr', {}, cols.map(function (k) { return h('td', {}, fmt(f[k], r[k])); }), (c.actions || []).length ? h('td', {}, (c.actions || []).join(' / ')) : null); })))));
        break;
      case 'stat':
        var vals = rows.map(function (r) { return Number(r[c.field]) || 0; }); var sum = vals.reduce(function (a, b) { return a + b; }, 0);
        var v = c.agg === 'sum' ? sum : c.agg === 'avg' ? (vals.length ? sum / vals.length : 0) : rows.length;
        card.className = 'card stat'; card.appendChild(h('div', { class: 'stat-label' }, c.label || 'Statistik')); card.appendChild(h('div', { class: 'stat-val' }, fmt(f[c.field] || { type: 'integer' }, Math.round(v))));
        break;
      case 'chart':
        card.appendChild(h('h3', {}, c.title || 'Grafik'));
        var lim = rows.slice(0, Number(c.limit) || 6); var max = Math.max.apply(null, lim.map(function (r) { return Number(r[c.field]) || 0; }).concat([1]));
        lim.forEach(function (r) { card.appendChild(h('div', { class: 'bar' }, h('span', {}, String(r[c.labelField] === undefined ? r.id : r[c.labelField])), h('meter', { min: '0', max: String(max), value: String(Number(r[c.field]) || 0) }), h('b', {}, String(Number(r[c.field]) || 0)))); });
        break;
      case 'form':
        card.appendChild(h('h3', {}, c.title || 'Form'));
        Object.keys(f).forEach(function (k) { card.appendChild(h('div', { class: 'field' }, h('label', {}, f[k].label || k), h('input', { disabled: true, placeholder: f[k].type }))); });
        break;
      case 'card': card.appendChild(h('h3', {}, c.title || 'Kartu')); card.appendChild(h('p', {}, c.text || '')); break;
      case 'text': card.appendChild(h('p', {}, c.text || '')); break;
      case 'image': card.className = 'card img-ph'; card.textContent = 'Gambar: ' + (c.src || '(belum dipilih)'); break;
      default: card.textContent = 'Komponen tidak dikenal';
    }
    return card;
  }

  /* ---------- 6. autentikasi ---------- */
  function copy(text) {
    function ok() { say('Disalin: ' + text); }
    if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(text).then(ok, ok); return; }
    var t = h('textarea', {}, text); document.body.appendChild(t); t.select(); try { document.execCommand('copy'); } catch (e) { /* abaikan */ } t.remove(); ok();
  }
  function panelAuth() {
    var d = W.auth.data; d.sso = d.sso || {};
    var sso = d.sso; var isLocal = d.driver === 'local';
    function field(label, key, type) {
      return h('div', { class: 'field' }, h('label', {}, label), h('input', { type: type || 'text', value: sso[key] === undefined ? '' : sso[key], onchange: function (ev) { sso[key] = type === 'number' ? Number(ev.target.value) : ev.target.value.trim(); render(); } }));
    }
    var urls = h('div', {}, h('p', { class: 'muted' }, 'Daftarkan URL ini ke admin BikininSSO:'));
    [['Callback login', S.urls.callback], ['Post-logout', S.urls.postLogout], ['Back-channel logout', S.urls.backchannel]].forEach(function (u) {
      var full = location.origin + u[1];
      urls.appendChild(h('div', { class: 'urlrow' }, h('span', { style: null }, u[0]), h('code', {}, full), h('button', { class: 'btn sm', type: 'button', onclick: function () { copy(full); } }, 'Salin')));
    });
    return h('div', { class: 'split' }, h('div', { class: 'card' }, h('h3', {}, 'Driver'),
      ['local', 'bikinin_sso', 'hybrid'].map(function (dr) {
        return h('label', { class: 'check' }, h('input', { type: 'radio', name: 'drv', value: dr, checked: d.driver === dr, onchange: function () { d.driver = dr; render(); } }),
          dr === 'local' ? 'local (bawaan)' : dr === 'bikinin_sso' ? 'bikinin_sso (hanya SSO)' : 'hybrid (SSO + login darurat)');
      }), h('p', { class: 'muted' }, 'Driver local: rute /auth/sso/* tidak terdaftar (SSO-19).')),
    h('div', { class: 'card' }, h('div', { class: 'toolbar' }, h('h3', { class: 'grow' }, 'Konfigurasi BikininSSO ', isDirty(W.auth) ? h('small', { class: 'dirty' }, '(belum disimpan)') : ''),
      jsonBtn(function () { return d; }), h('button', { class: 'btn primary', type: 'button', onclick: function () { save('auth', 'auth').then(render); } }, 'Simpan')),
    isLocal ? h('p', { class: 'muted' }, 'Pilih bikinin_sso atau hybrid untuk mengatur SSO.') : h('div', {},
      field('Issuer (https://...)', 'issuer'), field('Client ID', 'client_id'),
      h('div', { class: 'field' }, h('label', {}, 'Provisioning'), h('select', { onchange: function (ev) { sso.provisioning = ev.target.value; render(); } },
        ['jit', 'pre_registered'].map(function (o) { return h('option', { value: o, selected: sso.provisioning === o }, o); }))),
      field('Peran bawaan', 'default_role'), field('Cek sesi tiap (menit)', 'session_check_minutes', 'number'),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: !!sso.offline_access, onchange: function (ev) { sso.offline_access = ev.target.checked; render(); } }), 'Minta offline_access'),
      h('p', { class: 'muted' }, 'client_secret tidak disimpan di sini; isi di config/config.php (di luar docroot).'),
      urls,
      h('p', { class: 'muted' }, 'Tes koneksi SSO tersedia setelah modul SSO (M15) terpasang.'))));
  }

  /* ---------- boot ---------- */
  document.getElementById('dlg-close').addEventListener('click', function () { closeDlg(); });
  function saveCurrent() {
    if (cur.tab === 'model' && cur.model) { saveModel(cur.model); }
    else if (cur.tab === 'page' && cur.page) { save('page', cur.page).then(render); }
    else if (cur.tab === 'auth') { save('auth', 'auth').then(render); }
    else if (cur.tab === 'access' || cur.tab === 'hooks') { saveDirtyModels().then(render); }
  }
  function palette() {
    var cmds = TABS.map(function (t) { return [t[1], function () { cur.tab = t[0]; render(); }]; })
      .concat([['Simpan', saveCurrent], ['Urungkan', undo], ['Ulangi', redo]]);
    openDlg('Palet perintah', h('ul', { class: 'list' }, cmds.map(function (c) {
      return h('li', {}, h('button', { type: 'button', onclick: function () { closeDlg(); c[1](); } }, c[0]));
    })));
  }
  function inField(ev) { var t = ev.target && ev.target.tagName; return t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT'; }
  document.addEventListener('keydown', function (ev) {
    var mod = ev.ctrlKey || ev.metaKey; var k = ev.key.toLowerCase();
    if (mod && k === 's') { ev.preventDefault(); saveCurrent(); }
    else if (mod && k === 'k') { ev.preventDefault(); palette(); }
    else if (mod && k === 'z' && !inField(ev)) { ev.preventDefault(); if (ev.shiftKey) { redo(); } else { undo(); } }
    else if (mod && k === 'y' && !inField(ev)) { ev.preventDefault(); redo(); }
    if (ev.altKey && /^[1-6]$/.test(ev.key)) { ev.preventDefault(); cur.tab = TABS[Number(ev.key) - 1][0]; render(); }
  });
  window.addEventListener('beforeunload', function (ev) { if (anyDirty()) { ev.preventDefault(); ev.returnValue = ''; } });
  // BLD-04: pantau perubahan berkas di luar builder tiap 3 detik.
  setInterval(function () {
    if (!S || $dlg.open) { return; }
    api('/_builder/api/etag').then(function (r) {
      if (!r.body.etag || r.body.etag === S.etag) { return; }
      if (anyDirty()) { say('Berkas diubah di luar builder. Simpan akan menampilkan dialog konflik.', 'dirty'); S.etag = r.body.etag; }
      else { reload('Berkas diubah di luar builder; dimuat ulang.'); }
    });
  }, 3000);
  renderTabs();
  reload();
})();
