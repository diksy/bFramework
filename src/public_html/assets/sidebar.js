'use strict';
// Sidebar aplikasi: ciut di desktop (diingat), laci di mobile. Tanpa inline handler.
(function () {
  var KEY = 'bf.sidebar.collapsed';
  var root = document.documentElement;
  function store(v) {
    try { if (v === null) { return window.localStorage.getItem(KEY); } window.localStorage.setItem(KEY, v); } catch (e) { /* diabaikan */ }
    return null;
  }
  if (store(null) === '1') { root.classList.add('side-collapsed'); }

  document.addEventListener('DOMContentLoaded', function () {
    var side = document.getElementById('sidebar');
    if (!side) { return; }
    var openBtn = document.getElementById('side-open');
    var closeBtn = document.getElementById('side-close');
    var colBtn = document.getElementById('side-collapse');
    var overlay = document.getElementById('side-overlay');
    var mq = window.matchMedia('(min-width: 1024px)');

    function syncCol() {
      var c = root.classList.contains('side-collapsed');
      colBtn.setAttribute('aria-pressed', c ? 'true' : 'false');
      var t = c ? 'Perluas sidebar' : 'Ciutkan sidebar';
      colBtn.setAttribute('aria-label', t); colBtn.title = t;
      colBtn.firstChild.textContent = c ? '»' : '«';
    }
    function setDrawer(open) {
      root.classList.toggle('drawer-open', open);
      overlay.hidden = !open;
      openBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (open) { closeBtn.focus(); }
    }
    function isOpen() { return root.classList.contains('drawer-open'); }

    colBtn.addEventListener('click', function () {
      var c = root.classList.toggle('side-collapsed');
      store(c ? '1' : '0');
      syncCol();
    });
    openBtn.addEventListener('click', function () { setDrawer(!isOpen()); });
    closeBtn.addEventListener('click', function () { setDrawer(false); openBtn.focus(); });
    overlay.addEventListener('click', function () { setDrawer(false); openBtn.focus(); });
    document.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape' && isOpen()) { setDrawer(false); openBtn.focus(); }
    });
    var onChange = function () { if (mq.matches && isOpen()) { setDrawer(false); } };
    if (mq.addEventListener) { mq.addEventListener('change', onChange); } else if (mq.addListener) { mq.addListener(onChange); }
    syncCol();
  });
})();
