<div class="bld">
  {% if prod %}<div class="warnbox">Builder aktif di PRODUKSI (unsafeBuilderInProduction). Semua perubahan dicatat di audit_log. Matikan setelah selesai.
    <form method="post" action="/_builder/logout" class="inline"><input type="hidden" name="_csrf" value="{{ csrf }}"><button class="btn sm" type="submit">Keluar builder</button></form></div>{% endif %}
  <div class="bld-tabs" role="tablist" id="tabs"></div>
  <div class="bld-bar">
    <span id="status" class="muted">Memuat...</span>
    <span class="muted">Pintasan: Ctrl+S simpan, Alt+1..6 pindah panel, Ctrl+Z / Ctrl+Y urungkan / ulangi, Ctrl+K palet perintah</span>
  </div>
  <div id="panel"></div>
</div>
<dialog id="dlg"><div id="dlg-body"></div><form method="dialog" class="row end"><button class="btn" id="dlg-close">Tutup</button></form></dialog>
