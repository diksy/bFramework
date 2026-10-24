<div class="card">
  <h3>Pembaruan core</h3>
  <p>Versi terpasang: <strong>{{ version }}</strong></p>
  {% if noKey %}
  <p class="alert error">PERINGATAN: kunci penandatangan update belum ditanam di core (UpdateKey). Semua paket update ditolak sampai pemilik menanam public key asli.</p>
  {% endif %}
  {% if maintenance %}<p class="alert">Mode pemeliharaan sedang aktif (update berjalan).</p>{% endif %}
  <p>Paket update diterapkan lewat CLI: <code>php app/cli/update.php verify paket.zip</code> lalu <code>php app/cli/update.php apply paket.zip</code>.</p>
  <h4>Integritas file core</h4>
  {% if noManifest %}
  <p class="alert">MANIFEST.sha256 tidak ditemukan atau tidak valid; modifikasi file core tidak dapat diperiksa.</p>
  {% endif %}
  {% if clean %}<p>Semua file core cocok dengan MANIFEST.sha256.</p>{% endif %}
  {% if dirty %}
  <p class="alert error">File core berbeda dari rilis resmi (diubah, hilang, atau tambahan).</p>
  {% if changed %}<h5>Diubah</h5><ul>{% for f in changed %}<li><code>{{ f }}</code></li>{% endfor %}</ul>{% endif %}
  {% if missing %}<h5>Hilang</h5><ul>{% for f in missing %}<li><code>{{ f }}</code></li>{% endfor %}</ul>{% endif %}
  {% if extra %}<h5>Tambahan</h5><ul>{% for f in extra %}<li><code>{{ f }}</code></li>{% endfor %}</ul>{% endif %}
  {% endif %}
</div>
