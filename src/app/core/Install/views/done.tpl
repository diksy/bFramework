<div class="card">
  <h3>Instalasi selesai</h3>
  <p>Buka tautan berikut untuk menyetel password admin. Tautan sekali pakai, berlaku 1 jam, dan <strong>hanya tampil sekali</strong>; tidak disimpan.</p>
  <p><a href="{{ resetUrl|url }}">{{ resetUrl }}</a></p>
  {% if tlsWarn %}<div class="flash err">Peringatan: APP_URL berskema https tetapi permintaan installer tampak HTTP (TLS diputus di proxy/CDN?). Cookie sesi dipaksa Secure/__Host- dan HSTS dikirim; atur TRUSTED_PROXIES bila perlu.</div>{% endif %}
  <p class="muted">Installer kini nonaktif (404). Jangan bagikan tautan ini.</p>
</div>
