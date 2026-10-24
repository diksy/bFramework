<div class="card">
  <h3>Instalasi BikininFramework</h3>
  {% for e in errors %}<div class="flash err">{{ e }}</div>{% endfor %}
  <h4>Prasyarat</h4>
  <ul>
    {% for c in checks %}<li>{% if c.ok %}OK{% else %}{% if c.warn %}Peringatan{% else %}GAGAL{% endif %}{% endif %}: {{ c.msg }}</li>{% endfor %}
  </ul>
  {% if canaryUrl %}
  <div class="flash err" id="canary-box" data-url="{{ canaryUrl }}" data-content="{{ canaryContent }}" data-report="/install/canary" data-csrf="{{ csrf }}">
    Mode cadangan: folder app/ berada di dalam docroot. Memeriksa bahwa berkas di app/storage tidak dapat diunduh lewat web...
    <span id="canary-status">Pemeriksaan butuh JavaScript.</span>
  </div>
  {% endif %}
  {% if blocked %}
  <p class="muted">Instalasi ditolak sampai pemeriksaan lulus. Token instal belum dibuat. Pindahkan app/ ke luar docroot, atau aktifkan .htaccess (Apache: AllowOverride All) / blokir /app/ di Nginx, lalu muat ulang.</p>
  {% else %}
  <form method="post" action="/install" autocomplete="off" novalidate>
    <input type="hidden" name="_csrf" value="{{ csrf }}">
    <div class="field"><label for="f-token">Token instal</label>
      <input id="f-token" type="password" name="install_token" autocomplete="off" maxlength="128">
      <small class="muted">Baca isi file {{ tokenFile }} di server (lewat FTP/SSH). Token tidak pernah dikirim lewat URL.</small></div>
    <div class="field"><label for="f-url">APP_URL</label>
      <input id="f-url" type="text" name="app_url" value="{{ v.app_url }}" maxlength="255"></div>
    <div class="field"><label for="f-hosts">Host yang diizinkan (kosong = host APP_URL)</label>
      <input id="f-hosts" type="text" name="allowed_hosts" value="{{ v.allowed_hosts }}" maxlength="500"></div>
    <h4>Admin pertama</h4>
    <div class="field"><label for="f-an">Nama</label><input id="f-an" type="text" name="admin_name" value="{{ v.admin_name }}" maxlength="120"></div>
    <div class="field"><label for="f-ae">Email</label><input id="f-ae" type="text" name="admin_email" value="{{ v.admin_email }}" maxlength="254"></div>
    <p class="muted">Admin tidak punya password. Anda menyetelnya lewat tautan sekali pakai yang tampil setelah instal.</p>
    <h4>Database</h4>
    <div class="field"><label for="f-dd">Jenis</label>
      <select id="f-dd" name="db_driver">
        <option value="sqlite"{% if sel.sqlite %} selected{% endif %}>SQLite</option>
        <option value="mysql"{% if sel.mysql %} selected{% endif %}>MySQL</option>
      </select></div>
    <div class="field"><label for="f-df">File SQLite</label><input id="f-df" type="text" name="db_file" value="{{ v.db_file }}" maxlength="80"></div>
    <div class="field"><label for="f-dh">Host MySQL</label><input id="f-dh" type="text" name="db_host" value="{{ v.db_host }}" maxlength="255"></div>
    <div class="field"><label for="f-dp">Port MySQL</label><input id="f-dp" type="text" name="db_port" value="{{ v.db_port }}" maxlength="5"></div>
    <div class="field"><label for="f-dn">Nama database</label><input id="f-dn" type="text" name="db_name" value="{{ v.db_name }}" maxlength="64"></div>
    <div class="field"><label for="f-du">User database</label><input id="f-du" type="text" name="db_user" value="{{ v.db_user }}" maxlength="64"></div>
    <div class="field"><label for="f-dw">Password database</label><input id="f-dw" type="password" name="db_password" autocomplete="new-password" maxlength="256"></div>
    <h4>Email</h4>
    <div class="field"><label for="f-mf">Pengirim (MAIL_FROM)</label><input id="f-mf" type="text" name="mail_from" value="{{ v.mail_from }}" maxlength="254"></div>
    <div class="field"><label for="f-sh">Host SMTP (kosong = fungsi mail())</label><input id="f-sh" type="text" name="smtp_host" value="{{ v.smtp_host }}" maxlength="255"></div>
    <div class="field"><label for="f-sp">Port SMTP</label><input id="f-sp" type="text" name="smtp_port" value="{{ v.smtp_port }}" maxlength="5"></div>
    <div class="field"><label for="f-ss">Keamanan SMTP</label>
      <select id="f-ss" name="smtp_secure">
        <option value="starttls"{% if sel.starttls %} selected{% endif %}>STARTTLS</option>
        <option value="tls"{% if sel.tls %} selected{% endif %}>TLS</option>
      </select></div>
    <div class="field"><label for="f-su">User SMTP</label><input id="f-su" type="text" name="smtp_user" value="{{ v.smtp_user }}" maxlength="254"></div>
    <div class="field"><label for="f-sw">Password SMTP</label><input id="f-sw" type="password" name="smtp_password" autocomplete="new-password" maxlength="256"></div>
    <label class="check"><input type="checkbox" name="registration" value="1"> Izinkan pendaftaran mandiri (default mati)</label>
    <div class="row"><button class="btn primary" type="submit">Pasang</button></div>
  </form>
  {% endif %}
</div>
