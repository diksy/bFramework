<div class="card">
  <h3>{% if isNew %}Pengguna baru{% else %}Ubah pengguna{% endif %}</h3>
  <form method="post" action="{{ action|url }}" autocomplete="off" novalidate>
    <input type="hidden" name="_csrf" value="{{ csrf }}">
    <div class="field"><label for="f-name">Nama</label>
      <input id="f-name" type="text" name="name" value="{{ u.name }}" maxlength="120"></div>
    {% if isNew %}
    <div class="field"><label for="f-email">Email</label>
      <input id="f-email" type="email" name="email" value="{{ u.email }}" maxlength="254"></div>
    <p class="muted">Pengguna menyetel password sendiri lewat tautan yang dikirim ke emailnya.</p>
    {% else %}
    <div class="field"><label>Email</label> <span>{{ u.email }}</span> <small class="muted">({{ u.status }})</small></div>
    {% endif %}
    <fieldset class="field"><legend>Peran</legend>
      {% for r in roleOptions %}
      <label class="check">{% if r.on %}<input type="checkbox" name="roles[]" value="{{ r.name }}" checked>{% else %}<input type="checkbox" name="roles[]" value="{{ r.name }}">{% endif %} {{ r.label }}</label>
      {% endfor %}
    </fieldset>
    <div class="row"><button class="btn primary" type="submit">Simpan</button> <a class="btn" href="/admin/pengguna">Kembali</a></div>
  </form>
  {% if not isNew %}
  <hr>
  <div class="row">
    <form method="post" action="{{ u.resetAction|url }}" class="inline">
      <input type="hidden" name="_csrf" value="{{ csrf }}">
      <button class="btn sm" type="submit">Kirim tautan reset password</button>
    </form>
    {% if u.canDisable %}
    <form method="post" action="{{ u.statusAction|url }}" class="inline">
      <input type="hidden" name="_csrf" value="{{ csrf }}"><input type="hidden" name="status" value="disabled">
      <button class="btn sm danger" type="submit">Nonaktifkan</button>
    </form>
    {% endif %}
    {% if u.canEnable %}
    <form method="post" action="{{ u.statusAction|url }}" class="inline">
      <input type="hidden" name="_csrf" value="{{ csrf }}"><input type="hidden" name="status" value="active">
      <button class="btn sm" type="submit">Aktifkan</button>
    </form>
    {% endif %}
    <form method="post" action="{{ u.deleteAction|url }}" class="inline" data-confirm="Hapus pengguna ini?">
      <input type="hidden" name="_csrf" value="{{ csrf }}">
      <button class="btn sm danger" type="submit">Hapus</button>
    </form>
  </div>
  {% endif %}
</div>
