<div class="card">
  <h3>Peran</h3>
  <div class="scroll">
  <table class="table">
    <thead><tr><th>Nama</th><th>Label</th><th>Pengguna</th><th>Aksi</th></tr></thead>
    <tbody>
    {% for r in rows %}
      <tr>
        <td>{{ r.name }}{% if r.system %} <small class="muted">(sistem)</small>{% endif %}</td><td>{{ r.label }}</td><td>{{ r.count }}</td>
        <td class="actions">
          {% if r.canDelete %}
          <form method="post" action="{{ r.action|url }}" class="inline" data-confirm="Hapus peran ini?">
            <input type="hidden" name="_csrf" value="{{ csrf }}">
            <button class="btn sm danger" type="submit">Hapus</button>
          </form>
          {% endif %}
        </td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  </div>
  <h4>Peran baru</h4>
  <form method="post" action="/admin/peran" autocomplete="off" novalidate>
    <input type="hidden" name="_csrf" value="{{ csrf }}">
    <div class="field"><label for="r-name">Nama (huruf kecil, angka, - _)</label><input id="r-name" type="text" name="name" maxlength="32"></div>
    <div class="field"><label for="r-label">Label</label><input id="r-label" type="text" name="label" maxlength="120"></div>
    <div class="row"><button class="btn primary" type="submit">Tambah peran</button></div>
  </form>
</div>
