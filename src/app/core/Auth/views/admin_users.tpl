<div class="card">
  <div class="row between">
    <h3>Pengguna <small class="muted">({{ total }})</small></h3>
    <div class="row">
      <form method="post" action="/admin/pengguna/bersihkan" class="inline">
        <input type="hidden" name="_csrf" value="{{ csrf }}">
        <button class="btn sm" type="submit">Bersihkan akun pending kedaluwarsa</button>
      </form>
      <a class="btn primary" href="/admin/pengguna/baru">Tambah</a>
    </div>
  </div>
  <div class="scroll">
  <table class="table">
    <thead><tr><th>Nama</th><th>Email</th><th>Status</th><th>Peran</th><th>Aksi</th></tr></thead>
    <tbody>
    {% for u in rows %}
      <tr>
        <td>{{ u.name }}</td><td>{{ u.email }}</td><td>{{ u.status }}</td><td>{{ u.roles }}</td>
        <td class="actions"><a class="btn sm" href="{{ u.href|url }}">Ubah</a></td>
      </tr>
    {% endfor %}
    {% if empty %}<tr><td colspan="5" class="muted center">Belum ada pengguna.</td></tr>{% endif %}
    </tbody>
  </table>
  </div>
  {% if multiPage %}<div class="pager">{% for p in pager %}<a class="btn sm{% if p.on %} primary{% endif %}" href="{{ p.href|url }}">{{ p.n }}</a>{% endfor %}</div>{% endif %}
</div>
