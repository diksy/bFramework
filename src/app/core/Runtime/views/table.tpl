<div class="card">
  <div class="row between">
    <h3>{{ title }} <small class="muted">({{ total }} data)</small></h3>
    {% if canCreate %}<a class="btn primary" href="{{ createHref|url }}">Tambah</a>{% endif %}
  </div>
  <div class="scroll">
  <table class="table">
    <thead><tr>
      {% for h in heads %}<th><a href="{{ h.href|url }}">{{ h.label }}{% if h.asc %} ▲{% endif %}{% if h.desc %} ▼{% endif %}</a></th>{% endfor %}
      {% if hasActions %}<th>Aksi</th>{% endif %}
    </tr></thead>
    <tbody>
    {% for r in rows %}
      <tr>
        {% for c in r.cells %}<td class="{{ c.cls }}">{{ c.text }}</td>{% endfor %}
        {% if hasActions %}
        <td class="actions">
          {% if canEdit %}<a class="btn sm" href="{{ r.editHref|url }}">Ubah</a>{% endif %}
          {% if canDelete %}
          <form method="post" action="{{ r.deleteHref|url }}" class="inline" data-confirm="Hapus data ini?">
            <input type="hidden" name="_csrf" value="{{ csrf }}">
            <button class="btn sm danger" type="submit">Hapus</button>
          </form>
          {% endif %}
        </td>
        {% endif %}
      </tr>
    {% endfor %}
    {% if empty %}<tr><td colspan="{{ colspan }}" class="muted center">Belum ada data.</td></tr>{% endif %}
    </tbody>
  </table>
  </div>
  <div class="pager">
    <span>Halaman {{ page }} dari {{ pages }}</span>
    {% for p in pager %}<a class="btn sm{% if p.on %} primary{% endif %}" href="{{ p.href|url }}">{{ p.n }}</a>{% endfor %}
  </div>
</div>
