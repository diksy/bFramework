<section class="card narrow">
  <h2>{{ heading }}</h2>
  {% for m in formErrors %}<div class="flash err">{{ m }}</div>{% endfor %}
  <form method="post" action="{{ action|url }}" novalidate>
    <input type="hidden" name="_csrf" value="{{ csrf }}">
    {% for f in fields %}
    <div class="field{% if f.hasErr %} has-err{% endif %}">
      {% if f.isBool %}
        <label class="check"><input type="checkbox" name="{{ f.name }}" value="1"{% if f.checked %} checked{% endif %}> {{ f.label }}</label>
      {% else %}
        <label for="f-{{ f.name }}">{{ f.label }}{% if f.required %} *{% endif %}</label>
        {% if f.isFile %}
          <input id="f-{{ f.name }}" type="hidden" name="{{ f.name }}" value="{{ f.value }}">
          <input type="file" data-upload="f-{{ f.name }}" data-model="{{ f.fileModel }}" data-field="{{ f.name }}" accept="{{ f.accept }}">
          <div class="muted" data-upload-status="f-{{ f.name }}">{% if f.hasFile %}<a href="{{ f.fileHref|url }}">Lihat berkas saat ini</a>{% endif %}</div>
        {% else %}
        {% if f.isTextarea %}
          <textarea id="f-{{ f.name }}" name="{{ f.name }}" rows="4">{{ f.value }}</textarea>
        {% else %}
          {% if f.isSelect %}
          <select id="f-{{ f.name }}" name="{{ f.name }}">
            <option value="">- pilih -</option>
            {% for o in f.options %}<option value="{{ o.value }}"{% if o.sel %} selected{% endif %}>{{ o.label }}</option>{% endfor %}
          </select>
          {% else %}
          <input id="f-{{ f.name }}" type="{{ f.inputType }}" name="{{ f.name }}" value="{{ f.value }}">
          {% endif %}
        {% endif %}
        {% endif %}
      {% endif %}
      {% for m in f.errors %}<div class="err-text">{{ m }}</div>{% endfor %}
    </div>
    {% endfor %}
    <div class="row">
      <button class="btn primary" type="submit">Simpan</button>
      <a class="btn" href="{{ back|url }}">Batal</a>
    </div>
  </form>
</section>
