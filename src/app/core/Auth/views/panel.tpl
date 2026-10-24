<section class="card narrow">
  <h2>{{ heading }}</h2>
  {% for m in errors %}<div class="flash err">{{ m }}</div>{% endfor %}
  {% for p in paragraphs %}<p>{{ p }}</p>{% endfor %}
  {% if codes %}<ul class="codes">{% for c in codes %}<li><code>{{ c }}</code></li>{% endfor %}</ul>{% endif %}
  {% for form in forms %}
  <form method="post" action="{{ form.action|url }}" autocomplete="off" novalidate>
    <input type="hidden" name="_csrf" value="{{ csrf }}">
    {% for f in form.fields %}
    <div class="field">
      {% if f.isCheck %}
      <label class="check"><input type="checkbox" name="{{ f.name }}" value="1"> {{ f.label }}</label>
      {% else %}
      <label for="a-{{ form.id }}-{{ f.name }}">{{ f.label }}</label>
      <input id="a-{{ form.id }}-{{ f.name }}" type="{{ f.type }}" name="{{ f.name }}" value="{{ f.value }}" autocomplete="{{ f.autocomplete }}">
      {% endif %}
    </div>
    {% endfor %}
    <div class="row"><button class="btn primary" type="submit">{{ form.submit }}</button></div>
  </form>
  {% endfor %}
  {% for l in links %}<p><a href="{{ l.href|url }}">{{ l.label }}</a></p>{% endfor %}
</section>
