<div class="card"><h3>{{ title }}</h3>
{% for b in bars %}<div class="bar"><span>{{ b.label }}</span><meter min="0" max="{{ max }}" value="{{ b.value }}"></meter><b>{{ b.text }}</b></div>{% endfor %}
</div>
