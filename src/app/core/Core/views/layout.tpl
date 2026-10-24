<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="{{ csrf }}">
<title>{{ title }} - BikininFramework</title>
<link rel="stylesheet" href="/assets/app.css">
{% if user %}<script src="/assets/sidebar.js" nonce="{{ nonce }}"></script>{% endif %}
</head>
<body class="{{ bodyClass }}">
{% if user %}
<div class="shell">
<aside class="sidebar" id="sidebar" aria-label="Sidebar">
  <div class="side-head">
    <a class="brand" href="/">Bikinin<span>Framework</span></a>
  </div>
  <nav class="side-nav" aria-label="Menu utama">
    {% for group in nav %}
    <div class="side-group">
      <div class="side-title">{{ group.group }}</div>
      {% for item in group.items %}
      <a href="{{ item.href|url }}" class="side-link{% if item.key == active %} on{% endif %}" title="{{ item.label }}"><span class="ico" aria-hidden="true">{{ item.icon }}</span><span class="lbl">{{ item.label }}</span></a>
      {% endfor %}
    </div>
    {% endfor %}
  </nav>
  <div class="side-foot">
    <div class="side-user"><span class="uname">{{ user.name }}</span></div>
    <form method="post" action="/logout" class="side-logout">
      <input type="hidden" name="_csrf" value="{{ csrf }}">
      <button class="btn sm block" type="submit" title="Keluar"><span class="lbl">Keluar</span></button>
    </form>
  </div>
</aside>
<div class="content">
{% endif %}
{% for f in flash %}
  <div class="flash {{ f.type }}">{{ f.msg }}</div>
{% endfor %}
<main class="main">
{% block content %}{!! content !!}{% endblock %}
</main>
{% if user %}</div>
</div>
{% endif %}
{% for s in scripts %}
<script src="{{ s|url }}" nonce="{{ nonce }}"></script>
{% endfor %}
</body>
</html>
