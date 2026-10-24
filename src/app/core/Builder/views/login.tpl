<div class="card">
  <h3>Login Builder</h3>
  <p class="muted">Builder di produksi memerlukan kata sandi terpisah. Percobaan dicatat di audit log.</p>
  {% if error %}<div class="flash err">{{ error }}</div>{% endif %}
  <form method="post" action="/_builder/login" autocomplete="off" novalidate>
    <input type="hidden" name="_csrf" value="{{ csrf }}">
    <div class="field"><label for="bp">Kata sandi builder</label><input id="bp" type="password" name="password" maxlength="1024" autocomplete="off"></div>
    <div class="row"><button class="btn primary" type="submit">Masuk</button></div>
  </form>
</div>
