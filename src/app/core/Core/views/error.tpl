<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ status }} - BikininFramework</title>
<link rel="stylesheet" href="/assets/app.css">
</head>
<body class="err">
<main class="main">
<h1>{{ status }}</h1>
<p>{{ message }}</p>
{% if hint %}<p class="hint">{{ hint }}</p>{% endif %}
<p><a href="/">Kembali ke beranda</a></p>
</main>
</body>
</html>
