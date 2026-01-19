---
layout: archive
title: "Certificaciones y Logros"
permalink: /certs/
author_profile: true
---

Colección de mis certificaciones profesionales y logros destacados en el campo de la Ciberseguridad.

<div class="entries-list">
{% for post in site.certs reversed %}
  {% include archive-single.html %}
{% endfor %}
</div>
