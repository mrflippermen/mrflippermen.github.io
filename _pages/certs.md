---
title: "Certificaciones"
permalink: /certs/
layout: archive
author_profile: true
collection: certs
defaults:
  # _certs
  - scope:
      path: ""
      type: certs
    values:
      layout: single
      author_profile: true
      share: true
---

{% for post in site.certs reversed %}
  {% include archive-single.html %}
{% endfor %}
