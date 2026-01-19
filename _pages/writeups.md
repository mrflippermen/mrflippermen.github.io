---
title: "Writeups & CTFs"
permalink: /writeups/
layout: archive
author_profile: true
collection: writeups
defaults:
  # _writeups
  - scope:
      path: ""
      type: writeups
    values:
      layout: single
      author_profile: true
      share: true
---

{% for post in site.writeups reversed %}
  {% include archive-single.html %}
{% endfor %}
