---
layout: archive
title: "Writeups & Walkthroughs"
permalink: /writeups/
author_profile: true
sidebar:
  nav: "docs"
---

Aquí encontrarás mis guías detalladas y soluciones (writeups) de máquinas de HackTheBox, VulnHub y otros desafíos CTF.

<div class="entries-grid">
{% for post in site.writeups reversed %}
  {% include archive-single.html type="grid" %}
{% endfor %}
</div>
