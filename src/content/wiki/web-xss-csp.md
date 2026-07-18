---
title: "XSS y bypass de CSP"
description: "Ejecución de JS arbitrario en el navegador de la víctima en el origen del target."
category: "Web"
date: 2026-07-18
---
# 💉 XSS y bypass de CSP

Ejecución de JS arbitrario en el navegador de la víctima en el origen del target. Impacto real = robo de sesión/token, acciones en nombre de la víctima, ATO.

## Los tres tipos

| Tipo | Origen | Persistencia | Severidad típica |
|------|--------|--------------|------------------|
| **Reflejado** | Input en la request se refleja en la response | No | Medium |
| **Almacenado** | Payload guardado y servido a otros usuarios | Sí | High-Critical |
| **DOM-based** | Sink JS del lado cliente (`innerHTML`, `eval`) | Depende | Medium-High |

## Dónde buscar

- Reflejo de parámetros en HTML / atributos / `<script>` / JSON.
- Campos guardados: perfil, comentarios, nombre, `filename` de uploads.
- Sinks DOM: `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(str)`, `location`, `{@html}` (Svelte), `dangerouslySetInnerHTML` (React), `v-html` (Vue).
- Fuentes DOM: `location.hash`, `location.search`, `document.referrer`, `postMessage`.

## Payloads por contexto

```html
<!-- HTML body -->
"><svg onload=alert(document.domain)>
<!-- Atributo -->
" autofocus onfocus=alert(document.domain) x="
<!-- Dentro de <script> -->
';alert(document.domain)//
<!-- URL / href -->
javascript:alert(document.domain)
<!-- Sin paréntesis / filtros -->
<svg onload=alert`1`>
<img src=x onerror=alert(document.domain)>
```

## Bypass de sanitizers y filtros

```
- Etiquetas raras: <details open ontoggle=…>, <math>, <marquee>
- Case / anidado: <ScRiPt>, <scr<script>ipt>
- Sin espacios: <svg/onload=…>
- Encoding: &#x6a; (HTML entities), j (JS), doble URL
- mXSS: mutación al re-parsear (bypass DOMPurify antiguo)
- Ruptura de sanitizers ingenuos (ver **CTF Fluid Sheets**)
```

## Bypass de CSP

| CSP débil | Bypass |
|-----------|--------|
| `script-src 'self'` | Endpoint que refleja JS · JSONP con callback controlado · `<iframe srcdoc>` para heredar contexto |
| `unsafe-inline` presente | Inyección inline directa |
| Dominio CDN confiable | Gadget/JSONP en ese CDN (`angular`, `jsonp`) |
| `nonce` reusado/predecible | Reutilizar nonce filtrado |
| Sin `object-src`/`base-uri` | `<base href>` hijack, plugins |

> **JSONP**: si un endpoint confiable devuelve `callback(datos)` con el callback reflejado → ejecución de JS arbitrario aunque CSP sea `'self'`. (Explorado en **CTF Fluid Sheets**.)

## Herramientas

| Herramienta | Uso |
|-------------|-----|
| **Burp + DOM Invader** | Detección de sinks/sources DOM automatizada |
| **XSStrike / Dalfox** | `dalfox url https://target/?q=FUZZ` |
| **Collaborator / interactsh** | Confirmar blind XSS (payload que llama a tu OOB) |

> [!warning] Verificación segura (Gate 3 del **Hunting Ejecutable**)
> PoC = `alert(document.domain)` o `console.log`, que prueba ejecución en el origen correcto. **No** exfiltres cookies/sesiones reales de terceros. Para blind XSS usa tu propio canal OOB.

## Chaining
```
XSS almacenado → robo de token/sesión → ATO
XSS + CSRF → forzar acción con token robado (ver **CSRF moderno**)
XSS via SVG/HTML upload → almacenado (ver **File Upload**)
XSS via WebSocket broadcast (ver **WebSocket Security**)
SSTI/second-order SQLi → XSS reflejado
```

## Remediación (el fix para TI)
- **Output encoding contextual** (HTML/attr/JS/URL) — no solo "sanitizar".
- Sanitizer robusto y mantenido (DOMPurify actual) para HTML enriquecido.
- **CSP estricta**: `default-src 'self'`, nonces por request, sin `unsafe-inline`, `object-src 'none'`, `base-uri 'none'`.
- Cookies `HttpOnly` + `Secure` + `SameSite` para reducir impacto del robo.

## Relacionado
- **Autenticacion Web** — robo de token vía XSS → ATO
- **CSRF moderno** — cadena XSS + CSRF
- **File Upload** — SVG/HTML XSS almacenado
- **SSTI** — SSTI puede generar XSS reflejado
- **WebSocket Security** — XSS vía broadcast
- **Metodologia Bug Bounty** · **Hunting Ejecutable**
- **CTFs y Writeups** · **CTF Fluid Sheets**
- **Claude-BugHunter** (skill `hunt-xss`)
