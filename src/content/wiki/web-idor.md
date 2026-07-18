---
title: "IDOR — Insecure Direct Object Reference"
description: "El IDOR es la clase de vulnerabilidad más consistentemente recompensada en bug bounty."
category: "Web"
date: 2026-07-18
---
# 🔍 IDOR — Insecure Direct Object Reference

El IDOR es la clase de vulnerabilidad **más consistentemente recompensada** en bug bounty. Ocurre cuando una aplicación expone un identificador de objeto (ID, UUID, filename) y no verifica que el usuario autenticado tenga permiso para acceder a ese recurso.

## El concepto núcleo

```
GET /api/v1/invoices/1847  HTTP/1.1
Host: target.com
Cookie: session=MI_SESION
# Cambiar 1847 a 1846 — ¿devuelve factura de otro usuario?
```

Si la respuesta de `1846` contiene datos que no te pertenecen, has encontrado un IDOR.

## Horizontal vs Vertical

| Tipo | Descripción | Gravedad |
|------|-------------|----------|
| **Horizontal** | Acceder a datos de otro usuario al mismo nivel | Medium-High |
| **Vertical** | Usuario regular accede a funciones de admin | High-Critical |

## Dónde buscar

- **URL paths:** `/users/123`, `/orders/abc-def`, `/files/upload_id`
- **Query params:** `?user_id=123`, `?document=4592`, `?account=B77F`
- **Request body:** `{"recipient_id": 445, "message": "hello"}`
- **GraphQL:** `node(id: "gid://shopify/Order/12345")` — los IDs globales de GraphQL son enumerables
- **Headers:** `X-User-Id: 123`
- **Cookies:** IDs en cookies que pueden modificarse

## Técnicas de bypass

### UUID vs IDs secuenciales
Los UUIDs **no son seguridad**, solo ofuscación. Si encuentras un UUID leak en una respuesta, pruébalo en otros endpoints.

### Técnicas comprobadas (2024-2026)

```
# Trailing slash / path normalization
/users/10/          vs  /users/10

# Double slashes
/users//9

# API version downgrade (v5 bloquea, v4 no)
/api/v4/users/9     vs  /api/v5/users/9

# Endpoint variants
/users/9/details    /users/9/orders

# Multi-ID / filter abuse
/users/10,9

# Type confusion
"9", 09, 9.0

# Null byte / control injection
/users/9%00

# Header-based bypass
X-Original-URL: /users/9
X-Rewrite-URL: /users/9

# Encoded space
/users/9%20
```

### Bypass de UUID
```
# Probar arrays de UUIDs
/users/f47ac10b-58cc-4372-a567-0e02b2c3d479,aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee

# Type confusion
/users/f47ac10b  → truncar UUID
```

## Metodología de caza

1. **Mapear todos los endpoints** con Logger++ o HTTP History filtrado por requests autenticados
2. **Identificar cada parámetro** que parezca un identificador
3. **Probar 2-3 IDs alternativos** por endpoint
4. **Combinar técnicas** — downgrade de API + trailing slash + encoded space
5. **Analizar respuestas** — 403 vs 404 vs 200 revelan qué validación existe

## Herramientas

| Herramienta | Uso |
|-------------|-----|
| **Burp Suite Authorize** | Extensión que prueba IDOR automáticamente |
| **Paramalyzer** | Detecta parámetros ocultos en responses |
| **ffuf** | Fuzzing de IDs: `ffuf -w ids.txt -u https://target.com/api/users/FUZ2Z` |
| **Caido** | Alternativa moderna a Burp con AutoRepeater |

## Chaining — IDOR hacia ATO

El IDOR rara vez es el fin del camino. Las cadenas más comunes:

```
IDOR en profile → leak de email → password reset poisoning → ATO
IDOR en billing → leak de CC/secretos → acceso a cuenta
IDOR en GraphQL node() → leak masivo de datos → PII Critical
```

## Reports públicos

- [IDOR en cambio de password → ATO completo](https://rohit443.medium.com/idor-on-password-change-to-full-account-takeover-4d96b9f7f9f0)
- [$4,000 User Impersonation via simple IDOR](https://shahmeeramir.com/how-a-simple-idor-become-a-4k-user-impersonation-vulnerability-705291b55c0d)
- [IDOR leads to Access tokens of users linked to Google Drive](https://infosecwriteups.com/idor-leads-to-getting-access-tokens-of-users-linked-to-google-drive-on-edmodo-3978017134bd)

## Relacionado
- **Autenticacion Web** — IDOR puede escalar a ATO vía cambio de email/password
- **Business Logic** — IDOR en transacciones, órdenes, pagos
- **Metodologia Bug Bounty**
- **Race Conditions** — race en IDOR de email change
- **Subdomain Takeover y Recon Web** — API discovery en subdominios
- **Claude-BugHunter** (skill `hunt-idor`, 26 reports)
- **Web HTB Academy**
