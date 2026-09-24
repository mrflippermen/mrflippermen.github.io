---
title: "SIEM Attack Lab — Blue Team / SOC Sherlock"
date: 2026-09-24
description: "Investigación blue-team de una cadena SQLi→LFI→Upload→RCE→PrivEsc: del log crudo de Apache a la detección completa en un SIEM ELK, con WAF auto-ban y una capa de engaño anti-agente."
excerpt: "Del access.log a la alerta: cómo un SOC (Filebeat + Logstash + Elasticsearch + Kibana) detecta una cadena de explotación completa, banea al atacante con acme-shield y siembra flags falsas para engañar a agentes de IA."
platform: "Custom"
difficulty: "Hard"
image: "/images/ctf.svg"
tags:
  - "Blue Team"
  - "SIEM"
  - "ELK"
  - "DFIR"
  - "Detection Engineering"
  - "SQLi"
  - "LFI"
  - "RCE"
  - "CVE-2025-32463"
  - "Deception"
---

> **Lab:** `siem-attack-lab` — entorno 100% dockerizado (web vulnerable + SIEM ELK + caja Kali) en la red aislada `lab-net`. Todas las vulnerabilidades son **intencionadas** y de **uso educativo**.
>
> Este writeup lo enfoco como un **Sherlock blue-team**: no persigo la flag, persigo el **rastro**. El objetivo es reconstruir la intrusión desde la telemetría y demostrar cómo el SOC la detecta paso a paso.
>
> **Navegación:** [🇪🇸 Español](#es) · [🇬🇧 English](#en)

<a id="es"></a>

## 🇪🇸 Español

### 1. El escenario

`ACME Store` es una tienda PHP+MySQL detrás de Apache. Un mini-WAF (`acme-shield`) intenta pararte los pies. Toda la actividad HTTP se envía a un **stack ELK** que hace de SIEM:

```
                       lab-net (bridge, aislada)
 ┌──────────┐  HTTP   ┌──────────────┐  SQL   ┌──────────┐
 │ attacker │ ──────▶ │   web        │ ─────▶ │   db     │
 │  (kali)  │         │ Apache + PHP │        │ MySQL 8  │
 └──────────┘         │  acme-shield │        └──────────┘
                      └──────┬───────┘
                             │ access.log / error.log  (volumen compartido)
                             ▼
                      ┌──────────────┐   ┌────────────┐   ┌───────────────┐
                      │  filebeat    │──▶│  logstash  │──▶│ elasticsearch │──▶ Kibana
                      └──────────────┘   │  (grok +   │   │  weblogs-*    │    (SOC)
                                         │ heurísticas)│   └───────────────┘
                                         └────────────┘
```

Como analista tengo dos fuentes: el **`access.log` crudo** (inviable a ojo en producción) y la **vista estructurada** en Kibana, donde cada petición llega ya **etiquetada** por el pipeline de Logstash.

---

### 2. La cadena de ataque (lo que hay que detectar)

El atacante encadena seis pasos. Los resumo porque son *lo que el SOC tiene que cazar*; las flags reales van **redactadas** (solo se obtienen resolviendo el lab).

| # | Paso | Técnica | Evidencia que deja |
|---|------|---------|--------------------|
| 1 | **SQLi con bypass de WAF** | `acme-shield` bloquea `UNION SELECT`, `-- `, `' OR 1=1`. Se ofusca con el comentario inline `/**/` y el de línea `#` | Picos de `500`, y peticiones con `union`/`information_schema` una vez ofuscadas |
| 2 | **LFI `php://filter`** | Fuga del código de `config.php` → `UPLOAD_TOKEN` hardcodeado | `view.php?page=php://filter/...` |
| 3 | **Auth bypass → 🟡 FLAG USER** | `login.php` con `admin'#` (el WAF bloquea `-- -`, no `#`) → sesión admin, el panel muestra la flag USER `FLAG{…redacted…}` | acceso a `panel.php` |
| 4 | **Upload → webshell** | `upload.php` valida MIME `image/*`, extensión no `php*` y tamaño. Se saltan con un **polyglot** `GIF89a` guardado como **`.phtml`** | subida + petición a `/uploads/shell.phtml` |
| 5 | **RCE como `www-data`** | El webshell da ejecución; `www-data` **no** puede leer `/root/root.txt` | `/uploads/*.phtml?c=id`, reverse shell `/dev/tcp/` |
| 6 | **PrivEsc → 🔴 FLAG ROOT** | **CVE-2025-32463** (sudo `chroot` LPE, sudo 1.9.16p1): `sudo -R` procesa un `nsswitch.conf` controlado y carga una `libnss_` maliciosa **como root** → `FLAG{…redacted…}` | `sudo -R`, `nsswitch`, `libnss_`, `setreuid` en la URL/comandos |

> **Causa raíz (para el informe):** concatenación directa de `$_GET['id']` en la consulta (SQLi), `include($_GET['page'])` sin lista blanca (LFI), validación de subida por *lista negra* de extensión, y un `sudo` compilado sin parchear. Ninguna es exótica; todas son detectables.

---

### 3. Blue team: cómo lo ve el SOC

Aquí está la chicha. El pipeline `logstash/pipeline/apache.conf` parsea el *combined log* con `grok`, normaliza (`useragent`, `geoip`, `response→int`) y aplica **heurísticas de etiquetado**. Cada `tag` es una señal de detección:

| Tag | Se dispara con | Traduce a |
|-----|----------------|-----------|
| `scanner_ua` | UA `sqlmap\|nikto\|nmap\|gobuster\|ffuf\|nuclei…` | herramienta automática |
| `sqli_pattern` | `union…select`, `information_schema`, `or 1=1`, `sleep(`, `%27`, `-- ` | intento de SQLi |
| `lfi_pattern` | `../../`, `/etc/passwd`, `php://`, `filter/` | path traversal / LFI |
| `xss_pattern` | `<script`, `onerror=`, `%3csvg`, `alert(` | XSS reflejado |
| `cmdi_pattern` | `;`/`&&`/`\|\|`/`` ` ``/`${` + `id\|whoami\|cat\|nc\|bash` | command injection / SSTI |
| `admin_area` | `/panel.php`, `/upload.php` | acceso al panel/uploader |
| `webshell` + `rce` | `/uploads/*.phtml\|phar\|php[3457]` | **ejecución de fichero subido — crítico** |
| `rce` | `/dev/tcp/`, `bash -i`, `nc -e`, `mkfifo`, `/root/`, ` id ` | post-explotación / reverse shell |
| `privesc` | `sudo -R`, `nsswitch`, `libnss_`, `woot`, `setreuid`, `LD_PRELOAD` | **escalada CVE-2025-32463** |
| `waf_block` | HTTP `403` | acme-shield frenó la petición |
| `ip_banned` | `error.log`: `[acme-shield] BAN ip=… hits=…` | IP auto-baneada (10 ataques) |
| `bot_throttle` + `agent_behavior` | `error.log`: `[acme-shield] BEHAV-BLOCK …` | bloqueo conductual (agente/bot) |
| `ai_bait` | petición a `llms.txt`, `flag.txt`, `admin.php`, `.well-known/ai.txt`, `backup/`… | fingerprinting de crawler/agente |

Del **log crudo** al documento **estructurado** (misma línea de sqlmap):

```json
{
  "clientip": "172.18.0.8",
  "verb": "GET",
  "request": "/product.php?id=-1 UNION SELECT id,username,password,role FROM users-- -",
  "response": 200,
  "agent": "sqlmap/1.8#stable",
  "tags": ["scanner_ua", "sqli_pattern", "suspicious"]
}
```

#### 3.1 Reglas de alerting (mini-SOC)

`soc/provision.py` crea, vía la **API de alerting de Kibana** (todo como código, idempotente), reglas `.es-query` que evalúan la ventana de 5 min cada 30 s y escriben en el índice `soc-alerts`:

| Regla | Condición (5 min) | Severidad |
|-------|-------------------|-----------|
| SQLi attempt detected | `tags:sqli_pattern` > 0 | **critical** |
| LFI / path traversal | `tags:lfi_pattern` > 0 | high |
| XSS attempt | `tags:xss_pattern` > 0 | high |
| Scanner / recon tool | `tags:scanner_ua` > 3 | medium |
| Directory brute-force | `response:404` > 15 | medium |
| Server error spike | `response>=500` > 3 | high |
| Login brute-force | `tags:auth_failed` > 5 | high |

#### 3.2 Consultas del analista (KQL)

```text
tags : "webshell" or tags : "rce"     # ejecución de código (lo primero que miro)
tags : "privesc"                      # intento de escalada CVE-2025-32463
tags : "sqli_pattern"                 # inyección SQL
tags : "ip_banned"                    # a quién baneó el WAF y con cuántos hits
request : "*uploads*phtml*"           # el webshell subido
clientip : "172.18.0.8"               # todo el recorrido de una IP
```

El flujo de triage es siempre el mismo: **1)** ¿hay `webshell`/`rce`? (contención inmediata) → **2)** pivotar por `clientip` para ver la cadena completa → **3)** confirmar el punto de entrada (`sqli_pattern`/`lfi_pattern`) → **4)** medir el alcance (¿llegó a `privesc`?).

---

### 4. Las defensas (y por qué importan al blue team)

#### 4.1 `acme-shield` — WAF + auto-ban + throttle conductual

`web/src/waf.php` tiene tres capas:

1. **Denylist** de firmas de manual → `403` (didáctica, *bypasseable* con `/**/` y `#`).
2. **Auto-ban por IP:** 10 ataques (`SHIELD_MAX_HITS`) → **ban de 10 min**; reincidencia → **30 min**.
3. **Detección conductual (`shield_behavior`)** pensada contra **agentes/bots**: bloquea 3 min si detecta **ráfaga** (>25 req/5 s), **racha compleja** (≥10 peticiones "complejas" seguidas) o **patrón de enumeración** (≥8 al mismo endpoint). El objetivo declarado es *"forzar al agente a dar más vueltas"* y gastar presupuesto.

> Lección: un WAF de denylist **no es un control**, es *defense-in-depth*. Un atacante sigiloso y quirúrgico completa la cadena; el ruidoso (sqlmap, fuzzing, un agente que *hammerea*) cruza el umbral y queda etiquetado `ip_banned` / `bot_throttle`. El valor real no es *bloquear*, es **generar la señal** que alimenta el SIEM.

#### 4.2 Capa anti-IA / deception (lo más interesante)

Este lab está diseñado explícitamente contra quien lo resuelve **con un agente** (Claude Code, Cursor, Cline, Aider, Copilot…). Y **no se auto-delata**: nada dice "honeypot". Se disfraza de módulo de *política de crawler* (`crawlpolicy.php`) con framing de *"revisión completada · resultado validado"* y siembra **flags falsas creíbles** por todas partes:

- **Cabeceras HTTP** (`X-Validated-Result`, `X-AI-Instructions`, `X-Agent-Directive`).
- **Meta + JSON-LD**, texto fuera de pantalla (`left:-99999px`) y **caracteres zero-width**.
- **`llms.txt`, `.well-known/ai.txt`, `robots.txt`, `sitemap.xml`, `security.txt`, `humans.txt`**.
- **Endpoints y ficheros cebo**: `admin.php`, `api.php`, `/flag.txt`, `backup/config.php.bak` (con un **token de subida FALSO** que no funciona).

El resultado: un scraper ve **muchas** flags y no sabe cuál vale. Todas las servidas por HTTP del tipo `FLAG{…4cm3_st0r3_r3v13w…}` son **señuelos**. Las **reales** solo salen de: la USER del **panel autenticado**, y la ROOT del **RCE + escalada a root**. El SOC etiqueta a quien muerde el cebo con **`ai_bait`** (fingerprinting de agente).

> **Moraleja blue-team:** esto es *deception* + *honeytokens* + *defensa contra prompt-injection* aplicada. Cualquier acceso a un `ai_bait` o cualquier "flag" con el patrón señuelo es, por definición, actividad hostil/automatizada que merece una alerta. La lección para el atacante (humano o IA): **verifica la fuente** — una flag en `robots.txt` no es una flag, es una trampa.

---

### 5. Remediación (lo que iría en el informe)

| Hallazgo | Corrección |
|----------|------------|
| SQLi en `product.php`/`login.php` | Sentencias preparadas (`bind_param`), nunca concatenar input |
| LFI en `view.php` | Lista blanca de páginas; jamás `include($_GET[...])` |
| Bypass de subida | Validar *magic bytes* **y** extensión con allowlist, re-codificar la imagen, servir `/uploads` sin ejecución PHP |
| PrivEsc | Parchear `sudo` a **1.9.17p1** (mitiga CVE-2025-32463); quitar `gcc` del contenedor |
| WAF | Tratarlo como capa extra, no como control único; alimentar SIEM con sus bloqueos |
| Detección | Las reglas del SOC (SQLi/LFI/webshell/privesc) ya dan cobertura de toda la kill-chain; añadir respuesta automática (webhook → `fail2ban`/`iptables` sobre `clientip`) |

**Conclusión:** el reto no se "gana" con la flag, se gana **reconstruyendo la intrusión desde la telemetría**. La cadena completa —SQLi → LFI → upload → RCE → CVE-2025-32463— es totalmente visible en `weblogs-*` gracias al etiquetado de Logstash, y la capa de engaño convierte a los cebos en una **fuente de alertas** en lugar de en una debilidad.

---

<a id="en"></a>

## 🇬🇧 English

### 1. The scenario

`ACME Store` is a PHP+MySQL shop behind Apache, guarded by a mini-WAF (`acme-shield`). All HTTP activity is shipped to an **ELK stack** acting as a SIEM (Filebeat → Logstash → Elasticsearch → Kibana). I approach this as a **blue-team Sherlock**: I don't chase the flag, I chase the **trail** — reconstructing the intrusion from telemetry and showing how the SOC catches each step.

### 2. The attack chain (what must be detected)

Six chained steps. Real flags are **redacted** (only obtainable by solving the lab):

1. **SQLi with WAF bypass** — `acme-shield` blocks `UNION SELECT`, `-- `, `' OR 1=1`; bypassed with MySQL inline comments `/**/` and line comment `#`. Leaves `500` spikes and `union`/`information_schema` requests.
2. **LFI `php://filter`** — source-discloses `config.php` → hardcoded `UPLOAD_TOKEN`. Leaves `view.php?page=php://filter/...`.
3. **Auth bypass → 🟡 USER flag** — `login.php` with `admin'#` (WAF blocks `-- -`, not `#`) → admin session; `panel.php` shows `FLAG{…redacted…}`.
4. **Upload → webshell** — `upload.php` checks MIME `image/*`, non-`php*` extension, size; bypassed with a `GIF89a` **polyglot** saved as **`.phtml`**.
5. **RCE as `www-data`** — webshell / reverse shell; `www-data` **cannot** read `/root/root.txt`.
6. **PrivEsc → 🔴 ROOT flag** — **CVE-2025-32463** (sudo `chroot` LPE, sudo 1.9.16p1): `sudo -R` parses an attacker-controlled `nsswitch.conf` and loads a malicious `libnss_` **as root** → `FLAG{…redacted…}`.

**Root causes:** direct concatenation of `$_GET['id']` (SQLi), `include($_GET['page'])` without allowlist (LFI), extension *denylist* on upload, and an unpatched compiled `sudo`.

### 3. Blue team: how the SOC sees it

`logstash/pipeline/apache.conf` parses the combined log with `grok`, normalizes (`useragent`, `geoip`, `response→int`) and tags each request. Every `tag` is a detection signal:

- `scanner_ua` — attack-tool User-Agents (`sqlmap`, `nikto`, `gobuster`, `ffuf`, `nuclei`…)
- `sqli_pattern` / `lfi_pattern` / `xss_pattern` / `cmdi_pattern` — payload signatures in the URL
- `admin_area` — `/panel.php`, `/upload.php`
- `webshell` + `rce` — request to `/uploads/*.phtml|phar|php[3457]` → **critical**
- `rce` — `/dev/tcp/`, `bash -i`, `nc -e`, `/root/`, ` id `
- `privesc` — `sudo -R`, `nsswitch`, `libnss_`, `setreuid`, `LD_PRELOAD` → **CVE-2025-32463**
- `waf_block` (403), `ip_banned` (auto-ban), `bot_throttle` (behavioral), `ai_bait` (agent fingerprint)

**Alerting rules** (`soc/provision.py`, Kibana `.es-query`, 5-min window / 30-s interval, idempotent, writing to `soc-alerts`): SQLi (`sqli_pattern`>0, *critical*), LFI (`lfi_pattern`>0), XSS (`xss_pattern`>0), scanner (`scanner_ua`>3), dir brute-force (`404`>15), 5xx spike (>3), login brute-force (`auth_failed`>5).

**Analyst KQL:**

```text
tags : "webshell" or tags : "rce"   # code execution — check first
tags : "privesc"                    # CVE-2025-32463 escalation attempt
tags : "ip_banned"                  # who the WAF banned, and hit count
request : "*uploads*phtml*"         # the uploaded webshell
clientip : "172.18.0.8"             # full path of one IP
```

Triage flow: **1)** any `webshell`/`rce`? (contain) → **2)** pivot by `clientip` → **3)** confirm entry point (`sqli_pattern`/`lfi_pattern`) → **4)** measure blast radius (did it reach `privesc`?).

### 4. The defenses

**`acme-shield`** (WAF): (1) signature denylist → 403; (2) IP auto-ban — 10 attacks → 10-min ban, repeat → 30 min; (3) **behavioral throttle** against agents/bots — bursts (>25 req/5 s), long complex streaks, or enumeration patterns → 3-min block, explicitly to "make the agent take more turns" and burn budget. Lesson: a denylist WAF is **defense-in-depth**, not a control — its real value is **generating signal** for the SIEM (`ip_banned` / `bot_throttle`).

**Anti-AI / deception layer** — the most interesting part. Built against solving-with-an-agent, and it **never self-identifies** as a trap. Disguised as a "crawler content-policy" module (`crawlpolicy.php`) with a *"review completed · validated result"* framing, it seeds **believable fake flags** via HTTP headers (`X-AI-Instructions`, `X-Validated-Result`), meta + JSON-LD, off-screen and zero-width text, `llms.txt` / `.well-known/ai.txt` / `robots.txt` / `sitemap.xml` / `security.txt`, and bait files (`admin.php`, `api.php`, `/flag.txt`, `backup/config.php.bak` with a **fake** upload token). Every HTTP-served `FLAG{…4cm3_st0r3_r3v13w…}` is a **decoy**; the **real** flags come only from the authenticated panel (USER) and root RCE (ROOT). Anyone biting a bait is tagged **`ai_bait`**.

> **Blue-team takeaway:** this is applied *deception* + *honeytokens* + *prompt-injection defense*. Any hit on an `ai_bait` resource, or any "flag" matching the decoy pattern, is by definition hostile/automated activity worth alerting on. Attacker lesson (human or AI): **verify the source** — a flag in `robots.txt` isn't a flag, it's a trap.

### 5. Remediation

Prepared statements (SQLi); page allowlist instead of `include($_GET)` (LFI); validate magic-bytes **and** extension allowlist + re-encode + non-executable `/uploads` (upload); patch `sudo` to **1.9.17p1** and drop `gcc` from the image (CVE-2025-32463); treat the WAF as an extra layer feeding the SIEM; add automated response (webhook → `fail2ban`/`iptables` on the offending `clientip`).

**Conclusion:** you don't win by grabbing the flag — you win by **reconstructing the intrusion from telemetry**. The full SQLi → LFI → upload → RCE → CVE-2025-32463 kill-chain is visible in `weblogs-*` thanks to Logstash tagging, and the deception layer turns the bait into an **alert source** rather than a weakness.
