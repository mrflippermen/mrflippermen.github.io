---
title: "CiberRastro — HackRocks"
date: 2026-05-15
description: "Investigación OSINT: correlación de usuarios, redes sociales y fugas para reconstruir una identidad."
excerpt: "Pivotar entre username, redes y filtraciones para reconstruir el rastro digital del objetivo."
platform: "CTF"
difficulty: "Hard"
image: "/images/ctf.svg"
tags:
  - "OSINT"
  - "Username"
  - "Redes Sociales"
  - "Correlación"
  - "HackRocks"
---

> **OSINT · HackRocks UDLA · Hard** — reto de competición finalizado. Flags redactadas.

| | |
|---|---|
| **Categoría** | OSINT |
| **Dificultad** | Difícil |
| **Puntos** | 85 |
| **Punto de partida** | usuario `Tanta_sheesh_1337` (alerta SIEM) |
| **Flag** | `CVE-2022-38292` |

## Enunciado

El SIEM alerta de un intento de login de un usuario extraño: **`Tanta_sheesh_1337`**.
Inteligencia indica que existe una cuenta con nombre similar en alguna red social y que
el atacante tiene también una cuenta de GitHub bajo un alias. Hay que **encontrar el CVE
explotado**.

Pistas:
1. Algo relacionado a `/tantasheesh1337`.
2. Parece que tiene un **partner**; útil comprobar su GitHub.
3. ¿Quizás lo **archivaron**?

## 1. Localizar la red social

X, Instagram, TikTok, Twitch, Telegram, etc. dan 404 / login-wall. Con enumeración de
usuario (`sherlock`) y verificación manual, la cuenta real está en **Pinterest**:

```
https://www.pinterest.com/tantasheesh1337/
```

Bio del perfil:

> **"an alter and a partner for `thund3r42069`"**

→ El *partner* es **`thund3r42069`** (la cuenta de GitHub bajo alias).

## 2. El GitHub del partner

```
https://github.com/thund3r42069
```

El perfil **actual** está vacío: 0 repos públicos. Datos vía API:

```bash
$ curl -s https://api.github.com/users/thund3r42069/followers
# -> rorosudo   (follower; su repo "nuevo/nuevo.php" es un ejemplo SQLi
#                genérico copiado de rubennati/vulnerable-php-code-examples = señuelo)
```

La cuenta no muestra nada útil en su estado actual → Pista #3: **archivado**.

## 3. Recuperar el estado archivado (Wayback Machine)

Consultando el índice CDX de Web Archive aparecen capturas de 2023:

```bash
$ curl -s "https://web.archive.org/cdx/search/cdx?url=github.com/thund3r42069*&fl=original,timestamp&collapse=urlkey"
https://github.com/thund3r42069                       20231020095909
https://github.com/thund3r42069/some-exploits         20231020100038
...
```

Recuperando el **perfil archivado** de 2023:

```bash
$ curl -s "https://web.archive.org/web/20231020095909/https://github.com/thund3r42069" \
     | grep -oE 'data-bio-text="[^"]*"'
data-bio-text="hats off to CVE-2022-38292 for the stash :)"
```

La **bio archivada** revela directamente el CVE:

> *"hats off to **CVE-2022-38292** for the stash :)"*

## 4. Verificación del CVE

```bash
$ python3 tools/nvd-lookup.py CVE-2022-38292
DESCRIPTION: SLiMS (Senayan Library Management System) v9.4.2 was discovered to
contain multiple Server-Side Request Forgeries via the components
/bibliography/marcsru.php and /bibliography/z3950sru.php.
Published: 09/12/2022
```

## Flag

```
CVE-2022-38292
```

## Cadena resumida

```
SIEM: Tanta_sheesh_1337
   └─> Pinterest /tantasheesh1337   (bio: "partner for thund3r42069")
         └─> GitHub thund3r42069     (alias del atacante; perfil hoy vacío)
               └─> Wayback Machine 2023 (perfil archivado)
                     └─> bio: "hats off to CVE-2022-38292"   ← FLAG
```

## Señuelos encontrados (y descartados)

- `rorosudo/nuevo/nuevo.php` → SQLi **idéntico** a un ejemplo público genérico (sin CVE).
- `thund3r42069/some-exploits/temp.py` → repo borrado; el blob no está en ningún archivo
  (Wayback/SWH/archive.today/Common Crawl). La pista real estaba en la **bio del perfil**,
  no en el repo.
- Pin de Pinterest con atribución a `safiri_1337` → ruido.

## Conclusión

OSINT de pivoteo entre identidades: red social → alias de GitHub → estado histórico. La
clave fue entender que "archivaron" se refería al **perfil**, recuperable en la Wayback
Machine, donde la bio de 2023 confesaba el CVE. Lección defensiva: lo que publicas (y
luego borras) en perfiles públicos queda archivado y es trivialmente recuperable.
