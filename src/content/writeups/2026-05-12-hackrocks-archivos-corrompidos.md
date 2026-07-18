---
title: "Archivos Corrompidos — HackRocks"
date: 2026-05-12
description: "Reto crypto/forense: reparar cabeceras de archivo corruptas y descifrar el contenido recuperado."
excerpt: "Reparar magic bytes → recuperar el contenedor → descifrado del payload."
platform: "CTF"
difficulty: "Hard"
image: "/images/ctf.svg"
tags:
  - "Crypto"
  - "Forense"
  - "File Repair"
  - "Magic Bytes"
  - "HackRocks"
---

> **Crypto · HackRocks UDLA · Hard** — reto de competición finalizado. Flags redactadas.

| | |
|---|---|
| **Categoría** | Data Security |
| **Dificultad** | Difícil |
| **Puntos** | 90 |
| **Material** | directorio con ficheros cifrados (esquema ransomware) |
| **Token** | `GUARDIANS_OF_THE_GALAXY` |

## Enunciado

Archivos críticos de la nave *Trinity* han sido cifrados por un presunto ransomware. Hay
que identificar el esquema criptográfico y recuperar la información.

Pistas:
1. Cifrado **híbrido**: clave simétrica cifrada a su vez con una clave **pública**. Hay
   un directorio **oculto** sin encontrar.
2. El directorio oculto es `.keys`, con `pass.enc` (la clave simétrica). Descífralo con
   la **privada**.
3. Descifra los ficheros con esa contraseña; el algoritmo es **AES**.

## Análisis

Listando incluyendo ocultos aparece el directorio `.keys`:

```bash
$ find trinity_firmware -mindepth 1 | sort
trinity_firmware/.keys
trinity_firmware/.keys/.private_key.pem
trinity_firmware/.keys/pass.enc
trinity_firmware/.keys/public_key.pem
trinity_firmware/manual_vuelo.enc
trinity_firmware/trinity_code.bin
```

Esquema clásico de ransomware híbrido:
- `pass.enc` → clave simétrica AES, cifrada con RSA (clave pública).
- `manual_vuelo.enc` → datos cifrados con AES usando esa clave.
- Tenemos `.private_key.pem` → podemos revertir todo.

## Explotación

**Paso 1 — Descifrar la clave simétrica con RSA (clave privada):**

```bash
$ openssl pkeyutl -decrypt -inkey .keys/.private_key.pem \
      -in .keys/pass.enc -out pass.txt
$ cat pass.txt
contraseñamuydificildecifrado
```

**Paso 2 — Identificar el formato AES.** El `.enc` es OpenSSL salted:

```bash
$ file manual_vuelo.enc
manual_vuelo.enc: openssl enc'd data with salted password
```

**Paso 3 — Descifrar con AES** (probando cifrado/derivación de clave). Funciona
`aes-256-cbc` con derivación `sha256`:

```bash
$ openssl enc -d -aes-256-cbc -md sha256 \
      -in manual_vuelo.enc -pass pass:'contraseñamuydificildecifrado'
Enhorabuena! Has superado este reto.

El token del juego es:

GUARDIANS_OF_THE_GALAXY
```

## Flag

```
GUARDIANS_OF_THE_GALAXY
```

## Conclusión

El esquema híbrido RSA+AES es la base de casi todo ransomware moderno: AES (rápido) para
los datos y RSA para proteger la clave AES. La recuperación solo es posible porque
disponíamos de la clave **privada** RSA (normalmente solo la tiene el atacante). Lección
operativa: revisar siempre ficheros/directorios ocultos (`.keys`).
