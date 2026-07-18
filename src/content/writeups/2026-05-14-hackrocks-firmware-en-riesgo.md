---
title: "Firmware en Riesgo — HackRocks"
date: 2026-05-14
description: "Análisis de firmware: extracción del sistema de archivos con binwalk y búsqueda de secretos embebidos."
excerpt: "binwalk/unblob para extraer el filesystem → grep de credenciales y claves embebidas."
platform: "CTF"
difficulty: "Medium"
image: "/images/ctf.svg"
tags:
  - "Forense"
  - "Firmware"
  - "binwalk"
  - "IoT"
  - "Hardcoded Secrets"
  - "HackRocks"
---

> **Forense · HackRocks UDLA · Medium** — reto de competición finalizado. Flags redactadas.

| | |
|---|---|
| **Categoría** | Forensics |
| **Dificultad** | Medio |
| **Material** | `package_z5yZ8HZ.img` |
| **Puntos** | 60 |
| **Token** | `TQDIPQNOQY` |

## Enunciado

Analizar un firmware, rastrear la acción del malware y recuperar la información. Pistas:
1. Cifrado **híbrido** (clave simétrica cifrada con clave pública).
2. La clave privada está protegida por **contraseña** → fuerza bruta con `rockyou`.
3. Tarda mucho → **multithreading**.

## Análisis

La imagen es un sistema de ficheros **FAT16**:

```bash
$ file package_z5yZ8HZ.img
package_z5yZ8HZ.img: DOS/MBR boot sector ... FAT (16 bit)

$ binwalk package_z5yZ8HZ.img
40960  0xA000  OpenSSL encryption, salted, salt: 0x6A436A8568BE4584
```

Extraemos su contenido con `mtools`:

```bash
$ mdir -i package_z5yZ8HZ.img ::
original.enc      32   # OpenSSL "Salted__"
aes.key.enc      256   # clave AES cifrada con RSA
private.pem     1886   # clave privada CIFRADA (passphrase)
public.pem       451
$ mcopy -i package_z5yZ8HZ.img ::original.enc ::aes.key.enc ::private.pem ::public.pem .
```

`private.pem` empieza por `-----BEGIN ENCRYPTED PRIVATE KEY-----` → está protegida por
passphrase (PBES2 / PBKDF2 + AES).

## Explotación

### 1. Crackear la passphrase de la clave privada (rockyou + multithreading)

`john` no carga este tipo PKCS#8/PBES2, así que crackeamos **en memoria** con la librería
`cryptography` de Python y `multiprocessing` (16 procesos):

```python
from cryptography.hazmat.primitives import serialization
import multiprocessing as mp

PEM = open("private.pem","rb").read()
def try_pw(pw):
    try:
        serialization.load_pem_private_key(PEM, password=pw); return pw
    except Exception: return None
# ... pool sobre /usr/share/wordlists/rockyou.txt
```

Resultado:

```
PASSWORD FOUND: hunter4
```

### 2. Descifrar la clave AES con la privada (RSA)

```bash
$ openssl pkeyutl -decrypt -inkey private.pem -passin pass:hunter4 \
      -in aes.key.enc -out aeskey.bin
```

Salen **32 bytes binarios**. Detalle clave: el byte nº 30 es `0x0a` (`\n`).

### 3. Descifrar `original.enc` (el "truco" del reto)

`original.enc` es OpenSSL salted. Cuando los atacantes cifraron con `openssl enc -pass`,
OpenSSL **trunca la contraseña en el primer `\n`** → solo usó los **30 primeros bytes** de
la clave. Replicando exactamente eso (clave truncada, `aes-256-cbc`, KDF **PBKDF2-SHA256,
10000 iteraciones** = default de OpenSSL 3.x con `-pbkdf2`) el padding PKCS#7 sale
perfecto:

```python
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
raw  = open("aeskey.bin","rb").read()
pw   = raw.split(b"\n")[0]                 # <- truncado en \n
data = open("original.enc","rb").read()
salt, ct = data[8:16], data[16:]
dk = hashlib.pbkdf2_hmac("sha256", pw, salt, 10000, 48)
c  = Cipher(algorithms.AES(dk[:32]), modes.CBC(dk[32:48])).decryptor()
pt = c.update(ct) + c.finalize()
print(pt)   # b'TQDIPQNOQY\n\x05\x05\x05\x05\x05'  (padding válido)
```

Texto recuperado: `TQDIPQNOQY`.

## Flag

```
TQDIPQNOQY
```

> Comprobado que no decodifica a algo más legible (Caesar/atbash/base32/base64): es el
> valor recuperado directamente.

## Conclusión

Reto multi-capa: FAT16 → RSA con clave privada *passphrase-protected* (crackeada con
rockyou en paralelo) → AES OpenSSL salted. El detalle fino que rompe la mayoría de
intentos es el `0x0a` dentro de la clave binaria: `openssl enc -pass` la trunca en el
salto de línea, por lo que hay que reproducir ese comportamiento al descifrar.
