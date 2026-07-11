---
title: "Fluid Attacks CTF 2026: Crypto - ECDSA Broken Nonce"
date: 2026-02-01
description: "Recuperación de clave privada ECDSA explotando un generador de nonce sesgado."
tags: ["CTF", "Crypto", "ECDSA", "Math", "Python"]
image: "/images/blog/fluid-crypto.png"
---

## 🎯 Objetivo

El reto `Crypto1` presentaba un servicio de firma digital basado en curvás elípticas (**ECDSA**). Nos permitía firmar mensajes arbitrarios y nos entregaba la firma `(r, s)`.

El objetivo era falsificar una firma o recuperar la clave privada para descifrar la flag.

## 🧮 Teoría: La Importancia del Nonce (k)

En ECDSA, la seguridad de la clave privada (`d`) depende críticamente de que el número aleatorio `k` (nonce) sea:
1.  Único para cada firma.
2.  Impredecible (criptográficamente seguro).

Si `k` es predecible o se reutiliza, la clave privada `d` queda expuesta.

La ecuación de firma es:
$$ s = k^{-1} (h + r \cdot d) \pmod n $$

## 🔍 Análisis del Código Vulnerable

Al analizar el script `challenge.py`, encontramos la falla en la generación de `k`.

```python
# Falla crítica en la generación del nonce
# h = hash(mensaje)
# nonce = ((h // 2**128) * 2**128) + d
```

El desarrollador intentó hacer algo "inteligente" mezclando el hash con la propia clave privada `d`. Esto es catastrófico porque crea una relación lineal directa entre el nonce y la clave privada.

Podemos reescribir la relación como:
$$ k = H_{top} + d $$

Donde $H_{top}$ es la parte superior del hash (que conocemos).

## 💥 El Ataque

Teniendo la ecuación de firma y nuestra ecuación de nonce, tenemos un sistema con una incógnita (`d`).

Sustituimos $k$ en la ecuación de firma:
$$ s = (H_{top} + d)^{-1} (h + r \cdot d) \pmod n $$

Despejamos `d`:
$$ s(H_{top} + d) = h + r \cdot d $$
$$ s \cdot H_{top} + s \cdot d = h + r \cdot d $$
$$ s \cdot d - r \cdot d = h - s \cdot H_{top} $$
$$ d(s - r) = h - s \cdot H_{top} $$

Finalmente:
$$ d = (h - s \cdot H_{top}) \cdot (s - r)^{-1} \pmod n $$

### Implementación del Solver

### Full Solver Script (`solve.py`)

```python
import sys
import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from ecdsa.ecdsa import generator_256

# --- Exploit Constants ---
G = generator_256
q = G.order()

# --- Helper Math ---
def inverse(a, n):
    return pow(a, -1, n)

def recover_private_key(msg, r, s):
    # 1. Calc Hash
    h_int = int(hashlib.sha256(msg.encode()).hexdigest(), 16)
    
    # 2. Reconstruct H_top (the upper 128 bits of the hash)
    # The challenge does: nonce = ((h // 2**128) * 2**128) + d
    # So k = h_top + d
    h_top = (h_int // 2**128) * 2**128
    
    # 3. Use the derived formula:
    # d = (s * h_top - h) * (r - s)^(-1) mod q
    
    numerator = (s * h_top - h_int) % q
    denominator = (r - s) % q
    
    try:
        inv_denominator = inverse(denominator, q)
    except ValueError:
        return None

    d_recovered = (numerator * inv_denominator) % q
    return d_recovered

def decrypt_flag(d, enc_flag_hex):
    # Replicate key derivation from challenge
    key = hashlib.sha256(str(d).encode()).digest()[:16]
    aes = AES.new(key, AES.MODE_ECB)
    
    try:
        encrypted_bytes = bytes.fromhex(enc_flag_hex)
        decrypted = unpad(aes.decrypt(encrypted_bytes), 16)
        return decrypted.decode()
    except Exception as e:
        print(f"[!] Decryption failed: {e}")
        return None

# --- Remote Exploit logic (Simplified) ---
# ... (Connection logic omitted for brevity, see original script)
```

## 🏆 Resultado

Con la clave privada `d` recuperada, pudimos descifrar la flag que estaba encriptada con AES usando una clave derivada de `d`.

> **Lección**: Nunca inventes tu propio esquema de criptografía. Usa implementaciones estándar como RFC 6979 para la generación determinista de nonces.
