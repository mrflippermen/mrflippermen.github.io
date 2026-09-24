---
title: "Holmes CTF 2026 — S07 Iron Feather"
date: 2026-09-21
description: "RE del cifrado propietario de un drone PX4 (AES-256-GCM + PBKDF2 con un KDF custom) para descifrar dataman y flight.ulg, parsear el ULog/MAVLink y reconstruir un sabotaje aéreo hasta geolocalizar el punto de impacto."
excerpt: "Un quadcopter que no volvió: reversear el esquema PX4DMENC con Ghidra y GDB, reimplementar el KDF, descifrar los logs, seguir el MAV_CMD_INJECT_FAILURE y aterrizar el impacto en Knightsbridge."
platform: "HTB"
difficulty: "Hard"
image: "/images/ctf.svg"
tags:
  - "DFIR"
  - "Reverse Engineering"
  - "Drone"
  - "PX4"
  - "Crypto"
  - "Holmes CTF 2026"
---

> **Reto:** Holmes CTF 2026 — Sherlock 07 "Iron Feather" · RE del cifrado de un drone PX4 + análisis ULog/MAVLink. Parte del arco *The Reichenbach Directive*.
>
> **Navegación:** [🇪🇸 Español](#es) · [🇬🇧 English](#en)

<a id="es"></a>

## 🇪🇸 Español

### Escenario

Un quadcopter salió de un edificio seguro y **no volvió**. Lo que se recupera del dron es un almacenamiento "dañado" y unos registros de vuelo **cifrados**: `flight.ulg` (log ULog) y `dataman` (base de misión/waypoints de PX4), ambos presentes en claro y en su versión `.encrypted`, más el binario del autopiloto **`px4`**.

El truco: el cifrado **no es** el esquema oficial de PX4 (XChaCha20 + RSA). Es un formato **propietario** metido en este build concreto del firmware. No hay clave por ningún lado, así que la única vía es **reversear el binario**, entender el KDF, capturar/reproducir la clave derivada, descifrar los logs y luego **reconstruir el vuelo** por MAVLink hasta explicar por qué el dron se estrelló y dónde. Dificultad: **hard**.

### Artefacto y herramientas

- **Evidencia:** `flight.ulg` + `dataman` (claros de referencia) y `flight.ulg.encrypted` + `dataman.encrypted`; binario **`px4`** (ELF del autopiloto).
- **RE:** **Ghidra** (localizar la función de cifrado/KDF, leer constantes) + **GDB** (capturar la clave derivada en runtime).
- **Cripto:** `AES-256-GCM` (paquete `cryptography` / `AESGCM`), `PBKDF2-HMAC-SHA256` reimplementado en Python.
- **ULog/MAVLink:** `pyulog` (`ulog_info`, `ulog_messages`), diccionario de `MAV_CMD_*`.
- **Geolocalización:** Nominatim + Overpass + Photon para nombrar coordenadas y medir distancia perpendicular al eje de trayectoria.

### Metodología (paso a paso)

**1. Identificar el formato — `PX4DMENC`.** Los ficheros cifrados no empiezan por ningún magic estándar de PX4. Un `xxd` de la cabecera y un `strings` sobre el binario coinciden en un magic propietario:

```
$ xxd -l16 dataman.encrypted
00000000: 5058 3444 4d45 4e43 0100 0000 ...   PX4DMENC....
```

El `dataman` cifrado abre con **`PX4DMENC`** (y el ULog con `PX4ULENC`). La cabecera es:

```
[magic 8][ver u32][len u32][salt 16][nonce 12][tag 16][ciphertext]
```

Los **44 bytes** de cabecera se usan como **AAD** del GCM.

**2. Reversear el esquema en Ghidra.** Dentro de la rutina de descifrado, las constantes cantan el algoritmo:

- Uso de la S-box AES y bloque de 16B con **tag de 16B** → **AES-256-GCM**.
- Constantes de SHA-256 y bucle HMAC/PBKDF2 → derivación de clave por **PBKDF2-HMAC-SHA256** (fallback PBKDF2), `iter = 0x2000` (8192).
- El "password" de PBKDF2 no es una cadena fija: lo produce un **KDF custom** en `RVA 0x170af0` que mezcla tablas de `.rodata` a partir del **salt**.
- El bucle de mezcla termina con `cmp edx,0x17f` → **384** iteraciones (`0x180`).

**3. Reimplementar el KDF custom (`kdf_reimpl.py`).** Reimplementar la mezcla en Python puro replicando exactamente rotaciones y accesos a tablas (offsets de fichero == vaddr en `.rodata`). Núcleo del bucle:

```python
for i in range(rounds):                       # rounds = 0x180 = 384
    b = tblB[(5*i + st[(i+3) & 7]) & 0x1f]
    a = tblA[((st[(i+5) & 7] >> 27) + r11) & 0x1f]
    r11 = (r11 + 0xb) & M32
    c = tbl48[((b >> 24) + i) % 48]
    s = (a >> 27) & 0xf
    r8 = (r10 ^ a ^ b) & M32
    r10 = (r10 + GR) & M32                     # GR = 0x9e3779b9
    r8 = rol(r8, (c & 0xf) + 3)
    r8 = (r8 + st[i & 7] + c) & M32
    r8 = rol(r8, s + 5)
    st[i & 7] = r8
    ...
# etapa final -> primeros 32 bytes del password, luego PBKDF2:
key = hashlib.pbkdf2_hmac('sha256', pw, salt, 0x2000, 32)   # AES-256 key
```

**4. Verificar con GDB (`kdf_call.gdb`).** Antes de fiarse de la reimplementación, se **captura la clave real** llamando a la función del KDF en el propio binario, sin re-derivar a ciegas:

```gdb
break *($base+0x11edb0)
set {char[16]}$salt = "\x60\xc2..\xe8"                       # salt del fichero
set $r=((char(*)(void*,void*))($base+0x170af0))($salt,$key)  # llamar al KDF real
x/32xb $key                                                  # volcar la clave derivada
```

Ambas vías (reimplementación y captura en runtime) coinciden en la **misma clave AES-256**, y el **tag GCM valida** el descifrado — prueba de que la clave es correcta:

```
AES-256 key: a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce
```

**5. Descifrar (`decrypt.py`).** Con la clave, un AES-GCM sobre cada fichero (AAD = 44B de cabecera; en el formato el `tag` va antes del `ciphertext`, por eso se recompone `ct+tag`):

```python
KEY = bytes.fromhex('a40ba87b...d6ce')
d = open('dataman.encrypted','rb').read()
pt = AESGCM(KEY).decrypt(d[32:44], d[60:] + d[44:60], d[:44])   # nonce, ct+tag, AAD
```

Salen `dataman` y `flight.ulg` en claro (y **casan** con los ficheros de referencia).

**6. Parsear el ULog (`pyulog`) y leer la misión.** Con el log descifrado:

```bash
ulog_info flight.ulg ; ulog_messages flight.ulg
```

Topics clave: `vehicle_gps_position`/`vehicle_global_position` (lat/lon/alt), `vehicle_command` (comandos MAVLink), `actuator_armed`, `mission`/`mission_result`, `dataman` (waypoints). Del `dataman`: `mission_dataman_id = 6` → **`DM_KEY_WAYPOINTS_OFFBOARD_0`**; el `main` guarda el `dm_item_t`, cuyo valor relevante para el par consultado es **0**. El número de items de misión es **24**, con un **`DO_SET_ACTUATOR` (p1=1)** en el ítem **10** (alt. 11) = soltar carga.

**7. Reconstruir el sabotaje (MAVLink) y geolocalizar.** Recorriendo `vehicle_command` y correlacionando con las posiciones GPS por timestamp:

- El ítem **23** es un `NAV_LAND` en **`51.49970,-0.16080`**; el **home** es **`51.4996987,-0.1607999`**.
- **Release** de la carga (`DO_SET_ACTUATOR`) en **`51.5035602,-0.1608417`**, `t = 446.656`.
- El sabotaje: **`MAV_CMD_INJECT_FAILURE`** (cmd **420**, `source_system 0`) — un comando inyectado desde fuera, no de la misión — a `t = 520.764`.
- **Impacto** a `t = 525.82` en **`51.5016938,-0.1620929`**; **disarm** (`actuator_armed`→0) a `t = 576.968`.
- **Distancia recorrida (trayectoria):** **277** (suma de segmentos; "travel" → trayectoria, no la recta home→impacto = 224).
- **Geolocalización del impacto:** cruzando la coordenada con Nominatim/Overpass/Photon, el punto cae a **0,3 m del eje** sobre **Knightsbridge** (Edinburgh Gate quedaría a 9,8 m).

**Timeline reconstruida:**

```
arm 285.260 → takeoff 287.07 → release 446.656 → INJECT_FAILURE 520.764 → impacto 525.82 → disarm 576.968
```

### Respuestas / flags

| # | Pregunta | Respuesta |
|---|----------|-----------|
| 1 | Magic/cabecera del formato de cifrado | `PX4DMENC` |
| 2 | Algoritmo de cifrado simétrico | `AES-256-GCM` |
| 3 | RVA de la función KDF custom | `0x170af0` |
| 4 | Iteraciones del bucle de mezcla (cmp edx,0x17f) | `384` |
| 5 | Función de derivación de clave | `PBKDF2-HMAC-SHA256` |
| 6 | Clave AES-256 derivada (tag GCM válido) | `a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce` |
| 7 | Valor `dm_item_t` del par consultado | `0` |
| 8 | Nº de items de misión | `24` |
| 9 | Índice del `DO_SET_ACTUATOR` (p1=1) | `10` (alt. 11) |
| 10 | Coordenada `NAV_LAND` (ítem 23) | `51.49970,-0.16080` |
| 11 | Coordenada home | `51.4996987,-0.1607999` |
| 12 | Coordenada de release de carga (t=446.656) | `51.5035602,-0.1608417` |
| 13 | Comando de sabotaje (cmd 420, src 0) | `MAV_CMD_INJECT_FAILURE` |
| 14 | Distancia recorrida (trayectoria) | `277` |
| 15 | Coordenada de impacto (525.82 s) | `51.5016938,-0.1620929` |
| 16 | Timestamp de disarm (actuator_armed→0) | `576.968` |
| 17 | Lugar real del impacto | `Knightsbridge` |

### Lecciones

- **No re-derivar a ciegas.** Con un cifrado propietario, localizar la función en Ghidra por sus constantes (S-box AES, constantes SHA, tamaño de IV/tag) y **capturar la clave derivada con GDB** llamando al KDF real. Validar siempre con el **tag GCM / CRC**: si valida, la clave es correcta.
- **El formato oficial es una pista falsa.** PX4 usa XChaCha20/RSA; este build metía un esquema custom. Fiarse del magic real (`PX4DMENC`/`PX4ULENC`) y de la cabecera de 44B como AAD, no de la documentación.
- **"Travel" = trayectoria.** La pregunta de distancia pedía la suma de segmentos (277), no la recta home→impacto (224). Leer literal.
- **Geoloc con margen.** Nominatim/Overpass/Photon + distancia perpendicular al eje desambigua entre candidatos cercanos (Knightsbridge a 0,3 m frente a Edinburgh Gate a 9,8 m).

---

<a id="en"></a>

## 🇬🇧 English

### Scenario

A quadcopter left a secure building and **never came back**. What is recovered from the drone is a "damaged" storage and **encrypted** flight logs: `flight.ulg` (ULog) and `dataman` (PX4 mission/waypoint store), both present in cleartext and as their `.encrypted` counterparts, plus the autopilot binary **`px4`**.

The catch: the encryption is **not** PX4's official scheme (XChaCha20 + RSA). It's a **proprietary** format baked into this specific firmware build. No key anywhere, so the only path is to **reverse the binary**, understand the KDF, capture/reproduce the derived key, decrypt the logs, and then **reconstruct the flight** over MAVLink to explain why and where the drone crashed. Difficulty: **hard**.

### Artifact and tooling

- **Evidence:** `flight.ulg` + `dataman` (cleartext references) and `flight.ulg.encrypted` + `dataman.encrypted`; the **`px4`** autopilot ELF.
- **RE:** **Ghidra** (locate the crypto/KDF function, read constants) + **GDB** (capture the derived key at runtime).
- **Crypto:** `AES-256-GCM` (`cryptography` / `AESGCM`), `PBKDF2-HMAC-SHA256` reimplemented in Python.
- **ULog/MAVLink:** `pyulog` (`ulog_info`, `ulog_messages`), `MAV_CMD_*` dictionary.
- **Geolocation:** Nominatim + Overpass + Photon to name coordinates and measure perpendicular distance to the trajectory axis.

### Methodology (step by step)

**1. Identify the format — `PX4DMENC`.** The encrypted files start with no standard PX4 magic. An `xxd` of the header and `strings` on the binary agree on a proprietary magic:

```
$ xxd -l16 dataman.encrypted
00000000: 5058 3444 4d45 4e43 0100 0000 ...   PX4DMENC....
```

The encrypted `dataman` opens with **`PX4DMENC`** (and the ULog with `PX4ULENC`). Header layout:

```
[magic 8][ver u32][len u32][salt 16][nonce 12][tag 16][ciphertext]
```

The **44-byte** header is used as the GCM **AAD**.

**2. Reverse the scheme in Ghidra.** Inside the decrypt routine, the constants give away the algorithm:

- AES S-box usage and a 16B block with a **16B tag** → **AES-256-GCM**.
- SHA-256 constants and an HMAC/PBKDF2 loop → **PBKDF2-HMAC-SHA256** (PBKDF2 fallback), `iter = 0x2000` (8192).
- The PBKDF2 "password" is not a fixed string: it's produced by a **custom KDF** at **RVA 0x170af0** that mixes `.rodata` tables from the **salt**.
- The mixing loop ends on `cmp edx,0x17f` → **384** iterations (`0x180`).

**3. Reimplement the custom KDF (`kdf_reimpl.py`).** Reimplement the mix in pure Python, replicating rotations and table lookups exactly (file offsets == vaddr in `.rodata`). Loop core:

```python
for i in range(rounds):                       # rounds = 0x180 = 384
    b = tblB[(5*i + st[(i+3) & 7]) & 0x1f]
    a = tblA[((st[(i+5) & 7] >> 27) + r11) & 0x1f]
    r11 = (r11 + 0xb) & M32
    c = tbl48[((b >> 24) + i) % 48]
    s = (a >> 27) & 0xf
    r8 = (r10 ^ a ^ b) & M32
    r10 = (r10 + GR) & M32                     # GR = 0x9e3779b9
    r8 = rol(r8, (c & 0xf) + 3)
    r8 = (r8 + st[i & 7] + c) & M32
    r8 = rol(r8, s + 5)
    st[i & 7] = r8
    ...
# final stage -> first 32 bytes of the password, then PBKDF2:
key = hashlib.pbkdf2_hmac('sha256', pw, salt, 0x2000, 32)   # AES-256 key
```

**4. Verify with GDB (`kdf_call.gdb`).** Before trusting the reimplementation, **capture the real key** by calling the KDF function in the binary itself, instead of re-deriving blindly:

```gdb
break *($base+0x11edb0)
set {char[16]}$salt = "\x60\xc2..\xe8"                       # salt from the file
set $r=((char(*)(void*,void*))($base+0x170af0))($salt,$key)  # call the real KDF
x/32xb $key                                                  # dump the derived key
```

Both paths (reimplementation and runtime capture) agree on the **same AES-256 key**, and the **GCM tag validates** the decryption — proof the key is correct:

```
AES-256 key: a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce
```

**5. Decrypt (`decrypt.py`).** With the key, AES-GCM over each file (AAD = 44B header; in this format the `tag` precedes the `ciphertext`, so `ct+tag` is recomposed):

```python
KEY = bytes.fromhex('a40ba87b...d6ce')
d = open('dataman.encrypted','rb').read()
pt = AESGCM(KEY).decrypt(d[32:44], d[60:] + d[44:60], d[:44])   # nonce, ct+tag, AAD
```

This yields cleartext `dataman` and `flight.ulg` (which **match** the reference files).

**6. Parse the ULog (`pyulog`) and read the mission.** With the decrypted log:

```bash
ulog_info flight.ulg ; ulog_messages flight.ulg
```

Key topics: `vehicle_gps_position`/`vehicle_global_position` (lat/lon/alt), `vehicle_command` (MAVLink commands), `actuator_armed`, `mission`/`mission_result`, `dataman` (waypoints). From `dataman`: `mission_dataman_id = 6` → **`DM_KEY_WAYPOINTS_OFFBOARD_0`**; `main` stores the `dm_item_t`, whose relevant value for the queried pair is **0**. The mission has **24** items, with a **`DO_SET_ACTUATOR` (p1=1)** at item **10** (alt. 11) = payload release.

**7. Reconstruct the sabotage (MAVLink) and geolocate.** Walking `vehicle_command` and correlating with GPS positions by timestamp:

- Item **23** is a `NAV_LAND` at **`51.49970,-0.16080`**; the **home** point is **`51.4996987,-0.1607999`**.
- Payload **release** (`DO_SET_ACTUATOR`) at **`51.5035602,-0.1608417`**, `t = 446.656`.
- The sabotage: **`MAV_CMD_INJECT_FAILURE`** (cmd **420**, `source_system 0`) — a command injected from outside, not from the mission — at `t = 520.764`.
- **Impact** at `t = 525.82` at **`51.5016938,-0.1620929`**; **disarm** (`actuator_armed`→0) at `t = 576.968`.
- **Distance travelled (trajectory):** **277** (sum of segments; "travel" → trajectory, not the straight home→impact line = 224).
- **Impact geolocation:** cross-referencing the coordinate with Nominatim/Overpass/Photon, the point falls **0.3 m off the axis** onto **Knightsbridge** (Edinburgh Gate would be 9.8 m away).

**Reconstructed timeline:**

```
arm 285.260 → takeoff 287.07 → release 446.656 → INJECT_FAILURE 520.764 → impact 525.82 → disarm 576.968
```

### Answers / flags

| # | Question | Answer |
|---|----------|--------|
| 1 | Encryption format magic/header | `PX4DMENC` |
| 2 | Symmetric cipher | `AES-256-GCM` |
| 3 | Custom KDF function RVA | `0x170af0` |
| 4 | Mixing-loop iterations (cmp edx,0x17f) | `384` |
| 5 | Key derivation function | `PBKDF2-HMAC-SHA256` |
| 6 | Derived AES-256 key (valid GCM tag) | `a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce` |
| 7 | `dm_item_t` value of the queried pair | `0` |
| 8 | Number of mission items | `24` |
| 9 | Index of the `DO_SET_ACTUATOR` (p1=1) | `10` (alt. 11) |
| 10 | `NAV_LAND` coordinate (item 23) | `51.49970,-0.16080` |
| 11 | Home coordinate | `51.4996987,-0.1607999` |
| 12 | Payload release coordinate (t=446.656) | `51.5035602,-0.1608417` |
| 13 | Sabotage command (cmd 420, src 0) | `MAV_CMD_INJECT_FAILURE` |
| 14 | Distance travelled (trajectory) | `277` |
| 15 | Impact coordinate (525.82 s) | `51.5016938,-0.1620929` |
| 16 | Disarm timestamp (actuator_armed→0) | `576.968` |
| 17 | Real-world impact location | `Knightsbridge` |

### Lessons

- **Don't re-derive blindly.** With proprietary crypto, locate the function in Ghidra by its constants (AES S-box, SHA constants, IV/tag size) and **capture the derived key with GDB** by calling the real KDF. Always validate with the **GCM tag / CRC**: if it validates, the key is right.
- **The official format is a red herring.** PX4 uses XChaCha20/RSA; this build shipped a custom scheme. Trust the actual magic (`PX4DMENC`/`PX4ULENC`) and the 44B header as AAD, not the documentation.
- **"Travel" = trajectory.** The distance question asked for the sum of segments (277), not the straight home→impact line (224). Read literally.
- **Geolocate with a margin.** Nominatim/Overpass/Photon + perpendicular distance to the trajectory axis disambiguates nearby candidates (Knightsbridge at 0.3 m vs Edinburgh Gate at 9.8 m).
