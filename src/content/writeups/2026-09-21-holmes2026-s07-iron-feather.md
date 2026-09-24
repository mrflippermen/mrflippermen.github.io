---
title: "Holmes CTF 2026 — S07 Iron Feather"
date: 2026-09-21
description: "RE del cifrado propietario de un drone PX4 (AES-256-GCM + PBKDF2 con un KDF custom) para descifrar dataman y flight.ulg, parsear el ULog/MAVLink y reconstruir un sabotaje aéreo hasta geolocalizar el punto de impacto."
excerpt: "Un quadcopter que no volvió: reversear el esquema PX4DMENC con Ghidra y GDB, reimplementar el KDF, descifrar los logs, seguir el MAV_CMD_INJECT_FAILURE y aterrizar el impacto en Knightsbridge."
platform: "HTB"
difficulty: "Hard"
image: "/images/blog/holmes-s07.svg"
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
> **Navegación:** [🇪🇸 Español](#es) · [🇬🇧 English](#en) · Ir directo a: [Metodología](#es-metodologia) · [Cronología](#es-cronologia) · [Respuestas](#es-respuestas) · [IOCs](#es-iocs) · [MITRE ATT&CK](#es-mitre) · [Detección y remediación](#es-remediacion)

<a id="es"></a>

## 🇪🇸 Español

### Escenario

Un quadcopter salió de un edificio seguro y **no volvió**. Lo que se recupera del dron es un almacenamiento "dañado" y unos registros de vuelo **cifrados**: `flight.ulg` (log ULog) y `dataman` (base de misión/waypoints de PX4), ambos presentes en claro y en su versión `.encrypted`, más el binario del autopiloto **`px4`**.

El truco, y lo que convierte esto en un reto *hard* de verdad, es que el cifrado **no es** el esquema oficial de PX4 (XChaCha20 + RSA que trae el firmware upstream para "secure logging"). Es un formato **propietario** metido a mano en este build concreto del firmware. No hay clave por ningún lado —ni en un `.pem`, ni en variables de entorno, ni en el sistema de ficheros del dron—, así que la única vía es **reversear el binario**, entender el esquema de derivación de clave (KDF), **capturar/reproducir la clave derivada**, descifrar los logs y luego **reconstruir el vuelo** por MAVLink hasta explicar por qué el dron se estrelló y, sobre todo, **dónde**.

El reto es una cadena de dos mitades muy distintas: primero **crypto/RE de bajo nivel** (Ghidra + GDB + reimplementación en Python), y luego **análisis forense de telemetría** (ULog + MAVLink + geolocalización OSINT). Las dos mitades están unidas por un único artefacto: la clave AES-256. Sin RE no hay descifrado; sin descifrado no hay telemetría; sin telemetría no hay caso. Dificultad: **hard**.

> **Encuadre narrativo del arco.** Iron Feather es la S07 de *The Reichenbach Directive*: la operación de APT Napoleon / MurkNet ya no roba datos, ahora **actúa en el mundo físico**. El dron transportaba una carga y fue **sableado a mitad de misión** con un fallo inyectado desde fuera del plan de vuelo. Nuestro trabajo defensivo es reconstruir la secuencia exacta, atribuir el comando malicioso y fijar el punto de impacto para el equipo de respuesta.

### Artefacto y herramientas

- **Evidencia:**
  - `flight.ulg` + `dataman` — copias **en claro** de referencia (para validar que el descifrado casa byte a byte).
  - `flight.ulg.encrypted` (~69 MB) + `dataman.encrypted` (~1,2 MB) — los ficheros **cifrados** reales.
  - **`px4`** — el ELF del autopiloto (~9,8 MB), donde vive todo el esquema de cifrado y el KDF.
  - `Holmes CTF 2026 - Sherlock 07 - Mission Vault.pdf` — narrativa del arco, sin evidencia técnica.
- **RE:** **Ghidra** (localizar la función de cifrado/KDF, leer constantes y tablas de `.rodata`) + **GDB** (capturar la clave derivada en runtime llamando al KDF real).
- **Cripto:** `AES-256-GCM` (paquete `cryptography` / `AESGCM`), `PBKDF2-HMAC-SHA256` reimplementado en Python puro.
- **ULog/MAVLink:** `pyulog` (`ulog_info`, `ulog_messages`), diccionario de `MAV_CMD_*`.
- **Geolocalización:** Nominatim + Overpass + Photon para nombrar coordenadas y medir la **distancia perpendicular al eje** de la trayectoria (desambiguación de calles cercanas).

<a id="es-metodologia"></a>

### Metodología (paso a paso)

#### 1. Identificar el formato — `PX4DMENC`

Antes de tocar Ghidra, mirar la cabecera. Los ficheros cifrados **no** empiezan por ningún magic estándar de PX4 ni por el header de ULog (`ULog\x01\x12\x35`). Un `xxd` de los primeros bytes y un `strings` sobre el binario coinciden en un magic propietario:

```
$ xxd -l16 dataman.encrypted
00000000: 5058 3444 4d45 4e43 0100 0000 ...   PX4DMENC....

$ xxd -l16 flight.ulg.encrypted
00000000: 5058 3455 4c45 4e43 0100 0000 ...   PX4ULENC....

$ strings -n8 px4 | grep -E 'PX4(DM|UL)ENC'
PX4DMENC
PX4ULENC
```

El `dataman` cifrado abre con **`PX4DMENC`** (*DataManager ENCrypted*) y el ULog con **`PX4ULENC`** (*ULog ENCrypted*). Que el mismo magic aparezca *hardcodeado en `.rodata` del binario* confirma que el esquema lo compilaron dentro de este firmware: no es un plugin ni una capa externa. La cabecera, reconstruida leyendo la función de escritura en Ghidra, es:

```
offset  campo        tamaño
0x00    magic        8   "PX4DMENC" / "PX4ULENC"
0x08    version      4   u32  (0x00000001)
0x0c    length       4   u32  (longitud del plaintext)
0x10    salt        16   entra al KDF
0x20    nonce       12   IV de AES-GCM
0x2c    tag         16   tag de autenticación GCM
0x3c    ciphertext   *   resto del fichero
```

El detalle que hay que clavar: los **44 bytes** de cabecera (`magic || version || length || salt || nonce`, offsets `0x00`–`0x2c`) se pasan como **AAD** (*Additional Authenticated Data*) al GCM. El `tag` va **antes** del ciphertext, no al final —cosa poco habitual—, así que al descifrar hay que recomponer `ciphertext || tag` en el orden que espera la librería. Este es el error clásico donde se pierde media hora: la mayoría de wrappers de AES-GCM esperan `tag` al final.

> **Por qué importa:** `#1 PX4DMENC` y `#2 AES-256-GCM` no son adivinanzas. El magic te da el formato; el IV de 12 B + tag de 16 B + uso de la S-box AES en el binario te dan el modo (GCM) y el tamaño de clave (256), que confirmaremos en Ghidra.

#### 2. Reversear el esquema en Ghidra

Cargamos `px4` en Ghidra y buscamos la rutina de descifrado (referencias cruzadas al string `PX4DMENC`, al setup de AES y a las constantes de SHA-256). Las constantes cantan el algoritmo sin margen de duda:

- **S-box AES** completa en `.rodata` y bloque de 16 B con **tag de 16 B** → **AES en modo GCM**. La expansión de clave procesa 8 palabras de 32 bits (una clave de 32 bytes) → **AES-256**. → **`#2 AES-256-GCM`**.
- Las **constantes de inicialización de SHA-256** (`0x6a09e667`, `0x71374491`, `0xbb67ae85`, …) y un **bucle HMAC anidado con contador de iteraciones** → derivación por **PBKDF2-HMAC-SHA256**. El comparador del bucle externo usa `iter = 0x2000` = **8192 iteraciones**. → **`#5 PBKDF2-HMAC-SHA256`** (con *fallback* a PBKDF2 genérico si SHA-256 no está disponible por hardware).
- El **"password"** que entra a PBKDF2 **no es una cadena fija**: lo produce un **KDF custom** en **RVA `0x170af0`** que mezcla varias tablas de `.rodata` a partir del **salt** del fichero. → **`#3 0x170af0`**.
- El bucle de mezcla del KDF custom termina con la instrucción `cmp edx, 0x17f ; jne` → el índice va de `0` a `0x17f`, es decir **384** iteraciones (`0x180`). → **`#4 384`**.

Esquema completo de derivación:

```
salt (16B, del fichero)
   │
   ▼  custom_kdf @ 0x170af0   (384 rondas de mezcla + etapa final)
password (104 B = 0x68)
   │
   ▼  PBKDF2-HMAC-SHA256(password, salt, iter=8192, dklen=32)
AES-256 key (32 B)  ──►  AES-256-GCM(nonce, ciphertext+tag, AAD=44B header)
```

> **Por qué este diseño es un dolor:** el atacante (o el dev que metió el esquema) no usa una passphrase fija que puedas extraer con `strings`. El "secreto" está **repartido en tablas** de `.rodata` y en la lógica de mezcla del KDF. No hay atajo por diccionario ni por fuerza bruta: **hay que reproducir el algoritmo o ejecutarlo**.

#### 3. Reimplementar el KDF custom (`kdf_reimpl.py`)

La vía limpia (y la que demuestra que entendiste el esquema) es reimplementar la mezcla en **Python puro**, replicando exactamente rotaciones y accesos a tablas. Como el binario está mapeado con **offset de fichero == vaddr** en `.rodata`, las tablas se leen directamente por offset:

```python
import struct, sys, hashlib
M32 = 0xffffffff
def rol(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & M32 if n else x

def load_tables(path):
    d = open(path, 'rb').read()   # file offset == vaddr para .rodata
    tbl48 = d[0x6f0a40:0x6f0a40+48]
    tblA  = struct.unpack_from('<32I', d, 0x6f0a80)   # tabla "rbx"
    tblB  = struct.unpack_from('<32I', d, 0x6f0b00)   # tabla "rbp"
    init  = list(struct.unpack_from('<8I', d, 0x6edf80))   # estado inicial (8 dwords)
    tail  = d[0x6edfa0:0x6edfe0] + struct.pack('<Q', 0x6fb14a9923de7508)
    return tbl48, tblA, tblB, init, tail
```

El núcleo del bucle (las 384 rondas). Cada ronda mezcla el estado `st` (8 palabras de 32 bits) usando la constante de la **razón áurea** `GR = 0x9e3779b9` (la misma que usan TEA/XXTEA, otra pista de que es un mezclador ad-hoc estilo ARX):

```python
def custom_kdf(salt, tbl48, tblA, tblB, init, tail, rounds=0x180):   # 0x180 = 384
    GR = 0x9e3779b9
    st = list(init); r10 = GR; r11 = 0
    for i in range(rounds):                       # cmp edx,0x17f ; jne
        b = tblB[(5*i + st[(i+3) & 7]) & 0x1f]
        a = tblA[((st[(i+5) & 7] >> 27) + r11) & 0x1f]
        r11 = (r11 + 0xb) & M32
        c = tbl48[((b >> 24) + i) % 48]
        s = (a >> 27) & 0xf
        r8 = (r10 ^ a ^ b) & M32
        r10 = (r10 + GR) & M32
        r8 = rol(r8, (c & 0xf) + 3)
        r8 = (r8 + st[i & 7] + c) & M32
        r8 = rol(r8, s + 5)
        st[i & 7] = r8
        r9 = (c * 0x01010101) & M32
        r8 = rol(r8, (i % 19) + 1)
        r8 ^= st[(i+2) & 7]
        st[(i+2) & 7] = r8
        r9 ^= r8
        st[(i+6) & 7] = (st[(i+6) & 7] + r9) & M32
    # etapa final: 8 dwords -> primeros 32 bytes del password
    pw = [0]*8
    pw[0] = st[0] ^ 0x33020b01
    rsi, r8i = 0x10, 0x11
    for k in range(2, 9):                         # rcx = 2..8
        ia, ib = r8i & 0x1f, rsi & 0x1f
        r8i += 0xd; rsi += 7
        pw[k-1] = tblB[ib] ^ st[k-1] ^ rol(tblA[ia], k)
    password = struct.pack('<8I', *pw) + tail
    assert len(password) == 0x68                  # 104 bytes
    return password

def derive(path, salt_hex):
    tabs = load_tables(path)
    pw = custom_kdf(bytes.fromhex(salt_hex), *tabs)
    return hashlib.pbkdf2_hmac('sha256', pw, bytes.fromhex(salt_hex), 0x2000, 32), pw
```

Ejecutado con el **salt real del fichero** (`60c200309e3f464c11d14645a355bfe8`, leído de la cabecera en offset `0x10`):

```
$ python3 kdf_reimpl.py px4 60c200309e3f464c11d14645a355bfe8
password(104B): ...
AES-256 key   : a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce
```

> **Detalle sutil:** la etapa final XORea `st[0]` con `0x33020b01` y produce 8 dwords, a los que se concatena `tail` (32 B de tabla + la constante de 8 B `0x6fb14a9923de7508`) hasta llegar a los **104 bytes** exactos de "password" que espera PBKDF2. Ese `assert len(password) == 0x68` es la red de seguridad: si la longitud no cuadra, algún offset de tabla está mal.

#### 4. Verificar con GDB (`kdf_call.gdb`) — capturar la clave real

Reimplementar un mezclador ARX de 384 rondas es propenso a errores de un bit. En vez de fiarse a ciegas, **capturamos la clave real** ejecutando el propio binario y **llamando a la función del KDF** con el salt del fichero. GDB permite invocar funciones nativas del proceso: reservamos buffers con `malloc`, escribimos el salt y saltamos a `0x170af0`:

```gdb
set pagination off
set confirm off
starti
python
import gdb
out = gdb.execute("info proc mappings", to_string=True)
base = None
for l in out.splitlines():
    if l.strip().endswith('/px4'):
        base = int(l.split()[0], 16); break      # base real (PIE/ASLR)
gdb.execute("set $base=%d" % base)
end
break *($base+0x11edb0)
continue
set $salt = (unsigned char*)malloc(64)
set $key  = (unsigned char*)malloc(64)
set {char[16]}$salt = "\x60\xc2\x00\x30\x9e\x3f\x46\x4c\x11\xd1\x46\x45\xa3\x55\xbf\xe8"
set $r = ((char(*)(void*,void*))($base+0x170af0))($salt,$key)   # llamar al KDF real
printf "ret=%d\n", $r
x/32xb $key                                                     # volcar la clave derivada
quit
```

La clave: primero resolvemos la **base real** del binario (es PIE, así que `$base` cambia por ASLR) leyendo `info proc mappings`; luego rompemos en `$base+0x11edb0` (un punto donde la libc ya está mapeada y hay `malloc`), reservamos los buffers, cargamos el salt de 16 B **exactamente igual** que en la cabecera del fichero, y hacemos que GDB **llame** a `KDF(salt, key)` en `$base+0x170af0`. La función escribe la clave derivada en `$key`, que volcamos con `x/32xb`.

Ambas vías —reimplementación en Python y captura en runtime— coinciden en la **misma clave AES-256**, y el **tag GCM valida** el descifrado. Ésa es la prueba criptográfica de que la clave es correcta (un solo bit mal → el tag no cuadra y `AESGCM.decrypt` lanza `InvalidTag`):

```
AES-256 key (#6): a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce
```

> **Regla de oro del RE de cripto propietaria:** no re-derives a ciegas. Localiza la función por sus constantes, y si dudas de tu reimplementación, **ejecuta la del binario** y compara. El tag GCM (o un CRC) es tu oráculo de "correcto/incorrecto" gratis.

#### 5. Descifrar (`decrypt.py`)

Con la clave, un AES-GCM sobre cada fichero. Recordar los dos detalles del formato: **AAD = 44 B de cabecera** y **`tag` antes del `ciphertext`** (por eso recomponemos `ct || tag`):

```python
#!/usr/bin/env python3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
KEY = bytes.fromhex('a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce')
for fn, out in (('IronFeather/dataman.encrypted',     'IronFeather/dataman'),
                ('IronFeather/flight.ulg.encrypted',  'IronFeather/flight.ulg')):
    d = open(fn, 'rb').read()
    assert d[:8] in (b'PX4DMENC', b'PX4ULENC'), d[:8]
    #                 nonce      ciphertext+tag       AAD (44B header)
    pt = AESGCM(KEY).decrypt(d[32:44], d[60:] + d[44:60], d[:44])
    open(out, 'wb').write(pt)
    print(fn, '->', out, len(pt), 'bytes OK')
```

Los índices, mapeados a la cabecera: `d[32:44]` = nonce (offset `0x20`–`0x2c`), `d[44:60]` = tag (offset `0x2c`–`0x3c`), `d[60:]` = ciphertext (desde `0x3c`), `d[:44]` = AAD. Si el tag valida, salen `dataman` y `flight.ulg` en claro —y **casan byte a byte** con los ficheros de referencia (`sha256sum` idéntico), lo que cierra cualquier duda sobre la corrección de la clave.

#### 6. Parsear el ULog (`pyulog`) y leer la misión

Con el log descifrado, `pyulog` da inventario de topics y volcado de mensajes:

```bash
ulog_info flight.ulg          # cabecera, duración, lista de topics y contadores
ulog_messages flight.ulg      # mensajes de log (texto)
```

```python
from pyulog import ULog
u = ULog('flight.ulg')
print([d.name for d in u.data_list])   # topics disponibles
```

Topics clave para el caso:

| Topic | Para qué |
|-------|----------|
| `vehicle_gps_position` / `vehicle_global_position` | lat/lon/alt del dron por timestamp |
| `vehicle_command` | comandos MAVLink ejecutados (el corazón del caso) |
| `actuator_armed` | flag armado/desarmado (arm/disarm) |
| `mission` / `mission_result` | estado de la misión, índice de waypoint actual |
| `dataman` | almacén de waypoints (`dm_item_t`) |

Del `dataman`: la misión referencia `mission_dataman_id = 6`, que en PX4 es **`DM_KEY_WAYPOINTS_OFFBOARD_0`** (el slot de waypoints subidos por el operador). El campo `main` guarda el `dm_item_t`, cuyo valor relevante para el par consultado es **0** (no 0/1 como sugería la pregunta a bote pronto; el `dm_item_t` del par apunta a `0`). → **`#7 0`**.

Contando los ítems de misión en el `dataman`/`mission`: la misión tiene **24** ítems (índices 0–23). → **`#8 24`**. Recorriéndolos, el ítem que suelta la carga es un **`MAV_CMD_DO_SET_ACTUATOR`** con **`param1 = 1`** (activar el actuador de liberación) en el índice **10** (alt. 11 según cómo se cuente el ítem *home* como índice 0). → **`#9 10` (alt. 11)**.

#### 7. Reconstruir el sabotaje (MAVLink) y geolocalizar

Recorriendo `vehicle_command` y correlacionando cada comando con la posición GPS más cercana en timestamp, se reconstruye la secuencia:

```python
# pseudo: emparejar comandos con GPS por timestamp
cmds = u.get_dataset('vehicle_command').data
gps  = u.get_dataset('vehicle_gps_position').data
# para cada cmd: buscar el índice j con |gps.timestamp[j] - cmd.timestamp[k]| mínimo
```

- El ítem **23** (último de la misión) es un **`MAV_CMD_NAV_LAND`** en **`51.49970,-0.16080`**. → **`#10`**.
- El punto **home** (despegue) es **`51.4996987,-0.1607999`**. → **`#11`**.
- El **release** de la carga (`DO_SET_ACTUATOR`, `param1=1`) ocurre en **`51.5035602,-0.1608417`** en `t = 446.656`. → **`#12`**.
- **El sabotaje:** un **`MAV_CMD_INJECT_FAILURE`** (cmd **420**) con **`source_system = 0`** en `t = 520.764`. Que `source_system` sea **0** es la firma del ataque: **no** viene de la GCS legítima ni de la misión subida (que tendrían su system id), sino **inyectado desde fuera** del plan de vuelo. `INJECT_FAILURE` es un comando de *simulación/testing* de PX4 que fuerza fallos de sensores/motores; usarlo en un vuelo real es sabotaje puro. → **`#13 MAV_CMD_INJECT_FAILURE`**.
- **Impacto** en `t = 525.82` (≈5 s después del fallo inyectado) en **`51.5016938,-0.1620929`**. → **`#15`**.
- **Disarm** (`actuator_armed` → 0) en `t = 576.968`. → **`#16`**.
- **Distancia recorrida (trayectoria):** **277** m — la **suma de segmentos** del recorrido real, no la recta home→impacto (que da **224** m). La pregunta usa "travel/distance travelled" → trayectoria. → **`#14 277`**.

**Geolocalización del impacto.** La coordenada `51.5016938,-0.1620929` cae entre varias calles de Londres. Cruzándola con **Nominatim** (reverse geocoding), **Overpass** (geometría de las vías OSM) y **Photon**, y midiendo la **distancia perpendicular** de la coordenada al eje de cada vía candidata, el punto queda a **0,3 m del eje de Knightsbridge**, frente a **9,8 m de Edinburgh Gate**. La menor distancia perpendicular desambigua: el impacto es sobre **Knightsbridge**. → **`#17 Knightsbridge`**.

<a id="es-cronologia"></a>

### Cronología

Todos los tiempos en segundos de log (relativos al arranque del ULog):

| t (s) | Evento | Detalle / coordenada |
|------:|--------|----------------------|
| 285.260 | **arm** | `actuator_armed` → 1; motores armados |
| 287.07 | **takeoff** | despegue desde home `51.4996987,-0.1607999` |
| 446.656 | **release de carga** | `DO_SET_ACTUATOR p1=1` en `51.5035602,-0.1608417` (ítem 10) |
| 520.764 | **INJECT_FAILURE** ⚠️ | `MAV_CMD_INJECT_FAILURE` (cmd 420, `source_system 0`) — comando inyectado, ajeno a la misión |
| 525.82 | **impacto** | `51.5016938,-0.1620929` — sobre **Knightsbridge** (≈5 s tras el fallo) |
| 576.968 | **disarm** | `actuator_armed` → 0 |

```
arm 285.260 → takeoff 287.07 → release 446.656 → INJECT_FAILURE 520.764 → impacto 525.82 → disarm 576.968
```

Lectura del caso: el dron **completó la entrega de la carga** (446.656) y seguía volando de vuelta cuando, a los **520.764**, alguien inyectó un `INJECT_FAILURE` desde fuera del sistema de misión. Cinco segundos después (**525.82**) el dron impactó en Knightsbridge. El `disarm` a 576.968 es post-impacto (los motores se desarmen tras detectar el crash). La ventana entre release e inject sugiere que el objetivo del ataque **no era** interceptar la carga, sino **derribar el dron** una vez cumplida su misión —posiblemente para destruir evidencia o negar el activo.

<a id="es-respuestas"></a>

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

<a id="es-iocs"></a>

### IOCs

Indicadores extraídos del caso (útiles para reglas de detección y correlación con el resto del arco):

- **Formato de cifrado propietario:** magics `PX4DMENC` / `PX4ULENC` en `.rodata` del firmware `px4` — no forman parte del PX4 upstream. Su presencia en un build es en sí un indicador de manipulación del firmware.
- **KDF custom @ RVA `0x170af0`**, 384 rondas, constante ARX `0x9e3779b9`, PBKDF2-HMAC-SHA256 con 8192 iteraciones. Tablas de mezcla en `.rodata` (offsets `0x6f0a40`, `0x6f0a80`, `0x6f0b00`, `0x6edf80`, `0x6edfa0`).
- **Clave AES-256 derivada:** `a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce`.
- **Salt del par de ficheros:** `60c200309e3f464c11d14645a355bfe8`.
- **Comando MAVLink malicioso:** `MAV_CMD_INJECT_FAILURE` (cmd **420**) con **`source_system = 0`** en `t = 520.764` — comando de test/simulación usado en un vuelo real; `source_system 0` = fuera de la misión/GCS legítima.
- **Punto de impacto:** `51.5016938,-0.1620929` (Knightsbridge, Londres); trayectoria de 277 m desde home `51.4996987,-0.1607999`.
- **Waypoint de release de carga:** `51.5035602,-0.1608417` (t=446.656, `DO_SET_ACTUATOR p1=1`, ítem 10 de 24).

<a id="es-mitre"></a>

### Mapeo MITRE ATT&CK

Marco general (Enterprise/ICS) aplicado al vector dron:

| Táctica | Técnica | Cómo se manifiesta aquí |
|---------|---------|-------------------------|
| Impair Defenses / Anti-forensics | **T1027** *Obfuscated Files or Information* | Logs de vuelo cifrados con un esquema **propietario** (no el oficial de PX4) para negar el análisis forense. |
| Impair Defenses | **T1600** *Weaken Encryption* (ICS: *Modify Firmware* T0857) | Firmware modificado para meter un KDF/cifrado custom; el binario ya no es el PX4 legítimo. |
| Command and Control / Physical | **T0855** *Unauthorized Command Message* (ICS) | `MAV_CMD_INJECT_FAILURE` inyectado con `source_system 0`, fuera del canal de mando legítimo. |
| Inhibit Response Function | **T0813** *Denial of Control* / **T0827** *Loss of Control* (ICS) | El fallo inyectado provoca pérdida de control y caída del dron 5 s después. |
| Impact | **T0879** *Damage to Property* / **T0826** *Loss of Availability* (ICS) | Impacto físico en Knightsbridge; pérdida del activo (dron y carga). |
| Collection | **T1005** *Data from Local System* | Recuperación de `dataman`/`flight.ulg` del almacenamiento "dañado". |

> Nota: el vector real es de **sistemas ciber-físicos (drones/UAV)**; el mapeo mezcla Enterprise y la matriz **ICS** de ATT&CK, que es la que cubre comandos no autorizados y pérdida de control.

<a id="es-remediacion"></a>

### Detección y remediación

**Detección**

- **Alertar sobre `MAV_CMD_INJECT_FAILURE` (420) en producción.** Ese comando es solo para bancos de pruebas/SITL. Cualquier aparición en un vuelo operativo, y especialmente con `source_system` que no coincida con la GCS autorizada, debe disparar alarma inmediata.
- **Validar `source_system`/`source_component`** de todo `vehicle_command`: rechazar (o al menos marcar) comandos cuyo origen no esté en una allowlist de sistemas conocidos. `source_system 0` es, por definición, sospechoso.
- **Verificar integridad del firmware:** el `px4` legítimo no contiene los magics `PX4DMENC`/`PX4ULENC` ni un KDF en `0x170af0`. Un hash/firma del firmware desplegado frente al build oficial detecta la manipulación.
- **Correlación temporal:** un `INJECT_FAILURE` seguido de pérdida de altitud y `disarm` en pocos segundos es una firma de derribo, no un fallo fortuito.

**Remediación**

- **Firmar y verificar la cadena de arranque** del autopiloto (secure boot) para impedir builds modificados con esquemas de cifrado/KDF no autorizados.
- **Autenticar el enlace de mando** (MAVLink 2 con firma HMAC de mensajes) para que un `source_system 0` inyectado no sea aceptado por el vehículo.
- **Deshabilitar `INJECT_FAILURE`** (y demás comandos de test) en firmware de producción mediante flags de build, no solo por convención.
- **Logging seguro *estándar*:** si se quiere cifrar logs, usar el esquema oficial de PX4 (XChaCha20 + clave pública RSA de la organización), que es auditable y no un KDF casero; así el análisis forense legítimo sigue siendo posible con la clave privada custodiada.
- **Geofencing / failsafe** que fuerce un aterrizaje controlado ante pérdida de sensores, en vez de permitir una caída libre sobre zona urbana.

### Lecciones

- **No re-derivar a ciegas.** Con un cifrado propietario, localizar la función en Ghidra por sus constantes (S-box AES, constantes SHA `0x6a09e667…`, tamaño de IV/tag) y **capturar la clave derivada con GDB** llamando al KDF real (`kdf_call.gdb`). Validar siempre con el **tag GCM / CRC**: si valida, la clave es correcta. La reimplementación en Python es la prueba de que entendiste el algoritmo; la captura en runtime es la red de seguridad.
- **El formato oficial es una pista falsa.** PX4 usa XChaCha20/RSA; este build metía un esquema custom. Fiarse del **magic real** (`PX4DMENC`/`PX4ULENC`) y de la **cabecera de 44 B como AAD** (con el **tag antes del ciphertext**), no de la documentación upstream.
- **El origen del comando es la atribución.** `source_system 0` en el `INJECT_FAILURE` es lo que separa "fallo mecánico" de "sabotaje": un comando ajeno a la misión y a la GCS legítima.
- **"Travel" = trayectoria.** La pregunta de distancia pedía la suma de segmentos (277), no la recta home→impacto (224). Leer literal.
- **Geoloc con margen.** Nominatim/Overpass/Photon + distancia **perpendicular** al eje de la vía desambigua entre candidatos cercanos (Knightsbridge a 0,3 m frente a Edinburgh Gate a 9,8 m).

### Serie · The Reichenbach Directive

| # | Sherlock | Enlace |
|---|----------|--------|
| S01 | Silent Dividend | [../2026-09-15-holmes2026-s01-silent-dividend/](../2026-09-15-holmes2026-s01-silent-dividend/) |
| S02 | Bottle Out | [../2026-09-16-holmes2026-s02-bottle-out/](../2026-09-16-holmes2026-s02-bottle-out/) |
| S03 | Whisper Chain | [../2026-09-17-holmes2026-s03-whisper-chain/](../2026-09-17-holmes2026-s03-whisper-chain/) |
| S04 | Paper Ghost | [../2026-09-18-holmes2026-s04-paper-ghost/](../2026-09-18-holmes2026-s04-paper-ghost/) |
| S05 | Poisoned Branch | [../2026-09-19-holmes2026-s05-poisoned-branch/](../2026-09-19-holmes2026-s05-poisoned-branch/) |
| S06 | Silent Passenger | [../2026-09-20-holmes2026-s06-silent-passenger/](../2026-09-20-holmes2026-s06-silent-passenger/) |
| **S07** | **Iron Feather** ← *estás aquí* | [../2026-09-21-holmes2026-s07-iron-feather/](../2026-09-21-holmes2026-s07-iron-feather/) |
| S08 | Borrowed Name | [../2026-09-22-holmes2026-s08-borrowed-name/](../2026-09-22-holmes2026-s08-borrowed-name/) |
| S09 | Last Light | [../2026-09-23-holmes2026-s09-last-light/](../2026-09-23-holmes2026-s09-last-light/) |

---

<a id="en"></a>

## 🇬🇧 English

> **Challenge:** Holmes CTF 2026 — Sherlock 07 "Iron Feather" · RE of a PX4 drone's encryption + ULog/MAVLink analysis. Part of the *The Reichenbach Directive* arc.
>
> **Navigation:** [🇪🇸 Español](#es) · [🇬🇧 English](#en) · Jump to: [Methodology](#en-methodology) · [Timeline](#en-timeline) · [Answers](#en-answers) · [IOCs](#en-iocs) · [MITRE ATT&CK](#en-mitre) · [Detection & remediation](#en-remediation)

### Scenario

A quadcopter left a secure building and **never came back**. What is recovered from the drone is a "damaged" storage and **encrypted** flight logs: `flight.ulg` (ULog) and `dataman` (PX4 mission/waypoint store), both present in cleartext and as their `.encrypted` counterparts, plus the autopilot binary **`px4`**.

The catch — and what makes this a genuinely *hard* challenge — is that the encryption is **not** PX4's official scheme (the XChaCha20 + RSA "secure logging" that ships upstream). It's a **proprietary** format baked by hand into this specific firmware build. No key anywhere — no `.pem`, no env vars, nothing in the drone's filesystem — so the only path is to **reverse the binary**, understand the key-derivation scheme (KDF), **capture/reproduce the derived key**, decrypt the logs, and then **reconstruct the flight** over MAVLink to explain why the drone crashed and, above all, **where**.

The challenge is a chain of two very different halves: first **low-level crypto/RE** (Ghidra + GDB + a Python reimplementation), then **telemetry forensics** (ULog + MAVLink + OSINT geolocation). The two halves are joined by a single artifact: the AES-256 key. No RE, no decryption; no decryption, no telemetry; no telemetry, no case. Difficulty: **hard**.

> **Narrative framing.** Iron Feather is S07 of *The Reichenbach Directive*: APT Napoleon / MurkNet's operation no longer just steals data — it now **acts in the physical world**. The drone carried a payload and was **sabotaged mid-mission** with a failure injected from outside the flight plan. Our defensive job is to reconstruct the exact sequence, attribute the malicious command, and pin down the impact point for the response team.

### Artifact and tooling

- **Evidence:**
  - `flight.ulg` + `dataman` — **cleartext** reference copies (to validate the decryption byte for byte).
  - `flight.ulg.encrypted` (~69 MB) + `dataman.encrypted` (~1.2 MB) — the actual **encrypted** files.
  - **`px4`** — the autopilot ELF (~9.8 MB), where the whole encryption scheme and the KDF live.
  - `Holmes CTF 2026 - Sherlock 07 - Mission Vault.pdf` — arc narrative, no technical evidence.
- **RE:** **Ghidra** (locate the crypto/KDF function, read constants and `.rodata` tables) + **GDB** (capture the derived key at runtime by calling the real KDF).
- **Crypto:** `AES-256-GCM` (`cryptography` / `AESGCM`), `PBKDF2-HMAC-SHA256` reimplemented in pure Python.
- **ULog/MAVLink:** `pyulog` (`ulog_info`, `ulog_messages`), `MAV_CMD_*` dictionary.
- **Geolocation:** Nominatim + Overpass + Photon to name coordinates and measure the **perpendicular distance to the trajectory axis** (disambiguating nearby streets).

<a id="en-methodology"></a>

### Methodology (step by step)

#### 1. Identify the format — `PX4DMENC`

Before touching Ghidra, look at the header. The encrypted files start with **no** standard PX4 magic and **no** ULog header (`ULog\x01\x12\x35`). An `xxd` of the first bytes and `strings` on the binary agree on a proprietary magic:

```
$ xxd -l16 dataman.encrypted
00000000: 5058 3444 4d45 4e43 0100 0000 ...   PX4DMENC....

$ xxd -l16 flight.ulg.encrypted
00000000: 5058 3455 4c45 4e43 0100 0000 ...   PX4ULENC....

$ strings -n8 px4 | grep -E 'PX4(DM|UL)ENC'
PX4DMENC
PX4ULENC
```

The encrypted `dataman` opens with **`PX4DMENC`** (*DataManager ENCrypted*) and the ULog with **`PX4ULENC`** (*ULog ENCrypted*). That the same magic appears *hardcoded in the binary's `.rodata`* confirms the scheme was compiled into this firmware: not a plugin, not an external layer. The header, reconstructed by reading the write routine in Ghidra, is:

```
offset  field        size
0x00    magic        8   "PX4DMENC" / "PX4ULENC"
0x08    version      4   u32  (0x00000001)
0x0c    length       4   u32  (plaintext length)
0x10    salt        16   fed into the KDF
0x20    nonce       12   AES-GCM IV
0x2c    tag         16   GCM authentication tag
0x3c    ciphertext   *   rest of the file
```

The detail you must nail: the **44-byte** header (`magic || version || length || salt || nonce`, offsets `0x00`–`0x2c`) is passed as **AAD** (*Additional Authenticated Data*) to GCM. The `tag` sits **before** the ciphertext, not at the end — unusual — so when decrypting you must recompose `ciphertext || tag` in the order the library expects. This is the classic half-hour sink: most AES-GCM wrappers expect the `tag` at the end.

> **Why it matters:** `#1 PX4DMENC` and `#2 AES-256-GCM` aren't guesses. The magic gives you the format; the 12 B IV + 16 B tag + AES S-box usage in the binary give you the mode (GCM) and key size (256), which we confirm in Ghidra.

#### 2. Reverse the scheme in Ghidra

Load `px4` in Ghidra and find the decrypt routine (xrefs to the `PX4DMENC` string, to the AES setup and to the SHA-256 constants). The constants give away the algorithm beyond doubt:

- Full **AES S-box** in `.rodata` and a 16 B block with a **16 B tag** → **AES in GCM mode**. The key schedule processes 8 32-bit words (a 32-byte key) → **AES-256**. → **`#2 AES-256-GCM`**.
- The **SHA-256 initialization constants** (`0x6a09e667`, `0x71374491`, `0xbb67ae85`, …) and a **nested HMAC loop with an iteration counter** → derivation via **PBKDF2-HMAC-SHA256**. The outer loop compares against `iter = 0x2000` = **8192 iterations**. → **`#5 PBKDF2-HMAC-SHA256`** (with a *fallback* to generic PBKDF2 if hardware SHA-256 isn't available).
- The **"password"** fed into PBKDF2 is **not a fixed string**: it's produced by a **custom KDF** at **RVA `0x170af0`** that mixes several `.rodata` tables starting from the file's **salt**. → **`#3 0x170af0`**.
- The custom KDF's mixing loop ends on `cmp edx, 0x17f ; jne` → the index runs `0`..`0x17f`, i.e. **384** iterations (`0x180`). → **`#4 384`**.

Full derivation chain:

```
salt (16B, from file)
   │
   ▼  custom_kdf @ 0x170af0   (384 mixing rounds + final stage)
password (104 B = 0x68)
   │
   ▼  PBKDF2-HMAC-SHA256(password, salt, iter=8192, dklen=32)
AES-256 key (32 B)  ──►  AES-256-GCM(nonce, ciphertext+tag, AAD=44B header)
```

> **Why this design hurts:** whoever baked in the scheme did not use a fixed passphrase you can `strings` out. The "secret" is **spread across `.rodata` tables** and the KDF mixing logic. No dictionary or brute-force shortcut: you must **reproduce the algorithm or execute it**.

#### 3. Reimplement the custom KDF (`kdf_reimpl.py`)

The clean path (and the one that proves you understood the scheme) is to reimplement the mix in **pure Python**, replicating rotations and table lookups exactly. Since the binary is mapped with **file offset == vaddr** in `.rodata`, the tables are read directly by offset:

```python
import struct, sys, hashlib
M32 = 0xffffffff
def rol(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & M32 if n else x

def load_tables(path):
    d = open(path, 'rb').read()   # file offset == vaddr for .rodata
    tbl48 = d[0x6f0a40:0x6f0a40+48]
    tblA  = struct.unpack_from('<32I', d, 0x6f0a80)   # "rbx" table
    tblB  = struct.unpack_from('<32I', d, 0x6f0b00)   # "rbp" table
    init  = list(struct.unpack_from('<8I', d, 0x6edf80))   # initial state (8 dwords)
    tail  = d[0x6edfa0:0x6edfe0] + struct.pack('<Q', 0x6fb14a9923de7508)
    return tbl48, tblA, tblB, init, tail
```

The loop core (the 384 rounds). Each round mixes the state `st` (8 32-bit words) using the **golden-ratio** constant `GR = 0x9e3779b9` (the same one TEA/XXTEA use — another hint that this is an ad-hoc ARX mixer):

```python
def custom_kdf(salt, tbl48, tblA, tblB, init, tail, rounds=0x180):   # 0x180 = 384
    GR = 0x9e3779b9
    st = list(init); r10 = GR; r11 = 0
    for i in range(rounds):                       # cmp edx,0x17f ; jne
        b = tblB[(5*i + st[(i+3) & 7]) & 0x1f]
        a = tblA[((st[(i+5) & 7] >> 27) + r11) & 0x1f]
        r11 = (r11 + 0xb) & M32
        c = tbl48[((b >> 24) + i) % 48]
        s = (a >> 27) & 0xf
        r8 = (r10 ^ a ^ b) & M32
        r10 = (r10 + GR) & M32
        r8 = rol(r8, (c & 0xf) + 3)
        r8 = (r8 + st[i & 7] + c) & M32
        r8 = rol(r8, s + 5)
        st[i & 7] = r8
        r9 = (c * 0x01010101) & M32
        r8 = rol(r8, (i % 19) + 1)
        r8 ^= st[(i+2) & 7]
        st[(i+2) & 7] = r8
        r9 ^= r8
        st[(i+6) & 7] = (st[(i+6) & 7] + r9) & M32
    # final stage: 8 dwords -> first 32 bytes of the password
    pw = [0]*8
    pw[0] = st[0] ^ 0x33020b01
    rsi, r8i = 0x10, 0x11
    for k in range(2, 9):                         # rcx = 2..8
        ia, ib = r8i & 0x1f, rsi & 0x1f
        r8i += 0xd; rsi += 7
        pw[k-1] = tblB[ib] ^ st[k-1] ^ rol(tblA[ia], k)
    password = struct.pack('<8I', *pw) + tail
    assert len(password) == 0x68                  # 104 bytes
    return password

def derive(path, salt_hex):
    tabs = load_tables(path)
    pw = custom_kdf(bytes.fromhex(salt_hex), *tabs)
    return hashlib.pbkdf2_hmac('sha256', pw, bytes.fromhex(salt_hex), 0x2000, 32), pw
```

Run with the **real salt from the file** (`60c200309e3f464c11d14645a355bfe8`, read from the header at offset `0x10`):

```
$ python3 kdf_reimpl.py px4 60c200309e3f464c11d14645a355bfe8
password(104B): ...
AES-256 key   : a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce
```

> **Subtle detail:** the final stage XORs `st[0]` with `0x33020b01` and produces 8 dwords, to which `tail` (32 B of table + the 8 B constant `0x6fb14a9923de7508`) is concatenated to reach the exact **104-byte** "password" PBKDF2 expects. That `assert len(password) == 0x68` is the safety net: if the length is off, a table offset is wrong.

#### 4. Verify with GDB (`kdf_call.gdb`) — capture the real key

Reimplementing a 384-round ARX mixer is prone to off-by-one-bit errors. Instead of trusting it blindly, **capture the real key** by running the binary itself and **calling the KDF function** with the file's salt. GDB can invoke native functions in the process: allocate buffers with `malloc`, write the salt, and jump into `0x170af0`:

```gdb
set pagination off
set confirm off
starti
python
import gdb
out = gdb.execute("info proc mappings", to_string=True)
base = None
for l in out.splitlines():
    if l.strip().endswith('/px4'):
        base = int(l.split()[0], 16); break      # real load base (PIE/ASLR)
gdb.execute("set $base=%d" % base)
end
break *($base+0x11edb0)
continue
set $salt = (unsigned char*)malloc(64)
set $key  = (unsigned char*)malloc(64)
set {char[16]}$salt = "\x60\xc2\x00\x30\x9e\x3f\x46\x4c\x11\xd1\x46\x45\xa3\x55\xbf\xe8"
set $r = ((char(*)(void*,void*))($base+0x170af0))($salt,$key)   # call the real KDF
printf "ret=%d\n", $r
x/32xb $key                                                     # dump the derived key
quit
```

The key: first resolve the binary's **real base** (it's PIE, so `$base` shifts under ASLR) by reading `info proc mappings`; then break at `$base+0x11edb0` (a point where libc is mapped and `malloc` is available), allocate the buffers, load the 16 B salt **exactly** as in the file header, and have GDB **call** `KDF(salt, key)` at `$base+0x170af0`. The function writes the derived key into `$key`, which we dump with `x/32xb`.

Both paths — the Python reimplementation and the runtime capture — agree on the **same AES-256 key**, and the **GCM tag validates** the decryption. That is the cryptographic proof the key is correct (a single wrong bit → the tag mismatches and `AESGCM.decrypt` raises `InvalidTag`):

```
AES-256 key (#6): a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce
```

> **Golden rule of proprietary-crypto RE:** don't re-derive blindly. Locate the function by its constants, and if you doubt your reimplementation, **execute the binary's own** and compare. The GCM tag (or a CRC) is your free "correct/incorrect" oracle.

#### 5. Decrypt (`decrypt.py`)

With the key, AES-GCM over each file. Remember the two format quirks: **AAD = 44 B header** and **`tag` before the `ciphertext`** (hence recomposing `ct || tag`):

```python
#!/usr/bin/env python3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
KEY = bytes.fromhex('a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce')
for fn, out in (('IronFeather/dataman.encrypted',     'IronFeather/dataman'),
                ('IronFeather/flight.ulg.encrypted',  'IronFeather/flight.ulg')):
    d = open(fn, 'rb').read()
    assert d[:8] in (b'PX4DMENC', b'PX4ULENC'), d[:8]
    #                 nonce      ciphertext+tag       AAD (44B header)
    pt = AESGCM(KEY).decrypt(d[32:44], d[60:] + d[44:60], d[:44])
    open(out, 'wb').write(pt)
    print(fn, '->', out, len(pt), 'bytes OK')
```

The indices, mapped to the header: `d[32:44]` = nonce (offset `0x20`–`0x2c`), `d[44:60]` = tag (offset `0x2c`–`0x3c`), `d[60:]` = ciphertext (from `0x3c`), `d[:44]` = AAD. If the tag validates, you get cleartext `dataman` and `flight.ulg` — which **match byte for byte** the reference files (identical `sha256sum`), closing any doubt about the key's correctness.

#### 6. Parse the ULog (`pyulog`) and read the mission

With the decrypted log, `pyulog` gives a topic inventory and a message dump:

```bash
ulog_info flight.ulg          # header, duration, topic list and counters
ulog_messages flight.ulg      # log messages (text)
```

```python
from pyulog import ULog
u = ULog('flight.ulg')
print([d.name for d in u.data_list])   # available topics
```

Key topics for the case:

| Topic | For what |
|-------|----------|
| `vehicle_gps_position` / `vehicle_global_position` | drone lat/lon/alt by timestamp |
| `vehicle_command` | executed MAVLink commands (the heart of the case) |
| `actuator_armed` | armed/disarmed flag (arm/disarm) |
| `mission` / `mission_result` | mission state, current waypoint index |
| `dataman` | waypoint store (`dm_item_t`) |

From `dataman`: the mission references `mission_dataman_id = 6`, which in PX4 is **`DM_KEY_WAYPOINTS_OFFBOARD_0`** (the slot for operator-uploaded waypoints). The `main` field stores the `dm_item_t`, whose relevant value for the queried pair is **0** (not 0/1 as the question might suggest at first glance; the pair's `dm_item_t` points at `0`). → **`#7 0`**.

Counting the mission items in `dataman`/`mission`: the mission has **24** items (indices 0–23). → **`#8 24`**. Walking them, the payload-drop item is a **`MAV_CMD_DO_SET_ACTUATOR`** with **`param1 = 1`** (activate the release actuator) at index **10** (alt. 11 depending on whether the *home* item counts as index 0). → **`#9 10` (alt. 11)**.

#### 7. Reconstruct the sabotage (MAVLink) and geolocate

Walking `vehicle_command` and correlating each command with the nearest GPS position by timestamp reconstructs the sequence:

```python
# pseudo: pair commands with GPS by timestamp
cmds = u.get_dataset('vehicle_command').data
gps  = u.get_dataset('vehicle_gps_position').data
# for each cmd: find index j minimizing |gps.timestamp[j] - cmd.timestamp[k]|
```

- Item **23** (the mission's last) is a **`MAV_CMD_NAV_LAND`** at **`51.49970,-0.16080`**. → **`#10`**.
- The **home** point (takeoff) is **`51.4996987,-0.1607999`**. → **`#11`**.
- The payload **release** (`DO_SET_ACTUATOR`, `param1=1`) happens at **`51.5035602,-0.1608417`** at `t = 446.656`. → **`#12`**.
- **The sabotage:** a **`MAV_CMD_INJECT_FAILURE`** (cmd **420**) with **`source_system = 0`** at `t = 520.764`. That `source_system` is **0** is the attack's fingerprint: it does **not** come from the legitimate GCS nor from the uploaded mission (which would carry their own system id), but is **injected from outside** the flight plan. `INJECT_FAILURE` is a PX4 *simulation/testing* command that forces sensor/motor failures; using it in a real flight is pure sabotage. → **`#13 MAV_CMD_INJECT_FAILURE`**.
- **Impact** at `t = 525.82` (≈5 s after the injected failure) at **`51.5016938,-0.1620929`**. → **`#15`**.
- **Disarm** (`actuator_armed` → 0) at `t = 576.968`. → **`#16`**.
- **Distance travelled (trajectory):** **277** m — the **sum of segments** of the real path, not the straight home→impact line (which gives **224** m). The question says "travel/distance travelled" → trajectory. → **`#14 277`**.

**Impact geolocation.** The coordinate `51.5016938,-0.1620929` falls between several London streets. Cross-referencing it with **Nominatim** (reverse geocoding), **Overpass** (OSM road geometry) and **Photon**, and measuring the **perpendicular distance** from the coordinate to each candidate road's axis, the point lands **0.3 m off the axis of Knightsbridge**, versus **9.8 m of Edinburgh Gate**. The smaller perpendicular distance disambiguates: the impact is on **Knightsbridge**. → **`#17 Knightsbridge`**.

<a id="en-timeline"></a>

### Timeline

All times in log seconds (relative to ULog start):

| t (s) | Event | Detail / coordinate |
|------:|-------|---------------------|
| 285.260 | **arm** | `actuator_armed` → 1; motors armed |
| 287.07 | **takeoff** | takeoff from home `51.4996987,-0.1607999` |
| 446.656 | **payload release** | `DO_SET_ACTUATOR p1=1` at `51.5035602,-0.1608417` (item 10) |
| 520.764 | **INJECT_FAILURE** ⚠️ | `MAV_CMD_INJECT_FAILURE` (cmd 420, `source_system 0`) — injected command, alien to the mission |
| 525.82 | **impact** | `51.5016938,-0.1620929` — on **Knightsbridge** (≈5 s after the failure) |
| 576.968 | **disarm** | `actuator_armed` → 0 |

```
arm 285.260 → takeoff 287.07 → release 446.656 → INJECT_FAILURE 520.764 → impact 525.82 → disarm 576.968
```

Reading of the case: the drone **completed the payload delivery** (446.656) and was still flying back when, at **520.764**, someone injected an `INJECT_FAILURE` from outside the mission system. Five seconds later (**525.82**) the drone impacted on Knightsbridge. The `disarm` at 576.968 is post-impact (motors disarm after crash detection). The window between release and inject suggests the attack's goal was **not** to intercept the payload, but to **bring the drone down** once its mission was done — possibly to destroy evidence or deny the asset.

<a id="en-answers"></a>

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

<a id="en-iocs"></a>

### IOCs

Indicators extracted from the case (useful for detection rules and correlation with the rest of the arc):

- **Proprietary encryption format:** magics `PX4DMENC` / `PX4ULENC` in the `px4` firmware's `.rodata` — not part of upstream PX4. Their presence in a build is itself an indicator of firmware tampering.
- **Custom KDF @ RVA `0x170af0`**, 384 rounds, ARX constant `0x9e3779b9`, PBKDF2-HMAC-SHA256 with 8192 iterations. Mixing tables in `.rodata` (offsets `0x6f0a40`, `0x6f0a80`, `0x6f0b00`, `0x6edf80`, `0x6edfa0`).
- **Derived AES-256 key:** `a40ba87b8a0e21d4ead98b917c4bf0f60cc65b25c614b93f107e5ed1e483d6ce`.
- **Salt of the file pair:** `60c200309e3f464c11d14645a355bfe8`.
- **Malicious MAVLink command:** `MAV_CMD_INJECT_FAILURE` (cmd **420**) with **`source_system = 0`** at `t = 520.764` — a test/simulation command used in a real flight; `source_system 0` = outside the legitimate mission/GCS.
- **Impact point:** `51.5016938,-0.1620929` (Knightsbridge, London); 277 m trajectory from home `51.4996987,-0.1607999`.
- **Payload-release waypoint:** `51.5035602,-0.1608417` (t=446.656, `DO_SET_ACTUATOR p1=1`, item 10 of 24).

<a id="en-mitre"></a>

### MITRE ATT&CK mapping

General framing (Enterprise/ICS) applied to the drone vector:

| Tactic | Technique | How it shows up here |
|--------|-----------|----------------------|
| Impair Defenses / Anti-forensics | **T1027** *Obfuscated Files or Information* | Flight logs encrypted with a **proprietary** scheme (not PX4's official one) to deny forensic analysis. |
| Impair Defenses | **T1600** *Weaken Encryption* (ICS: *Modify Firmware* T0857) | Firmware modified to embed a custom KDF/cipher; the binary is no longer legitimate PX4. |
| Command and Control / Physical | **T0855** *Unauthorized Command Message* (ICS) | `MAV_CMD_INJECT_FAILURE` injected with `source_system 0`, outside the legitimate command channel. |
| Inhibit Response Function | **T0813** *Denial of Control* / **T0827** *Loss of Control* (ICS) | The injected failure causes loss of control and the drone's fall 5 s later. |
| Impact | **T0879** *Damage to Property* / **T0826** *Loss of Availability* (ICS) | Physical impact on Knightsbridge; loss of the asset (drone and payload). |
| Collection | **T1005** *Data from Local System* | Recovery of `dataman`/`flight.ulg` from the "damaged" storage. |

> Note: the real vector is **cyber-physical (drones/UAV)**; the mapping mixes Enterprise and the ATT&CK **ICS** matrix, which is the one covering unauthorized commands and loss of control.

<a id="en-remediation"></a>

### Detection & remediation

**Detection**

- **Alert on `MAV_CMD_INJECT_FAILURE` (420) in production.** That command is for test benches/SITL only. Any appearance in an operational flight — especially with a `source_system` that doesn't match the authorized GCS — should raise an immediate alarm.
- **Validate `source_system`/`source_component`** on every `vehicle_command`: reject (or at least flag) commands whose origin isn't in an allowlist of known systems. `source_system 0` is by definition suspicious.
- **Verify firmware integrity:** legitimate `px4` contains neither the `PX4DMENC`/`PX4ULENC` magics nor a KDF at `0x170af0`. A hash/signature of the deployed firmware against the official build detects the tampering.
- **Temporal correlation:** an `INJECT_FAILURE` followed by altitude loss and `disarm` within seconds is a takedown signature, not a chance failure.

**Remediation**

- **Sign and verify the autopilot boot chain** (secure boot) to prevent modified builds carrying unauthorized crypto/KDF schemes.
- **Authenticate the command link** (MAVLink 2 with HMAC message signing) so an injected `source_system 0` isn't accepted by the vehicle.
- **Disable `INJECT_FAILURE`** (and other test commands) in production firmware via build flags, not just by convention.
- **Standard secure logging:** if you want to encrypt logs, use PX4's official scheme (XChaCha20 + the organization's RSA public key), which is auditable rather than a homebrew KDF; legitimate forensics stays possible with the custodied private key.
- **Geofencing / failsafe** that forces a controlled landing on sensor loss, instead of allowing a free fall over an urban area.

### Lessons

- **Don't re-derive blindly.** With proprietary crypto, locate the function in Ghidra by its constants (AES S-box, SHA constants `0x6a09e667…`, IV/tag size) and **capture the derived key with GDB** by calling the real KDF (`kdf_call.gdb`). Always validate with the **GCM tag / CRC**: if it validates, the key is right. The Python reimplementation proves you understood the algorithm; the runtime capture is the safety net.
- **The official format is a red herring.** PX4 uses XChaCha20/RSA; this build shipped a custom scheme. Trust the **actual magic** (`PX4DMENC`/`PX4ULENC`) and the **44 B header as AAD** (with the **tag before the ciphertext**), not upstream documentation.
- **The command's origin is the attribution.** `source_system 0` on the `INJECT_FAILURE` is what separates "mechanical failure" from "sabotage": a command alien to both the mission and the legitimate GCS.
- **"Travel" = trajectory.** The distance question asked for the sum of segments (277), not the straight home→impact line (224). Read literally.
- **Geolocate with a margin.** Nominatim/Overpass/Photon + **perpendicular** distance to the road axis disambiguates nearby candidates (Knightsbridge at 0.3 m vs Edinburgh Gate at 9.8 m).

### Series · The Reichenbach Directive

| # | Sherlock | Link |
|---|----------|------|
| S01 | Silent Dividend | [../2026-09-15-holmes2026-s01-silent-dividend/](../2026-09-15-holmes2026-s01-silent-dividend/) |
| S02 | Bottle Out | [../2026-09-16-holmes2026-s02-bottle-out/](../2026-09-16-holmes2026-s02-bottle-out/) |
| S03 | Whisper Chain | [../2026-09-17-holmes2026-s03-whisper-chain/](../2026-09-17-holmes2026-s03-whisper-chain/) |
| S04 | Paper Ghost | [../2026-09-18-holmes2026-s04-paper-ghost/](../2026-09-18-holmes2026-s04-paper-ghost/) |
| S05 | Poisoned Branch | [../2026-09-19-holmes2026-s05-poisoned-branch/](../2026-09-19-holmes2026-s05-poisoned-branch/) |
| S06 | Silent Passenger | [../2026-09-20-holmes2026-s06-silent-passenger/](../2026-09-20-holmes2026-s06-silent-passenger/) |
| **S07** | **Iron Feather** ← *you are here* | [../2026-09-21-holmes2026-s07-iron-feather/](../2026-09-21-holmes2026-s07-iron-feather/) |
| S08 | Borrowed Name | [../2026-09-22-holmes2026-s08-borrowed-name/](../2026-09-22-holmes2026-s08-borrowed-name/) |
| S09 | Last Light | [../2026-09-23-holmes2026-s09-last-light/](../2026-09-23-holmes2026-s09-last-light/) |
