---
title: "Holmes CTF 2026 — S04 Paper Ghost"
date: 2026-09-18
description: "Triage KAPE de Windows: reconstruir un ataque de USB dropper (spyware) con registro, SRUM y Windows.edb."
excerpt: "Un pendrive falso de actualización enciende mic y webcam y exfiltra 172 MB; lo reconstruimos desde hives, ConsentStore, SRUM e índice de Windows Search."
platform: "HTB"
difficulty: "Easy"
image: "/images/blog/holmes-s04.svg"
tags:
  - "DFIR"
  - "KAPE"
  - "Registry"
  - "SRUM"
  - "Windows"
  - "Holmes CTF 2026"
---

> **Reto:** Holmes CTF 2026 — Sherlock 04 "Paper Ghost" · Triage KAPE de Windows (registro, SRUM, Windows.edb). Parte del arco *The Reichenbach Directive*.
>
> **Navegación:** [🇪🇸 Español](#es) · [🇬🇧 English](#en) — estructura espejo: mismas secciones, mismos comandos, mismas 9 flags.

<a id="es"></a>
## 🇪🇸 Español

### Escenario

Un supuesto contratista de IT, **Elias Venn**, deja un pendrive en la mesa de **Clara Voss** (usuario `cvoss`) del host **CO-LT-0469** (Windows 10 19045, VM). Ella lo abre como si fuera una actualización de drivers y el "instalador" `update.exe` enciende el micrófono y la webcam y vuelca **172 MB** a un C2. No hay disco completo: solo un **triage de KAPE** de 74 ficheros (hives de registro, LNK/JumpLists, SRUM y el índice de Windows Search). Hay que reconstruir el incidente entero a partir de esos artefactos.

- **Host:** CO-LT-0469 (Win10 19045, VM) · **Usuario:** `cvoss` · **Equipo:** CyberFlippers.
- **Zona horaria del host:** Pacific (UTC−7, en agosto es PDT). **Todas las respuestas se dan en UTC.**
- **Dificultad:** easy · 9 flags.

La historia de fondo importa para el arco: DIOGENES es la plataforma de ticketing interna del objetivo, y NAPOLEON (el APT del arco) usa este *paper ghost* — un contratista que existe solo en el papeleo — para robar credenciales de desarrolladores con acceso al backend de tickets. El USB no es un implante técnico sofisticado: es ingeniería social envuelta en un kit de "soporte" con carpetas de atrezzo. Nuestro trabajo es puramente forense: sin binario, sin PCAP, sin disco completo, reconstruir quién, qué, cuándo y cuánto **solo con los rastros que Windows deja en el registro y en dos bases ESE**.

### Por qué este reto es interesante (modelo de artefactos)

La gracia de *Paper Ghost* es que **ninguna pregunta se responde con un log de eventos**. No hay `Security.evtx`, no hay `setupapi.dev.log`, no hay Sysmon. Todo sale de artefactos "pasivos" que Windows mantiene para su propio funcionamiento y que el analista reinterpreta:

- El **registro** guarda el historial de dispositivos USB porque el Plug-and-Play Manager necesita recordar drivers y letras de unidad.
- **ConsentStore** guarda `LastUsed` de mic/cámara porque el panel de Privacidad de Windows lo muestra al usuario.
- **SRUM** contabiliza bytes por proceso porque el diagnóstico de batería/datos lo necesita.
- **Windows.edb** indexa el texto de los PDF porque Windows Search ofrece búsqueda de contenido.

Cada uno de esos subsistemas es, para nosotros, una cámara de seguridad que el atacante no sabía que estaba grabando. La lección transversal: **el forense de endpoint moderno vive en los artefactos de conveniencia del SO, no en los logs de seguridad** (que aquí ni existen).

### Artefacto y herramientas

El ZIP es un triage de KAPE (targets `RegistryHives, LNKFilesAndJumpLists, SRUM`; `ConsoleLog.txt` confirma host y targets). Estructura relevante:

- `Windows\System32\config\` → SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT + transaction logs (`.LOG1/.LOG2`). Dispositivos USB, BAM, zona horaria, WPD, VolumeInfoCache.
- `Users\cvoss\NTUSER.DAT` · `UsrClass.dat` → UserAssist, RecentDocs, ConsentStore (mic/cam), shellbags.
- `Users\cvoss\…\Recent\*.lnk` + `AutomaticDestinations`/`CustomDestinations` (JumpLists) → apuntan a `Desktop\DIOGENES_26\` (Schedule.pdf, EXT-0419.pdf, IT_SUPPORT.pdf, Driver Update Package.pdf). Los PDFs **no** están en el triage.
- `Windows\System32\SRU\SRUDB.dat` → SRUM: uso de red y de aplicaciones por proceso, en buckets de ~1 h.
- `ProgramData\Microsoft\search\…\Windows.edb` → índice de Windows Search (16 MB): rutas y resúmenes de texto de todo lo indexado, incluido `E:` y los PDFs.

> **Antes de tocar nada: aplica los transaction logs.** Los hives que KAPE copia en vivo suelen tener escrituras pendientes en `.LOG1/.LOG2`. Si no los aplicas, puedes leer una versión "sucia" del hive y perder la última LastWrite. `regripper` moderno lo hace solo; para leer a mano conviene usar `registryFlush`/`reglookup` o `yarp` con soporte de dirty pages. En este reto no cambió ninguna flag, pero es el paso 0 de todo triage serio.

**Herramientas por artefacto:**

- `regripper` (plugins `usbstor`, `usbdevices`, `mountdev`, `timezone`, `volinfocache`, `userassist`, `bam`) — cubre las preguntas 1, 2, 4 y 5 en cinco comandos.
- `python-registry` (`Registry.Registry`) para claves sin plugin: WPD, ConsentStore, y las propiedades `0064–0067` que hay que leer como FILETIME crudo.
- Para SRUM y Windows.edb: **`dissect.esedb`**. `libesedb-python`/`pyesedb` sirve para el SRUM básico, pero **falla con Windows.edb** (`unsupported data flags: 0x03` de los long values comprimidos y columnas 7-bit). `dissect.esedb` descomprime XPRESS y 7-bit de forma transparente, así que unifico ambas ESE con una sola librería.
- `LECmd` / `lnkparse3` para los LNK y JumpLists.

```bash
# venv obligatorio en Parrot/Debian moderno (PEP 668)
python3 -m venv /tmp/pg && source /tmp/pg/bin/activate
pip install python-registry dissect.esedb lnkparse3
# regripper vía paquete de distro o clonado:
#   git clone https://github.com/keydet89/RegRipper3.0
```

> **Trampa de zona horaria (léela antes de tocar timestamps).** `SYSTEM\ControlSet001\Control\TimeZoneInformation` = *Pacific Standard Time*, con `Bias` 480 y `DaylightBias` −60 → `ActiveTimeBias` **420** minutos = local = UTC−7 (PDT en agosto). **Todo** lo que hay en registro, SRUM y ConsentStore es **FILETIME en UTC**: no hay que aplicar ningún offset, ya están en UTC. La única cosa en local es el `ConsoleLog.txt` de KAPE (marca `01:21`), mientras que el **nombre del fichero** de triage va en UTC (`08:21`). Esa discrepancia de 7 h es la pista para no confundirte de referencia. **Las flags se aceptan en UTC.**

```bash
regripper -r Windows/System32/config/SYSTEM -p timezone
#   TimeZoneKeyName : Pacific Standard Time
#   Bias           : 480 (0x1E0)  -> 8 h
#   DaylightBias   : -60           -> verano
#   ActiveTimeBias : 420 (0x1A4)  -> UTC-7 efectivo (PDT)
```

### FILETIME en 20 segundos

Casi todos los timestamps de este reto son **FILETIME**: un entero de 64 bits que cuenta **intervalos de 100 ns desde 1601-01-01 00:00:00 UTC**. Dos operaciones lo resuelven todo:

- **A fecha absoluta:** `epoch_1601 + (filetime / 10_000_000) segundos`. En Unix: `unix = filetime/1e7 − 11644473600`.
- **A duración:** dos FILETIME se restan directamente; `(stop − start) / 1e7` = segundos (unidades de 100 ns → ÷10⁷).

```python
import datetime
def ft(v):                       # FILETIME -> datetime UTC
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=v // 10)
ft(134316274881131799)           # -> 2026-08-19 15:38:08.113179  (inicio de mic, Q6)
(134316278756619812 - 134316277486814313) / 1e7   # -> 126.98 s (webcam, Q7)
```

Esto es lo que usan por debajo `regripper`, `python-registry` y `dissect.esedb`; saberlo permite verificar a mano cualquier valor sospechoso y responder Q6/Q7/Q1 sin depender de que la herramienta formatee bien.

### Cronología

Reconstruida en UTC, todo el día **2026-08-19** salvo la adquisición:

| Hora (UTC) | Evento | Fuente |
|---|---|---|
| `15:35:50` | Se conecta el Lexar `RS200000000627E4`, etiqueta `CO-USB-0091`, montado en `E:` (+ partición Ventoy `F:` VTOYEFI) | SYSTEM · `0065` First Install; MountedDevices/VolumeInfoCache |
| `15:36:25` | cvoss ejecuta `E:\CO-LT-0469 update package\update.exe` (1 ejecución) | NTUSER · UserAssist |
| `15:38:08 → 15:41:03` | Captura de micrófono, ~175 s | ConsentStore\microphone |
| `15:42:28 → 15:44:35` | Stream de webcam, 127 s | ConsentStore\webcam |
| `~15:50` (bucket SRUM) | 172 064 531 B enviados / 615 595 B recibidos por `update.exe` | SRUDB.dat · Network Usage |
| `15:51:06` | Última llegada y retirada del USB (`0066`/`0067` idénticos) | SYSTEM · Properties |
| `2026-08-20 08:21` | Adquisición con KAPE (`RegistryHives, LNKFilesAndJumpLists, SRUM`) | nombre del triage (UTC) |

Lectura del patrón: **conectar → ejecutar (35 s) → mic (~2,5 min) → cam (~2 min) → exfiltrar → retirar**, todo en **~15 minutos** y con el USB fuera antes de las 15:52. El `update.exe` graba mic y cámara de forma **secuencial, no simultánea** (el stop del mic a las 15:41:03 precede al start de la cámara a las 15:42:28), lo que sugiere una rutina scriptada de "primero audio, luego vídeo, luego subir". La subida (SRUM 15:50) solapa el final de la webcam: exfiltra mientras aún graba.

### Metodología (paso a paso)

Cada paso explica **el porqué del artefacto**, el **comando real** y **cómo se cruza** con el resto.

#### 1 — Primera conexión del USB

**Pregunta:** *When did Clara Voss first connect the device Elias Venn left at her desk?*

Sin `setupapi.dev.log` en el triage, la fuente son las **propiedades del dispositivo** en el hive SYSTEM. Bajo cada instancia de `Enum\USB` y `Enum\USBSTOR` hay `Properties\{83da6326-97a6-4088-9453-a1923f573b29}` con FILETIMEs indexados por un número de propiedad (PID):

- `0064` → `DEVPKEY_Device_InstallDate` (instalación del driver).
- `0065` → `DEVPKEY_Device_FirstInstallDate` (**primera inserción del dispositivo** — la respuesta).
- `0066` → `DEVPKEY_Device_LastArrivalDate` (última conexión).
- `0067` → `DEVPKEY_Device_LastRemovalDate` (última retirada).

Esas cuatro propiedades sustituyen perfectamente a `setupapi.dev.log` cuando este falta. `regripper` las resuelve con `usbstor`/`usbdevices`:

```bash
regripper -r Windows/System32/config/SYSTEM -p usbstor
#   Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00
#     S/N: RS200000000627E4&0
#     First InstallDate : 2026-08-19 15:35:50Z    <- 0065
#     Last Arrival      : 2026-08-19 15:51:06Z    <- 0066
#     Last Removal      : 2026-08-19 15:51:06Z    <- 0067
```

Verificación a mano (útil cuando el plugin no muestra la propiedad exacta que quieres, o para leer los milisegundos): las propiedades son un `REG_BINARY` de 8 bytes little-endian que hay que interpretar como FILETIME.

```python
from Registry import Registry
import struct, datetime
def ft(v): return datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=v//10)

reg = Registry.Registry("Windows/System32/config/SYSTEM")
inst = reg.open(r"ControlSet001\Enum\USBSTOR"
                r"\Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00\RS200000000627E4&0")
props = inst.subkey("Properties").subkey("{83da6326-97a6-4088-9453-a1923f573b29}")
for pid in ("0064","0065","0066","0067"):
    raw = props.subkey(pid).value("").raw_data()       # 8 bytes LE
    print(pid, ft(struct.unpack("<Q", raw)[0]))
# 0065 -> 2026-08-19 15:35:50.428  (USBSTOR)   |  15:35:50.397 en la rama USB
```

`MountedDevices` (mapea `\DosDevices\E:` a la firma del volumen) y `Windows Search\VolumeInfoCache\E:` comparten LastWrite en ese mismo instante: el volumen se **montó como `E:`** al conectar. La flag se da al segundo, en UTC.

**Flag 1 → `2026-08-19 15:35:50`**

#### 2 — Serial del USB

**Pregunta:** *What serial number did the dropped device leave behind?*

Solo hay **un** dispositivo de almacenamiento USB en todo el hive, así que no hay ambigüedad. El serial que **reporta el propio dispositivo** (no el que Windows inventa cuando el descriptor no trae iSerialNumber — esos llevan `&` como segundo carácter) es el nombre de la instancia bajo el VID/PID. En `USBSTOR` aparece con el sufijo de instancia `&0`:

```bash
regripper -r Windows/System32/config/SYSTEM -p usbdevices
# USB\VID_21C4&PID_0CD1\RS200000000627E4                       <- serial "limpio"
# USBSTOR\Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00\RS200000000627E4&0
#   HardwareID  : USB\VID_21C4&PID_0CD1&REV_0200
#   ContainerID : {c12e83c9-7a97-53d0-ac60-72526287e69e}
#   Vendor/Prod : Lexar USB Flash Drive
```

El `ContainerID` es el pegamento que agrupa **todas** las interfaces del mismo dispositivo físico (la partición de datos `E:` y la EFI de Ventoy `F:` comparten ContainerID): confirma que el "Lexar" y el "VTOYEFI" son **un solo pendrive**, no dos. La flag es el serial sin el sufijo `&0`.

**Flag 2 → `RS200000000627E4`**

#### 3 — Ruta completa del payload

**Pregunta:** *What is the full path of the payload?*

Cuatro artefactos **independientes** coinciden en la ruta — corroboración cruzada gratis, y cada uno la guarda con un formato distinto:

```text
UserAssist   : E:\CO-LT-0469 update package\update.exe (1)          (ROT13 ya decodificado)
ConsentStore : …\microphone\NonPackaged\E:#CO-LT-0469 update package#update.exe   (# en vez de \)
SRUM IdMap   : 436  \device\harddiskvolume5\co-lt-0469 update package\update.exe  (ruta de dispositivo)
Windows.edb  : E:\CO-LT-0469 update package\update.exe   Size=210432            (índice de Search)
```

- **UserAssist** es el más directo: da la ruta con letra de unidad. `regripper` deshace el ROT13 por ti.
- **ConsentStore** usa `#` como separador porque el nombre de la app va como un solo token en la clave.
- **SRUM** no tiene letra de unidad (el USB ya no está montado cuando lees): `\Device\HarddiskVolume5` es el número de volumen que el kernel asignó al pendrive.
- **Windows.edb** indexó el árbol de `E:` y dice que el "paquete" contiene **un único fichero de 210 432 bytes**.

El resto del pendrive (`Drivers\Audio|Camera|Chipset|BadgNFC`, `Utils`, `Recovery`, `Manifest`) son **carpetas vacías de atrezzo** para que parezca un kit de soporte legítimo. Las vemos en Windows.edb (indexó la estructura de directorios) aunque el USB ya no exista físicamente.

**Flag 3 → `E:\CO-LT-0469 update package\update.exe`**

#### 4 — Timestamp exacto de ejecución del paquete

**Pregunta:** *At what exact timestamp did she execute the malicious package?*

**UserAssist** (`HKCU\…\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`) registra todo lo lanzado **por Explorer** (doble clic del usuario), con contador de ejecuciones y **última fecha de ejecución** en FILETIME. Los nombres van cifrados en **ROT13**; `regripper` los decodifica:

```bash
regripper -r Users/cvoss/NTUSER.DAT -p userassist | grep -B1 update.exe
# 2026-08-19 15:36:25Z
#   E:\CO-LT-0469 update package\update.exe (1)
```

**Por qué UserAssist y no BAM:** `BAM`/`DAM` (`SYSTEM\...\bam\State\UserSettings\<SID>`) también data ejecuciones, pero **solo de binarios en volúmenes locales**; el exe estaba en el USB (`E:`), así que BAM no lo registra. Prefetch tampoco viene en el triage (KAPE no incluyó ese target). UserAssist es la única fuente que **data la ejecución del usuario** aquí.

El timestamp encaja con la narrativa: **35 s después de enchufar el USB**, y el señuelo (`Driver Update Package.pdf`, ver Q9) le decía literalmente *"Open Q4_Briefing_Notes to begin the update… No restart required"*. Un solo contador `(1)`: se ejecutó una única vez.

**Flag 4 → `2026-08-19 15:36:25`**

#### 5 — Asset name del USB

**Pregunta:** *DIOGENES tagged the USB with an asset name that surfaced as the device name on connection.*

El nombre que ve el usuario al conectar es la **etiqueta de volumen**, que Windows cachea en dos sitios del hive SOFTWARE — el bus WPD (Windows Portable Devices) y la caché de volúmenes de Windows Search:

```bash
# Windows Portable Devices — FriendlyName
python-registry / regripper -p port_dev:
SOFTWARE\Microsoft\Windows Portable Devices\Devices\
  SWD#WPDBUSENUM#_??_USBSTOR#DISK&VEN_LEXAR&…#RS200000000627E4&0#{53F56307-…}
    FriendlyName = CO-USB-0091

# Windows Search VolumeInfoCache
regripper -r Windows/System32/config/SOFTWARE -p volinfocache
SOFTWARE\Microsoft\Windows Search\VolumeInfoCache\E:  VolumeLabel = CO-USB-0091
SOFTWARE\Microsoft\Windows Search\VolumeInfoCache\F:  VolumeLabel = VTOYEFI   <- Ventoy, ruido
```

Que la etiqueta sea `CO-USB-0091` (un código de inventario) y no algo genérico como "UPDATE" delata que **DIOGENES la etiquetó**: el pendrive salió de un inventario de la organización, no de una tienda. La partición `F: VTOYEFI` es de Ventoy (el multi-boot que usaron para preparar el USB) y es **ruido**: no confundirla con la respuesta.

**Flag 5 → `CO-USB-0091`**

#### 6 — Inicio de captura de micrófono

**Pregunta:** *At what time did capture begin?*

Desde **Windows 10 1903**, cada acceso a micrófono, cámara o ubicación deja rastro en `CapabilityAccessManager\ConsentStore\<capacidad>\NonPackaged\<ruta con #>`, con dos valores FILETIME: `LastUsedTimeStart` y `LastUsedTimeStop`. Está en el NTUSER del usuario (con espejo en SOFTWARE para apps de máquina). Es el **artefacto estrella para spyware de escritorio**: dice qué binario usó el mic/cámara y cuándo, **sin ningún log de eventos**.

```python
from Registry import Registry
import datetime
def ft(v): return datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=v//10)

reg = Registry.Registry("Users/cvoss/NTUSER.DAT")
base = (r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager"
        r"\ConsentStore\microphone\NonPackaged")
for sk in reg.open(base).subkeys():
    if "update.exe" in sk.name():
        start = sk.value("LastUsedTimeStart").value()
        stop  = sk.value("LastUsedTimeStop").value()
        print(sk.name())
        print("  start", ft(start), "| stop", ft(stop),
              "|", round((stop-start)/1e7,1), "s")
# E:#CO-LT-0469 update package#update.exe
#   start 2026-08-19 15:38:08.113 | stop 2026-08-19 15:41:03.259 | 175.1 s
```

`LastUsedTimeStart = 134316274881131799 → 2026-08-19 15:38:08.113`. La flag es el inicio, al segundo.

**Flag 6 → `2026-08-19 15:38:08`**

#### 7 — Duración del stream de webcam

**Pregunta:** *For how many seconds did the webcam stream?*

Misma clave, capacidad `webcam`. La **duración** es la resta de FILETIMEs (unidades de 100 ns → ÷10⁷):

```python
base = base.replace("microphone", "webcam")     # ...ConsentStore\webcam\NonPackaged
# E:#CO-LT-0469 update package#update.exe
#   LastUsedTimeStart = 134316277486814313 -> 15:42:28.681
#   LastUsedTimeStop  = 134316278756619812 -> 15:44:35.662
(134316278756619812 - 134316277486814313) / 1e7      # = 126.98 s
```

126,98 s se redondea a **127**. Nota de precisión: la flag pide **segundos enteros**; usar `round()` (127), no truncar (126). El mic (Q6) duró ~175 s y precede a la cámara: grabación **secuencial**.

**Flag 7 → `127`**

#### 8 — Tráfico saliente hacia el C2

**Pregunta:** *How many decimal megabytes of outbound traffic flowed from the compromised machine to the C2?*

SRUM (`SRUDB.dat`, base ESE) contabiliza el uso de red **por proceso** en la tabla `{973F5D5C-1D90-4944-BE8E-24B94231A174}` (Network Data Usage). El `AppId` de cada fila es un índice que se resuelve contra `SruDbIdMapTable` (que mapea id → ruta de proceso como blob). Cada `TimeStamp` es un bucket de ~1 h.

```python
from dissect.esedb import EseDB
db = EseDB(open("Windows/System32/SRU/SRUDB.dat", "rb"))

# 1) resolver el id map: id -> ruta de proceso
idmap = {}
for r in db.table("SruDbIdMapTable").records():
    blob = r.get("IdBlob")
    idmap[r.get("IdIndex")] = blob.decode("utf-16-le", "ignore") if blob else ""

# 2) recorrer Network Usage y filtrar por update.exe
net = db.table("{973F5D5C-1D90-4944-BE8E-24B94231A174}")
for r in net.records():
    app = idmap.get(r.get("AppId"), "")
    if "update.exe" in app.lower():
        sent, recv = r.get("BytesSent"), r.get("BytesRecvd")
        print(r.get("AppId"), app)
        print("  sent", sent, "recv", recv, "ts", r.get("TimeStamp"))
# 436  \device\harddiskvolume5\co-lt-0469 update package\update.exe
#   sent 172064531 recv 615595 ts 2026-08-19 15:50
```

`BytesSent` es un entero de 8 bytes little-endian (tipo ESE 15, "long long"). **Atención con `libesedb`:** su helper `get_value_data_as_integer` falla con los tipos 15/8; si usas pyesedb, decodifica por longitud del blob (`int.from_bytes(blob, "little")`) en vez del helper. Con `dissect.esedb` el valor ya viene tipado.

La pregunta pide **megabytes decimales** (SI, ÷10⁶), no MiB:

```text
172 064 531 / 1 000 000 = 172.064531 MB      <- flag
172 064 531 / 1 048 576 = 164.09 MiB          (binario — NO es lo que piden)
```

Solo hay una fila para `update.exe`, así que no hay que sumar buckets. La flag es `172.064531`.

**Flag 8 → `172.064531`**

#### 9 — Credenciales del dev de tickets DIOGENES

**Pregunta:** *What set of credentials did the spying surface for a developer working on DIOGENES tickets?*

Los LNK y JumpLists (`AutomaticDestinations-ms`) dicen que cvoss abrió `Desktop\DIOGENES_26\EXT-0419.pdf`, con su volumen origen y timestamps — pero **el PDF no viene en el triage**. Sí viene `Windows.edb`: para cada fichero indexado, Windows Search guarda un `System_Search_AutoSummary` con los primeros **~1000 caracteres** de texto que el **IFilter de PDF** extrajo al indexar. Es decir: el índice conserva el contenido del documento aunque el documento haya desaparecido.

```bash
lnkparse3 "Users/cvoss/.../Recent/EXT-0419.lnk"
#   Local path: C:\Users\cvoss\Desktop\DIOGENES_26\EXT-0419.pdf
#   Drive serial / volume label: CO-... (confirma que se abrió desde el Desktop)
```

El truco es el formato de la columna. En Win10, `AutoSummary` va como **long value comprimido** (flags `0x03`, XPRESS) y las columnas cortas usan **compresión 7-bit** (primer byte `0x10–0x17`). `libesedb` no lo soporta (`unsupported data flags: 0x03`); **`dissect.esedb` descomprime ambas de forma transparente**:

```python
from dissect.esedb import EseDB
db = EseDB(open("ProgramData/Microsoft/search/Data/Applications/Windows/Windows.edb", "rb"))
for rec in db.table("SystemIndex_PropertyStore").records():
    p = rec.get("4447-System_ItemPathDisplay")
    if p and "DIOGENES_26\\" in p:
        print(p)
        print(rec.get("4625-System_Search_AutoSummary"))

# C:\Users\cvoss\Desktop\DIOGENES_26\EXT-0419.pdf
#   PERSONNEL & ACCESS FILE — EXTERNAL CONTRACTOR · DIOGENES Ticketing Support
#   Name: Tom Ainsworth   Title: Software Developer, DIOGENES Ticketing Support
#   Contractor ID: EXT-0419   Internal server: srv-diogenes-tickets-01.internal
#   Username: tainsworth   Password: D10g3n3s_T1ck3ts#2026
#   Access scope: EXT-3 (ticketing host only)   Repository: parse_diogenese_tickets
```

(Los IDs de columna `4447`/`4625` son los property-store IDs de `System_ItemPathDisplay` y `System_Search_AutoSummary`; pueden variar entre versiones, así que en la práctica conviene volcar todas las columnas de una fila y localizar el path/summary por contenido.)

El mismo índice revela **el resto de la trama** — y por eso Windows.edb es tan valioso: es un *dump de texto de todo lo que estuvo en disco*:

- `IT_SUPPORT.pdf` → ficha de onboarding de **Elias Venn** (EXT-0431, portátil CO-LT-0431, *"delivery address: Unit 14, Silvertown East Yard"*): el paper ghost tenía credenciales de acceso legítimas.
- `Driver Update Package.pdf` → las instrucciones del señuelo que empujaron a cvoss a ejecutar `update.exe`.
- `DIOGENES_Contractor_Assignments.csv` / `IT_Asset_Inventory.csv` → la lista de contratistas y activos que NAPOLEON puede cazar ahora con las credenciales robadas.

**Flag 9 → `tainsworth:D10g3n3s_T1ck3ts#2026`**

### Respuestas / flags

| # | Pregunta | Respuesta | Fuente |
|---|----------|-----------|--------|
| 1 | Primera conexión del USB | `2026-08-19 15:35:50` | SYSTEM · `Properties\{83da6326…}\0065` |
| 2 | Serial del USB | `RS200000000627E4` | SYSTEM · `Enum\USB` / `Enum\USBSTOR\…&0` |
| 3 | Ruta completa del payload | `E:\CO-LT-0469 update package\update.exe` | UserAssist · ConsentStore · SRUM · Windows.edb |
| 4 | Ejecución del paquete | `2026-08-19 15:36:25` | NTUSER · UserAssist |
| 5 | Asset name del USB | `CO-USB-0091` | SOFTWARE · WPD FriendlyName / VolumeInfoCache |
| 6 | Inicio de captura de micrófono | `2026-08-19 15:38:08` | ConsentStore\microphone · LastUsedTimeStart |
| 7 | Segundos de stream de webcam | `127` | ConsentStore\webcam · Stop−Start = 126,98 s |
| 8 | MB decimales salientes al C2 | `172.064531` | SRUDB.dat · `{973F5D5C…}` AppId 436 |
| 9 | Credenciales del dev de tickets | `tainsworth:D10g3n3s_T1ck3ts#2026` | Windows.edb · AutoSummary de EXT-0419.pdf |

### IOCs

| Tipo | Valor | Notas |
|---|---|---|
| Fichero (payload) | `E:\CO-LT-0469 update package\update.exe` | 210 432 B; único fichero real del USB |
| Dispositivo USB | Lexar, `VID_21C4&PID_0CD1`, S/N `RS200000000627E4` | HardwareID `USB\VID_21C4&PID_0CD1&REV_0200` |
| ContainerID | `{c12e83c9-7a97-53d0-ac60-72526287e69e}` | Agrupa `E:` (datos) + `F:` (VTOYEFI/Ventoy) |
| Volumen | Label `CO-USB-0091`, montado `E:`, `\Device\HarddiskVolume5` | `F:` = `VTOYEFI` (ruido de Ventoy) |
| Red (exfil) | 172 064 531 B out / 615 595 B in por `update.exe` | Bucket SRUM `~15:50` UTC |
| Credencial robada | `tainsworth : D10g3n3s_T1ck3ts#2026` | Host `srv-diogenes-tickets-01.internal`, scope EXT-3 |
| Actor/alias | Elias Venn (EXT-0431), Tom Ainsworth (EXT-0419) | Contratista falso + víctima cuyo acceso se roba |
| Directorio señuelo | `E:\...\Drivers\{Audio,Camera,Chipset,BadgNFC}`, `Utils`, `Recovery`, `Manifest` | Carpetas vacías de atrezzo |

> **Nota de scope.** No hay IP/dominio del C2 en el triage: SRUM contabiliza bytes por proceso pero **no guarda el destino**. Para obtener la IP haría falta un PCAP, `dnscache`, o el propio binario — ninguno presente aquí. La cantidad exfiltrada sí es firme.

### Mapeo MITRE ATT&CK

| Táctica | Técnica | Evidencia en este caso |
|---|---|---|
| Initial Access | **T1091** Replication Through Removable Media / **T1200** Hardware Additions | USB dropper dejado físicamente en la mesa |
| Initial Access / Execution | **T1204.002** User Execution: Malicious File | cvoss ejecuta `update.exe` (UserAssist, 1 run) |
| Collection | **T1123** Audio Capture | ConsentStore\microphone, ~175 s |
| Collection | **T1125** Video Capture | ConsentStore\webcam, 127 s |
| Collection | **T1119 / T1005** Automated / Local Data Collection | CSVs de contratistas y activos indexados |
| Credential Access | **T1552.001** Unsecured Credentials: Credentials In Files | credencial en claro dentro de EXT-0419.pdf |
| Exfiltration | **T1041** Exfiltration Over C2 Channel | 172 MB salientes vía `update.exe` (SRUM) |
| Defense Evasion | **T1070 / atrezzo** | carpetas vacías para simular kit de soporte; USB retirado en <16 min |

### Detección y remediación

**Detección (lo que habría disparado antes):**

- **Control de dispositivos USB.** Una política de Device Control / GPO (`RemovableStorageDevices` deny, o EDR con device control) habría bloqueado el montaje de un USB no inventariado. Alerta sobre nuevas subclaves en `USBSTOR` / eventos `Microsoft-Windows-DriverFrameworks-UserMode/2003,2100,2102`.
- **Acceso anómalo a mic/cámara.** Monitorizar cambios en `ConsentStore\{microphone,webcam}\NonPackaged` para procesos **no interactivos o fuera de una allowlist** (Teams, Zoom, cámara del sistema). Un binario recién ejecutado desde `E:\` encendiendo mic+cam en secuencia es señal de alto valor.
- **Ejecución desde medio extraíble.** UserAssist/Prefetch con ruta en unidad extraíble; regla SIEM: `NewProcess` cuyo `Image` esté en `\Device\HarddiskVolume` mapeado a USB.
- **Exfiltración por volumen.** Un proceso desconocido con `BytesSent` de cientos de MB en un bucket SRUM es anómalo; correlacionar con firewall/NetFlow para el destino.
- **DLP en documentos.** Credenciales en claro dentro de PDFs de RRHH/contratistas: escanear repos y shares con reglas de secretos.

**Remediación / respuesta:**

1. **Rotar ya** `tainsworth : D10g3n3s_T1ck3ts#2026` y cualquier reuso; auditar accesos a `srv-diogenes-tickets-01.internal` y al repo `parse_diogenese_tickets` desde el 2026-08-19.
2. **Contener** CO-LT-0469: aislar, capturar disco+memoria completos (aquí solo hubo triage), buscar persistencia del `update.exe` (aunque UserAssist marca 1 ejecución y el USB salió, verificar Run keys, tareas, servicios).
3. **Cazar el "paper ghost":** revocar el onboarding de Elias Venn (EXT-0431), la entrega a *Unit 14, Silvertown East Yard*, y todo contratista de `DIOGENES_Contractor_Assignments.csv` no verificado por un humano.
4. **Endurecer:** Device Control por defecto-deny, cámara/mic con indicador y allowlist, cifrado de PDFs de RRHH, y prohibir credenciales en claro en documentos.

### Lecciones

- **Sin `setupapi.dev.log`**, las propiedades `{83da6326…}\0064–0067` del hive SYSTEM dan install / first-install / last-arrival / last-removal del USB. El `ContainerID` prueba que las dos particiones son un solo dispositivo.
- La **ruta del payload aparece en 4 artefactos independientes** (UserAssist, ConsentStore, SRUM, Windows.edb): corroboración cruzada gratis, cada uno con su propio formato de ruta.
- **ConsentStore** es el artefacto estrella para spyware de escritorio: qué binario usó mic/cámara y cuándo, sin logs de eventos. `LastUsedTimeStop − LastUsedTimeStart` = duración exacta.
- **SRUM** cuantifica la exfiltración por proceso; decodificar `BytesSent` por longitud del blob, no con helpers que fallan con tipos 15/8. Pide **MB decimales** (÷10⁶), no MiB.
- **Windows.edb como sustituto del fichero**: cuando faltan documentos en el triage, el `AutoSummary` suele tener texto suficiente para responder. Usar `dissect.esedb` (descomprime XPRESS/7-bit); `libesedb` se atraganta con `flags 0x03`.
- **Cuidado con la zona horaria**: registro/SRUM/ConsentStore en UTC; el ConsoleLog de KAPE en local (−7 h). Responder en UTC.
- **Paso 0 de todo triage:** aplicar transaction logs antes de leer hives.

### Serie · The Reichenbach Directive

| # | Sherlock | Enlace |
|---|----------|--------|
| S01 | Silent Dividend | [../2026-09-15-holmes2026-s01-silent-dividend/](../2026-09-15-holmes2026-s01-silent-dividend/) |
| S02 | Bottle Out | [../2026-09-16-holmes2026-s02-bottle-out/](../2026-09-16-holmes2026-s02-bottle-out/) |
| S03 | Whisper Chain | [../2026-09-17-holmes2026-s03-whisper-chain/](../2026-09-17-holmes2026-s03-whisper-chain/) |
| **S04** | **Paper Ghost** ← estás aquí | [../2026-09-18-holmes2026-s04-paper-ghost/](../2026-09-18-holmes2026-s04-paper-ghost/) |
| S05 | Poisoned Branch | [../2026-09-19-holmes2026-s05-poisoned-branch/](../2026-09-19-holmes2026-s05-poisoned-branch/) |
| S06 | Silent Passenger | [../2026-09-20-holmes2026-s06-silent-passenger/](../2026-09-20-holmes2026-s06-silent-passenger/) |
| S07 | Iron Feather | [../2026-09-21-holmes2026-s07-iron-feather/](../2026-09-21-holmes2026-s07-iron-feather/) |
| S08 | Borrowed Name | [../2026-09-22-holmes2026-s08-borrowed-name/](../2026-09-22-holmes2026-s08-borrowed-name/) |
| S09 | Last Light | [../2026-09-23-holmes2026-s09-last-light/](../2026-09-23-holmes2026-s09-last-light/) |

<a id="en"></a>
## 🇬🇧 English

### Scenario

A fake IT contractor, **Elias Venn**, leaves a USB stick on the desk of **Clara Voss** (user `cvoss`) on host **CO-LT-0469** (Windows 10 19045, VM). She opens it as if it were a driver update and the "installer" `update.exe` turns on the microphone and webcam and dumps **172 MB** to a C2. There is no full disk image: only a **74-file KAPE triage** (registry hives, LNK/JumpLists, SRUM and the Windows Search index). The whole incident must be reconstructed from those artifacts.

- **Host:** CO-LT-0469 (Win10 19045, VM) · **User:** `cvoss` · **Team:** CyberFlippers.
- **Host timezone:** Pacific (UTC−7, PDT in August). **All answers are given in UTC.**
- **Difficulty:** easy · 9 flags.

Backstory matters for the arc: DIOGENES is the target's internal ticketing platform, and NAPOLEON (the arc's APT) uses this *paper ghost* — a contractor who exists only on paper — to steal credentials from developers with access to the ticketing backend. The USB is not a sophisticated technical implant: it's social engineering wrapped in a "support kit" with prop folders. Our job is purely forensic: no binary, no PCAP, no full disk — reconstruct who, what, when and how much **from the traces Windows leaves in the registry and two ESE databases**.

### Why this challenge is interesting (artifact model)

The point of *Paper Ghost* is that **no question is answered by an event log**. There is no `Security.evtx`, no `setupapi.dev.log`, no Sysmon. Everything comes from "passive" artifacts Windows keeps for its own operation, reinterpreted by the analyst:

- The **registry** keeps USB device history because the Plug-and-Play Manager must remember drivers and drive letters.
- **ConsentStore** keeps mic/camera `LastUsed` because Windows' Privacy panel shows it to the user.
- **SRUM** accounts bytes per process because battery/data diagnostics need it.
- **Windows.edb** indexes PDF text because Windows Search offers content search.

Each subsystem is, to us, a security camera the attacker didn't know was recording. The transversal lesson: **modern endpoint forensics lives in the OS convenience artifacts, not in the security logs** (which here don't even exist).

### Artifact and tools

The ZIP is a KAPE triage (targets `RegistryHives, LNKFilesAndJumpLists, SRUM`; `ConsoleLog.txt` confirms host and targets). Relevant structure:

- `Windows\System32\config\` → SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT + transaction logs (`.LOG1/.LOG2`). USB devices, BAM, timezone, WPD, VolumeInfoCache.
- `Users\cvoss\NTUSER.DAT` · `UsrClass.dat` → UserAssist, RecentDocs, ConsentStore (mic/cam), shellbags.
- `Users\cvoss\…\Recent\*.lnk` + `AutomaticDestinations`/`CustomDestinations` (JumpLists) → point at `Desktop\DIOGENES_26\` (Schedule.pdf, EXT-0419.pdf, IT_SUPPORT.pdf, Driver Update Package.pdf). The PDFs are **not** in the triage.
- `Windows\System32\SRU\SRUDB.dat` → SRUM: per-process network and application usage in ~1 h buckets.
- `ProgramData\Microsoft\search\…\Windows.edb` → Windows Search index (16 MB): paths and text summaries of everything indexed, including `E:` and the PDFs.

> **Before touching anything: apply the transaction logs.** Hives KAPE copies live usually have pending writes in `.LOG1/.LOG2`. If you don't apply them you may read a "dirty" hive and lose the last LastWrite. Modern `regripper` does it for you; to read by hand use `registryFlush`/`reglookup` or `yarp` with dirty-page support. No flag changed here, but it's step 0 of any serious triage.

**Tools per artifact:**

- `regripper` (plugins `usbstor`, `usbdevices`, `mountdev`, `timezone`, `volinfocache`, `userassist`, `bam`) — covers questions 1, 2, 4 and 5 in five commands.
- `python-registry` (`Registry.Registry`) for keys with no plugin: WPD, ConsentStore, and the `0064–0067` properties read as raw FILETIME.
- For SRUM and Windows.edb: **`dissect.esedb`**. `libesedb-python`/`pyesedb` handles basic SRUM but **chokes on Windows.edb** (`unsupported data flags: 0x03` for compressed long values and 7-bit columns). `dissect.esedb` transparently decompresses XPRESS and 7-bit, so I unify both ESE databases with one library.
- `LECmd` / `lnkparse3` for LNK and JumpLists.

```bash
# venv required on modern Parrot/Debian (PEP 668)
python3 -m venv /tmp/pg && source /tmp/pg/bin/activate
pip install python-registry dissect.esedb lnkparse3
# regripper via distro package or cloned:
#   git clone https://github.com/keydet89/RegRipper3.0
```

> **Timezone trap (read before touching timestamps).** `SYSTEM\ControlSet001\Control\TimeZoneInformation` = *Pacific Standard Time*, with `Bias` 480 and `DaylightBias` −60 → `ActiveTimeBias` **420** minutes = local = UTC−7 (PDT in August). **All** registry, SRUM and ConsentStore data is **FILETIME in UTC**: no offset to apply, they're already UTC. The only thing in local time is KAPE's `ConsoleLog.txt` (`01:21`), while the **triage file name** is UTC (`08:21`). That 7 h gap is the clue not to mix references. **Flags are accepted in UTC.**

```bash
regripper -r Windows/System32/config/SYSTEM -p timezone
#   TimeZoneKeyName : Pacific Standard Time
#   Bias           : 480 (0x1E0)  -> 8 h
#   DaylightBias   : -60           -> summer
#   ActiveTimeBias : 420 (0x1A4)  -> effective UTC-7 (PDT)
```

### FILETIME in 20 seconds

Almost every timestamp here is **FILETIME**: a 64-bit integer counting **100-ns intervals since 1601-01-01 00:00:00 UTC**. Two operations solve everything:

- **To absolute date:** `epoch_1601 + (filetime / 10_000_000) seconds`. In Unix: `unix = filetime/1e7 − 11644473600`.
- **To duration:** subtract two FILETIMEs directly; `(stop − start) / 1e7` = seconds (100-ns units → ÷10⁷).

```python
import datetime
def ft(v):                       # FILETIME -> UTC datetime
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=v // 10)
ft(134316274881131799)           # -> 2026-08-19 15:38:08.113179  (mic start, Q6)
(134316278756619812 - 134316277486814313) / 1e7   # -> 126.98 s (webcam, Q7)
```

This is what `regripper`, `python-registry` and `dissect.esedb` use under the hood; knowing it lets you hand-verify any suspicious value and answer Q6/Q7/Q1 without depending on the tool's formatting.

### Timeline

Reconstructed in UTC, all on **2026-08-19** except acquisition:

| Time (UTC) | Event | Source |
|---|---|---|
| `15:35:50` | Lexar `RS200000000627E4` connected, label `CO-USB-0091`, mounted as `E:` (+ Ventoy partition `F:` VTOYEFI) | SYSTEM · `0065` First Install; MountedDevices/VolumeInfoCache |
| `15:36:25` | cvoss runs `E:\CO-LT-0469 update package\update.exe` (1 run) | NTUSER · UserAssist |
| `15:38:08 → 15:41:03` | Microphone capture, ~175 s | ConsentStore\microphone |
| `15:42:28 → 15:44:35` | Webcam stream, 127 s | ConsentStore\webcam |
| `~15:50` (SRUM bucket) | 172,064,531 B sent / 615,595 B received by `update.exe` | SRUDB.dat · Network Usage |
| `15:51:06` | Last arrival and removal of the USB (`0066`/`0067` identical) | SYSTEM · Properties |
| `2026-08-20 08:21` | KAPE acquisition (`RegistryHives, LNKFilesAndJumpLists, SRUM`) | triage name (UTC) |

Pattern reading: **plug in → run (35 s) → mic (~2.5 min) → cam (~2 min) → exfiltrate → remove**, all in **~15 minutes** with the USB gone before 15:52. `update.exe` records mic and camera **sequentially, not simultaneously** (mic stop at 15:41:03 precedes camera start at 15:42:28), suggesting a scripted "audio first, then video, then upload" routine. The upload (SRUM 15:50) overlaps the end of the webcam: it exfiltrates while still recording.

### Methodology (step by step)

Each step explains **why the artifact**, the **real command** and **how it cross-checks** the rest.

#### 1 — First USB connection

**Question:** *When did Clara Voss first connect the device Elias Venn left at her desk?*

With no `setupapi.dev.log` in the triage, the source is the **device properties** in the SYSTEM hive. Under each `Enum\USB` and `Enum\USBSTOR` instance there is `Properties\{83da6326-97a6-4088-9453-a1923f573b29}` with FILETIMEs indexed by a property number (PID):

- `0064` → `DEVPKEY_Device_InstallDate` (driver install).
- `0065` → `DEVPKEY_Device_FirstInstallDate` (**first insertion of the device** — the answer).
- `0066` → `DEVPKEY_Device_LastArrivalDate` (last connect).
- `0067` → `DEVPKEY_Device_LastRemovalDate` (last removal).

Those four properties perfectly substitute for `setupapi.dev.log` when it's missing. `regripper` resolves them with `usbstor`/`usbdevices`:

```bash
regripper -r Windows/System32/config/SYSTEM -p usbstor
#   Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00
#     S/N: RS200000000627E4&0
#     First InstallDate : 2026-08-19 15:35:50Z    <- 0065
#     Last Arrival      : 2026-08-19 15:51:06Z    <- 0066
#     Last Removal      : 2026-08-19 15:51:06Z    <- 0067
```

Hand verification (useful when the plugin doesn't show the exact property, or to read the milliseconds): the properties are an 8-byte little-endian `REG_BINARY` to be read as FILETIME.

```python
from Registry import Registry
import struct, datetime
def ft(v): return datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=v//10)

reg = Registry.Registry("Windows/System32/config/SYSTEM")
inst = reg.open(r"ControlSet001\Enum\USBSTOR"
                r"\Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00\RS200000000627E4&0")
props = inst.subkey("Properties").subkey("{83da6326-97a6-4088-9453-a1923f573b29}")
for pid in ("0064","0065","0066","0067"):
    raw = props.subkey(pid).value("").raw_data()       # 8 bytes LE
    print(pid, ft(struct.unpack("<Q", raw)[0]))
# 0065 -> 2026-08-19 15:35:50.428  (USBSTOR)   |  15:35:50.397 on the USB branch
```

`MountedDevices` (maps `\DosDevices\E:` to the volume signature) and `Windows Search\VolumeInfoCache\E:` share LastWrite at that same instant: the volume **mounted as `E:`** on connect. The flag is to the second, in UTC.

**Flag 1 → `2026-08-19 15:35:50`**

#### 2 — USB serial number

**Question:** *What serial number did the dropped device leave behind?*

There is only **one** USB storage device in the whole hive, so no ambiguity. The serial the **device itself reports** (not the one Windows invents when the descriptor lacks iSerialNumber — those carry `&` as the second character) is the instance name under VID/PID. In `USBSTOR` it carries the instance suffix `&0`:

```bash
regripper -r Windows/System32/config/SYSTEM -p usbdevices
# USB\VID_21C4&PID_0CD1\RS200000000627E4                       <- "clean" serial
# USBSTOR\Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00\RS200000000627E4&0
#   HardwareID  : USB\VID_21C4&PID_0CD1&REV_0200
#   ContainerID : {c12e83c9-7a97-53d0-ac60-72526287e69e}
#   Vendor/Prod : Lexar USB Flash Drive
```

The `ContainerID` is the glue that groups **all** interfaces of the same physical device (data partition `E:` and Ventoy EFI `F:` share ContainerID): it confirms the "Lexar" and the "VTOYEFI" are **one single stick**, not two. The flag is the serial without the `&0` suffix.

**Flag 2 → `RS200000000627E4`**

#### 3 — Full payload path

**Question:** *What is the full path of the payload?*

Four **independent** artifacts agree on the path — free cross-corroboration, each storing it in a different format:

```text
UserAssist   : E:\CO-LT-0469 update package\update.exe (1)          (ROT13 already decoded)
ConsentStore : …\microphone\NonPackaged\E:#CO-LT-0469 update package#update.exe   (# instead of \)
SRUM IdMap   : 436  \device\harddiskvolume5\co-lt-0469 update package\update.exe  (device path)
Windows.edb  : E:\CO-LT-0469 update package\update.exe   Size=210432            (Search index)
```

- **UserAssist** is the most direct: gives the path with drive letter. `regripper` undoes the ROT13 for you.
- **ConsentStore** uses `#` as separator because the app name is a single token in the key.
- **SRUM** has no drive letter (the USB is already unmounted when you read): `\Device\HarddiskVolume5` is the volume number the kernel assigned the stick.
- **Windows.edb** indexed the `E:` tree and says the "package" holds **one single 210,432-byte file**.

The rest of the stick (`Drivers\Audio|Camera|Chipset|BadgNFC`, `Utils`, `Recovery`, `Manifest`) are **empty prop folders** to look like a legit support kit. We see them in Windows.edb (it indexed the directory structure) even though the USB no longer physically exists.

**Flag 3 → `E:\CO-LT-0469 update package\update.exe`**

#### 4 — Exact package execution timestamp

**Question:** *At what exact timestamp did she execute the malicious package?*

**UserAssist** (`HKCU\…\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`) records everything launched **through Explorer** (user double-click), with run count and **last-run time** in FILETIME. Names are **ROT13**-encoded; `regripper` decodes them:

```bash
regripper -r Users/cvoss/NTUSER.DAT -p userassist | grep -B1 update.exe
# 2026-08-19 15:36:25Z
#   E:\CO-LT-0469 update package\update.exe (1)
```

**Why UserAssist and not BAM:** `BAM`/`DAM` (`SYSTEM\...\bam\State\UserSettings\<SID>`) also dates executions, but **only for binaries on local volumes**; the exe was on the USB (`E:`), so BAM doesn't record it. Prefetch isn't in the triage either (KAPE didn't include that target). UserAssist is the only source that **dates the user execution** here.

The timestamp fits the narrative: **35 s after plugging in the USB**, and the decoy (`Driver Update Package.pdf`, see Q9) literally told her *"Open Q4_Briefing_Notes to begin the update… No restart required"*. A single counter `(1)`: it ran exactly once.

**Flag 4 → `2026-08-19 15:36:25`**

#### 5 — USB asset name

**Question:** *DIOGENES tagged the USB with an asset name that surfaced as the device name on connection.*

The name the user sees on connect is the **volume label**, which Windows caches in two places in the SOFTWARE hive — the WPD (Windows Portable Devices) bus and the Windows Search volume cache:

```bash
# Windows Portable Devices — FriendlyName
python-registry / regripper -p port_dev:
SOFTWARE\Microsoft\Windows Portable Devices\Devices\
  SWD#WPDBUSENUM#_??_USBSTOR#DISK&VEN_LEXAR&…#RS200000000627E4&0#{53F56307-…}
    FriendlyName = CO-USB-0091

# Windows Search VolumeInfoCache
regripper -r Windows/System32/config/SOFTWARE -p volinfocache
SOFTWARE\Microsoft\Windows Search\VolumeInfoCache\E:  VolumeLabel = CO-USB-0091
SOFTWARE\Microsoft\Windows Search\VolumeInfoCache\F:  VolumeLabel = VTOYEFI   <- Ventoy, noise
```

That the label is `CO-USB-0091` (an inventory code) and not something generic like "UPDATE" gives away that **DIOGENES tagged it**: the stick came from an org inventory, not a shop. The `F: VTOYEFI` partition is Ventoy's (the multi-boot used to prep the USB) and is **noise**: don't confuse it with the answer.

**Flag 5 → `CO-USB-0091`**

#### 6 — Microphone capture start

**Question:** *At what time did capture begin?*

Since **Windows 10 1903**, each microphone, camera or location access leaves a trace under `CapabilityAccessManager\ConsentStore\<capability>\NonPackaged\<path with #>`, with two FILETIME values: `LastUsedTimeStart` and `LastUsedTimeStop`. It's in the user's NTUSER (mirrored in SOFTWARE for machine apps). It's the **star artifact for desktop spyware**: it says which binary used mic/camera and when, **with no event logs**.

```python
from Registry import Registry
import datetime
def ft(v): return datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=v//10)

reg = Registry.Registry("Users/cvoss/NTUSER.DAT")
base = (r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager"
        r"\ConsentStore\microphone\NonPackaged")
for sk in reg.open(base).subkeys():
    if "update.exe" in sk.name():
        start = sk.value("LastUsedTimeStart").value()
        stop  = sk.value("LastUsedTimeStop").value()
        print(sk.name())
        print("  start", ft(start), "| stop", ft(stop),
              "|", round((stop-start)/1e7,1), "s")
# E:#CO-LT-0469 update package#update.exe
#   start 2026-08-19 15:38:08.113 | stop 2026-08-19 15:41:03.259 | 175.1 s
```

`LastUsedTimeStart = 134316274881131799 → 2026-08-19 15:38:08.113`. The flag is the start, to the second.

**Flag 6 → `2026-08-19 15:38:08`**

#### 7 — Webcam stream duration

**Question:** *For how many seconds did the webcam stream?*

Same key, `webcam` capability. The **duration** is the FILETIME subtraction (100-ns units → ÷10⁷):

```python
base = base.replace("microphone", "webcam")     # ...ConsentStore\webcam\NonPackaged
# E:#CO-LT-0469 update package#update.exe
#   LastUsedTimeStart = 134316277486814313 -> 15:42:28.681
#   LastUsedTimeStop  = 134316278756619812 -> 15:44:35.662
(134316278756619812 - 134316277486814313) / 1e7      # = 126.98 s
```

126.98 s rounds to **127**. Precision note: the flag wants **whole seconds**; use `round()` (127), not truncation (126). The mic (Q6) lasted ~175 s and precedes the camera: **sequential** recording.

**Flag 7 → `127`**

#### 8 — Outbound traffic to the C2

**Question:** *How many decimal megabytes of outbound traffic flowed from the compromised machine to the C2?*

SRUM (`SRUDB.dat`, ESE database) accounts network usage **per process** in table `{973F5D5C-1D90-4944-BE8E-24B94231A174}` (Network Data Usage). Each row's `AppId` is an index resolved against `SruDbIdMapTable` (which maps id → process path as a blob). Each `TimeStamp` is a ~1 h bucket.

```python
from dissect.esedb import EseDB
db = EseDB(open("Windows/System32/SRU/SRUDB.dat", "rb"))

# 1) resolve the id map: id -> process path
idmap = {}
for r in db.table("SruDbIdMapTable").records():
    blob = r.get("IdBlob")
    idmap[r.get("IdIndex")] = blob.decode("utf-16-le", "ignore") if blob else ""

# 2) walk Network Usage and filter by update.exe
net = db.table("{973F5D5C-1D90-4944-BE8E-24B94231A174}")
for r in net.records():
    app = idmap.get(r.get("AppId"), "")
    if "update.exe" in app.lower():
        sent, recv = r.get("BytesSent"), r.get("BytesRecvd")
        print(r.get("AppId"), app)
        print("  sent", sent, "recv", recv, "ts", r.get("TimeStamp"))
# 436  \device\harddiskvolume5\co-lt-0469 update package\update.exe
#   sent 172064531 recv 615595 ts 2026-08-19 15:50
```

`BytesSent` is an 8-byte little-endian integer (ESE type 15, "long long"). **Watch out with `libesedb`:** its helper `get_value_data_as_integer` fails on types 15/8; if you use pyesedb, decode by blob length (`int.from_bytes(blob, "little")`) instead of the helper. With `dissect.esedb` the value comes typed already.

The question asks for **decimal megabytes** (SI, ÷10⁶), not MiB:

```text
172,064,531 / 1,000,000 = 172.064531 MB      <- flag
172,064,531 / 1,048,576 = 164.09 MiB          (binary — NOT what they ask)
```

There is only one row for `update.exe`, so no buckets to sum. The flag is `172.064531`.

**Flag 8 → `172.064531`**

#### 9 — DIOGENES ticketing dev credentials

**Question:** *What set of credentials did the spying surface for a developer working on DIOGENES tickets?*

The LNK and JumpLists (`AutomaticDestinations-ms`) show cvoss opened `Desktop\DIOGENES_26\EXT-0419.pdf`, with its source volume and timestamps — but **the PDF is not in the triage**. `Windows.edb` is: for each indexed file, Windows Search keeps a `System_Search_AutoSummary` with the first **~1000 characters** of text the **PDF IFilter** extracted at index time. That is: the index keeps the document's content even after the document is gone.

```bash
lnkparse3 "Users/cvoss/.../Recent/EXT-0419.lnk"
#   Local path: C:\Users\cvoss\Desktop\DIOGENES_26\EXT-0419.pdf
#   Drive serial / volume label: CO-... (confirms it was opened from the Desktop)
```

The trick is the column format. In Win10, `AutoSummary` is a **compressed long value** (flags `0x03`, XPRESS) and short columns use **7-bit compression** (first byte `0x10–0x17`). `libesedb` doesn't support it (`unsupported data flags: 0x03`); **`dissect.esedb` transparently decompresses both**:

```python
from dissect.esedb import EseDB
db = EseDB(open("ProgramData/Microsoft/search/Data/Applications/Windows/Windows.edb", "rb"))
for rec in db.table("SystemIndex_PropertyStore").records():
    p = rec.get("4447-System_ItemPathDisplay")
    if p and "DIOGENES_26\\" in p:
        print(p)
        print(rec.get("4625-System_Search_AutoSummary"))

# C:\Users\cvoss\Desktop\DIOGENES_26\EXT-0419.pdf
#   PERSONNEL & ACCESS FILE — EXTERNAL CONTRACTOR · DIOGENES Ticketing Support
#   Name: Tom Ainsworth   Title: Software Developer, DIOGENES Ticketing Support
#   Contractor ID: EXT-0419   Internal server: srv-diogenes-tickets-01.internal
#   Username: tainsworth   Password: D10g3n3s_T1ck3ts#2026
#   Access scope: EXT-3 (ticketing host only)   Repository: parse_diogenese_tickets
```

(The column ids `4447`/`4625` are the property-store IDs of `System_ItemPathDisplay` and `System_Search_AutoSummary`; they can vary across versions, so in practice dump all columns of one row and locate path/summary by content.)

The same index reveals **the rest of the plot** — this is why Windows.edb is so valuable: it's a *text dump of everything that was on disk*:

- `IT_SUPPORT.pdf` → onboarding sheet for **Elias Venn** (EXT-0431, laptop CO-LT-0431, *"delivery address: Unit 14, Silvertown East Yard"*): the paper ghost had legit access credentials.
- `Driver Update Package.pdf` → the decoy instructions that pushed cvoss to run `update.exe`.
- `DIOGENES_Contractor_Assignments.csv` / `IT_Asset_Inventory.csv` → the list of contractors and assets NAPOLEON can now hunt with the stolen credentials.

**Flag 9 → `tainsworth:D10g3n3s_T1ck3ts#2026`**

### Answers / flags

| # | Question | Answer | Source |
|---|----------|--------|--------|
| 1 | First USB connection | `2026-08-19 15:35:50` | SYSTEM · `Properties\{83da6326…}\0065` |
| 2 | USB serial number | `RS200000000627E4` | SYSTEM · `Enum\USB` / `Enum\USBSTOR\…&0` |
| 3 | Full payload path | `E:\CO-LT-0469 update package\update.exe` | UserAssist · ConsentStore · SRUM · Windows.edb |
| 4 | Package execution timestamp | `2026-08-19 15:36:25` | NTUSER · UserAssist |
| 5 | USB asset name | `CO-USB-0091` | SOFTWARE · WPD FriendlyName / VolumeInfoCache |
| 6 | Microphone capture start | `2026-08-19 15:38:08` | ConsentStore\microphone · LastUsedTimeStart |
| 7 | Webcam stream seconds | `127` | ConsentStore\webcam · Stop−Start = 126.98 s |
| 8 | Decimal MB outbound to the C2 | `172.064531` | SRUDB.dat · `{973F5D5C…}` AppId 436 |
| 9 | DIOGENES ticketing dev credentials | `tainsworth:D10g3n3s_T1ck3ts#2026` | Windows.edb · AutoSummary of EXT-0419.pdf |

### IOCs

| Type | Value | Notes |
|---|---|---|
| File (payload) | `E:\CO-LT-0469 update package\update.exe` | 210,432 B; only real file on the USB |
| USB device | Lexar, `VID_21C4&PID_0CD1`, S/N `RS200000000627E4` | HardwareID `USB\VID_21C4&PID_0CD1&REV_0200` |
| ContainerID | `{c12e83c9-7a97-53d0-ac60-72526287e69e}` | Groups `E:` (data) + `F:` (VTOYEFI/Ventoy) |
| Volume | Label `CO-USB-0091`, mounted `E:`, `\Device\HarddiskVolume5` | `F:` = `VTOYEFI` (Ventoy noise) |
| Network (exfil) | 172,064,531 B out / 615,595 B in by `update.exe` | SRUM bucket `~15:50` UTC |
| Stolen credential | `tainsworth : D10g3n3s_T1ck3ts#2026` | Host `srv-diogenes-tickets-01.internal`, scope EXT-3 |
| Actor/alias | Elias Venn (EXT-0431), Tom Ainsworth (EXT-0419) | Fake contractor + victim whose access is stolen |
| Decoy directory | `E:\...\Drivers\{Audio,Camera,Chipset,BadgNFC}`, `Utils`, `Recovery`, `Manifest` | Empty prop folders |

> **Scope note.** There is no C2 IP/domain in the triage: SRUM accounts bytes per process but **does not keep the destination**. Getting the IP would need a PCAP, `dnscache`, or the binary itself — none present here. The exfiltrated amount is solid, though.

### MITRE ATT&CK mapping

| Tactic | Technique | Evidence in this case |
|---|---|---|
| Initial Access | **T1091** Replication Through Removable Media / **T1200** Hardware Additions | USB dropper physically left on the desk |
| Initial Access / Execution | **T1204.002** User Execution: Malicious File | cvoss runs `update.exe` (UserAssist, 1 run) |
| Collection | **T1123** Audio Capture | ConsentStore\microphone, ~175 s |
| Collection | **T1125** Video Capture | ConsentStore\webcam, 127 s |
| Collection | **T1119 / T1005** Automated / Local Data Collection | contractor and asset CSVs indexed |
| Credential Access | **T1552.001** Unsecured Credentials: Credentials In Files | plaintext credential inside EXT-0419.pdf |
| Exfiltration | **T1041** Exfiltration Over C2 Channel | 172 MB outbound via `update.exe` (SRUM) |
| Defense Evasion | **T1070 / props** | empty folders to fake a support kit; USB removed in <16 min |

### Detection and remediation

**Detection (what would have caught it earlier):**

- **USB device control.** A Device Control / GPO policy (`RemovableStorageDevices` deny, or EDR device control) would have blocked mounting a non-inventoried USB. Alert on new `USBSTOR` subkeys / `Microsoft-Windows-DriverFrameworks-UserMode/2003,2100,2102` events.
- **Anomalous mic/camera access.** Monitor changes to `ConsentStore\{microphone,webcam}\NonPackaged` for **non-interactive or non-allowlisted** processes (Teams, Zoom, system camera). A just-executed binary from `E:\` turning on mic+cam in sequence is high-value signal.
- **Execution from removable media.** UserAssist/Prefetch with a path on removable drive; SIEM rule: `NewProcess` whose `Image` is on `\Device\HarddiskVolume` mapped to USB.
- **Exfiltration by volume.** An unknown process with `BytesSent` of hundreds of MB in one SRUM bucket is anomalous; correlate with firewall/NetFlow for the destination.
- **DLP on documents.** Plaintext credentials inside HR/contractor PDFs: scan repos and shares with secret-detection rules.

**Remediation / response:**

1. **Rotate now** `tainsworth : D10g3n3s_T1ck3ts#2026` and any reuse; audit access to `srv-diogenes-tickets-01.internal` and the `parse_diogenese_tickets` repo since 2026-08-19.
2. **Contain** CO-LT-0469: isolate, capture full disk+memory (only triage here), look for `update.exe` persistence (even though UserAssist marks 1 run and the USB left, verify Run keys, tasks, services).
3. **Hunt the "paper ghost":** revoke Elias Venn's onboarding (EXT-0431), the delivery to *Unit 14, Silvertown East Yard*, and every contractor in `DIOGENES_Contractor_Assignments.csv` not verified by a human.
4. **Harden:** default-deny Device Control, camera/mic with indicator and allowlist, HR PDF encryption, and ban plaintext credentials in documents.

### Lessons

- **Without `setupapi.dev.log`**, the SYSTEM hive `{83da6326…}\0064–0067` properties give install / first-install / last-arrival / last-removal of the USB. The `ContainerID` proves both partitions are a single device.
- The **payload path appears in 4 independent artifacts** (UserAssist, ConsentStore, SRUM, Windows.edb): free cross-corroboration, each with its own path format.
- **ConsentStore** is the star artifact for desktop spyware: which binary used mic/camera and when, with no event logs. `LastUsedTimeStop − LastUsedTimeStart` = exact duration.
- **SRUM** quantifies exfiltration per process; decode `BytesSent` by blob length, not with helpers that fail on types 15/8. It asks for **decimal MB** (÷10⁶), not MiB.
- **Windows.edb as a file substitute**: when documents are missing from the triage, the `AutoSummary` usually holds enough text to answer. Use `dissect.esedb` (decompresses XPRESS/7-bit); `libesedb` chokes on `flags 0x03`.
- **Mind the timezone**: registry/SRUM/ConsentStore in UTC; KAPE's ConsoleLog in local (−7 h). Answer in UTC.
- **Step 0 of any triage:** apply transaction logs before reading hives.

### Serie · The Reichenbach Directive

| # | Sherlock | Link |
|---|----------|------|
| S01 | Silent Dividend | [../2026-09-15-holmes2026-s01-silent-dividend/](../2026-09-15-holmes2026-s01-silent-dividend/) |
| S02 | Bottle Out | [../2026-09-16-holmes2026-s02-bottle-out/](../2026-09-16-holmes2026-s02-bottle-out/) |
| S03 | Whisper Chain | [../2026-09-17-holmes2026-s03-whisper-chain/](../2026-09-17-holmes2026-s03-whisper-chain/) |
| **S04** | **Paper Ghost** ← you are here | [../2026-09-18-holmes2026-s04-paper-ghost/](../2026-09-18-holmes2026-s04-paper-ghost/) |
| S05 | Poisoned Branch | [../2026-09-19-holmes2026-s05-poisoned-branch/](../2026-09-19-holmes2026-s05-poisoned-branch/) |
| S06 | Silent Passenger | [../2026-09-20-holmes2026-s06-silent-passenger/](../2026-09-20-holmes2026-s06-silent-passenger/) |
| S07 | Iron Feather | [../2026-09-21-holmes2026-s07-iron-feather/](../2026-09-21-holmes2026-s07-iron-feather/) |
| S08 | Borrowed Name | [../2026-09-22-holmes2026-s08-borrowed-name/](../2026-09-22-holmes2026-s08-borrowed-name/) |
| S09 | Last Light | [../2026-09-23-holmes2026-s09-last-light/](../2026-09-23-holmes2026-s09-last-light/) |
