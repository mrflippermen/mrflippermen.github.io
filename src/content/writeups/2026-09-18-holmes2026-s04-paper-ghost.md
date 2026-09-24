---
title: "Holmes CTF 2026 — S04 Paper Ghost"
date: 2026-09-18
description: "Triage KAPE de Windows: reconstruir un ataque de USB dropper (spyware) con registro, SRUM y Windows.edb."
excerpt: "Un pendrive falso de actualización enciende mic y webcam y exfiltra 172 MB; lo reconstruimos desde hives, ConsentStore, SRUM e índice de Windows Search."
platform: "HTB"
difficulty: "Easy"
image: "/images/ctf.svg"
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
> **Navegación:** [🇪🇸 Español](#es) · [🇬🇧 English](#en)

<a id="es"></a>
## 🇪🇸 Español

### Escenario

Un supuesto contratista de IT, **Elias Venn**, deja un pendrive en la mesa de **Clara Voss** (usuario `cvoss`) del host **CO-LT-0469** (Windows 10 19045, VM). Ella lo abre como si fuera una actualización de drivers y el "instalador" `update.exe` enciende el micrófono y la webcam y vuelca **172 MB** a un C2. No hay disco completo: solo un **triage de KAPE** de 74 ficheros (hives de registro, LNK/JumpLists, SRUM y el índice de Windows Search). Hay que reconstruir el incidente entero a partir de esos artefactos.

- **Host:** CO-LT-0469 (Win10 19045, VM) · **Usuario:** `cvoss`
- **Zona horaria del host:** Pacific (UTC−7). **Todas las respuestas se dan en UTC.**
- **Dificultad:** easy · 9 flags.

### Artefacto y herramientas

El ZIP es un triage de KAPE (targets `RegistryHives, LNKFilesAndJumpLists, SRUM`; `ConsoleLog.txt` confirma host y targets). Lo relevante:

- `Windows\System32\config\` → SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT + transaction logs. Dispositivos USB, BAM, zona horaria, WPD.
- `Users\cvoss\NTUSER.DAT` · `UsrClass.dat` → UserAssist, RecentDocs, ConsentStore (mic/cam), shellbags.
- `Users\cvoss\…\Recent\*.lnk` + JumpLists → apuntan a `Desktop\DIOGENES_26\` (Schedule.pdf, EXT-0419.pdf, IT_SUPPORT.pdf, Driver Update Package.pdf). Los PDFs **no** están en el triage.
- `Windows\System32\SRU\SRUDB.dat` → SRUM: uso de red y de aplicaciones por proceso, en buckets de ~1 h.
- `ProgramData\Microsoft\search\…\Windows.edb` → índice de Windows Search (16 MB): rutas y resúmenes de texto de todo lo indexado, incluido `E:` y los PDFs.

**Herramientas:** `regripper` (plugins `usbstor`, `usbdevices`, `mountdev`, `timezone`, `volinfocache`, `userassist`, `bam`), `python-registry` para claves sin plugin (WPD, ConsentStore, propiedades 0064–0067), `libesedb-python`/`pyesedb` para SRUM, y **`dissect.esedb`** para Windows.edb (descomprime long values XPRESS y columnas 7-bit que `libesedb` no soporta).

> **Trampa de zona horaria.** `TimeZoneInformation` = Pacific Standard Time, `ActiveTimeBias` 420 → local = UTC−7. Todo el registro, SRUM y ConsentStore es FILETIME en UTC; el `ConsoleLog.txt` de KAPE va en local (01:21) mientras el nombre del fichero va en UTC (08:21). Las flags se aceptan en UTC.

### Metodología (paso a paso)

**Cronología reconstruida (UTC, 2026-08-19):**

- `15:35:50` — Se conecta el Lexar `RS200000000627E4`, etiqueta `CO-USB-0091`, montado en `E:` (+ partición Ventoy `F:` VTOYEFI).
- `15:36:25` — cvoss ejecuta `E:\CO-LT-0469 update package\update.exe` (UserAssist, 1 ejecución).
- `15:38:08 → 15:41:03` — Captura de micrófono, 175 s (ConsentStore\microphone).
- `15:42:28 → 15:44:35` — Stream de webcam, 127 s (ConsentStore\webcam).
- `15:50` (bucket SRUM) — 172 064 531 bytes enviados / 615 595 recibidos por `update.exe`.
- `15:51:06` — Última llegada y retirada del USB (propiedades 0066/0067).
- `2026-08-20 08:21` — Adquisición con KAPE.

**1 — Primera conexión del USB.** Sin `setupapi.dev.log`, la fuente son las propiedades del dispositivo en SYSTEM. Bajo cada instancia de `Enum\USB` y `Enum\USBSTOR` hay `Properties\{83da6326-97a6-4088-9453-a1923f573b29}` con FILETIMEs: `0064` Install, `0065` First Install (primera inserción), `0066` Last Arrival, `0067` Last Removal.

```
regripper -r Windows/System32/config/SYSTEM -p usbstor
  Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00
    S/N: RS200000000627E4&0
    First InstallDate : 2026-08-19 15:35:50Z
    Last Arrival      : 2026-08-19 15:51:06Z
    Last Removal      : 2026-08-19 15:51:06Z
```

`MountedDevices` y `VolumeInfoCache` tienen la misma LastWrite: el volumen se montó como `E:` en ese instante.

**2 — Serial del USB.** Solo hay un dispositivo de almacenamiento USB en todo el hive. El serial que reporta el propio dispositivo es el nombre de la instancia bajo el VID/PID; en USBSTOR aparece con el sufijo `&0`.

```
USB\VID_21C4&PID_0CD1\RS200000000627E4          ← serial del dispositivo
USBSTOR\Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00\RS200000000627E4&0
```

**3 — Ruta completa del payload.** Cuatro artefactos independientes coinciden: UserAssist (ROT13 ya decodificado), ConsentStore (con `#` en vez de `\`), SRUM (ruta de dispositivo `HarddiskVolume5` = el pendrive) y Windows.edb.

```
UserAssist   : E:\CO-LT-0469 update package\update.exe (1)
ConsentStore : …\microphone\NonPackaged\E:#CO-LT-0469 update package#update.exe
SRUM IdMap   : 436  \device\harddiskvolume5\co-lt-0469 update package\update.exe
Windows.edb  : E:\CO-LT-0469 update package\update.exe   Size=210432
```

El resto del pendrive (`Drivers\Audio|Camera|Chipset|BadgNFC`, `Utils`, `Recovery`, `Manifest`) son carpetas vacías de atrezzo.

**4 — Ejecución del paquete.** UserAssist (`HKCU\…\Explorer\UserAssist\{CEBFF5CD…}\Count`) guarda contador y última ejecución. BAM no lo registra porque solo ve volúmenes locales, y el exe estaba en el USB.

```
regripper -r Users/cvoss/NTUSER.DAT -p userassist | grep -B1 update.exe
2026-08-19 15:36:25Z
  E:\CO-LT-0469 update package\update.exe (1)
```

35 s después de enchufar el USB.

**5 — Asset name del USB.** El nombre que ve el usuario al conectar es la etiqueta de volumen, cacheada en dos sitios del hive SOFTWARE:

```
SOFTWARE\...\Windows Portable Devices\Devices\...  FriendlyName = CO-USB-0091
SOFTWARE\...\Windows Search\VolumeInfoCache\E:      VolumeLabel  = CO-USB-0091
SOFTWARE\...\Windows Search\VolumeInfoCache\F:      VolumeLabel  = VTOYEFI   ← Ventoy, ruido
```

**6 — Inicio de captura de micrófono.** Desde Win10 1903, cada acceso a micrófono/cámara/ubicación deja `LastUsedTimeStart`/`LastUsedTimeStop` (FILETIME) en `CapabilityAccessManager\ConsentStore\<capacidad>\NonPackaged\<ruta con #>`.

```
ConsentStore\microphone\NonPackaged\E:#CO-LT-0469 update package#update.exe
  LastUsedTimeStart = 134316274881131799 → 2026-08-19 15:38:08.113
  LastUsedTimeStop  = 134316276632589248 → 2026-08-19 15:41:03.259   (175,1 s)
```

**7 — Duración del stream de webcam.** Misma clave, capacidad `webcam`. La diferencia de FILETIMEs (unidades de 100 ns) da el tiempo exacto.

```
ConsentStore\webcam\NonPackaged\E:#CO-LT-0469 update package#update.exe
  LastUsedTimeStart = 134316277486814313 → 15:42:28.681
  LastUsedTimeStop  = 134316278756619812 → 15:44:35.662
  (134316278756619812 − 134316277486814313) / 1e7 = 126.98 s → 127
```

**8 — Tráfico saliente hacia el C2.** SRUM (`SRUDB.dat`, ESE) guarda el uso de red por proceso en la tabla `{973F5D5C-1D90-4944-BE8E-24B94231A174}`; `AppId` se resuelve contra `SruDbIdMapTable`. `BytesSent` es un entero de 8 bytes little-endian.

```
SruDbIdMapTable: 436 → \device\harddiskvolume5\co-lt-0469 update package\update.exe
{973F5D5C-…}: AutoIncId=228 TimeStamp=2026-08-19 15:50 AppId=436 UserId=374
              BytesSent=172064531  BytesRecvd=615595
172 064 531 / 1 000 000 = 172.064531 MB
```

**9 — Credenciales del dev de tickets DIOGENES.** Los LNK/JumpLists dicen que cvoss abrió `Desktop\DIOGENES_26\EXT-0419.pdf`, pero el PDF no viene en el triage. Sí viene `Windows.edb`: el índice guarda para cada fichero un `System_Search_AutoSummary` con los primeros ~1000 caracteres extraídos por el IFilter de PDF. En Win10 esa columna va como long value comprimido (flags 0x03) que `libesedb` no soporta; `dissect.esedb` lo descomprime.

```python
from dissect.esedb import EseDB
db = EseDB(open("Windows.edb","rb"))
for rec in db.table("SystemIndex_PropertyStore").records():
    p = rec.get("4447-System_ItemPathDisplay")
    if p and "DIOGENES_26\\" in p:
        print(p, rec.get("4625-System_Search_AutoSummary"))

# C:\Users\cvoss\Desktop\DIOGENES_26\EXT-0419.pdf
#   Name: Tom Ainsworth   Title: Software Developer, DIOGENES Ticketing Support
#   Username: tainsworth   Password: D10g3n3s_T1ck3ts#2026
```

El mismo índice revela el resto de la trama: `IT_SUPPORT.pdf` (onboarding de Elias Venn, EXT-0431), `Driver Update Package.pdf` (instrucciones del señuelo) y los CSV de contratistas que NAPOLEON puede cazar ahora.

### Respuestas / flags

| # | Pregunta | Respuesta |
|---|----------|-----------|
| 1 | Primera conexión del USB (When did Clara Voss first connect the device?) | `2026-08-19 15:35:50` |
| 2 | Serial del USB | `RS200000000627E4` |
| 3 | Ruta completa del payload | `E:\CO-LT-0469 update package\update.exe` |
| 4 | Timestamp exacto de ejecución del paquete | `2026-08-19 15:36:25` |
| 5 | Asset name del USB | `CO-USB-0091` |
| 6 | Inicio de captura de micrófono | `2026-08-19 15:38:08` |
| 7 | Segundos de stream de webcam | `127` |
| 8 | MB decimales salientes al C2 | `172.064531` |
| 9 | Credenciales del dev de tickets DIOGENES | `tainsworth:D10g3n3s_T1ck3ts#2026` |

### Lecciones

- **Sin `setupapi.dev.log`**, las propiedades `{83da6326…}\0064–0067` del hive SYSTEM dan install / first-install / last-arrival / last-removal del USB.
- La **ruta del payload aparece en 4 artefactos independientes** (UserAssist, ConsentStore, SRUM, Windows.edb): corroboración cruzada gratis.
- **ConsentStore** es el artefacto estrella para spyware de escritorio: qué binario usó mic/cámara y cuándo, sin logs de eventos.
- **SRUM** cuantifica la exfiltración por proceso; decodificar `BytesSent` por longitud del blob, no con helpers que fallan con tipos 15/8.
- **Windows.edb como sustituto del fichero**: cuando faltan documentos en el triage, el AutoSummary suele tener texto suficiente para responder. Usar `dissect.esedb` (descomprime XPRESS/7-bit).
- **Cuidado con la zona horaria**: registro/SRUM/ConsentStore en UTC; el ConsoleLog de KAPE en local. Responder en UTC.

<a id="en"></a>
## 🇬🇧 English

### Escenario

A fake IT contractor, **Elias Venn**, leaves a USB stick on the desk of **Clara Voss** (user `cvoss`) on host **CO-LT-0469** (Windows 10 19045, VM). She opens it as if it were a driver update and the "installer" `update.exe` turns on the microphone and webcam and dumps **172 MB** to a C2. There is no full disk image: only a **74-file KAPE triage** (registry hives, LNK/JumpLists, SRUM and the Windows Search index). The whole incident must be reconstructed from those artifacts.

- **Host:** CO-LT-0469 (Win10 19045, VM) · **User:** `cvoss`
- **Host timezone:** Pacific (UTC−7). **All answers are given in UTC.**
- **Difficulty:** easy · 9 flags.

### Artefacto y herramientas

The ZIP is a KAPE triage (targets `RegistryHives, LNKFilesAndJumpLists, SRUM`; `ConsoleLog.txt` confirms host and targets). What matters:

- `Windows\System32\config\` → SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT + transaction logs. USB devices, BAM, timezone, WPD.
- `Users\cvoss\NTUSER.DAT` · `UsrClass.dat` → UserAssist, RecentDocs, ConsentStore (mic/cam), shellbags.
- `Users\cvoss\…\Recent\*.lnk` + JumpLists → point at `Desktop\DIOGENES_26\` (Schedule.pdf, EXT-0419.pdf, IT_SUPPORT.pdf, Driver Update Package.pdf). The PDFs are **not** in the triage.
- `Windows\System32\SRU\SRUDB.dat` → SRUM: per-process network and application usage in ~1 h buckets.
- `ProgramData\Microsoft\search\…\Windows.edb` → Windows Search index (16 MB): paths and text summaries of everything indexed, including `E:` and the PDFs.

**Tools:** `regripper` (plugins `usbstor`, `usbdevices`, `mountdev`, `timezone`, `volinfocache`, `userassist`, `bam`), `python-registry` for keys with no plugin (WPD, ConsentStore, properties 0064–0067), `libesedb-python`/`pyesedb` for SRUM, and **`dissect.esedb`** for Windows.edb (decompresses XPRESS long values and 7-bit columns that `libesedb` cannot).

> **Timezone trap.** `TimeZoneInformation` = Pacific Standard Time, `ActiveTimeBias` 420 → local = UTC−7. All registry, SRUM and ConsentStore data is FILETIME in UTC; KAPE's `ConsoleLog.txt` is in local time (01:21) while the file name is UTC (08:21). Flags are accepted in UTC.

### Metodología (paso a paso)

**Reconstructed timeline (UTC, 2026-08-19):**

- `15:35:50` — Lexar `RS200000000627E4` connected, label `CO-USB-0091`, mounted as `E:` (+ Ventoy partition `F:` VTOYEFI).
- `15:36:25` — cvoss runs `E:\CO-LT-0469 update package\update.exe` (UserAssist, 1 run).
- `15:38:08 → 15:41:03` — Microphone capture, 175 s (ConsentStore\microphone).
- `15:42:28 → 15:44:35` — Webcam stream, 127 s (ConsentStore\webcam).
- `15:50` (SRUM bucket) — 172,064,531 bytes sent / 615,595 received by `update.exe`.
- `15:51:06` — Last arrival and removal of the USB (properties 0066/0067).
- `2026-08-20 08:21` — KAPE acquisition.

**1 — First USB connection.** With no `setupapi.dev.log`, the source is the device properties in SYSTEM. Under each `Enum\USB` and `Enum\USBSTOR` instance there is `Properties\{83da6326-97a6-4088-9453-a1923f573b29}` with FILETIMEs: `0064` Install, `0065` First Install (first insertion), `0066` Last Arrival, `0067` Last Removal.

```
regripper -r Windows/System32/config/SYSTEM -p usbstor
  Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00
    S/N: RS200000000627E4&0
    First InstallDate : 2026-08-19 15:35:50Z
    Last Arrival      : 2026-08-19 15:51:06Z
    Last Removal      : 2026-08-19 15:51:06Z
```

`MountedDevices` and `VolumeInfoCache` share the same LastWrite: the volume mounted as `E:` at that instant.

**2 — USB serial.** There is only one USB storage device in the whole hive. The serial the device reports is the instance name under VID/PID; in USBSTOR it carries the `&0` suffix.

```
USB\VID_21C4&PID_0CD1\RS200000000627E4          ← device serial
USBSTOR\Disk&Ven_Lexar&Prod_USB_Flash_Drive&Rev_2.00\RS200000000627E4&0
```

**3 — Full payload path.** Four independent artifacts agree: UserAssist (ROT13 already decoded), ConsentStore (with `#` instead of `\`), SRUM (device path `HarddiskVolume5` = the stick) and Windows.edb.

```
UserAssist   : E:\CO-LT-0469 update package\update.exe (1)
ConsentStore : …\microphone\NonPackaged\E:#CO-LT-0469 update package#update.exe
SRUM IdMap   : 436  \device\harddiskvolume5\co-lt-0469 update package\update.exe
Windows.edb  : E:\CO-LT-0469 update package\update.exe   Size=210432
```

The rest of the stick (`Drivers\Audio|Camera|Chipset|BadgNFC`, `Utils`, `Recovery`, `Manifest`) are empty prop folders.

**4 — Package execution.** UserAssist (`HKCU\…\Explorer\UserAssist\{CEBFF5CD…}\Count`) stores run count and last-run time. BAM does not log it because it only sees local volumes, and the exe was on the USB.

```
regripper -r Users/cvoss/NTUSER.DAT -p userassist | grep -B1 update.exe
2026-08-19 15:36:25Z
  E:\CO-LT-0469 update package\update.exe (1)
```

35 s after plugging in the USB.

**5 — USB asset name.** The name the user sees on connect is the volume label, cached in two places in the SOFTWARE hive:

```
SOFTWARE\...\Windows Portable Devices\Devices\...  FriendlyName = CO-USB-0091
SOFTWARE\...\Windows Search\VolumeInfoCache\E:      VolumeLabel  = CO-USB-0091
SOFTWARE\...\Windows Search\VolumeInfoCache\F:      VolumeLabel  = VTOYEFI   ← Ventoy, noise
```

**6 — Microphone capture start.** Since Win10 1903, each microphone/camera/location access leaves `LastUsedTimeStart`/`LastUsedTimeStop` (FILETIME) under `CapabilityAccessManager\ConsentStore\<capability>\NonPackaged\<path with #>`.

```
ConsentStore\microphone\NonPackaged\E:#CO-LT-0469 update package#update.exe
  LastUsedTimeStart = 134316274881131799 → 2026-08-19 15:38:08.113
  LastUsedTimeStop  = 134316276632589248 → 2026-08-19 15:41:03.259   (175.1 s)
```

**7 — Webcam stream duration.** Same key, `webcam` capability. The FILETIME difference (100 ns units) gives the exact time.

```
ConsentStore\webcam\NonPackaged\E:#CO-LT-0469 update package#update.exe
  LastUsedTimeStart = 134316277486814313 → 15:42:28.681
  LastUsedTimeStop  = 134316278756619812 → 15:44:35.662
  (134316278756619812 − 134316277486814313) / 1e7 = 126.98 s → 127
```

**8 — Outbound traffic to the C2.** SRUM (`SRUDB.dat`, ESE) stores per-process network usage in table `{973F5D5C-1D90-4944-BE8E-24B94231A174}`; `AppId` resolves against `SruDbIdMapTable`. `BytesSent` is an 8-byte little-endian integer.

```
SruDbIdMapTable: 436 → \device\harddiskvolume5\co-lt-0469 update package\update.exe
{973F5D5C-…}: AutoIncId=228 TimeStamp=2026-08-19 15:50 AppId=436 UserId=374
              BytesSent=172064531  BytesRecvd=615595
172,064,531 / 1,000,000 = 172.064531 MB
```

**9 — DIOGENES ticketing dev credentials.** The LNK/JumpLists show cvoss opened `Desktop\DIOGENES_26\EXT-0419.pdf`, but the PDF is not in the triage. `Windows.edb` is: for each file the index keeps a `System_Search_AutoSummary` with the first ~1000 characters extracted by the PDF IFilter. In Win10 that column is a compressed long value (flags 0x03) that `libesedb` cannot handle; `dissect.esedb` decompresses it.

```python
from dissect.esedb import EseDB
db = EseDB(open("Windows.edb","rb"))
for rec in db.table("SystemIndex_PropertyStore").records():
    p = rec.get("4447-System_ItemPathDisplay")
    if p and "DIOGENES_26\\" in p:
        print(p, rec.get("4625-System_Search_AutoSummary"))

# C:\Users\cvoss\Desktop\DIOGENES_26\EXT-0419.pdf
#   Name: Tom Ainsworth   Title: Software Developer, DIOGENES Ticketing Support
#   Username: tainsworth   Password: D10g3n3s_T1ck3ts#2026
```

The same index reveals the rest of the plot: `IT_SUPPORT.pdf` (Elias Venn's onboarding, EXT-0431), `Driver Update Package.pdf` (the decoy instructions) and the contractor CSVs NAPOLEON can now hunt.

### Respuestas / flags

| # | Pregunta | Respuesta |
|---|----------|-----------|
| 1 | First USB connection (When did Clara Voss first connect the device?) | `2026-08-19 15:35:50` |
| 2 | USB serial number | `RS200000000627E4` |
| 3 | Full payload path | `E:\CO-LT-0469 update package\update.exe` |
| 4 | Exact package execution timestamp | `2026-08-19 15:36:25` |
| 5 | USB asset name | `CO-USB-0091` |
| 6 | Microphone capture start | `2026-08-19 15:38:08` |
| 7 | Webcam stream seconds | `127` |
| 8 | Decimal MB outbound to the C2 | `172.064531` |
| 9 | DIOGENES ticketing dev credentials | `tainsworth:D10g3n3s_T1ck3ts#2026` |

### Lecciones

- **Without `setupapi.dev.log`**, the SYSTEM hive `{83da6326…}\0064–0067` properties give install / first-install / last-arrival / last-removal of the USB.
- The **payload path appears in 4 independent artifacts** (UserAssist, ConsentStore, SRUM, Windows.edb): free cross-corroboration.
- **ConsentStore** is the star artifact for desktop spyware: which binary used mic/camera and when, with no event logs.
- **SRUM** quantifies exfiltration per process; decode `BytesSent` by blob length, not with helpers that fail on types 15/8.
- **Windows.edb as a file substitute**: when documents are missing from the triage, the AutoSummary usually holds enough text to answer. Use `dissect.esedb` (decompresses XPRESS/7-bit).
- **Mind the timezone**: registry/SRUM/ConsentStore in UTC; KAPE's ConsoleLog in local. Answer in UTC.
