---
title: "Holmes CTF 2026 — S02 Bottle Out"
date: 2026-09-16
description: "Forense de imagen E01 (host BLUEBOX) con Velociraptor headless: recuperación de un log OpenVPN, registro de Tactical RMM y la cuenta Gajim/XMPP del carcelero de Watson."
excerpt: "DFIR sobre un E01: Velociraptor por WinRM, recuperación por MFT del chat borrado, Tactical RMM en el registro y la cuenta XMPP en SQLite."
platform: "HTB"
difficulty: "Easy"
image: "/images/blog/holmes-s02.svg"
tags:
  - "DFIR"
  - "Velociraptor"
  - "E01"
  - "Windows"
  - "Registry"
  - "Holmes CTF 2026"
---

> **Reto:** Holmes CTF 2026 — Sherlock 02 "Bottle Out" · Forense de imagen E01 con Velociraptor headless. Parte del arco *The Reichenbach Directive* (capítulos 03–05: *The Ledger*, *Silvertown*, *The Voices Behind the Names*).
>
> **Navegación:** [🇪🇸 Español](#es) · [🇬🇧 English](#en) · Estado: **9/10** flags · Q10 ⏳ pendiente (negativo probado)

<a id="es"></a>
## 🇪🇸 Español

### Escenario

Los pagos seguían un patrón que Watson había intuido pero nunca probó: cada víctima confiaba en el mismo proceso de *settlement* pulido antes de que el miedo se cerrara sobre ella. Un superviviente entregó el siguiente lead — el ordenador usado durante un pago — y Lestrade lo incautó antes de que nadie pudiera alterar lo que quedaba. El rastro apuntó al este, a los depósitos de contenedores de **Silvertown**, donde encontraron a Watson vivo. Su carcelero huyó minutos antes de que llegara la policía y dejó atrás un **portátil encendido**.

La máquina muestra un intento apresurado de borrar la actividad reciente: sobrevive un único cliente de comunicaciones, pero su cuenta, su servidor y su propósito siguen siendo desconocidos. La evidencia se sella y se entrega como una **imagen de disco E01** del host **BLUEBOX** (usuario sospechoso `spur`). El objetivo es reconstruir lo que sobrevivió al intento de wipe y determinar cómo el portátil conectaba a su operador anónimo con el resto de la operación de *The Reichenbach Directive*.

Dificultad: **Easy**. Pero el "easy" engaña: la clave no es *encontrar* los datos, es **poder abrir la evidencia** sin herramientas comerciales y **entender por qué unos artefactos borrados se recuperan y otros no**.

### El problema de partida: un E01 que nada abre

La evidencia no es un `.raw` ni un `.vmdk` montable a la ligera. Es un **EnCase Evidence Format (E01)**: un contenedor comprimido y con checksums (Adler-32 por bloque + MD5/SHA-1 global) que envuelve la imagen NTFS del sospechoso.

- **7-Zip 24.09** en la VM **no abre E01** (no lleva el codec `ewf`).
- No hay **Arsenal Image Mounter**, ni **FTK Imager CLI**, ni licencia de EnCase.
- Sólo disponemos de acceso **WinRM (5985)** / RDP (3389) a la VM `BLUEBOX` con `Administrator : Holmes2026!`, y un binario suelto: `velociraptor.exe` instalado por Scoop.

La solución headless es **Velociraptor**: su motor VQL trae un *accessor* `ewf` nativo que descomprime el E01 al vuelo, y encima de él un `raw_ntfs` que interpreta el sistema de ficheros. Se opera **sin GUI**, mandando VQL por WinRM con `nxc`.

```bash
# Plantilla de ejecución: VQL por WinRM (nxc), filtrando el prefijo del host
nxc winrm 10.129.1.203 -u Administrator -p 'Holmes2026!' \
  -X "& 'C:\ProgramData\scoop\apps\velociraptor\current\velociraptor.exe' query --format=json 'SELECT ... FROM ...'"
# Regla de oro: comillas SIMPLES dentro del VQL. PowerShell se come las dobles
# al pasar los argumentos a un exe nativo, y el query llega roto.
```

Un pequeño helper local (`/tmp/vql_run.sh "VQL"`) envuelve ese patrón y recorta el ruido de `nxc`; `/tmp/vql_read.sh "/ruta"` lee un fichero de dentro de la imagen. Son efímeros (viven en `/tmp`), se recrean si se pierden. En los ejemplos de abajo `<E01>` = `C:/Users/Administrator/Desktop/DESKTOP-QMTIG5I.E01`.

### Artefacto y herramientas

- **Imagen E01** `DESKTOP-QMTIG5I.E01` en `C:/Users/Administrator/Desktop/` de la VM `BLUEBOX`.
- **Velociraptor** (`C:\ProgramData\scoop\apps\velociraptor\current\velociraptor.exe`) por WinRM/`nxc`, sin GUI.
- **`parse_mft` + `copy(accessor='mft')`** para recuperar ficheros borrados por número de entrada MFT.
- **`impacket-secretsdump`** en local sobre los hives SAM/SYSTEM/SECURITY descargados.
- **`regripper`** / `sqlite3` en local como alternativa de análisis offline del registro y de las bases de Gajim.
- Lectura de **SQLite** (Gajim portable 2.6.0: `Settings.sqlite`, `Logs.db`, bases OMEMO/OpenPGP).

#### El patrón que hace todo posible: pathspec anidado sobre `ewf`

Todo el reto se reduce a encadenar *accessors* con un `pathspec`. El `ewf` descomprime; lo que va encima interpreta:

```bash
# 1) Sistema de ficheros de la imagen (NTFS dentro del EWF)
SELECT Name, Size, Mtime FROM glob(
  globs='/Users/spur/**',
  accessor='raw_ntfs',
  root=pathspec(DelegateAccessor='ewf', DelegatePath='<E01>'))

# 2) Registro OFFLINE (raw_reg sobre raw_ntfs sobre ewf — triple anidamiento)
SELECT * FROM glob(
  globs='/TacticalRMM/*',
  accessor='raw_reg',
  root=pathspec(DelegateAccessor='raw_ntfs',
    DelegatePath=pathspec(Path='/Windows/System32/config/SOFTWARE',
                          DelegateAccessor='ewf', DelegatePath='<E01>')))

# 3) MFT completa (para localizar entradas de ficheros borrados)
SELECT EntryNumber, InUse, FileName, FileSize FROM parse_mft(
  filename=pathspec(Path='/$MFT', DelegateAccessor='ewf', DelegatePath='<E01>'),
  accessor='raw_ntfs')
WHERE FileName =~ 'Settings.sqlite|Logs.db|spur.log'

# 4) Recuperar un borrado por nº de entrada MFT (clusters aún no reutilizados)
SELECT * FROM copy(
  accessor='mft',
  filename=pathspec(Path='156449', DelegateAccessor='ewf', DelegatePath='<E01>'),
  dest='C:/Windows/Temp/rec_Settings.sqlite')
```

Para bajar a local cualquier fichero que dejemos en `C:\Windows\Temp\` de la VM:

```bash
# En la VM: serializar a base64; en local: decodificar
nxc winrm 10.129.1.203 -u Administrator -p 'Holmes2026!' \
  -X "[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\Windows\Temp\rec_Settings.sqlite'))" \
  | tr -d '\r\n ' | base64 -d > /tmp/rec_Settings.sqlite
```

> **Nota sobre `yara`:** en Velociraptor sólo escanea con `accessor='raw_ntfs'` sobre **ficheros concretos** (p. ej. `/pagefile.sys`). Lanzado con `accessor='ewf'` contra el **disco completo** devuelve **0 hits** (no recorre el *unallocated*). Y `rules=` toma **texto**, no ruta: hay que pasar la regla con `base64decode(string='...')`. Esto marca el límite de Q10 (ver más abajo).

### Metodología (paso a paso)

#### Q1–Q3 · El log de OpenVPN — el hilo del que tirar

**Por qué aquí:** el `todo.txt` del escritorio (`C:\Users\spur\Desktop\todo.txt`) es una nota operativa de tres líneas — *"Connect to OpenVPN / Enter the chat / Wait to be invited"* — que ordena la investigación: primero la VPN, luego el chat. El cliente OpenVPN estaba en `C:\Users\spur\OpenVPN`, carpeta que el wipe borró; pero su **log** dejó rastro recuperable.

```bash
# Localizar la entrada del log en la MFT (aunque el fichero esté "borrado")
/tmp/vql_run.sh "SELECT EntryNumber, InUse, FileName FROM parse_mft(
  filename=pathspec(Path='/\$MFT', DelegateAccessor='ewf', DelegatePath='<E01>'),
  accessor='raw_ntfs') WHERE FileName =~ 'spur.log'"
# → EntryNumber 154158  InUse false  FileName 'spur.log'

# Recuperar por MFT y leer
/tmp/vql_run.sh "SELECT * FROM copy(accessor='mft',
  filename=pathspec(Path='154158', DelegateAccessor='ewf', DelegatePath='<E01>'),
  dest='C:/Windows/Temp/spur.log')"
```

Recortes del `spur.log` recuperado, con las tres respuestas:

```text
Preserving recently used remote address: [AF_INET]18.156.81.166:7577      # Q1
TLS: Initial packet from [AF_INET]18.156.81.166:7577 ...
VERIFY OK: depth=1, CN=NPLN-CA                                            # Q2
VERIFY OK: depth=0, CN=NPLN-VPN-7577
PUSH: Received control message: 'PUSH_REPLY,route ...,ifconfig 10.129.175.2 255.255.255.0'  # Q3
OPTIONS IMPORT: --ifconfig/up options modified
```

- **Q1 — Servidor VPN:** `18.156.81.166:7577`. La línea `Preserving recently used remote address` da el par IP:puerto real al que conecta el cliente.
- **Q2 — CA emisora del certificado:** `NPLN-CA`. El truco está en el **`depth`** de la cadena TLS: `depth=1` es la **autoridad certificadora** que firma; `depth=0` es el certificado **de servidor** (`NPLN-VPN-7577`). Si la pregunta es por la CA → `depth=1` → `NPLN-CA`. Confundir ambos es el error clásico.
- **Q3 — IP asignada al cliente:** `10.129.175.2`. Viene en el `PUSH_REPLY` que el servidor envía tras el handshake (`ifconfig 10.129.175.2 255.255.255.0`), no en la config local.

#### Q4–Q6 · Tactical RMM — el agente de administración remota (= el C2)

**Por qué aquí:** la nota del enunciado dice que el carcelero hablaba "con alguien que consideraba su superior" a través de un altavoz. Traducido a disco: **algo administraba la máquina en remoto**. Enumerando `C:\Program Files\` aparece `TacticalAgent\`, el agente de **Tactical RMM** (AmidaWare Inc), un RMM legítimo re-propósito como C2.

```bash
# Q4 — versión, leída del VersionInfo del PE (sin ejecutarlo)
/tmp/vql_run.sh "SELECT FileName, VersionInformation FROM parse_pe(
  file=pathspec(Path='/Program Files/TacticalAgent/tacticalrmm.exe',
                DelegateAccessor='ewf', DelegatePath='<E01>'),
  accessor='raw_ntfs')"
# VersionInformation: CompanyName='AmidaWare Inc'  ProductName='Tactical RMM Agent'
#                     FileVersion='2.11.0'  ProductVersion='2.11.0'
```

- **Q4 — Agente + versión:** `Tactical RMM Agent v.2.11.0`. Se lee del **VersionInfo del binario**, sin ejecutarlo (forense estático puro).

La configuración del agente vive en el registro. La leemos **offline** con `raw_reg` — y, como control cruzado, con `regripper` sobre el hive descargado:

```bash
# Q5/Q6 — vía Velociraptor, registro offline
/tmp/vql_run.sh "SELECT * FROM read_reg_key(
  globs='/TacticalRMM/*',
  accessor='raw_reg',
  root=pathspec(DelegateAccessor='raw_ntfs',
    DelegatePath=pathspec(Path='/Windows/System32/config/SOFTWARE',
                          DelegateAccessor='ewf', DelegatePath='<E01>')))"
# ApiURL   = https://api.antimattercommunication.xyz
# Token    = 98ec588da683c01820232943a6151e8e7772419b
# AgentID  = HYlezOqYIjpJGWxfUkEQgUbYzDzReiejGHslxkTH

# Alternativa de control: bajar el hive SOFTWARE y parsearlo en local
/tmp/vql_run.sh "SELECT * FROM copy(accessor='raw_ntfs',
  filename=pathspec(Path='/Windows/System32/config/SOFTWARE',
                    DelegateAccessor='ewf', DelegatePath='<E01>'),
  dest='C:/Windows/Temp/SOFTWARE')"   # …luego base64 → local
regripper -r /tmp/SOFTWARE -p installedcomp 2>/dev/null | grep -i tactical
```

- **Q5 — Dominio del agente:** `api.antimattercommunication.xyz` (el `ApiURL`/`BaseURL` es `https://api.antimattercommunication.xyz`).
- **Q6 — Token de autenticación:** `98ec588da683c01820232943a6151e8e7772419b` (SHA-1 de 40 hex, en `Token`).

> **Correlación de infraestructura (el pivote del arco):** `api.antimattercommunication.xyz` resuelve a **18.156.81.166**, la **misma IP** que el servidor VPN `:7577`. VPN de entrada + RMM/C2 de control cuelgan del **mismo host AWS eu-central**. Esa única IP compartida entre el log de OpenVPN y el `ApiURL` del registro es el hilo que une esta caja con el resto de *The Reichenbach Directive*.

#### Q7 · Operation Vanish — el wipe apresurado

**Por qué aquí:** el enunciado habla de un "intento apresurado de borrar". En un host con RMM, un wipe no se teclea a mano: lo **empuja el C2**. Lo confirmamos en el log de creación de procesos.

```bash
# Buscar EID 4688 (process creation) con powershell -Enc lanzado por el RMM
/tmp/vql_run.sh "SELECT System.TimeCreated.SystemTime AS T, EventData
  FROM parse_evtx(filename=pathspec(
    Path='/Windows/System32/winevt/Logs/Security.evtx',
    DelegateAccessor='ewf', DelegatePath='<E01>'), accessor='raw_ntfs')
  WHERE System.EventID.Value = 4688
    AND EventData.NewProcessName =~ 'powershell|cmd'"
# Cadena padre→hijo:
#   tacticalrmm.exe  →  cmd.exe /c powershell -NonInteractive -Enc <BASE64…>
```

El `-Enc` es base64 de UTF-16LE. Se decodifica en local:

```bash
echo '<BASE64>' | base64 -d | iconv -f UTF-16LE -t UTF-8
```

El script resultante empieza por su **primer comando destructivo** (Q7) y sigue borrando el resto:

```powershell
Remove-Item -LiteralPath C:\Users\spur\Gajim   -Recurse -Force   # ← Q7
Remove-Item -LiteralPath C:\Users\spur\OpenVPN -Recurse -Force
Remove-Item -LiteralPath C:\VPN                -Recurse -Force
```

- **Q7 — Primer comando de Operation Vanish:** `Remove-Item -LiteralPath C:\Users\spur\Gajim -Recurse -Force`. El orden importa: borra **primero** la mensajería (lo más incriminatorio), luego el cliente VPN y la carpeta de perfiles `.ovpn`.

#### Q8–Q9 · La cuenta de mensajería — Gajim/XMPP

**Por qué se recupera:** `Remove-Item` desasigna la entrada MFT y marca los clusters como libres, pero **no los sobrescribe**. Mientras nada los reclame, `copy(accessor='mft')` los relee. `Settings.sqlite` de Gajim tuvo esa suerte (entrada íntegra); `Logs.db` no (ver Q10).

```bash
# Localizar y recuperar Settings.sqlite de la carpeta Gajim borrada
/tmp/vql_run.sh "SELECT EntryNumber, InUse, FileName FROM parse_mft(
  filename=pathspec(Path='/\$MFT', DelegateAccessor='ewf', DelegatePath='<E01>'),
  accessor='raw_ntfs') WHERE FileName = 'Settings.sqlite'"
# → EntryNumber 156449  InUse false

/tmp/vql_run.sh "SELECT * FROM copy(accessor='mft',
  filename=pathspec(Path='156449', DelegateAccessor='ewf', DelegatePath='<E01>'),
  dest='C:/Windows/Temp/rec_Settings.sqlite')"
# …base64 → /tmp/rec_Settings.sqlite

# Leer la cuenta: Gajim guarda la config como JSON dentro de SQLite
sqlite3 /tmp/rec_Settings.sqlite '.tables'
#   account_settings  settings  ...
sqlite3 /tmp/rec_Settings.sqlite "SELECT settings FROM account_settings;" \
  | python3 -m json.tool | egrep -i 'address|password|resource'
#   "address": "spurio9@murknet.htb",
#   "password": "spur999!*",
#   "resource": "gajim.XXXX"
```

- **Q8 — Cuenta de mensajería:** `spurio9@murknet.htb`. El JID sale del campo `address` del JSON de `account_settings`, y se confirma **de forma independiente** en la base OMEMO recuperada (entrada MFT 156526, fichero `omemo_spurio9…`).
- **Q9 — Contraseña:** `spur999!*`. Estaba **en claro** en el mismo JSON (`"password":"spur999!*"`). Gajim, con el backend de secretos deshabilitado en modo portable, guarda la credencial sin cifrar en disco.

> El `hosts` de la imagen (`C:\Windows\System32\drivers\etc\hosts`) resuelve `murknet.htb`, `upload.murknet.htb` y `command.murknet.htb` a **10.129.244.202** — el servidor XMPP interno, alcanzable **sólo por la VPN**. Con `spurio9@murknet.htb` / `spur999!*` se leería el roster… si la VPN levantara (ver Q10).

#### Q10 · El nombre real del carcelero — pendiente (negativo probado)

**Por qué debería estar ahí y por qué no está.** El carcelero es el usuario `spur` = `spurio9@murknet.htb`. Su **nombre real** sólo tendría sentido en dos sitios: (a) el **historial de chat** de Gajim, donde su superior lo llamaría por su nombre; (b) el **CN del certificado cliente** del `.ovpn`. Ambos fueron destruidos por Operation Vanish, y **esta vez los clusters sí se reutilizaron**.

```bash
# Logs.db (el chat) — recuperable por MFT pero CORRUPTO
/tmp/vql_run.sh "SELECT EntryNumber, InUse FROM parse_mft(...) WHERE FileName='Logs.db'"
# → EntryNumber 156456
sqlite3 /tmp/rec_Logs.db 'PRAGMA integrity_check;'    # → malformed

# Diagnóstico página a página (page_size 4096): de 14 páginas de datos,
# sólo sobreviven las de sqlite_master (esquema). Las páginas con los
# mensajes están pisadas por caché de Edge/AppX/Windows Defender.
python3 - <<'PY'
data=open('/tmp/rec_Logs.db','rb').read(); ps=4096
for i in range(len(data)//ps):
    pg=data[i*ps:(i+1)*ps]
    tag=('sqlite_master' if b'CREATE TABLE' in pg else
         'edge/appx cache' if b'microsoft.windows' in pg.lower() else 'reused/other')
    print(i, tag)
PY
```

El `.ovpn` (`C:\VPN\spur.ovpn`, ~63 725 bytes con `<ca>/<cert>/<key>` inline) está **igual de destruido**: su entrada MFT (137132) hoy apunta a "162.png". El **CN del cert cliente** habría sido el nombre, pero la clave privada no es regenerable.

**Descartado sistemáticamente (todo negativo, para no repetir):**

| Fuente | Resultado |
|--------|-----------|
| SAM (`fullname`) / LogonUI `LastLoggedOnDisplayName` / OOBE `RegisteredOwner` | `spur` / `spur` / vacío |
| Gajim `Settings.sqlite` roster/contacts | `{}` (vacío) |
| Gajim `omemo_spurio9` / `openpgp.db` | sólo claves **propias**, sin contactos |
| Edge + Chrome (History, logins, Preferences, autofill) | 0 filas, sin cuenta MSA/Google |
| `wpndatabase.db` (notificaciones) | sólo tiles de tiempo (London), sin toasts |
| `pagefile.sys` (yara `raw_ntfs`) | sólo el JID `spurio9`; "Chris Holbrow"/"Katrina" = **firmas antiphishing de Defender**, falsos positivos |
| Documentos / Jumplists / RecentDocs | sólo `todo.txt` y LNKs (VPN.lnk, spur.lnk→`C:\VPN\spur.ovpn`, hosts.lnk) |
| Windows Timeline (`ActivitiesCache.db`) | 3 actividades de sistema, sin nombres |
| Thumbcache (16–768) / Cert store / Volume Shadow Copies | wallpapers por defecto / vacío / no existen |

**DPAPI — el camino que quedó cortado.** Existe una credencial DPAPI en `C:\Users\spur\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D` (masterkey `df1fa43d…`, flag `CRYPTPROTECT_SYSTEM`). Descifrarla necesita la **contraseña de Windows en claro** de `spur`:

```bash
# Hashes locales de la imagen
impacket-secretsdump -sam /tmp/hive_SAM -system /tmp/hive_SYSTEM \
  -security /tmp/hive_SECURITY LOCAL
# spur:1002:aad3b...:bdc0b75b0938ac5ad7d5330a9c1c66c5:::   (NT hash)
# DPAPI_SYSTEM  machinekey:0x3d92263052435e6109d91201a7ac42c78a90af5c
#               userkey   :0xb530dff5a61a70f6e27f0fde6ff06348fc26355c

# Crackeo agotado (rockyou seco + best64 + dive + diccionario temático)
hashcat -m 1000 bdc0b75b0938ac5ad7d5330a9c1c66c5 rockyou.txt -r best64.rule
```

- **Tope técnico:** en una **cuenta local Win10**, el KDF de la masterkey usa **`SHA1(password_UTF16LE)`**, **no el NT hash**. Por eso `dpapi.py … -hashes :NT` da *padding error*: sin la password en claro (que el crackeo no reventó), la masterkey no se descifra y la credencial DPAPI queda cerrada.

**Conclusión Q10:** el nombre real del carcelero **no es recuperable de esta imagen**. Cuando el **único** artefacto que contenía un dato (el chat XMPP) ha sido borrado **y sobrescrito**, ninguna técnica de carving lo devuelve. El JID `spurio9@murknet.htb` es el único identificador que sobrevive. Documentamos un **negativo probado**, no un paso sin intentar.

**Leads abiertos (para retomar, con alcance confirmado):**
1. **Re-carve del unallocated en Linux** (probablemente la vía correcta): `ewfmount E01 /mnt` + `losetup`, y luego `sqlite_dissect` / `bulk_extractor` / `photorec` sobre el espacio no asignado buscando restos de `Logs.db` o mensajes XMPP en claro. El `yara` de Velociraptor **no** cubre esto.
2. **`swapfile.sys`** (256 MB, no escaneado a fondo) por restos de `openvpn_gui.exe` o del `.ovpn` en memoria paginada.
3. **XMPP `murknet.htb`** (`10.129.244.202`) por la VPN, con `spurio9`/`spur999!*` → roster/chat. **Bloqueado**: la VPN es cert-based y el `.ovpn` (cert+clave) está destruido.

### Cronología

| Instante (relativo) | Evento | Artefacto |
|---|---|---|
| T0 | `spur` edita `hosts` para resolver `murknet.htb` → `10.129.244.202` | LNK `hosts.lnk`, `hosts` |
| T0+ | Conexión OpenVPN al `18.156.81.166:7577`, IP asignada `10.129.175.2` | `spur.log` (MFT 154158) |
| T1 | Gajim (portable 2.6.0) se autentica como `spurio9@murknet.htb` y chatea con su superior | `Settings.sqlite` / `Logs.db` |
| T2 | El C2 (Tactical RMM `api.antimattercommunication.xyz`) empuja **Operation Vanish** | `Security.evtx` EID 4688 |
| T2+ | `tacticalrmm.exe → cmd → powershell -Enc` borra `Gajim`, `OpenVPN`, `C:\VPN` | script `-Enc` |
| T3 | El carcelero huye; el laptop queda encendido y Lestrade lo incauta | — |
| T4 | Sellado como E01 `DESKTOP-QMTIG5I.E01`; análisis DFIR headless | Velociraptor/WinRM |

### IOCs

| Tipo | Valor | Contexto |
|---|---|---|
| IPv4 | `18.156.81.166` | VPN `:7577` **y** C2/RMM (mismo host, AWS eu-central) |
| IPv4 | `10.129.244.202` | XMPP interno `murknet.htb` (por VPN) |
| IPv4 | `10.129.175.2` | IP asignada al cliente VPN |
| Puerto | `7577/tcp` | OpenVPN (cert-based, CA `NPLN-CA`, server `NPLN-VPN-7577`) |
| Dominio | `api.antimattercommunication.xyz` | C2 / `ApiURL` de Tactical RMM |
| Dominio | `murknet.htb`, `upload.murknet.htb`, `command.murknet.htb` | infra XMPP del arco |
| JID XMPP | `spurio9@murknet.htb` | cuenta del carcelero (pass `spur999!*`) |
| Token | `98ec588da683c01820232943a6151e8e7772419b` | auth Tactical RMM |
| AgentID | `HYlezOqYIjpJGWxfUkEQgUbYzDzReiejGHslxkTH` | Tactical RMM |
| Binario | `C:\Program Files\TacticalAgent\tacticalrmm.exe` | Tactical RMM Agent 2.11.0 (AmidaWare) |
| Hash NT | `bdc0b75b0938ac5ad7d5330a9c1c66c5` | usuario local `spur` (RID 1002) |
| SID | `S-1-5-21-637257722-930404403-2393314281-1002` | `spur` |

### Mapeo MITRE ATT&CK

| Táctica | Técnica | Evidencia en la imagen |
|---|---|---|
| Command & Control | **T1219** Remote Access Software | Tactical RMM Agent 2.11.0 como C2 |
| Command & Control | **T1071.001** Application Layer Protocol: Web | `ApiURL https://api.antimattercommunication.xyz` |
| Command & Control | **T1573** Encrypted Channel | OpenVPN cert-based `:7577` (CA `NPLN-CA`) |
| Execution | **T1059.001** PowerShell | `powershell -Enc` empujado por el RMM |
| Execution | **T1059.003** Windows Command Shell | `tacticalrmm.exe → cmd.exe /c` |
| Defense Evasion | **T1140** Deobfuscate/Decode Files or Information | payload `-Enc` base64/UTF-16LE |
| Defense Evasion | **T1070.004** File Deletion | `Remove-Item -Recurse -Force` (Operation Vanish) |
| Credential Access | **T1555** Credentials from Password Stores | contraseña XMPP en claro en `Settings.sqlite` |
| Credential Access | **T1552.001** Unsecured Credentials: In Files | JSON de Gajim con `password` |

### Detección y remediación

- **Detección — Tactical RMM no autorizado:** alertar sobre la creación del servicio/proceso `tacticalrmm.exe` y sobre claves `HKLM\SOFTWARE\TacticalRMM\{ApiURL,Token,AgentID}` fuera del inventario de RMM aprobado. Un RMM legítimo usado como C2 es difícil de distinguir por firma: hay que casarlo con **allowlist de instancias** y destinos (`api.antimattercommunication.xyz` no está en el catálogo corporativo).
- **Detección — wipe empujado por RMM:** EID 4688 con cadena `tacticalrmm.exe → cmd → powershell -Enc` seguido de borrados masivos es una firma fuerte. Vigilar `Remove-Item -Recurse -Force` sobre perfiles de usuario, y `-EncodedCommand` con padre RMM.
- **Detección — OpenVPN a destinos no corporativos:** conexiones salientes cert-based a puertos altos no estándar (`7577`) hacia IPs cloud recién vistas; correlacionar `VERIFY OK: depth=1, CN=<CA no interna>`.
- **Remediación:** rotar/revocar el token y el `AgentID` del RMM y bloquear el dominio/IP en el perímetro; forzar rotación de la credencial `spurio9@murknet.htb` y purga de la cuenta en el XMPP; eliminar el agente RMM no autorizado y su servicio; **no** confiar en clientes de escritorio (Gajim portable) para guardar secretos — habilitar keyring/DPAPI o Secret Service. Conservar la imagen: aunque el chat esté sobrescrito aquí, el unallocated puede rendir en un re-carve offline.

### Lecciones

- **Velociraptor en headless** (WinRM + `ewf`/`raw_ntfs`) es una alternativa completa a FTK/Arsenal para trabajar un E01 sin GUI ni herramientas comerciales. Todo el reto se sostiene sobre el **pathspec anidado**.
- **Borrar ≠ destruir, hasta que se sobrescribe.** `Settings.sqlite` sobrevivió al `Remove-Item` (clusters intactos → recuperable por MFT); `Logs.db` no (páginas de datos reutilizadas por caché). El mismo wipe deja unos artefactos vivos y otros irrecuperables — y no lo sabes hasta comprobar la integridad **página a página**.
- **Correlación de infraestructura:** una sola IP compartida entre el log VPN y el `ApiURL` del RMM une VPN de entrada y C2 de control en un solo host — el pivote hacia el resto de la operación.
- **Credenciales en claro** en el JSON de configuración de Gajim: los clientes de escritorio en modo portable siguen guardando contraseñas recuperables.
- **DPAPI de cuenta local** deriva la masterkey de `SHA1(password)`, no del NT hash: tener el hash no basta sin la password en claro.
- **Límite honesto:** Q10 documenta un **negativo probado**, no un paso sin intentar. Saber cuándo un dato es irrecuperable — y dejarlo escrito con las fuentes descartadas — es parte del trabajo forense.

### Serie · The Reichenbach Directive

| # | Sherlock | Enlace |
|---|----------|--------|
| S01 | Silent Dividend | [../2026-09-15-holmes2026-s01-silent-dividend/](../2026-09-15-holmes2026-s01-silent-dividend/) |
| **S02** | **Bottle Out** *(este)* | [../2026-09-16-holmes2026-s02-bottle-out/](../2026-09-16-holmes2026-s02-bottle-out/) |
| S03 | Whisper Chain | [../2026-09-17-holmes2026-s03-whisper-chain/](../2026-09-17-holmes2026-s03-whisper-chain/) |
| S04 | Paper Ghost | [../2026-09-18-holmes2026-s04-paper-ghost/](../2026-09-18-holmes2026-s04-paper-ghost/) |
| S05 | Poisoned Branch | [../2026-09-19-holmes2026-s05-poisoned-branch/](../2026-09-19-holmes2026-s05-poisoned-branch/) |
| S06 | Silent Passenger | [../2026-09-20-holmes2026-s06-silent-passenger/](../2026-09-20-holmes2026-s06-silent-passenger/) |
| S07 | Iron Feather | [../2026-09-21-holmes2026-s07-iron-feather/](../2026-09-21-holmes2026-s07-iron-feather/) |
| S08 | Borrowed Name | [../2026-09-22-holmes2026-s08-borrowed-name/](../2026-09-22-holmes2026-s08-borrowed-name/) |
| S09 | Last Light | [../2026-09-23-holmes2026-s09-last-light/](../2026-09-23-holmes2026-s09-last-light/) |

<a id="en"></a>
## 🇬🇧 English

### Scenario

The payments followed a pattern Watson had sensed but never proved: each victim trusted the same polished *settlement* process before fear closed around them. A survivor supplied the next lead — the computer used during a payment — and Lestrade recovered it before anyone could alter what remained. The trail pointed east, to the **Silvertown** container yards, where they found Watson alive. His jailer fled minutes before the police arrived, leaving behind a **powered-on laptop**.

The machine shows a hurried attempt to erase recent activity: a single communications client survives, but its account, server and purpose remain unknown. The evidence is sealed and handed over as an **E01 disk image** of host **BLUEBOX** (suspect user `spur`). The goal is to recover what survived the wiping attempt and determine how the laptop tied its unknown operator to the wider operation of *The Reichenbach Directive*.

Difficulty: **Easy**. But "easy" is deceptive: the point is not *finding* the data, it is **being able to open the evidence** without commercial tooling and **understanding why some deleted artefacts come back and others do not**.

### The opening problem: an E01 nothing opens

The evidence is not a `.raw` or a casually mountable `.vmdk`. It is an **EnCase Evidence Format (E01)**: a compressed, checksummed container (per-block Adler-32 + global MD5/SHA-1) wrapping the suspect's NTFS image.

- **7-Zip 24.09** on the VM **won't open E01** (no `ewf` codec).
- No **Arsenal Image Mounter**, no **FTK Imager CLI**, no EnCase license.
- We only have **WinRM (5985)** / RDP (3389) access to VM `BLUEBOX` with `Administrator : Holmes2026!`, and one loose binary: `velociraptor.exe` installed via Scoop.

The headless answer is **Velociraptor**: its VQL engine ships a native `ewf` *accessor* that decompresses the E01 on the fly, and a `raw_ntfs` on top that parses the filesystem. It runs **without a GUI**, sending VQL over WinRM with `nxc`.

```bash
# Execution template: VQL over WinRM (nxc), filtering the host prefix
nxc winrm 10.129.1.203 -u Administrator -p 'Holmes2026!' \
  -X "& 'C:\ProgramData\scoop\apps\velociraptor\current\velociraptor.exe' query --format=json 'SELECT ... FROM ...'"
# Golden rule: SINGLE quotes inside the VQL. PowerShell eats the double quotes
# when passing args to a native exe, and the query arrives broken.
```

A small local helper (`/tmp/vql_run.sh "VQL"`) wraps that pattern and trims `nxc` noise; `/tmp/vql_read.sh "/path"` reads a file from inside the image. They are ephemeral (they live in `/tmp`), recreated if lost. In the examples below `<E01>` = `C:/Users/Administrator/Desktop/DESKTOP-QMTIG5I.E01`.

### Artefact and tooling

- **E01 image** `DESKTOP-QMTIG5I.E01` in `C:/Users/Administrator/Desktop/` on VM `BLUEBOX`.
- **Velociraptor** (`C:\ProgramData\scoop\apps\velociraptor\current\velociraptor.exe`) over WinRM/`nxc`, no GUI.
- **`parse_mft` + `copy(accessor='mft')`** to recover deleted files by MFT entry number.
- **`impacket-secretsdump`** locally against the downloaded SAM/SYSTEM/SECURITY hives.
- **`regripper`** / `sqlite3` locally as an offline cross-check for the registry and Gajim databases.
- **SQLite** reading (Gajim portable 2.6.0: `Settings.sqlite`, `Logs.db`, OMEMO/OpenPGP databases).

#### The pattern that makes everything possible: nested pathspec over `ewf`

The whole challenge reduces to chaining *accessors* with a `pathspec`. `ewf` decompresses; whatever sits on top interprets:

```bash
# 1) Image filesystem (NTFS inside the EWF)
SELECT Name, Size, Mtime FROM glob(
  globs='/Users/spur/**',
  accessor='raw_ntfs',
  root=pathspec(DelegateAccessor='ewf', DelegatePath='<E01>'))

# 2) OFFLINE registry (raw_reg over raw_ntfs over ewf — triple nesting)
SELECT * FROM glob(
  globs='/TacticalRMM/*',
  accessor='raw_reg',
  root=pathspec(DelegateAccessor='raw_ntfs',
    DelegatePath=pathspec(Path='/Windows/System32/config/SOFTWARE',
                          DelegateAccessor='ewf', DelegatePath='<E01>')))

# 3) Full MFT (to locate entries of deleted files)
SELECT EntryNumber, InUse, FileName, FileSize FROM parse_mft(
  filename=pathspec(Path='/$MFT', DelegateAccessor='ewf', DelegatePath='<E01>'),
  accessor='raw_ntfs')
WHERE FileName =~ 'Settings.sqlite|Logs.db|spur.log'

# 4) Recover a deleted file by MFT entry (clusters not yet reused)
SELECT * FROM copy(
  accessor='mft',
  filename=pathspec(Path='156449', DelegateAccessor='ewf', DelegatePath='<E01>'),
  dest='C:/Windows/Temp/rec_Settings.sqlite')
```

To pull any file we drop in `C:\Windows\Temp\` on the VM down to local:

```bash
# On the VM: serialize to base64; locally: decode
nxc winrm 10.129.1.203 -u Administrator -p 'Holmes2026!' \
  -X "[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\Windows\Temp\rec_Settings.sqlite'))" \
  | tr -d '\r\n ' | base64 -d > /tmp/rec_Settings.sqlite
```

> **Note on `yara`:** in Velociraptor it only scans with `accessor='raw_ntfs'` over **specific files** (e.g. `/pagefile.sys`). Fired with `accessor='ewf'` against the **whole disk** it returns **0 hits** (it doesn't walk unallocated space). And `rules=` takes **text**, not a path: pass the rule with `base64decode(string='...')`. This marks the limit of Q10 (below).

### Methodology (step by step)

#### Q1–Q3 · The OpenVPN log — the thread to pull

**Why here:** the desktop `todo.txt` (`C:\Users\spur\Desktop\todo.txt`) is a three-line operational note — *"Connect to OpenVPN / Enter the chat / Wait to be invited"* — that orders the investigation: VPN first, then the chat. The OpenVPN client sat in `C:\Users\spur\OpenVPN`, a folder the wipe deleted; but its **log** left a recoverable trace.

```bash
# Locate the log's MFT entry (even though the file is "deleted")
/tmp/vql_run.sh "SELECT EntryNumber, InUse, FileName FROM parse_mft(
  filename=pathspec(Path='/\$MFT', DelegateAccessor='ewf', DelegatePath='<E01>'),
  accessor='raw_ntfs') WHERE FileName =~ 'spur.log'"
# → EntryNumber 154158  InUse false  FileName 'spur.log'

# Recover by MFT and read
/tmp/vql_run.sh "SELECT * FROM copy(accessor='mft',
  filename=pathspec(Path='154158', DelegateAccessor='ewf', DelegatePath='<E01>'),
  dest='C:/Windows/Temp/spur.log')"
```

Trimmed lines from the recovered `spur.log`, with the three answers:

```text
Preserving recently used remote address: [AF_INET]18.156.81.166:7577      # Q1
TLS: Initial packet from [AF_INET]18.156.81.166:7577 ...
VERIFY OK: depth=1, CN=NPLN-CA                                            # Q2
VERIFY OK: depth=0, CN=NPLN-VPN-7577
PUSH: Received control message: 'PUSH_REPLY,route ...,ifconfig 10.129.175.2 255.255.255.0'  # Q3
OPTIONS IMPORT: --ifconfig/up options modified
```

- **Q1 — VPN server:** `18.156.81.166:7577`. The `Preserving recently used remote address` line gives the real IP:port the client connects to.
- **Q2 — Issuing CA:** `NPLN-CA`. The trick is the TLS chain **`depth`**: `depth=1` is the signing **certificate authority**; `depth=0` is the **server** certificate (`NPLN-VPN-7577`). If the question is about the CA → `depth=1` → `NPLN-CA`. Confusing the two is the classic mistake.
- **Q3 — Client-assigned IP:** `10.129.175.2`. It comes in the `PUSH_REPLY` the server sends after the handshake (`ifconfig 10.129.175.2 255.255.255.0`), not in local config.

#### Q4–Q6 · Tactical RMM — the remote management agent (= the C2)

**Why here:** the briefing says the jailer spoke "to someone he clearly considered his superior" through a speaker. Translated to disk: **something managed the machine remotely**. Enumerating `C:\Program Files\` reveals `TacticalAgent\`, the **Tactical RMM** agent (AmidaWare Inc), a legitimate RMM repurposed as a C2.

```bash
# Q4 — version, read from the PE VersionInfo (without executing it)
/tmp/vql_run.sh "SELECT FileName, VersionInformation FROM parse_pe(
  file=pathspec(Path='/Program Files/TacticalAgent/tacticalrmm.exe',
                DelegateAccessor='ewf', DelegatePath='<E01>'),
  accessor='raw_ntfs')"
# VersionInformation: CompanyName='AmidaWare Inc'  ProductName='Tactical RMM Agent'
#                     FileVersion='2.11.0'  ProductVersion='2.11.0'
```

- **Q4 — Agent + version:** `Tactical RMM Agent v.2.11.0`. Read from the **binary's VersionInfo**, without executing it (pure static forensics).

The agent config lives in the registry. We read it **offline** with `raw_reg` — and, as a cross-check, with `regripper` on the downloaded hive:

```bash
# Q5/Q6 — via Velociraptor, offline registry
/tmp/vql_run.sh "SELECT * FROM read_reg_key(
  globs='/TacticalRMM/*',
  accessor='raw_reg',
  root=pathspec(DelegateAccessor='raw_ntfs',
    DelegatePath=pathspec(Path='/Windows/System32/config/SOFTWARE',
                          DelegateAccessor='ewf', DelegatePath='<E01>')))"
# ApiURL   = https://api.antimattercommunication.xyz
# Token    = 98ec588da683c01820232943a6151e8e7772419b
# AgentID  = HYlezOqYIjpJGWxfUkEQgUbYzDzReiejGHslxkTH

# Cross-check: download the SOFTWARE hive and parse it locally
regripper -r /tmp/SOFTWARE -p installedcomp 2>/dev/null | grep -i tactical
```

- **Q5 — Agent domain:** `api.antimattercommunication.xyz` (the `ApiURL`/`BaseURL` is `https://api.antimattercommunication.xyz`).
- **Q6 — Auth token:** `98ec588da683c01820232943a6151e8e7772419b` (40-hex SHA-1, in `Token`).

> **Infrastructure correlation (the arc's pivot):** `api.antimattercommunication.xyz` resolves to **18.156.81.166**, the **same IP** as the VPN server `:7577`. Entry VPN + control RMM/C2 hang off the **same AWS eu-central host**. That single shared IP between the OpenVPN log and the registry `ApiURL` is the thread tying this box to the rest of *The Reichenbach Directive*.

#### Q7 · Operation Vanish — the hurried wipe

**Why here:** the briefing mentions a "hurried attempt to erase". On an RMM-managed host a wipe isn't typed by hand: it is **pushed by the C2**. We confirm it in the process-creation log.

```bash
# Find EID 4688 (process creation) with powershell -Enc spawned by the RMM
/tmp/vql_run.sh "SELECT System.TimeCreated.SystemTime AS T, EventData
  FROM parse_evtx(filename=pathspec(
    Path='/Windows/System32/winevt/Logs/Security.evtx',
    DelegateAccessor='ewf', DelegatePath='<E01>'), accessor='raw_ntfs')
  WHERE System.EventID.Value = 4688
    AND EventData.NewProcessName =~ 'powershell|cmd'"
# Parent→child chain:
#   tacticalrmm.exe  →  cmd.exe /c powershell -NonInteractive -Enc <BASE64…>
```

The `-Enc` is base64 of UTF-16LE. Decode it locally:

```bash
echo '<BASE64>' | base64 -d | iconv -f UTF-16LE -t UTF-8
```

The resulting script opens with its **first destructive command** (Q7) and keeps deleting the rest:

```powershell
Remove-Item -LiteralPath C:\Users\spur\Gajim   -Recurse -Force   # ← Q7
Remove-Item -LiteralPath C:\Users\spur\OpenVPN -Recurse -Force
Remove-Item -LiteralPath C:\VPN                -Recurse -Force
```

- **Q7 — First command of Operation Vanish:** `Remove-Item -LiteralPath C:\Users\spur\Gajim -Recurse -Force`. Order matters: it deletes the **messaging first** (the most incriminating), then the VPN client and the `.ovpn` profile folder.

#### Q8–Q9 · The messaging account — Gajim/XMPP

**Why it recovers:** `Remove-Item` deallocates the MFT entry and marks the clusters free, but **doesn't overwrite them**. As long as nothing claims them, `copy(accessor='mft')` reads them back. Gajim's `Settings.sqlite` got that luck (intact entry); `Logs.db` did not (see Q10).

```bash
# Locate and recover Settings.sqlite from the deleted Gajim folder
/tmp/vql_run.sh "SELECT EntryNumber, InUse, FileName FROM parse_mft(
  filename=pathspec(Path='/\$MFT', DelegateAccessor='ewf', DelegatePath='<E01>'),
  accessor='raw_ntfs') WHERE FileName = 'Settings.sqlite'"
# → EntryNumber 156449  InUse false

/tmp/vql_run.sh "SELECT * FROM copy(accessor='mft',
  filename=pathspec(Path='156449', DelegateAccessor='ewf', DelegatePath='<E01>'),
  dest='C:/Windows/Temp/rec_Settings.sqlite')"
# …base64 → /tmp/rec_Settings.sqlite

# Read the account: Gajim stores config as JSON inside SQLite
sqlite3 /tmp/rec_Settings.sqlite "SELECT settings FROM account_settings;" \
  | python3 -m json.tool | egrep -i 'address|password|resource'
#   "address": "spurio9@murknet.htb",
#   "password": "spur999!*",
#   "resource": "gajim.XXXX"
```

- **Q8 — Messaging account:** `spurio9@murknet.htb`. The JID comes from the `address` field of the `account_settings` JSON, and is **independently confirmed** in the recovered OMEMO database (MFT entry 156526, file `omemo_spurio9…`).
- **Q9 — Password:** `spur999!*`. It sat **in cleartext** in the same JSON (`"password":"spur999!*"`). Gajim, with the secret backend disabled in portable mode, stores the credential unencrypted on disk.

> The image's `hosts` (`C:\Windows\System32\drivers\etc\hosts`) resolves `murknet.htb`, `upload.murknet.htb` and `command.murknet.htb` to **10.129.244.202** — the internal XMPP server, reachable **only over the VPN**. With `spurio9@murknet.htb` / `spur999!*` you could read the roster… if the VPN would come up (see Q10).

#### Q10 · The jailer's real name — pending (proven negative)

**Why it should be there and why it isn't.** The jailer is user `spur` = `spurio9@murknet.htb`. His **real name** would only make sense in two places: (a) Gajim's **chat history**, where his superior would call him by name; (b) the `.ovpn` **client certificate CN**. Both were destroyed by Operation Vanish, and **this time the clusters were reused**.

```bash
# Logs.db (the chat) — MFT-recoverable but CORRUPT
/tmp/vql_run.sh "SELECT EntryNumber, InUse FROM parse_mft(...) WHERE FileName='Logs.db'"
# → EntryNumber 156456
sqlite3 /tmp/rec_Logs.db 'PRAGMA integrity_check;'    # → malformed

# Page-by-page diagnosis (page_size 4096): of 14 data pages, only the
# sqlite_master (schema) pages survive. The message pages are clobbered
# by Edge/AppX/Windows Defender cache.
python3 - <<'PY'
data=open('/tmp/rec_Logs.db','rb').read(); ps=4096
for i in range(len(data)//ps):
    pg=data[i*ps:(i+1)*ps]
    tag=('sqlite_master' if b'CREATE TABLE' in pg else
         'edge/appx cache' if b'microsoft.windows' in pg.lower() else 'reused/other')
    print(i, tag)
PY
```

The `.ovpn` (`C:\VPN\spur.ovpn`, ~63,725 bytes with inline `<ca>/<cert>/<key>`) is **equally destroyed**: its MFT entry (137132) now points to "162.png". The **client cert CN** would have been the name, but the private key is not regenerable.

**Systematically ruled out (all negative, to avoid repeating):**

| Source | Result |
|--------|--------|
| SAM (`fullname`) / LogonUI `LastLoggedOnDisplayName` / OOBE `RegisteredOwner` | `spur` / `spur` / empty |
| Gajim `Settings.sqlite` roster/contacts | `{}` (empty) |
| Gajim `omemo_spurio9` / `openpgp.db` | own keys only, no contacts |
| Edge + Chrome (History, logins, Preferences, autofill) | 0 rows, no MSA/Google account |
| `wpndatabase.db` (notifications) | weather tiles only (London), no toasts |
| `pagefile.sys` (yara `raw_ntfs`) | only the JID `spurio9`; "Chris Holbrow"/"Katrina" = **Defender antiphishing signatures**, false positives |
| Documents / Jumplists / RecentDocs | only `todo.txt` and LNKs (VPN.lnk, spur.lnk→`C:\VPN\spur.ovpn`, hosts.lnk) |
| Windows Timeline (`ActivitiesCache.db`) | 3 system activities, no names |
| Thumbcache (16–768) / Cert store / Volume Shadow Copies | default wallpapers / empty / none exist |

**DPAPI — the road that got cut off.** A DPAPI credential exists at `C:\Users\spur\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D` (masterkey `df1fa43d…`, flag `CRYPTPROTECT_SYSTEM`). Decrypting it needs `spur`'s **cleartext Windows password**:

```bash
# Local hashes from the image
impacket-secretsdump -sam /tmp/hive_SAM -system /tmp/hive_SYSTEM \
  -security /tmp/hive_SECURITY LOCAL
# spur:1002:aad3b...:bdc0b75b0938ac5ad7d5330a9c1c66c5:::   (NT hash)
# DPAPI_SYSTEM  machinekey:0x3d92263052435e6109d91201a7ac42c78a90af5c
#               userkey   :0xb530dff5a61a70f6e27f0fde6ff06348fc26355c

# Cracking exhausted (rockyou dry + best64 + dive + themed wordlist)
hashcat -m 1000 bdc0b75b0938ac5ad7d5330a9c1c66c5 rockyou.txt -r best64.rule
```

- **Technical ceiling:** on a **local Win10 account**, the masterkey KDF uses **`SHA1(password_UTF16LE)`**, **not the NT hash**. That's why `dpapi.py … -hashes :NT` gives a *padding error*: without the cleartext password (which cracking didn't break), the masterkey won't decrypt and the DPAPI credential stays closed.

**Q10 conclusion:** the jailer's real name **is not recoverable from this image**. When the **only** artefact holding a value (the XMPP chat) has been deleted **and overwritten**, no carving technique returns it. The JID `spurio9@murknet.htb` is the only surviving identifier. We document a **proven negative**, not an untried step.

**Open leads (to resume, with confirmed scope):**
1. **Unallocated re-carve on Linux** (probably the right path): `ewfmount E01 /mnt` + `losetup`, then `sqlite_dissect` / `bulk_extractor` / `photorec` over unallocated space hunting for `Logs.db` remnants or cleartext XMPP messages. Velociraptor's `yara` does **not** cover this.
2. **`swapfile.sys`** (256 MB, not deep-scanned) for `openvpn_gui.exe` or `.ovpn` remnants in paged memory.
3. **XMPP `murknet.htb`** (`10.129.244.202`) over the VPN, with `spurio9`/`spur999!*` → roster/chat. **Blocked**: the VPN is cert-based and the `.ovpn` (cert+key) is destroyed.

### Timeline

| Instant (relative) | Event | Artefact |
|---|---|---|
| T0 | `spur` edits `hosts` to resolve `murknet.htb` → `10.129.244.202` | LNK `hosts.lnk`, `hosts` |
| T0+ | OpenVPN connection to `18.156.81.166:7577`, assigned IP `10.129.175.2` | `spur.log` (MFT 154158) |
| T1 | Gajim (portable 2.6.0) authenticates as `spurio9@murknet.htb` and chats with his superior | `Settings.sqlite` / `Logs.db` |
| T2 | The C2 (Tactical RMM `api.antimattercommunication.xyz`) pushes **Operation Vanish** | `Security.evtx` EID 4688 |
| T2+ | `tacticalrmm.exe → cmd → powershell -Enc` deletes `Gajim`, `OpenVPN`, `C:\VPN` | `-Enc` script |
| T3 | The jailer flees; the laptop stays powered on and Lestrade seizes it | — |
| T4 | Sealed as E01 `DESKTOP-QMTIG5I.E01`; headless DFIR analysis | Velociraptor/WinRM |

### IOCs

| Type | Value | Context |
|---|---|---|
| IPv4 | `18.156.81.166` | VPN `:7577` **and** C2/RMM (same host, AWS eu-central) |
| IPv4 | `10.129.244.202` | internal XMPP `murknet.htb` (over VPN) |
| IPv4 | `10.129.175.2` | IP assigned to the VPN client |
| Port | `7577/tcp` | OpenVPN (cert-based, CA `NPLN-CA`, server `NPLN-VPN-7577`) |
| Domain | `api.antimattercommunication.xyz` | C2 / Tactical RMM `ApiURL` |
| Domain | `murknet.htb`, `upload.murknet.htb`, `command.murknet.htb` | arc XMPP infra |
| XMPP JID | `spurio9@murknet.htb` | jailer's account (pass `spur999!*`) |
| Token | `98ec588da683c01820232943a6151e8e7772419b` | Tactical RMM auth |
| AgentID | `HYlezOqYIjpJGWxfUkEQgUbYzDzReiejGHslxkTH` | Tactical RMM |
| Binary | `C:\Program Files\TacticalAgent\tacticalrmm.exe` | Tactical RMM Agent 2.11.0 (AmidaWare) |
| NT hash | `bdc0b75b0938ac5ad7d5330a9c1c66c5` | local user `spur` (RID 1002) |
| SID | `S-1-5-21-637257722-930404403-2393314281-1002` | `spur` |

### MITRE ATT&CK mapping

| Tactic | Technique | Evidence in the image |
|---|---|---|
| Command & Control | **T1219** Remote Access Software | Tactical RMM Agent 2.11.0 as C2 |
| Command & Control | **T1071.001** Application Layer Protocol: Web | `ApiURL https://api.antimattercommunication.xyz` |
| Command & Control | **T1573** Encrypted Channel | OpenVPN cert-based `:7577` (CA `NPLN-CA`) |
| Execution | **T1059.001** PowerShell | `powershell -Enc` pushed by the RMM |
| Execution | **T1059.003** Windows Command Shell | `tacticalrmm.exe → cmd.exe /c` |
| Defense Evasion | **T1140** Deobfuscate/Decode Files or Information | `-Enc` base64/UTF-16LE payload |
| Defense Evasion | **T1070.004** File Deletion | `Remove-Item -Recurse -Force` (Operation Vanish) |
| Credential Access | **T1555** Credentials from Password Stores | cleartext XMPP password in `Settings.sqlite` |
| Credential Access | **T1552.001** Unsecured Credentials: In Files | Gajim JSON with `password` |

### Detection and remediation

- **Detection — unauthorized Tactical RMM:** alert on `tacticalrmm.exe` service/process creation and on `HKLM\SOFTWARE\TacticalRMM\{ApiURL,Token,AgentID}` keys outside the approved RMM inventory. A legitimate RMM used as a C2 is hard to distinguish by signature: match it against an **instance allowlist** and destinations (`api.antimattercommunication.xyz` is not in the corporate catalog).
- **Detection — RMM-pushed wipe:** EID 4688 with the chain `tacticalrmm.exe → cmd → powershell -Enc` followed by mass deletions is a strong signature. Watch for `Remove-Item -Recurse -Force` over user profiles, and `-EncodedCommand` with an RMM parent.
- **Detection — OpenVPN to non-corporate destinations:** outbound cert-based connections to non-standard high ports (`7577`) toward newly-seen cloud IPs; correlate `VERIFY OK: depth=1, CN=<non-internal CA>`.
- **Remediation:** rotate/revoke the RMM token and `AgentID` and block the domain/IP at the perimeter; force rotation of the `spurio9@murknet.htb` credential and purge the account on the XMPP server; remove the unauthorized RMM agent and its service; do **not** trust desktop clients (Gajim portable) to store secrets — enable keyring/DPAPI or Secret Service. Preserve the image: even though the chat is overwritten here, unallocated space may yield in an offline re-carve.

### Lessons

- **Headless Velociraptor** (WinRM + `ewf`/`raw_ntfs`) is a full substitute for FTK/Arsenal when working an E01 without a GUI or commercial tools. The whole challenge rests on the **nested pathspec**.
- **Deleted ≠ destroyed, until it is overwritten.** `Settings.sqlite` survived the `Remove-Item` (clusters intact → MFT-recoverable); `Logs.db` did not (data pages reused by cache). The same wipe leaves some artefacts alive and others gone — and you don't know until you check integrity **page by page**.
- **Infrastructure correlation:** one shared IP between the VPN log and the RMM `ApiURL` ties entry VPN and control C2 to a single host — the pivot into the rest of the operation.
- **Cleartext credentials** in Gajim's config JSON: portable desktop clients still store recoverable passwords.
- **Local-account DPAPI** derives the masterkey from `SHA1(password)`, not the NT hash: having the hash is not enough without the cleartext password.
- **An honest limit:** Q10 documents a **proven negative**, not an untried step. Knowing when a value is unrecoverable — and writing it up with the ruled-out sources — is part of forensic work.

### Series · The Reichenbach Directive

| # | Sherlock | Link |
|---|----------|------|
| S01 | Silent Dividend | [../2026-09-15-holmes2026-s01-silent-dividend/](../2026-09-15-holmes2026-s01-silent-dividend/) |
| **S02** | **Bottle Out** *(this one)* | [../2026-09-16-holmes2026-s02-bottle-out/](../2026-09-16-holmes2026-s02-bottle-out/) |
| S03 | Whisper Chain | [../2026-09-17-holmes2026-s03-whisper-chain/](../2026-09-17-holmes2026-s03-whisper-chain/) |
| S04 | Paper Ghost | [../2026-09-18-holmes2026-s04-paper-ghost/](../2026-09-18-holmes2026-s04-paper-ghost/) |
| S05 | Poisoned Branch | [../2026-09-19-holmes2026-s05-poisoned-branch/](../2026-09-19-holmes2026-s05-poisoned-branch/) |
| S06 | Silent Passenger | [../2026-09-20-holmes2026-s06-silent-passenger/](../2026-09-20-holmes2026-s06-silent-passenger/) |
| S07 | Iron Feather | [../2026-09-21-holmes2026-s07-iron-feather/](../2026-09-21-holmes2026-s07-iron-feather/) |
| S08 | Borrowed Name | [../2026-09-22-holmes2026-s08-borrowed-name/](../2026-09-22-holmes2026-s08-borrowed-name/) |
| S09 | Last Light | [../2026-09-23-holmes2026-s09-last-light/](../2026-09-23-holmes2026-s09-last-light/) |
