---
title: "Holmes CTF 2026 — S08 Borrowed Name"
date: 2026-09-22
description: "DFIR de un incidente Active Directory: agente AdaptixC2 vía DLL sideloading, tráfico NTLM descifrado y privesc ResetNightmare (CVE-2026-27912)."
excerpt: "USB con DLL sideloading despliega AdaptixC2; se descifra el PCAP RC4 y se reconstruye la cadena Internal Monologue → ResetNightmare → movimiento lateral a DC02."
platform: "HTB"
difficulty: "Insane"
image: "/images/blog/holmes-s08.svg"
tags:
  - "DFIR"
  - "Active Directory"
  - "PCAP"
  - "DLL Sideloading"
  - "NTLM"
  - "Holmes CTF 2026"
---

> **Reto:** Holmes CTF 2026 — Sherlock 08 "Borrowed Name" · Incidente Active Directory (pcap NTLM + DLL sideloading). Parte del arco *The Reichenbach Directive*.
>
> **Navegación:** [🇪🇸 Español](#es) · [🇬🇧 English](#en)

<a id="es"></a>

## 🇪🇸 Español

### Escenario

Tras la recuperación de un dron (Sherlock anterior, *Iron Feather*), Eleanor Mercer detecta una **sesión saliente no autorizada** desde una estación de trabajo protegida (WS02) del bosque **DIOGENES**. La actividad no coincide con ningún software aprobado y —lo más inquietante— **continúa después de que un objeto físico es retirado** del puesto: un pendrive dejado con apariencia de documento de RRHH ("Q3 Salary Review"). El malware ya se ha copiado a disco y no depende del USB.

Este Sherlock es puro **DFIR de intrusión Active Directory reconstruido desde la red**: no tenemos una shell ni logs completos del EDR, solo un **PCAP de tráfico C2 cifrado**, la **imagen del USB**, unos binarios y **un único EVTX** (el canal NTLM operativo). Todo lo demás —qué C2 es, qué claves usa, qué comandos ejecutó el operador, cómo escaló y cómo saltó al DC— hay que **deducirlo descifrando el tráfico**. Ese es el corazón del reto: sin la reconstrucción del PCAP, casi ninguna respuesta se puede contestar.

El bosque objetivo:

- Raíz **`diogenes.htb`** → DC **DIOCORE**
- Hijo **`core.diogenes.htb`** → DC **DC02** (`192.168.56.11`)
- Estación comprometida **WS02** (`192.168.56.22`)
- Team server C2 del atacante: **`192.168.56.1:8818`**
- Usuarios implicados: **afenwick** (comprometido inicial, WS02, SID `...-1125`), **jreed** (objetivo del privesc), rfairfax (DA/EA de la raíz, aparece en S09).
- Implante final desplegado en DC02: proceso **`svc_bkup`** secuestrando el service group **`defragsvc`**.
- Atacante: APT **NAPOLEON** (arco DIOGENES/MurkNet).

El objetivo del análisis es reconstruir **toda** la cadena: cómo entró el operador (entrega), qué C2 usó y con qué claves, qué recon hizo, cómo abusó de un permiso de AD para robar la identidad de otro usuario, y cómo se movió lateralmente hasta el DC hijo como SYSTEM.

### Artefacto y herramientas

**Evidencia entregada (`BorrowedName/`):**

| Artefacto | Descripción |
|-----------|-------------|
| `evidence/capture.pcapng` | Tráfico C2 (HTTP con cifrado RC4 propietario), 692 KB, ~900 frames |
| `evidence/Q3_Salary_Review.img` | Imagen FAT32 del USB (134 MB), `.lnk` → `docviewer.exe` |
| `evidence/usb/` | Contenido carveado del USB: `docviewer.exe`, `version.dll`, `winupdate.exe`, `Salary_Review_Q3_2026.pdf.lnk`, `temp.pdf`, `README.txt` |
| `evidence/C/Windows/System32/winevt/logs/Microsoft-Windows-NTLM%4Operational.evtx` | Logs NTLM del host (EventID **4021**) |
| PDF narrativo (Chapters 10-12) | Contexto del arco *The Reichenbach Directive* |

La evidencia venía dentro de un ZIP protegido (`danger.zip`, password `PaedeiRae1xiexahwuno`) — un patrón habitual en estos Sherlocks para evitar que los AV del analista revienten las muestras al descomprimir.

**Herramientas:** `tshark`/`pyshark` (triage y extracción del PCAP), análisis PE (`file`, `strings`, `pefile`, Ghidra/radare2), **extractor de config AdaptixC2** (metodología Unit42), scripts **RC4** en Python para descifrar el tráfico, **The Sleuth Kit** (`mmls`/`fls`/`icat`) y `mount -o loop` para el USB, `python-evtx`/`evtx_dump`/Chainsaw para el EVTX, y **hashcat** (mode 5600 + rockyou) para el NetNTLMv2.

Hashes de los binarios del USB (`md5sum usb/*`):

```
aca111935d339b17544ead3e8c2c8831  docviewer.exe   (host legítimo del sideload)
6e787589a69ce783b0380b0de86a2d68  version.dll     (DLL maliciosa sideloaded)
b1c8c95d3bfa22780076084377584739  winupdate.exe   (agente AdaptixC2)
```

### Topología de red y actores

Antes de bajar al detalle, conviene fijar quién habla con quién en el PCAP (lo confirma el propio tráfico y la resolución DNS que el C2 devuelve):

```
[ WS02 192.168.56.22 ]  ──HTTP/RC4──►  [ C2 team server 192.168.56.1:8818 ]
   afenwick (winupdate.exe)                     APT NAPOLEON
        │
        │  (tras ResetNightmare + impersonación jreed)
        ▼
[ DC02 192.168.56.11 ]  ──HTTP/RC4──►  [ C2 team server 192.168.56.1:8818 ]
   SYSTEM (svc_bkup, service group defragsvc)   segundo beacon
```

El PCAP contiene **dos beacons** distintos: el inicial desde WS02 (usuario `afenwick`) y el segundo desde DC02 (`SYSTEM`) tras el movimiento lateral. Cada uno tiene su propio **BeaconID** y su propia **SessionKey**, pero comparten el mismo perfil y por tanto la misma **EncryptionKey** de perfil.

### Metodología (paso a paso)

#### Paso 0 — Triage del PCAP: encontrar la conversación C2

Lo primero es entender la forma del tráfico sin descifrar nada todavía. Jerarquía de protocolos, conversaciones TCP y peticiones HTTP:

```bash
capinfos capture.pcapng
tshark -r capture.pcapng -q -z io,phs          # jerarquía de protocolos
tshark -r capture.pcapng -q -z conv,tcp        # conversaciones TCP

# ¿Qué peticiones HTTP hay? URIs, método, User-Agent
tshark -r capture.pcapng -Y http.request \
  -T fields -e frame.number -e ip.src -e ip.dst \
  -e http.request.method -e http.request.uri -e http.user_agent
```

**Por qué:** el patrón de un beacon C2 salta a la vista — la víctima (`192.168.56.22`) hace **POST/GET periódicos** contra `192.168.56.1:8818` con un **User-Agent fijo** (Firefox 20) y tres URIs que rotan: `/api/v1/status`, `/updates/check.php`, `/content.html`. Las respuestas del servidor son JSON `{"status":"ok","data":"...","metrics":"sync"}` donde `data` es la **tarea cifrada**, y cada petición del agente lleva una cabecera propietaria **`X-Beacon-Id`** con un blob base64. Esa cabecera es la primera pista fuerte del framework.

#### Paso 1 — USB drop → montaje de la imagen → DLL sideloading

El vector de entrada es el `.img` del USB. Se identifica y se monta:

```bash
file Q3_Salary_Review.img          # DOS/MBR boot sector, FAT (12/16/32)
mmls Q3_Salary_Review.img          # tabla de particiones (offset en sectores)

# Montaje read-only por loop (offset 1048576 = 2048 sectores * 512)
sudo mount -o ro,loop,offset=1048576 Q3_Salary_Review.img mnt/

# Alternativa forense sin montar: The Sleuth Kit
fls -r -o 2048 Q3_Salary_Review.img          # lista inodos y ficheros
# Carve por inodo (más fiable que copiar del punto de montaje)
for i in 5:docviewer.exe 6:README.txt 10:Salary_Review_Q3_2026.pdf.lnk \
         11:temp.pdf 12:version.dll 14:winupdate.exe; do
  icat -o 2048 Q3_Salary_Review.img ${i%%:*} > "usb/${i#*:}"
done
md5sum usb/*
```

El `.lnk` es el señuelo: `strings -e l usb/Salary_Review_Q3_2026.pdf.lnk` muestra que apunta a **`docviewer.exe`** (no a un PDF), con `Icon number=70` (icono de documento) para engañar al usuario. El `README.txt` refuerza el pretexto de RRHH ("Q3 2026 Salary Review - CONFIDENTIAL ... open the attached document viewer").

**El truco del sideloading:** `docviewer.exe` es un PE **legítimo** (probablemente un visor firmado). En su mismo directorio está `version.dll` **maliciosa**. Windows resuelve `version.dll` por **orden de búsqueda de DLLs** (primero el directorio del ejecutable), así que `docviewer.exe` carga la DLL del atacante en vez de la de `C:\Windows\System32`. Analizando la DLL:

```bash
file usb/version.dll               # PE32+ DLL x86-64, 11 secciones
# Exports: una version.dll legítima reexporta GetFileVersionInfoW, etc.
# La maliciosa suele hacer "export forwarding" a la real + un DllMain que
# despliega el payload. Confirmar en Ghidra/radare2:
rabin2 -E usb/version.dll          # tabla de exports (¿forwards?)
rabin2 -z usb/version.dll | grep -iE "winupdate|http|\.exe|temp"
```

**Por qué funciona el vector:** al ser `docviewer.exe` un binario firmado y legítimo, un allowlisting basado en firma **lo deja pasar**; la DLL maliciosa viaja "a hombros" del proceso de confianza (DLL search-order hijacking). El resultado: `version.dll` deja caer y ejecuta **`winupdate.exe`**, el agente C2, que persiste en disco (por eso la sesión sigue tras retirar el USB).

#### Paso 2 — Identificación del C2: es AdaptixC2

`winupdate.exe` (91 KB, PE32+ con 6 secciones) se analiza en busca de la huella del framework:

```bash
strings -n 5 usb/winupdate.exe | grep -iE \
  "api/v1|check.php|content.html|X-Beacon|Firefox|ConnectorHTTP|pipe|status|metrics"
```

Artefactos clave encontrados:

- Clase **`ConnectorHTTP`** (nombre de clase C++ del transporte HTTP).
- Cabecera **`X-Beacon-Id`** (el blob base64 de la beat).
- Named pipe **`\\.\pipe\%08lx`** (patrón de pipe de tareas/BOF).
- Perfil "malleable" con **3 URIs rotando** y **User-Agent Firefox 20** fijo.
- Respuestas JSON **`{"status":"ok","data":"...","metrics":"sync"}`**.
- Terminología **BeaconID / SessionKey / EncryptionKey / BOF**.

Todo eso es la firma exacta de **AdaptixC2**, un framework de post-explotación open-source (beacons HTTP/SMB/TCP, SOCKS, BOFs), documentado por **Unit42 (Palo Alto)** con un extractor de configuración. El protocolo: `X-Beacon-Id = base64(RC4(beat, EncryptionKey))`; la **beat** contiene el **BeaconID** + una **SessionKey de 16 bytes**; y **todas** las tareas/outputs van cifradas con RC4 usando esa SessionKey.

> **Respuesta Q1 — C2 usado:** `AdaptixC2` (el nombre oficial lleva espacio, `Adaptix C2`; el corrector aceptó `AdaptixC2`).

#### Paso 3 — Extracción de la EncryptionKey del perfil (`.rdata`)

Para descifrar `X-Beacon-Id` necesitamos la **EncryptionKey** (la clave RC4 del perfil), embebida en la sección `.rdata` del agente. El layout de AdaptixC2 es `[4 bytes tamaño LE][config RC4][16 bytes encrypt_key]`:

```python
# adaptix_extract.py — extrae la encrypt_key del .rdata de winupdate.exe
import struct, pefile

pe = pefile.PE("usb/winupdate.exe")
rdata = next(s.get_data() for s in pe.sections
             if s.Name.rstrip(b"\x00") == b".rdata")

def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    out = bytearray(); i = j = 0
    for b in data:
        i = (i + 1) & 0xff; j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xff])
    return bytes(out)

# Buscar el patrón [size][blob][16-byte key] dentro de .rdata
# El size (LE) precede al blob cifrado; los 16 bytes finales = encrypt_key
# (la posición exacta se localiza probando candidatos de 'size' plausibles)
```

Resultado: **EncryptionKey `4580221ac3fe51be1797524a048e552d`** (16 bytes).

#### Paso 3b — Descifrar la beat y su estructura de campos

Con la EncryptionKey se descifra el `X-Beacon-Id` de la primera petición del agente:

```python
import base64
key  = bytes.fromhex("4580221ac3fe51be1797524a048e552d")
xbid = "Cl7gY6So2/cT4yDjuRKh1/IIIliFthBvHdi8nHSIZZzsxjYE8JPn813viEOOLb5Zse"\
       "RfO8DwChiYClLzDqjyf0eDVXoNvAc6Vfrqw/m0oGhyeHUBMdyO87QiBJ3T4Bacp"\
       "HsA0A2W8UW/vbcTyJE6BG+ByNMSSQMzNvQ="
beat = rc4(key, base64.b64decode(xbid))
print(beat.hex())
```

La beat es una serie de campos, muchos **length-prefixed** (4 bytes LE de longitud + valor). Descodificada, la beat de WS02 tiene esta estructura:

| Offset | Campo | Valor (WS02) | Valor (DC02) |
|--------|-------|--------------|--------------|
| `[0:4]`  | Constante de agente/perfil | `be4c0149` | `be4c0149` |
| `[4:8]`  | **BeaconID** (por sesión) | `58debcbb` | **`ddc68fa7`** |
| …        | flags / contadores / arquitectura | | |
| `+len 0x10` | **SessionKey** (16 bytes) | `53fc4c03c7b461befe5dcb268e3d9208` | `289122cf1ec91c67eb89c30642adfea4` |
| `+len 0x11` | dominio | `core.diogenes.htb` | `core.diogenes.htb` |
| `+len`   | host | `WS02` | `DC02` |
| `+len`   | usuario | `afenwick` | `SYSTEM` |
| `+len`   | proceso | `winupdate.exe` | `svc_bkup` |

**Matiz importante:** los primeros 4 bytes (`be4c0149`) son **constantes del perfil compartido** entre ambos beacons; el identificador que cambia por sesión son los **bytes 4-7**. Por eso el BeaconID real del segundo beacon (DC02) es **`ddc68fa7`** (respuesta Q12), y el del primero (WS02) es `58debcbb`. Como ambos `X-Beacon-Id` empiezan cifrando los mismos 4 bytes con la misma clave, ambos blobs base64 comienzan igual (`Cl7gY…`), un detalle útil para reconocer el patrón a ojo en el PCAP.

> **Respuesta Q2 — SessionKey:EncryptionKey:** `53fc4c03c7b461befe5dcb268e3d9208:4580221ac3fe51be1797524a048e552d`

#### Paso 4 — Descifrado completo del PCAP con la SessionKey

Con la SessionKey (RC4) se descifran **todas** las tareas (C2→agente) y outputs (agente→C2). El campo `data` del JSON de respuesta y los cuerpos POST del agente son RC4(SessionKey):

```python
import subprocess
SK = bytes.fromhex("53fc4c03c7b461befe5dcb268e3d9208")

# Sacar todos los cuerpos HTTP con datos, ordenados por frame
out = subprocess.run(
    ["tshark","-r","capture.pcapng",
     "-Y","http && http.file_data && ip.addr==192.168.56.22",
     "-T","fields","-e","frame.number","-e","http.request","-e","http.file_data"],
    capture_output=True, text=True).stdout

for line in out.splitlines():
    fn, is_req, hexdata = (line.split("\t") + ["","",""])[:3]
    raw = bytes.fromhex(hexdata) if hexdata else b""
    # Las respuestas del server envuelven el ciphertext en JSON base64:
    # {"status":"ok","data":"<base64(RC4(task))>","metrics":"sync"}
    dec = rc4(SK, raw)   # (previo strip del envoltorio JSON/base64 según sentido)
    print(f"frame {fn} [{'AGENT->C2' if is_req=='1' else 'C2->AGENT'}] {dec[:200]}")
```

Aparecen los comandos del operador en orden cronológico. El **recon** inicial:

- `whoami` → **`DIOCORE\afenwick`** (SID que termina en `-1125`).
- Routing, interfaces de red, `netstat`.
- **Enum LDAP** de usuarios y equipos del dominio.
- Info de dominio: hijo **`core.diogenes.htb`** + padre **`diogenes.htb`**.

A partir de aquí, cada BOF que el operador sube al agente (COFF amd64, cabecera `64 86`) se puede **carvear** del stream descifrado y analizar con `strings` para identificar la técnica.

#### Paso 5 — Lectura del DACL: WriteProperty sobre userPrincipalName

Un BOF enumera el descriptor de seguridad de `afenwick` (frames 491/494). En el output descifrado aparece un ACE crítico:

```
ACE #4:
  ActiveDirectoryRights : WriteProperty
  ObjectAceType         : 28630ebb-41d5-11d1-a9c1-0000f80367c1   ← schemaIDGUID de userPrincipalName
  SecurityIdentifier    : S-1-5-21-2253468260-689643353-167204612-1125   ← afenwick (quien TIENE el permiso)
  ObjectSID             : S-1-5-21-2253468260-689643353-167204612-1125   ← objeto donde reside la property
```

**Por qué importa:** `afenwick` tiene **`WriteProperty` sobre su propio `userPrincipalName`**. El GUID `28630ebb-41d5-11d1-a9c1-0000f80367c1` es el **schemaIDGUID** del atributo `userPrincipalName` (verificable en el schema de AD). Poder reescribir el UPN de una cuenta es **exactamente el requisito** de ResetNightmare (CVE-2026-27912): permite pedir un TGT "enterprise" que resuelve a **otra** cuenta.

> **Respuesta Q5 — ObjectSID de la Property con WriteProperty:** `28630ebb-41d5-11d1-a9c1-0000f80367c1` *(schemaIDGUID de `userPrincipalName`; alternativa en formato SID del objeto afenwick: `S-1-5-21-2253468260-689643353-167204612-1125`)*.

#### Paso 6 — Internal Monologue + correlación EVTX + hashcat

Para tener credenciales de `afenwick` (no solo su token), el operador ejecuta un BOF de **Internal Monologue** (frame 609). Esta técnica **captura NetNTLMv2 sin tocar LSASS**: fuerza una autenticación NTLM local del SSP con un **challenge fijo `1122334455667788`** y `SessionKeyStatus: Missing` (fuerza NetNTLMv2 downgradeado y capturable), y se queda con la respuesta.

Ese acto deja **una huella en el único EVTX entregado**. Se parsea y se busca el EventID 4021:

```bash
# Con evtx_dump (rust) o python-evtx
evtx_dump "C/.../Microsoft-Windows-NTLM%4Operational.evtx" | \
  grep -A20 "EventID>4021"
# o con Chainsaw para hunting con reglas:
chainsaw hunt "C/.../winevt/logs/" -s sigma/ --mapping mappings/sigma-event-logs-all.yml
```

```python
# python-evtx: extraer EventID 4021 y su timestamp
import evtx, xml.etree.ElementTree as ET
ns = {"ns":"http://schemas.microsoft.com/win/2004/08/events/event"}
for r in evtx.PyEvtxParser("Microsoft-Windows-NTLM%4Operational.evtx").records():
    root = ET.fromstring(r["data"])
    if root.find(".//ns:EventID", ns).text == "4021":
        print(r["timestamp"])   # ProcessName: winupdate, NtlmUsageReason: NTLM was called directly
```

El EventID **4021** ("NTLM was called directly") con `ProcessName: winupdate` fija el momento del ataque: **`2026-09-09 20:44:11`**.

Con el NetNTLMv2 capturado en el PCAP se monta el hash de hashcat y se crackea:

```bash
cat > ntlmv2.txt <<'EOF'
afenwick::DIOCORE:1122334455667788:032b0b4aa446b7d68c6780135ef2ec24:0101000000000000b98318f89b40dd0188710ab71b4825d100000000080050005000000000000000000000000020000048e7e02afbb4d8dd89a1bf00f8976f4da60de7b351998f52913b13ae3f7908aad383770bcba0bda27095df48e2e35cf4256ad28f010d93ad6af198c52ab6f9be0a00100000000000000000000000000000000000090000000000000000000000
EOF
hashcat -m 5600 ntlmv2.txt /usr/share/wordlists/rockyou.txt -O
hashcat -m 5600 ntlmv2.txt --show
# afenwick::DIOCORE:...:*Seash5lls*
```

La password sale de rockyou: **`*Seash5lls*`**. Se confirma además en los argumentos del BOF de ResetNightmare (`/upnpass:*Seash5lls*`).

> **Respuesta Q6 — Ataque nombrado + fecha:** `INTERNAL_MONOLOGUE:2026-09-09 20:44:11`
>
> **Respuesta Q7 — Credenciales usadas:** `afenwick:*Seash5lls*`

#### Paso 7 — ResetNightmare (CVE-2026-27912)

El operador sube un **BOF custom** de 70169 bytes (frames 730/746) con funciones `RESET_NIGHTMARE_RUN`, `LdapSetUPN`, `ResetTargetPassword`. Su md5:

```bash
md5sum /tmp/bofs/reset_nightmare.o   # 583236cc3ef2488fb133385bcd75825e
```

**Cómo funciona ResetNightmare (Semperis):** el parche de 2021 contra el "Bronze Bit"/PAC forzó la comprobación `PAC_REQUESTOR` **solo en el path TGS-REQ**. El protocolo **change-password (RFC 3244, Kerberos puerto 464)** no pasa por esa comprobación. Encadenando:

1. Con `WriteProperty` sobre su UPN, `afenwick` escribe un **UPN falso** que coincide con el de la víctima (jreed).
2. Solicita un **AS-REQ *enterprise*** (usando el UPN como principal enterprise) → el KDC emite un **TGT que resuelve a `jreed`**.
3. Con ese TGT usa **kadmin/changepw (puerto 464)** para **resetear la contraseña de jreed** — sin DCSync, sin ser DA.

El output descifrado lo confirma:

```
[*] Action: ResetNightmare (CVE-2026-27912)
[+] ResetNightmare succeeded! jreed's password is now: Aigohng8vai0seish4zi
```

> **Respuesta Q3 — CVE de privesc:** `CVE-2026-27912`
>
> **Respuesta Q4 — md5sum del BOF custom:** `583236cc3ef2488fb133385bcd75825e`
>
> **Respuesta Q8 — Usuario objetivo + password resultante:** `jreed:Aigohng8vai0seish4zi`

#### Paso 8 — Impersonación de token

Con las credenciales de `jreed` ya bajo control, el agente llama a `LogonUser(jreed)` y genera un token de impersonación:

```
The user impersonated successfully: DIOCORE\jreed (logon: 9)
```

**LogonType 9 = `NewCredentials`**, el equivalente a `runas /netonly`: el proceso mantiene la identidad local pero usa las nuevas credenciales **para autenticaciones de red salientes**. Es exactamente lo que se necesita para autenticarse contra DC02 como `jreed` sin cargar un perfil interactivo. LogonType 9 es una huella muy útil para threat hunting.

> **Respuesta Q9 — Nuevo token logon type:** `9`

#### Paso 9 — Movimiento lateral a DC02 y segundo beacon

Con el token `jreed`, el operador copia un nuevo agente (**103936 bytes**) al share administrativo de DC02 y secuestra un servicio existente:

```
Uploading binary (103936 bytes) to: \\dc02\ADMIN$\svc_bkup
Opening service: defragsvc          (original: svchost.exe -k defragsvc)
```

Se **secuestra el service group `defragsvc`** (el `-k defragsvc` de `svchost.exe` define el grupo de servicios). Al reiniciar el servicio, nace un **segundo beacon en DC02 como SYSTEM** (proceso `svc_bkup`). Su beat descifrada (misma EncryptionKey de perfil, ver Paso 3b) da:

- **BeaconID `ddc68fa7`**
- **SessionKey `289122cf1ec91c67eb89c30642adfea4`**

Este segundo beacon es el punto de partida del siguiente Sherlock (S09 *Last Light*, forense de memoria de DC02: golden tickets, RBCD, robo de token).

> **Respuesta Q10 — Ruta del movimiento lateral:** `\\dc02\ADMIN$\svc_bkup` *(con IP: `\\192.168.56.11\ADMIN$\svc_bkup`)*
>
> **Respuesta Q11 — Service group usado:** `defragsvc`
>
> **Respuesta Q12 — Nuevo BeaconID:SessionKey:** `ddc68fa7:289122cf1ec91c67eb89c30642adfea4`

### Cronología

| Fecha/hora (UTC) | Evento | Evidencia |
|------------------|--------|-----------|
| 2026-09-10 01:24:47 | Timestamps del `.lnk` señuelo en el USB | `.lnk` ctime/atime/mtime |
| (t0) | Ejecución del `.lnk` → `docviewer.exe` sideloadea `version.dll` → deja `winupdate.exe` | USB / disco |
| (t0+) | Primer beacon WS02 → C2 `192.168.56.1:8818` (`X-Beacon-Id` `Cl7gY…`) | PCAP frames iniciales |
| (recon) | `whoami`, routing, LDAP user/computer enum, dominio hijo+padre | PCAP (SessionKey WS02) |
| (DACL) | BOF lee el descriptor de seguridad de afenwick → WriteProperty sobre UPN | PCAP frames 491/494 |
| **2026-09-09 20:44:11** | **Internal Monologue** captura NetNTLMv2 de afenwick | EVTX EventID 4021 |
| (crack) | hashcat 5600 + rockyou → `*Seash5lls*` | offline |
| (privesc) | BOF ResetNightmare (CVE-2026-27912) → password de jreed reseteada | PCAP frames 730/746 |
| (token) | `LogonUser(jreed)` → token LogonType 9 | PCAP output |
| (lateral) | Upload 103936 B a `\\dc02\ADMIN$\svc_bkup`, hijack `defragsvc` | PCAP output |
| (t_final) | Segundo beacon DC02 SYSTEM (`svc_bkup`, BeaconID `ddc68fa7`) | PCAP (SessionKey DC02) |

> Nota sobre fechas: el EventID 4021 registra **2026-09-09 20:44:11** para la captura NTLM, mientras que los timestamps del `.lnk` son del **2026-09-10**. La discrepancia es habitual en estos labs (relojes de generación de artefactos vs. tráfico); la respuesta graduada de Q6 es la del EVTX.

### Respuestas / flags

| # | Pregunta | Respuesta |
|---|----------|-----------|
| 1 | C2 usado (string) | `AdaptixC2` |
| 2 | SessionKey:EncryptionKey | `53fc4c03c7b461befe5dcb268e3d9208:4580221ac3fe51be1797524a048e552d` |
| 3 | CVE de privesc | `CVE-2026-27912` |
| 4 | md5sum del BOF custom | `583236cc3ef2488fb133385bcd75825e` |
| 5 | ObjectSID de la Property con WriteProperty | `28630ebb-41d5-11d1-a9c1-0000f80367c1` *(schemaIDGUID de `userPrincipalName`; alternativa en formato SID del objeto afenwick: `S-1-5-21-2253468260-689643353-167204612-1125`)* |
| 6 | Ataque nombrado + fecha | `INTERNAL_MONOLOGUE:2026-09-09 20:44:11` |
| 7 | Credenciales usadas | `afenwick:*Seash5lls*` |
| 8 | Usuario objetivo + password resultante | `jreed:Aigohng8vai0seish4zi` |
| 9 | Nuevo token logon type | `9` |
| 10 | Ruta del movimiento lateral | `\\dc02\ADMIN$\svc_bkup` *(con IP: `\\192.168.56.11\ADMIN$\svc_bkup`)* |
| 11 | Service group usado | `defragsvc` |
| 12 | Nuevo BeaconID:SessionKey | `ddc68fa7:289122cf1ec91c67eb89c30642adfea4` |

> **Nota:** las preguntas 5 y 10 tienen formato ambiguo. La pregunta 5 etiqueta como "ObjectSID" el `ObjectAceType` de la property (`userPrincipalName`); si el corrector exige formato SID real, usar `S-1-5-21-2253468260-689643353-167204612-1125`. Para la 10, si pide IP en vez de hostname, usar `\\192.168.56.11\ADMIN$\svc_bkup`.

### IOCs

| Tipo | Indicador | Contexto |
|------|-----------|----------|
| MD5 | `aca111935d339b17544ead3e8c2c8831` | `docviewer.exe` (host legítimo del sideload) |
| MD5 | `6e787589a69ce783b0380b0de86a2d68` | `version.dll` (DLL maliciosa sideloaded) |
| MD5 | `b1c8c95d3bfa22780076084377584739` | `winupdate.exe` (agente AdaptixC2) |
| MD5 | `583236cc3ef2488fb133385bcd75825e` | BOF custom ResetNightmare (70169 B) |
| Fichero | `Salary_Review_Q3_2026.pdf.lnk` | `.lnk` señuelo → `docviewer.exe` |
| IP:puerto | `192.168.56.1:8818` | Team server C2 (AdaptixC2) |
| Host | `192.168.56.22` (WS02) | Estación comprometida (afenwick) |
| Host | `192.168.56.11` (DC02) | DC hijo pivotado (SYSTEM) |
| HTTP | UA `Firefox 20`; URIs `/api/v1/status`, `/updates/check.php`, `/content.html` | Perfil malleable AdaptixC2 |
| HTTP | Cabecera `X-Beacon-Id`; JSON `{"status":"ok","data":"...","metrics":"sync"}` | Canal C2 |
| Cripto | EncryptionKey `4580221ac3fe51be1797524a048e552d` | RC4 de perfil |
| Cripto | SessionKey WS02 `53fc4c03c7b461befe5dcb268e3d9208` / DC02 `289122cf1ec91c67eb89c30642adfea4` | RC4 de sesión |
| BeaconID | `58debcbb` (WS02) · `ddc68fa7` (DC02) | Bytes 4-7 de la beat |
| NTLM | Challenge fijo `1122334455667788`, EventID 4021 | Firma de Internal Monologue |
| Servicio | `svc_bkup` / service group `defragsvc` | Persistencia SYSTEM en DC02 |
| Named pipe | `\\.\pipe\%08lx` | Pipe de tareas/BOF del agente |

### Mapeo MITRE ATT&CK

| Táctica | Técnica | ID | Evidencia |
|---------|---------|----|-----------|
| Initial Access | Replication Through Removable Media | T1091 | USB drop `Q3_Salary_Review.img` |
| Execution | User Execution: Malicious File (`.lnk`) | T1204.002 | `Salary_Review_Q3_2026.pdf.lnk` |
| Defense Evasion / Persistence | Hijack Execution Flow: DLL Side-Loading | T1574.002 | `docviewer.exe` + `version.dll` |
| Command & Control | Application Layer Protocol: Web (HTTP) | T1071.001 | Beacons AdaptixC2 HTTP |
| Command & Control | Encrypted Channel: Symmetric (RC4) | T1573.001 | EncryptionKey/SessionKey RC4 |
| Discovery | Domain Trust / Account / Remote System Discovery | T1482 / T1087 / T1018 | Recon LDAP, dominio hijo+padre |
| Credential Access | Forced Authentication (Internal Monologue) | T1187 | NetNTLMv2, challenge `1122334455667788` |
| Credential Access | Brute Force: Password Cracking | T1110.002 | hashcat 5600 + rockyou |
| Privilege Escalation | Abuse Elevation / Valid Accounts (ResetNightmare) | T1078 / T1484 | CVE-2026-27912, WriteProperty UPN |
| Privilege Escalation | Access Token Manipulation | T1134 | LogonType 9 (NewCredentials) |
| Lateral Movement | Remote Services: SMB Admin Shares | T1021.002 | `\\dc02\ADMIN$\svc_bkup` |
| Persistence / Priv Esc | Create or Modify System Process: Windows Service | T1543.003 | Hijack `defragsvc` → `svc_bkup` SYSTEM |

### Detección y remediación

**Detección**

- **DLL sideloading:** alertar sobre binarios legítimos (`docviewer.exe`, o cualquier host firmado) cargando DLLs desde rutas de usuario/removibles (`version.dll`, `dbghelp.dll`, etc.) fuera de `System32`. Sysmon EventID 7 (Image Loaded) con firma no coincidente + ruta sospechosa.
- **USB / removable media:** habilitar auditoría de montaje de dispositivos (Sysmon 25 / EventID 6416) y bloquear ejecución desde unidades extraíbles con AppLocker/WDAC.
- **Internal Monologue:** el **EventID 4021** del canal `Microsoft-Windows-NTLM/Operational` con `NtlmUsageReason: NTLM was called directly` y challenge **`1122334455667788`** es una firma directa. Alertar sobre NetNTLMv2 con ese challenge fijo.
- **ResetNightmare (CVE-2026-27912):** monitorizar cambios de `userPrincipalName` (Event 5136, modificación de atributo de directorio) y **cambios de contraseña vía kpasswd (puerto 464)** que no procedan de flujos legítimos; correlacionar AS-REQ con nombres *enterprise* anómalos.
- **AdaptixC2 network:** firmar el perfil malleable (UA Firefox 20 fijo, URIs `/api/v1/status` + `/updates/check.php` + `/content.html`, cabecera `X-Beacon-Id`, JSON `metrics: sync`) con reglas Suricata/Zeek.
- **Service hijack:** Event 7045/4697 (instalación/modificación de servicio) y cambios en `svchost -k <grupo>`; binario `svc_bkup` en `ADMIN$`.

**Remediación**

- **Parchear CVE-2026-27912** (fix de Microsoft de abr-2026 que extiende la comprobación `PAC_REQUESTOR` al path change-password).
- **Revisar y purgar ACEs peligrosos:** ningún usuario debe tener `WriteProperty` sobre su propio `userPrincipalName` (ni sobre el de otros). Auditar DACLs con BloodHound (`WriteSPN`/`WriteProperty`/`GenericWrite` sobre `userPrincipalName`).
- **Desactivar NTLM** donde sea posible y aplicar SMB/LDAP signing + channel binding para mitigar coerción/relay.
- **Endurecer allowlisting** con WDAC basado en **hash/atributos** (no solo firma del proceso padre) para frustrar el sideloading.
- **Contención:** aislar WS02 y DC02, rotar credenciales de `afenwick`, `jreed` y **krbtgt** (doble reset) del dominio hijo, y hunt de golden tickets/RBCD en DC02 (ver S09).

### Lecciones

- **DLL sideloading** con binario legítimo (`docviewer.exe` + `version.dll`) es un vector de entrega sigiloso vía USB que evade allowlisting basado en firmas: la DLL maliciosa viaja "a hombros" de un proceso de confianza y persiste tras retirar el medio.
- El tráfico de **AdaptixC2** es descifrable si se extrae la `encrypt_key` del `.rdata` del agente: la cadena `EncryptionKey → beat → SessionKey → todo el C2` reconstruye el PCAP, que es la llave que **desbloquea casi todas las respuestas**. Sin ese paso el reto es irresoluble.
- La **estructura de la beat** (constante de perfil + BeaconID por sesión + SessionKey length-prefixed + host/user/proceso) permite distinguir los dos beacons y sus claves independientes.
- **ResetNightmare (CVE-2026-27912)** encadena `WriteProperty` sobre `userPrincipalName` + AS-REQ enterprise + kadmin/changepw para tomar el password de otro usuario **sin DCSync** — un abuso de identidad Kerberos peligroso y silencioso que aprovecha un hueco en el check `PAC_REQUESTOR`.
- **Internal Monologue** captura NetNTLMv2 **sin tocar LSASS**; el challenge fijo `1122334455667788` en el EVTX (EventID 4021) es una firma detectable y a la vez la ancla temporal del ataque.
- **LogonType 9 (NewCredentials)** es la huella de impersonación tipo `runas /netonly`, útil para threat hunting y para explicar cómo el agente se autentica como `jreed` contra el DC.
- **Correlación multi-artefacto:** ninguna evidencia por separado cuenta la historia — PCAP (comandos y claves), USB/disco (entrega) y EVTX (timestamp del NTLM) hay que **cruzarlos** para reconstruir la línea temporal completa.

### Serie · The Reichenbach Directive

| # | Sherlock | Enlace |
|---|----------|--------|
| S01 | Silent Dividend | [../2026-09-15-holmes2026-s01-silent-dividend/](../2026-09-15-holmes2026-s01-silent-dividend/) |
| S02 | Bottle Out | [../2026-09-16-holmes2026-s02-bottle-out/](../2026-09-16-holmes2026-s02-bottle-out/) |
| S03 | Whisper Chain | [../2026-09-17-holmes2026-s03-whisper-chain/](../2026-09-17-holmes2026-s03-whisper-chain/) |
| S04 | Paper Ghost | [../2026-09-18-holmes2026-s04-paper-ghost/](../2026-09-18-holmes2026-s04-paper-ghost/) |
| S05 | Poisoned Branch | [../2026-09-19-holmes2026-s05-poisoned-branch/](../2026-09-19-holmes2026-s05-poisoned-branch/) |
| S06 | Silent Passenger | [../2026-09-20-holmes2026-s06-silent-passenger/](../2026-09-20-holmes2026-s06-silent-passenger/) |
| S07 | Iron Feather | [../2026-09-21-holmes2026-s07-iron-feather/](../2026-09-21-holmes2026-s07-iron-feather/) |
| **S08** | **Borrowed Name** ← *este* | [../2026-09-22-holmes2026-s08-borrowed-name/](../2026-09-22-holmes2026-s08-borrowed-name/) |
| S09 | Last Light | [../2026-09-23-holmes2026-s09-last-light/](../2026-09-23-holmes2026-s09-last-light/) |

<a id="en"></a>

## 🇬🇧 English

### Scenario

After the drone recovery (previous Sherlock, *Iron Feather*), Eleanor Mercer spots an **unauthorized outbound session** from a protected workstation (WS02) inside the **DIOGENES** forest. The activity matches no approved software and —most worryingly— **continues after a physical object is removed** from the machine: a USB drop disguised as an HR document ("Q3 Salary Review"). The malware has already copied itself to disk and no longer depends on the USB.

This Sherlock is pure **Active Directory intrusion DFIR reconstructed from the wire**: we have no shell and no full EDR logs, only an **encrypted C2 PCAP**, the **USB image**, a handful of binaries, and **a single EVTX** (the NTLM operational channel). Everything else —which C2 it is, what keys it uses, what commands the operator ran, how they escalated and how they jumped to the DC— must be **derived by decrypting the traffic**. That is the heart of the challenge: without reconstructing the PCAP, almost no answer can be given.

Target forest:

- Root **`diogenes.htb`** → DC **DIOCORE**
- Child **`core.diogenes.htb`** → DC **DC02** (`192.168.56.11`)
- Compromised workstation **WS02** (`192.168.56.22`)
- Attacker C2 team server: **`192.168.56.1:8818`**
- Users involved: **afenwick** (initial compromise, WS02, SID `...-1125`), **jreed** (privesc target), rfairfax (root DA/EA, appears in S09).
- Final implant deployed on DC02: process **`svc_bkup`** hijacking the **`defragsvc`** service group.
- Attacker: APT **NAPOLEON** (DIOGENES/MurkNet arc).

The goal is to reconstruct the **entire** chain: how the operator got in (delivery), which C2 with which keys, what recon they ran, how they abused an AD right to steal another user's identity, and how they moved laterally to the child DC as SYSTEM.

### Artifacts and tooling

**Provided evidence (`BorrowedName/`):**

| Artifact | Description |
|----------|-------------|
| `evidence/capture.pcapng` | C2 traffic (HTTP with proprietary RC4 encryption), 692 KB, ~900 frames |
| `evidence/Q3_Salary_Review.img` | FAT32 USB image (134 MB), `.lnk` → `docviewer.exe` |
| `evidence/usb/` | Carved USB contents: `docviewer.exe`, `version.dll`, `winupdate.exe`, `Salary_Review_Q3_2026.pdf.lnk`, `temp.pdf`, `README.txt` |
| `evidence/C/Windows/System32/winevt/logs/Microsoft-Windows-NTLM%4Operational.evtx` | Host NTLM logs (EventID **4021**) |
| Narrative PDF (Chapters 10-12) | *The Reichenbach Directive* arc context |

The evidence shipped inside a password-protected ZIP (`danger.zip`, password `PaedeiRae1xiexahwuno`) — a common pattern in these Sherlocks to keep the analyst's AV from nuking the samples on extraction.

**Tools:** `tshark`/`pyshark` (triage and PCAP extraction), PE analysis (`file`, `strings`, `pefile`, Ghidra/radare2), the **AdaptixC2 config extractor** (Unit42 methodology), Python **RC4** scripts to decrypt traffic, **The Sleuth Kit** (`mmls`/`fls`/`icat`) and `mount -o loop` for the USB, `python-evtx`/`evtx_dump`/Chainsaw for the EVTX, and **hashcat** (mode 5600 + rockyou) for the NetNTLMv2.

USB binary hashes (`md5sum usb/*`):

```
aca111935d339b17544ead3e8c2c8831  docviewer.exe   (legitimate sideload host)
6e787589a69ce783b0380b0de86a2d68  version.dll     (malicious sideloaded DLL)
b1c8c95d3bfa22780076084377584739  winupdate.exe   (AdaptixC2 agent)
```

### Network topology and actors

Before diving in, it helps to fix who talks to whom in the PCAP (confirmed by the traffic itself and by the DNS resolution the C2 returns):

```
[ WS02 192.168.56.22 ]  ──HTTP/RC4──►  [ C2 team server 192.168.56.1:8818 ]
   afenwick (winupdate.exe)                     APT NAPOLEON
        │
        │  (after ResetNightmare + jreed impersonation)
        ▼
[ DC02 192.168.56.11 ]  ──HTTP/RC4──►  [ C2 team server 192.168.56.1:8818 ]
   SYSTEM (svc_bkup, service group defragsvc)   second beacon
```

The PCAP carries **two distinct beacons**: the initial one from WS02 (user `afenwick`) and the second from DC02 (`SYSTEM`) after lateral movement. Each has its own **BeaconID** and its own **SessionKey**, but they share the same profile and therefore the same profile **EncryptionKey**.

### Methodology (step by step)

#### Step 0 — PCAP triage: find the C2 conversation

First, understand the shape of the traffic without decrypting anything yet. Protocol hierarchy, TCP conversations and HTTP requests:

```bash
capinfos capture.pcapng
tshark -r capture.pcapng -q -z io,phs          # protocol hierarchy
tshark -r capture.pcapng -q -z conv,tcp        # TCP conversations

# Which HTTP requests exist? URIs, method, User-Agent
tshark -r capture.pcapng -Y http.request \
  -T fields -e frame.number -e ip.src -e ip.dst \
  -e http.request.method -e http.request.uri -e http.user_agent
```

**Why:** the beacon pattern jumps out — the victim (`192.168.56.22`) makes **periodic POST/GET** to `192.168.56.1:8818` with a **fixed User-Agent** (Firefox 20) and three rotating URIs: `/api/v1/status`, `/updates/check.php`, `/content.html`. Server responses are JSON `{"status":"ok","data":"...","metrics":"sync"}` where `data` is the **encrypted task**, and each agent request carries a proprietary **`X-Beacon-Id`** header with a base64 blob. That header is the first strong hint at the framework.

#### Step 1 — USB drop → mounting the image → DLL sideloading

The entry vector is the USB `.img`. Identify and mount it:

```bash
file Q3_Salary_Review.img          # DOS/MBR boot sector, FAT (12/16/32)
mmls Q3_Salary_Review.img          # partition table (offset in sectors)

# Read-only loop mount (offset 1048576 = 2048 sectors * 512)
sudo mount -o ro,loop,offset=1048576 Q3_Salary_Review.img mnt/

# Mount-free forensic alternative: The Sleuth Kit
fls -r -o 2048 Q3_Salary_Review.img          # list inodes and files
# Carve by inode (more reliable than copying from the mount point)
for i in 5:docviewer.exe 6:README.txt 10:Salary_Review_Q3_2026.pdf.lnk \
         11:temp.pdf 12:version.dll 14:winupdate.exe; do
  icat -o 2048 Q3_Salary_Review.img ${i%%:*} > "usb/${i#*:}"
done
md5sum usb/*
```

The `.lnk` is the lure: `strings -e l usb/Salary_Review_Q3_2026.pdf.lnk` shows it points to **`docviewer.exe`** (not to a PDF), with `Icon number=70` (a document icon) to trick the user. The `README.txt` reinforces the HR pretext ("Q3 2026 Salary Review - CONFIDENTIAL ... open the attached document viewer").

**The sideloading trick:** `docviewer.exe` is a **legitimate** PE (likely a signed viewer). In the same folder sits a **malicious** `version.dll`. Windows resolves `version.dll` via **DLL search order** (executable directory first), so `docviewer.exe` loads the attacker DLL instead of the one in `C:\Windows\System32`. Analysing the DLL:

```bash
file usb/version.dll               # PE32+ DLL x86-64, 11 sections
# Exports: a legit version.dll re-exports GetFileVersionInfoW, etc.
# The malicious one usually forwards those exports to the real DLL + a
# DllMain that drops the payload. Confirm in Ghidra/radare2:
rabin2 -E usb/version.dll          # export table (forwards?)
rabin2 -z usb/version.dll | grep -iE "winupdate|http|\.exe|temp"
```

**Why the vector works:** because `docviewer.exe` is a signed, legitimate binary, signature-based allowlisting **lets it run**; the malicious DLL rides on the back of the trusted process (DLL search-order hijacking). The result: `version.dll` drops and runs **`winupdate.exe`**, the C2 agent, which persists on disk (hence the session survives once the USB is pulled).

#### Step 2 — C2 identification: it's AdaptixC2

`winupdate.exe` (91 KB, PE32+ with 6 sections) is analysed for the framework's fingerprint:

```bash
strings -n 5 usb/winupdate.exe | grep -iE \
  "api/v1|check.php|content.html|X-Beacon|Firefox|ConnectorHTTP|pipe|status|metrics"
```

Key artifacts found:

- **`ConnectorHTTP`** class (C++ class name of the HTTP transport).
- **`X-Beacon-Id`** header (the base64 beat blob).
- Named pipe **`\\.\pipe\%08lx`** (task/BOF pipe pattern).
- A "malleable" profile with **3 rotating URIs** and a **fixed Firefox 20** User-Agent.
- JSON responses **`{"status":"ok","data":"...","metrics":"sync"}`**.
- **BeaconID / SessionKey / EncryptionKey / BOF** terminology.

That is the exact signature of **AdaptixC2**, an open-source post-exploitation framework (HTTP/SMB/TCP beacons, SOCKS, BOFs), documented by **Unit42 (Palo Alto)** with a config extractor. The protocol: `X-Beacon-Id = base64(RC4(beat, EncryptionKey))`; the **beat** contains the **BeaconID** + a **16-byte SessionKey**; and **all** tasks/outputs are RC4-encrypted with that SessionKey.

> **Answer Q1 — C2 used:** `AdaptixC2` (the official name has a space, `Adaptix C2`; the grader accepted `AdaptixC2`).

#### Step 3 — Extracting the profile EncryptionKey from `.rdata`

To decrypt `X-Beacon-Id` we need the **EncryptionKey** (the profile RC4 key), embedded in the agent's `.rdata` section. AdaptixC2's layout is `[4-byte LE size][RC4 config][16-byte encrypt_key]`:

```python
# adaptix_extract.py — pull the encrypt_key from winupdate.exe's .rdata
import struct, pefile

pe = pefile.PE("usb/winupdate.exe")
rdata = next(s.get_data() for s in pe.sections
             if s.Name.rstrip(b"\x00") == b".rdata")

def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    out = bytearray(); i = j = 0
    for b in data:
        i = (i + 1) & 0xff; j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xff])
    return bytes(out)

# Locate the [size][blob][16-byte key] pattern inside .rdata
# The LE size precedes the encrypted blob; the trailing 16 bytes = encrypt_key
# (the exact position is found by testing plausible 'size' candidates)
```

Result: **EncryptionKey `4580221ac3fe51be1797524a048e552d`** (16 bytes).

#### Step 3b — Decrypting the beat and its field structure

With the EncryptionKey we decrypt the `X-Beacon-Id` of the agent's first request:

```python
import base64
key  = bytes.fromhex("4580221ac3fe51be1797524a048e552d")
xbid = "Cl7gY6So2/cT4yDjuRKh1/IIIliFthBvHdi8nHSIZZzsxjYE8JPn813viEOOLb5Zse"\
       "RfO8DwChiYClLzDqjyf0eDVXoNvAc6Vfrqw/m0oGhyeHUBMdyO87QiBJ3T4Bacp"\
       "HsA0A2W8UW/vbcTyJE6BG+ByNMSSQMzNvQ="
beat = rc4(key, base64.b64decode(xbid))
print(beat.hex())
```

The beat is a series of fields, many **length-prefixed** (4-byte LE length + value). Decoded, the WS02 beat has this structure:

| Offset | Field | Value (WS02) | Value (DC02) |
|--------|-------|--------------|--------------|
| `[0:4]`  | Agent/profile constant | `be4c0149` | `be4c0149` |
| `[4:8]`  | **BeaconID** (per session) | `58debcbb` | **`ddc68fa7`** |
| …        | flags / counters / architecture | | |
| `+len 0x10` | **SessionKey** (16 bytes) | `53fc4c03c7b461befe5dcb268e3d9208` | `289122cf1ec91c67eb89c30642adfea4` |
| `+len 0x11` | domain | `core.diogenes.htb` | `core.diogenes.htb` |
| `+len`   | host | `WS02` | `DC02` |
| `+len`   | user | `afenwick` | `SYSTEM` |
| `+len`   | process | `winupdate.exe` | `svc_bkup` |

**Important nuance:** the first 4 bytes (`be4c0149`) are a **shared profile constant** across both beacons; the per-session identifier lives in **bytes 4-7**. So the real BeaconID of the second beacon (DC02) is **`ddc68fa7`** (answer Q12), and of the first (WS02) is `58debcbb`. Since both `X-Beacon-Id` blobs encrypt the same first 4 bytes with the same key, both base64 blobs start identically (`Cl7gY…`) — a handy tell for spotting the pattern by eye in the PCAP.

> **Answer Q2 — SessionKey:EncryptionKey:** `53fc4c03c7b461befe5dcb268e3d9208:4580221ac3fe51be1797524a048e552d`

#### Step 4 — Full PCAP decryption with the SessionKey

With the SessionKey (RC4) we decrypt **all** tasks (C2→agent) and outputs (agent→C2). The response JSON `data` field and the agent's POST bodies are RC4(SessionKey):

```python
import subprocess
SK = bytes.fromhex("53fc4c03c7b461befe5dcb268e3d9208")

# Pull every HTTP body with data, ordered by frame
out = subprocess.run(
    ["tshark","-r","capture.pcapng",
     "-Y","http && http.file_data && ip.addr==192.168.56.22",
     "-T","fields","-e","frame.number","-e","http.request","-e","http.file_data"],
    capture_output=True, text=True).stdout

for line in out.splitlines():
    fn, is_req, hexdata = (line.split("\t") + ["","",""])[:3]
    raw = bytes.fromhex(hexdata) if hexdata else b""
    # Server responses wrap the ciphertext in JSON base64:
    # {"status":"ok","data":"<base64(RC4(task))>","metrics":"sync"}
    dec = rc4(SK, raw)   # (strip JSON/base64 wrapper first, per direction)
    print(f"frame {fn} [{'AGENT->C2' if is_req=='1' else 'C2->AGENT'}] {dec[:200]}")
```

The operator's commands surface in chronological order. Initial **recon**:

- `whoami` → **`DIOCORE\afenwick`** (SID ending in `-1125`).
- Routing, network interfaces, `netstat`.
- **LDAP enumeration** of domain users and computers.
- Domain info: child **`core.diogenes.htb`** + parent **`diogenes.htb`**.

From here, each BOF the operator uploads to the agent (amd64 COFF, `64 86` header) can be **carved** out of the decrypted stream and examined with `strings` to identify the technique.

#### Step 5 — DACL read: WriteProperty over userPrincipalName

A BOF enumerates `afenwick`'s security descriptor (frames 491/494). A critical ACE appears in the decrypted output:

```
ACE #4:
  ActiveDirectoryRights : WriteProperty
  ObjectAceType         : 28630ebb-41d5-11d1-a9c1-0000f80367c1   ← userPrincipalName schemaIDGUID
  SecurityIdentifier    : S-1-5-21-2253468260-689643353-167204612-1125   ← afenwick (who HOLDS the right)
  ObjectSID             : S-1-5-21-2253468260-689643353-167204612-1125   ← object where the property lives
```

**Why it matters:** `afenwick` holds **`WriteProperty` over its own `userPrincipalName`**. The GUID `28630ebb-41d5-11d1-a9c1-0000f80367c1` is the **schemaIDGUID** of the `userPrincipalName` attribute (verifiable in the AD schema). Being able to rewrite an account's UPN is **exactly the prerequisite** for ResetNightmare (CVE-2026-27912): it lets you request an "enterprise" TGT that resolves to **another** account.

> **Answer Q5 — ObjectSID of the WriteProperty property:** `28630ebb-41d5-11d1-a9c1-0000f80367c1` *(userPrincipalName schemaIDGUID; SID-format alternative for the afenwick object: `S-1-5-21-2253468260-689643353-167204612-1125`)*.

#### Step 6 — Internal Monologue + EVTX correlation + hashcat

To obtain `afenwick`'s credentials (not just its token), the operator runs an **Internal Monologue** BOF (frame 609). This technique **captures NetNTLMv2 without touching LSASS**: it coerces a local NTLM SSP authentication with a **fixed challenge `1122334455667788`** and `SessionKeyStatus: Missing` (forcing a downgraded, capturable NetNTLMv2), and keeps the response.

That act leaves **a trace in the only EVTX provided**. Parse it and look for EventID 4021:

```bash
# With evtx_dump (rust) or python-evtx
evtx_dump "C/.../Microsoft-Windows-NTLM%4Operational.evtx" | \
  grep -A20 "EventID>4021"
# or Chainsaw for rule-based hunting:
chainsaw hunt "C/.../winevt/logs/" -s sigma/ --mapping mappings/sigma-event-logs-all.yml
```

```python
# python-evtx: extract EventID 4021 and its timestamp
import evtx, xml.etree.ElementTree as ET
ns = {"ns":"http://schemas.microsoft.com/win/2004/08/events/event"}
for r in evtx.PyEvtxParser("Microsoft-Windows-NTLM%4Operational.evtx").records():
    root = ET.fromstring(r["data"])
    if root.find(".//ns:EventID", ns).text == "4021":
        print(r["timestamp"])   # ProcessName: winupdate, NtlmUsageReason: NTLM was called directly
```

EventID **4021** ("NTLM was called directly") with `ProcessName: winupdate` pins the attack time: **`2026-09-09 20:44:11`**.

With the NetNTLMv2 captured in the PCAP we build the hashcat hash and crack it:

```bash
cat > ntlmv2.txt <<'EOF'
afenwick::DIOCORE:1122334455667788:032b0b4aa446b7d68c6780135ef2ec24:0101000000000000b98318f89b40dd0188710ab71b4825d100000000080050005000000000000000000000000020000048e7e02afbb4d8dd89a1bf00f8976f4da60de7b351998f52913b13ae3f7908aad383770bcba0bda27095df48e2e35cf4256ad28f010d93ad6af198c52ab6f9be0a00100000000000000000000000000000000000090000000000000000000000
EOF
hashcat -m 5600 ntlmv2.txt /usr/share/wordlists/rockyou.txt -O
hashcat -m 5600 ntlmv2.txt --show
# afenwick::DIOCORE:...:*Seash5lls*
```

The password comes out of rockyou: **`*Seash5lls*`**. It is further confirmed in the ResetNightmare BOF arguments (`/upnpass:*Seash5lls*`).

> **Answer Q6 — Named attack + date:** `INTERNAL_MONOLOGUE:2026-09-09 20:44:11`
>
> **Answer Q7 — Credentials used:** `afenwick:*Seash5lls*`

#### Step 7 — ResetNightmare (CVE-2026-27912)

The operator uploads a **custom BOF** of 70169 bytes (frames 730/746) with functions `RESET_NIGHTMARE_RUN`, `LdapSetUPN`, `ResetTargetPassword`. Its md5:

```bash
md5sum /tmp/bofs/reset_nightmare.o   # 583236cc3ef2488fb133385bcd75825e
```

**How ResetNightmare works (Semperis):** the 2021 patch against "Bronze Bit"/PAC forgery enforced the `PAC_REQUESTOR` check **only on the TGS-REQ path**. The **change-password protocol (RFC 3244, Kerberos port 464)** does not go through that check. Chaining:

1. Using `WriteProperty` on its UPN, `afenwick` writes a **spoofed UPN** matching the victim's (jreed).
2. It requests an **enterprise AS-REQ** (using the UPN as enterprise principal) → the KDC issues a **TGT that resolves to `jreed`**.
3. With that TGT it uses **kadmin/changepw (port 464)** to **reset jreed's password** — without DCSync, without being DA.

The decrypted output confirms it:

```
[*] Action: ResetNightmare (CVE-2026-27912)
[+] ResetNightmare succeeded! jreed's password is now: Aigohng8vai0seish4zi
```

> **Answer Q3 — Privesc CVE:** `CVE-2026-27912`
>
> **Answer Q4 — Custom BOF md5sum:** `583236cc3ef2488fb133385bcd75825e`
>
> **Answer Q8 — Targeted user + resulting password:** `jreed:Aigohng8vai0seish4zi`

#### Step 8 — Token impersonation

With `jreed`'s credentials under control, the agent calls `LogonUser(jreed)` and produces an impersonation token:

```
The user impersonated successfully: DIOCORE\jreed (logon: 9)
```

**LogonType 9 = `NewCredentials`**, the equivalent of `runas /netonly`: the process keeps its local identity but uses the new credentials **for outbound network authentication**. That is exactly what's needed to authenticate to DC02 as `jreed` without loading an interactive profile. LogonType 9 is a very useful threat-hunting fingerprint.

> **Answer Q9 — New token logon type:** `9`

#### Step 9 — Lateral movement to DC02 and the second beacon

With the `jreed` token, the operator copies a new agent (**103936 bytes**) to DC02's admin share and hijacks an existing service:

```
Uploading binary (103936 bytes) to: \\dc02\ADMIN$\svc_bkup
Opening service: defragsvc          (original: svchost.exe -k defragsvc)
```

The **`defragsvc` service group is hijacked** (the `-k defragsvc` of `svchost.exe` defines the service group). On service restart, a **second beacon spawns on DC02 as SYSTEM** (process `svc_bkup`). Its decrypted beat (same profile EncryptionKey, see Step 3b) yields:

- **BeaconID `ddc68fa7`**
- **SessionKey `289122cf1ec91c67eb89c30642adfea4`**

This second beacon is the starting point of the next Sherlock (S09 *Last Light*, DC02 memory forensics: golden tickets, RBCD, token theft).

> **Answer Q10 — Lateral movement path:** `\\dc02\ADMIN$\svc_bkup` *(with IP: `\\192.168.56.11\ADMIN$\svc_bkup`)*
>
> **Answer Q11 — Service group used:** `defragsvc`
>
> **Answer Q12 — New BeaconID:SessionKey:** `ddc68fa7:289122cf1ec91c67eb89c30642adfea4`

### Timeline

| Date/time (UTC) | Event | Evidence |
|-----------------|-------|----------|
| 2026-09-10 01:24:47 | Decoy `.lnk` timestamps on the USB | `.lnk` ctime/atime/mtime |
| (t0) | `.lnk` execution → `docviewer.exe` sideloads `version.dll` → drops `winupdate.exe` | USB / disk |
| (t0+) | First WS02 beacon → C2 `192.168.56.1:8818` (`X-Beacon-Id` `Cl7gY…`) | PCAP initial frames |
| (recon) | `whoami`, routing, LDAP user/computer enum, child+parent domain | PCAP (WS02 SessionKey) |
| (DACL) | BOF reads afenwick's security descriptor → WriteProperty over UPN | PCAP frames 491/494 |
| **2026-09-09 20:44:11** | **Internal Monologue** captures afenwick's NetNTLMv2 | EVTX EventID 4021 |
| (crack) | hashcat 5600 + rockyou → `*Seash5lls*` | offline |
| (privesc) | ResetNightmare BOF (CVE-2026-27912) → jreed's password reset | PCAP frames 730/746 |
| (token) | `LogonUser(jreed)` → LogonType 9 token | PCAP output |
| (lateral) | Upload 103936 B to `\\dc02\ADMIN$\svc_bkup`, hijack `defragsvc` | PCAP output |
| (t_final) | Second DC02 SYSTEM beacon (`svc_bkup`, BeaconID `ddc68fa7`) | PCAP (DC02 SessionKey) |

> Note on dates: EventID 4021 records **2026-09-09 20:44:11** for the NTLM capture, while the `.lnk` timestamps are **2026-09-10**. Such a discrepancy is common in these labs (artifact-generation clocks vs. traffic); Q6's graded answer is the EVTX one.

### Answers / flags

| # | Question | Answer |
|---|----------|--------|
| 1 | C2 used (string) | `AdaptixC2` |
| 2 | SessionKey:EncryptionKey | `53fc4c03c7b461befe5dcb268e3d9208:4580221ac3fe51be1797524a048e552d` |
| 3 | Privesc CVE | `CVE-2026-27912` |
| 4 | Custom BOF md5sum | `583236cc3ef2488fb133385bcd75825e` |
| 5 | ObjectSID of the WriteProperty property | `28630ebb-41d5-11d1-a9c1-0000f80367c1` *(userPrincipalName schemaIDGUID; SID-format alternative for the afenwick object: `S-1-5-21-2253468260-689643353-167204612-1125`)* |
| 6 | Named attack + date | `INTERNAL_MONOLOGUE:2026-09-09 20:44:11` |
| 7 | Credentials used | `afenwick:*Seash5lls*` |
| 8 | Targeted user + resulting password | `jreed:Aigohng8vai0seish4zi` |
| 9 | New token logon type | `9` |
| 10 | Lateral movement path | `\\dc02\ADMIN$\svc_bkup` *(with IP: `\\192.168.56.11\ADMIN$\svc_bkup`)* |
| 11 | Service group used | `defragsvc` |
| 12 | New BeaconID:SessionKey | `ddc68fa7:289122cf1ec91c67eb89c30642adfea4` |

> **Note:** questions 5 and 10 have ambiguous formats. Q5 labels the property's `ObjectAceType` (`userPrincipalName`) as its "ObjectSID"; if the grader demands a real SID, use `S-1-5-21-2253468260-689643353-167204612-1125`. For Q10, if an IP is expected instead of the hostname, use `\\192.168.56.11\ADMIN$\svc_bkup`.

### IOCs

| Type | Indicator | Context |
|------|-----------|---------|
| MD5 | `aca111935d339b17544ead3e8c2c8831` | `docviewer.exe` (legitimate sideload host) |
| MD5 | `6e787589a69ce783b0380b0de86a2d68` | `version.dll` (malicious sideloaded DLL) |
| MD5 | `b1c8c95d3bfa22780076084377584739` | `winupdate.exe` (AdaptixC2 agent) |
| MD5 | `583236cc3ef2488fb133385bcd75825e` | Custom ResetNightmare BOF (70169 B) |
| File | `Salary_Review_Q3_2026.pdf.lnk` | Decoy `.lnk` → `docviewer.exe` |
| IP:port | `192.168.56.1:8818` | C2 team server (AdaptixC2) |
| Host | `192.168.56.22` (WS02) | Compromised workstation (afenwick) |
| Host | `192.168.56.11` (DC02) | Pivoted child DC (SYSTEM) |
| HTTP | UA `Firefox 20`; URIs `/api/v1/status`, `/updates/check.php`, `/content.html` | AdaptixC2 malleable profile |
| HTTP | Header `X-Beacon-Id`; JSON `{"status":"ok","data":"...","metrics":"sync"}` | C2 channel |
| Crypto | EncryptionKey `4580221ac3fe51be1797524a048e552d` | Profile RC4 |
| Crypto | SessionKey WS02 `53fc4c03c7b461befe5dcb268e3d9208` / DC02 `289122cf1ec91c67eb89c30642adfea4` | Session RC4 |
| BeaconID | `58debcbb` (WS02) · `ddc68fa7` (DC02) | Beat bytes 4-7 |
| NTLM | Fixed challenge `1122334455667788`, EventID 4021 | Internal Monologue signature |
| Service | `svc_bkup` / service group `defragsvc` | SYSTEM persistence on DC02 |
| Named pipe | `\\.\pipe\%08lx` | Agent task/BOF pipe |

### MITRE ATT&CK mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|----------|
| Initial Access | Replication Through Removable Media | T1091 | USB drop `Q3_Salary_Review.img` |
| Execution | User Execution: Malicious File (`.lnk`) | T1204.002 | `Salary_Review_Q3_2026.pdf.lnk` |
| Defense Evasion / Persistence | Hijack Execution Flow: DLL Side-Loading | T1574.002 | `docviewer.exe` + `version.dll` |
| Command & Control | Application Layer Protocol: Web (HTTP) | T1071.001 | AdaptixC2 HTTP beacons |
| Command & Control | Encrypted Channel: Symmetric (RC4) | T1573.001 | EncryptionKey/SessionKey RC4 |
| Discovery | Domain Trust / Account / Remote System Discovery | T1482 / T1087 / T1018 | LDAP recon, child+parent domain |
| Credential Access | Forced Authentication (Internal Monologue) | T1187 | NetNTLMv2, challenge `1122334455667788` |
| Credential Access | Brute Force: Password Cracking | T1110.002 | hashcat 5600 + rockyou |
| Privilege Escalation | Abuse Elevation / Valid Accounts (ResetNightmare) | T1078 / T1484 | CVE-2026-27912, WriteProperty UPN |
| Privilege Escalation | Access Token Manipulation | T1134 | LogonType 9 (NewCredentials) |
| Lateral Movement | Remote Services: SMB Admin Shares | T1021.002 | `\\dc02\ADMIN$\svc_bkup` |
| Persistence / Priv Esc | Create or Modify System Process: Windows Service | T1543.003 | Hijack `defragsvc` → `svc_bkup` SYSTEM |

### Detection and remediation

**Detection**

- **DLL sideloading:** alert on legitimate binaries (`docviewer.exe`, or any signed host) loading DLLs from user/removable paths (`version.dll`, `dbghelp.dll`, etc.) outside `System32`. Sysmon EventID 7 (Image Loaded) with mismatched signature + suspicious path.
- **USB / removable media:** enable device-mount auditing (Sysmon 25 / EventID 6416) and block execution from removable drives with AppLocker/WDAC.
- **Internal Monologue:** EventID **4021** on the `Microsoft-Windows-NTLM/Operational` channel with `NtlmUsageReason: NTLM was called directly` and challenge **`1122334455667788`** is a direct signature. Alert on NetNTLMv2 with that fixed challenge.
- **ResetNightmare (CVE-2026-27912):** monitor `userPrincipalName` changes (Event 5136, directory attribute modification) and **password changes via kpasswd (port 464)** not originating from legitimate flows; correlate AS-REQ with anomalous enterprise names.
- **AdaptixC2 network:** fingerprint the malleable profile (fixed Firefox 20 UA, URIs `/api/v1/status` + `/updates/check.php` + `/content.html`, `X-Beacon-Id` header, JSON `metrics: sync`) with Suricata/Zeek rules.
- **Service hijack:** Event 7045/4697 (service install/modification) and changes to `svchost -k <group>`; `svc_bkup` binary in `ADMIN$`.

**Remediation**

- **Patch CVE-2026-27912** (Microsoft's Apr-2026 fix extending the `PAC_REQUESTOR` check to the change-password path).
- **Review and purge dangerous ACEs:** no user should hold `WriteProperty` over its own `userPrincipalName` (or over another's). Audit DACLs with BloodHound (`WriteSPN`/`WriteProperty`/`GenericWrite` over `userPrincipalName`).
- **Disable NTLM** where possible and enforce SMB/LDAP signing + channel binding to mitigate coercion/relay.
- **Harden allowlisting** with **hash/attribute-based** WDAC (not just parent-process signature) to defeat sideloading.
- **Containment:** isolate WS02 and DC02, rotate credentials for `afenwick`, `jreed` and the child domain's **krbtgt** (double reset), and hunt for golden tickets/RBCD on DC02 (see S09).

### Lessons

- **DLL sideloading** with a legitimate binary (`docviewer.exe` + `version.dll`) is a stealthy USB delivery vector that evades signature-based allowlisting: the malicious DLL rides on the back of a trusted process and persists after the medium is removed.
- **AdaptixC2** traffic is decryptable once you extract the `encrypt_key` from the agent's `.rdata`: the chain `EncryptionKey → beat → SessionKey → whole C2` reconstructs the PCAP, which is the key that **unlocks nearly every answer**. Without that step the challenge is unsolvable.
- The **beat structure** (profile constant + per-session BeaconID + length-prefixed SessionKey + host/user/process) lets you distinguish the two beacons and their independent keys.
- **ResetNightmare (CVE-2026-27912)** chains `WriteProperty` over `userPrincipalName` + an enterprise AS-REQ + kadmin/changepw to take over another user's password **without DCSync** — a dangerous, quiet Kerberos identity abuse exploiting a gap in the `PAC_REQUESTOR` check.
- **Internal Monologue** captures NetNTLMv2 **without touching LSASS**; the fixed challenge `1122334455667788` in the EVTX (EventID 4021) is a detectable signature and, at the same time, the attack's temporal anchor.
- **LogonType 9 (NewCredentials)** is the fingerprint of `runas /netonly`-style impersonation, useful for threat hunting and for explaining how the agent authenticates as `jreed` against the DC.
- **Multi-artifact correlation:** no single piece of evidence tells the story — PCAP (commands and keys), USB/disk (delivery) and EVTX (NTLM timestamp) must be **cross-referenced** to rebuild the full timeline.

### Serie · The Reichenbach Directive

| # | Sherlock | Link |
|---|----------|------|
| S01 | Silent Dividend | [../2026-09-15-holmes2026-s01-silent-dividend/](../2026-09-15-holmes2026-s01-silent-dividend/) |
| S02 | Bottle Out | [../2026-09-16-holmes2026-s02-bottle-out/](../2026-09-16-holmes2026-s02-bottle-out/) |
| S03 | Whisper Chain | [../2026-09-17-holmes2026-s03-whisper-chain/](../2026-09-17-holmes2026-s03-whisper-chain/) |
| S04 | Paper Ghost | [../2026-09-18-holmes2026-s04-paper-ghost/](../2026-09-18-holmes2026-s04-paper-ghost/) |
| S05 | Poisoned Branch | [../2026-09-19-holmes2026-s05-poisoned-branch/](../2026-09-19-holmes2026-s05-poisoned-branch/) |
| S06 | Silent Passenger | [../2026-09-20-holmes2026-s06-silent-passenger/](../2026-09-20-holmes2026-s06-silent-passenger/) |
| S07 | Iron Feather | [../2026-09-21-holmes2026-s07-iron-feather/](../2026-09-21-holmes2026-s07-iron-feather/) |
| **S08** | **Borrowed Name** ← *this one* | [../2026-09-22-holmes2026-s08-borrowed-name/](../2026-09-22-holmes2026-s08-borrowed-name/) |
| S09 | Last Light | [../2026-09-23-holmes2026-s09-last-light/](../2026-09-23-holmes2026-s09-last-light/) |

---

*Créditos: técnica ResetNightmare documentada por [Semperis](https://www.semperis.com/blog/identity-crisis-novel-vulnerabilities-leading-to-kerberos-downgrade-dos-and-full-domain-takeover/); análisis de AdaptixC2 por [Unit42 (Palo Alto Networks)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/).*
