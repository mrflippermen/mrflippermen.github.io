---
title: "Holmes CTF 2026 — S02 Bottle Out"
date: 2026-09-16
description: "Forense de imagen E01 (host BLUEBOX) con Velociraptor headless: recuperación de un log OpenVPN, registro de Tactical RMM y la cuenta Gajim/XMPP del carcelero de Watson."
excerpt: "DFIR sobre un E01: Velociraptor por WinRM, recuperación por MFT del chat borrado, Tactical RMM en el registro y la cuenta XMPP en SQLite."
platform: "HTB"
difficulty: "Easy"
image: "/images/ctf.svg"
tags:
  - "DFIR"
  - "Velociraptor"
  - "E01"
  - "Windows"
  - "Registry"
  - "Holmes CTF 2026"
---

> **Reto:** Holmes CTF 2026 — Sherlock 02 "Bottle Out" · Forense de imagen E01 con Velociraptor. Parte del arco *The Reichenbach Directive*.
>
> **Navegación:** [🇪🇸 Español](#es) · [🇬🇧 English](#en)

<a id="es"></a>
## 🇪🇸 Español

### Escenario

Tras rescatar a Watson en los depósitos de contenedores de Silvertown, el carcelero huye minutos antes de que llegue la policía y deja atrás un portátil encendido. La máquina muestra un intento apresurado de borrar la actividad reciente: sobrevive un único cliente de comunicaciones, pero su cuenta, su servidor y su propósito siguen siendo desconocidos.

La evidencia se sella y se entrega como una **imagen de disco E01** del host **BLUEBOX** (usuario sospechoso `spur`). El objetivo es reconstruir lo que sobrevivió al intento de wipe y determinar cómo el portátil conectaba a su operador anónimo con el resto de la operación de *The Reichenbach Directive*.

Dificultad: **Easy**.

### Artefacto y herramientas

- **Imagen E01** `DESKTOP-QMTIG5I.E01` montada en una VM de análisis (host `BLUEBOX`), accesible por **WinRM (5985)** y RDP (3389).
- **Velociraptor** operado en modo *headless* por WinRM con `nxc`, sin GUI. Es la pieza clave: permite montar y consultar el E01 con VQL sin herramientas comerciales (7-Zip 24.09 no abre E01; no hay Arsenal/FTK CLI).
- Patrón de acceso al sistema de ficheros de la imagen (pathspec anidado sobre `ewf`):

```
# Sistema de ficheros de la imagen
accessor='raw_ntfs',
root=pathspec(DelegateAccessor='ewf',
              DelegatePath='C:/Users/Administrator/Desktop/DESKTOP-QMTIG5I.E01')

# Registro offline
accessor='raw_reg',
root=pathspec(DelegateAccessor='raw_ntfs',
              DelegatePath=pathspec(Path='/Windows/System32/config/SOFTWARE',
                                    DelegateAccessor='ewf', DelegatePath='<E01>'))
```

- **`impacket-secretsdump`** en local sobre los hives SAM/SYSTEM/SECURITY descargados.
- Recuperación de ficheros borrados por **MFT** (`parse_mft` + `copy(accessor='mft')`).
- Lectura de **SQLite** (Gajim: `Settings.sqlite`, `Logs.db`, bases OMEMO/OpenPGP).

### Metodología (paso a paso)

1. **Montaje headless del E01.** Con Velociraptor sobre WinRM se monta la imagen encadenando `ewf` → `raw_ntfs`. A partir de aquí todo el sistema de ficheros del sospechoso es consultable con VQL.

2. **Log de OpenVPN (Q1–Q3).** Se recupera por MFT (entrada 154158) el log `spur.log` del cliente OpenVPN. Contiene tres datos:
   - El servidor VPN: `Preserving recently used remote address: [AF_INET]18.156.81.166:7577`.
   - La verificación del certificado de servidor: `VERIFY OK: depth=1, CN=NPLN-CA` — a `depth=1` está la **CA**, `NPLN-CA` (el servidor es `NPLN-VPN-7577`).
   - El `PUSH_REPLY`/`ASSIGN_IP` con la IP asignada al cliente: `ifconfig 10.129.175.2 255.255.255.0`.

3. **Agente de administración remota (Q4–Q6).** El disco tiene instalado **Tactical RMM**:
   - El PE `C:\Program Files\TacticalAgent\tacticalrmm.exe` (AmidaWare Inc) declara en su VersionInfo la versión **2.11.0**.
   - En el registro offline `HKLM\SOFTWARE\TacticalRMM\ApiURL` está el dominio del C2: `api.antimattercommunication.xyz`.
   - `HKLM\SOFTWARE\TacticalRMM\Token` guarda el token de autenticación (SHA-1): `98ec588da683c01820232943a6151e8e7772419b`.

   > Dato de correlación: `api.antimattercommunication.xyz` resuelve a **18.156.81.166**, la **misma IP** que el servidor VPN `:7577`. Toda la infraestructura (VPN + RMM/C2) cuelga del mismo host AWS eu-central.

4. **Operation Vanish (Q7).** En `Security.evtx` (evento 4688) se ve cómo `tacticalrmm.exe` lanza `cmd → powershell -Enc`. Al descodificar el script, el primer comando destructivo es:

   ```powershell
   Remove-Item -LiteralPath C:\Users\spur\Gajim -Recurse -Force
   ```

   El script borra tres carpetas: `C:\Users\spur\Gajim`, `C:\Users\spur\OpenVPN` y `C:\VPN`. Es el "intento apresurado de wipe" del enunciado.

5. **Cuenta de mensajería (Q8–Q9).** La carpeta `Gajim` fue borrada, pero sus clusters no se reutilizaron del todo: `Settings.sqlite` (entrada MFT 156449) se recupera intacta con `copy(accessor='mft')`. En la tabla `account_settings`:
   - JID de la cuenta XMPP: `spurio9@murknet.htb` (confirmado también en la base OMEMO, entrada 156526).
   - La contraseña estaba almacenada **en claro** en el JSON de settings: `"password":"spur999!*"`.

6. **El nombre del carcelero (Q10) — pendiente.** La respuesta natural vivía en el historial de chat XMPP de Gajim (`Logs.db`, entrada MFT 156456). A diferencia de `Settings.sqlite`, sus **14 páginas de datos están sobrescritas** por caché de Edge/AppX/Defender (verificado página a página: solo sobreviven las de `sqlite_master`). El chat que contenía el nombre real fue borrado por Operation Vanish y su espacio en disco, reutilizado. Ver la nota en la tabla.

### Respuestas / flags

| # | Pregunta | Respuesta |
|---|----------|-----------|
| 1 | Servidor VPN (IPv4:puerto) | `18.156.81.166:7577` |
| 2 | CA que emitió el certificado de cliente | `NPLN-CA` |
| 3 | IP asignada al usuario | `10.129.175.2` |
| 4 | Agente de gestión remota (nombre + versión) | `Tactical RMM Agent v.2.11.0` |
| 5 | Dominio del agente | `api.antimattercommunication.xyz` |
| 6 | Token de autenticación (SHA-1) | `98ec588da683c01820232943a6151e8e7772419b` |
| 7 | 1er comando de *Operation Vanish* | `Remove-Item -LiteralPath C:\Users\spur\Gajim -Recurse -Force` |
| 8 | Cuenta de mensajería (Gajim/XMPP) | `spurio9@murknet.htb` |
| 9 | Contraseña de la cuenta | `spur999!*` |
| 10 | Nombre real del carcelero | ⏳ **pendiente** — el chat XMPP que lo contenía (`Logs.db`, MFT 156456) fue **borrado por Operation Vanish** y sus páginas de datos quedaron **sobrescritas** por caché de Edge/AppX/Defender; el nombre no es recuperable desde esta imagen. Descartados SAM (`spur`), LogonUI, OMEMO/OpenPGP, navegadores, pagefile, timeline, thumbcache y VSC. El JID `spurio9@murknet.htb` es el único identificador que sobrevive. |

### Lecciones

- **Velociraptor en headless** (WinRM + `ewf`/`raw_ntfs`) es una alternativa completa a FTK/Arsenal para trabajar un E01 sin GUI ni herramientas comerciales.
- **Borrar ≠ destruir, hasta que se sobrescribe.** `Settings.sqlite` sobrevivió al `Remove-Item` (clusters intactos → recuperable por MFT); `Logs.db` no (páginas de datos reutilizadas). El mismo wipe deja unos artefactos vivos y otros irrecuperables.
- **Correlación de infraestructura:** una IP compartida entre el log VPN y el `ApiURL` del RMM une VPN y C2 en un solo host — el pivote hacia el resto de la operación.
- **Credenciales en claro** en el JSON de configuración de Gajim: los clientes de escritorio siguen guardando contraseñas recuperables.
- **Límite honesto:** cuando el único artefacto que contiene un dato ha sido sobrescrito, ninguna técnica de carving lo devuelve. Q10 documenta un negativo probado, no un paso sin intentar.

<a id="en"></a>
## 🇬🇧 English

### Scenario

After Watson is rescued at the Silvertown container yards, his jailer flees minutes before the police arrive, leaving behind a powered-on laptop. The machine shows a hurried attempt to erase recent activity: a single communications client survives, but its account, server and purpose remain unknown.

The evidence is sealed and handed over as an **E01 disk image** of host **BLUEBOX** (suspect user `spur`). The goal is to recover what survived the wiping attempt and determine how the laptop tied its unknown operator to the wider operation of *The Reichenbach Directive*.

Difficulty: **Easy**.

### Artefact and tooling

- **E01 image** `DESKTOP-QMTIG5I.E01` mounted on an analysis VM (host `BLUEBOX`), reachable over **WinRM (5985)** and RDP (3389).
- **Velociraptor** driven *headless* over WinRM with `nxc`, no GUI. It is the key piece: it mounts and queries the E01 with VQL without commercial tooling (7-Zip 24.09 won't open E01; no Arsenal/FTK CLI available).
- Nested pathspec pattern to reach the image's filesystem over `ewf`:

```
# Image filesystem
accessor='raw_ntfs',
root=pathspec(DelegateAccessor='ewf',
              DelegatePath='C:/Users/Administrator/Desktop/DESKTOP-QMTIG5I.E01')

# Offline registry
accessor='raw_reg',
root=pathspec(DelegateAccessor='raw_ntfs',
              DelegatePath=pathspec(Path='/Windows/System32/config/SOFTWARE',
                                    DelegateAccessor='ewf', DelegatePath='<E01>'))
```

- **`impacket-secretsdump`** locally against the downloaded SAM/SYSTEM/SECURITY hives.
- Deleted-file recovery via the **MFT** (`parse_mft` + `copy(accessor='mft')`).
- **SQLite** reading (Gajim: `Settings.sqlite`, `Logs.db`, OMEMO/OpenPGP databases).

### Methodology (step by step)

1. **Headless E01 mount.** With Velociraptor over WinRM the image is mounted by chaining `ewf` → `raw_ntfs`. From there the suspect's entire filesystem is queryable with VQL.

2. **OpenVPN log (Q1–Q3).** The OpenVPN client log `spur.log` is recovered by MFT (entry 154158). It carries three facts:
   - The VPN server: `Preserving recently used remote address: [AF_INET]18.156.81.166:7577`.
   - The server-certificate verification: `VERIFY OK: depth=1, CN=NPLN-CA` — at `depth=1` sits the **CA**, `NPLN-CA` (the server itself is `NPLN-VPN-7577`).
   - The `PUSH_REPLY`/`ASSIGN_IP` line with the client's assigned IP: `ifconfig 10.129.175.2 255.255.255.0`.

3. **Remote management agent (Q4–Q6).** The disk has **Tactical RMM** installed:
   - The PE `C:\Program Files\TacticalAgent\tacticalrmm.exe` (AmidaWare Inc) declares version **2.11.0** in its VersionInfo.
   - The offline registry key `HKLM\SOFTWARE\TacticalRMM\ApiURL` holds the C2 domain: `api.antimattercommunication.xyz`.
   - `HKLM\SOFTWARE\TacticalRMM\Token` stores the auth token (SHA-1): `98ec588da683c01820232943a6151e8e7772419b`.

   > Correlation note: `api.antimattercommunication.xyz` resolves to **18.156.81.166**, the **same IP** as the VPN server `:7577`. The whole infrastructure (VPN + RMM/C2) hangs off one AWS eu-central host.

4. **Operation Vanish (Q7).** In `Security.evtx` (event 4688) `tacticalrmm.exe` spawns `cmd → powershell -Enc`. Decoding the script, the first destructive command is:

   ```powershell
   Remove-Item -LiteralPath C:\Users\spur\Gajim -Recurse -Force
   ```

   The script deletes three folders: `C:\Users\spur\Gajim`, `C:\Users\spur\OpenVPN` and `C:\VPN`. This is the "hurried wipe" of the briefing.

5. **Messaging account (Q8–Q9).** The `Gajim` folder was deleted, but its clusters were not fully reused: `Settings.sqlite` (MFT entry 156449) is recovered intact with `copy(accessor='mft')`. In the `account_settings` table:
   - XMPP account JID: `spurio9@murknet.htb` (also confirmed in the OMEMO database, entry 156526).
   - The password was stored **in cleartext** in the settings JSON: `"password":"spur999!*"`.

6. **The jailer's name (Q10) — pending.** The natural answer lived in Gajim's XMPP chat history (`Logs.db`, MFT entry 156456). Unlike `Settings.sqlite`, its **14 data pages are overwritten** by Edge/AppX/Defender cache (verified page by page: only the `sqlite_master` pages survive). The chat that held the real name was deleted by Operation Vanish and its on-disk space reused. See the table note.

### Answers / flags

| # | Question | Answer |
|---|----------|--------|
| 1 | VPN server (IPv4:port) | `18.156.81.166:7577` |
| 2 | CA that issued the client certificate | `NPLN-CA` |
| 3 | IP assigned to the user | `10.129.175.2` |
| 4 | Remote management agent (name + version) | `Tactical RMM Agent v.2.11.0` |
| 5 | Agent domain | `api.antimattercommunication.xyz` |
| 6 | Authentication token (SHA-1) | `98ec588da683c01820232943a6151e8e7772419b` |
| 7 | First command of *Operation Vanish* | `Remove-Item -LiteralPath C:\Users\spur\Gajim -Recurse -Force` |
| 8 | Messaging account (Gajim/XMPP) | `spurio9@murknet.htb` |
| 9 | Account password | `spur999!*` |
| 10 | Jailer's real name | ⏳ **pending** — the XMPP chat that held it (`Logs.db`, MFT 156456) was **deleted by Operation Vanish** and its data pages were **overwritten** by Edge/AppX/Defender cache; the name is not recoverable from this image. Ruled out: SAM (`spur`), LogonUI, OMEMO/OpenPGP, browsers, pagefile, timeline, thumbcache and VSC. The JID `spurio9@murknet.htb` is the only surviving identifier. |

### Lessons

- **Headless Velociraptor** (WinRM + `ewf`/`raw_ntfs`) is a full substitute for FTK/Arsenal when working an E01 without a GUI or commercial tools.
- **Deleted ≠ destroyed, until it is overwritten.** `Settings.sqlite` survived the `Remove-Item` (clusters intact → MFT-recoverable); `Logs.db` did not (data pages reused). The same wipe leaves some artefacts alive and others gone.
- **Infrastructure correlation:** one shared IP between the VPN log and the RMM `ApiURL` ties VPN and C2 to a single host — the pivot into the rest of the operation.
- **Cleartext credentials** in Gajim's config JSON: desktop clients still store recoverable passwords.
- **An honest limit:** when the only artefact holding a value has been overwritten, no carving technique returns it. Q10 documents a proven negative, not an untried step.
