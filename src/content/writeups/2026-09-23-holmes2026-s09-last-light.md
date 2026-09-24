---
title: "Holmes CTF 2026 — S09 Last Light"
date: 2026-09-23
description: "Forense de un volcado de memoria Windows (DC02, bosque DIOGENES): reconstruir un golden ticket con extra-SID, un abuso de RBCD y un robo de token, sin volcar LSASS."
excerpt: "El escenario final del arco. Un memory.elf de QEMU esconde la toma total del bosque DIOGENES: implante svc_bkup, golden ticket de Administrator con SID-history de Enterprise Admins raíz, RBCD y robo de _TOKEN de una sesión RDP de un Domain Admin."
platform: "HTB"
difficulty: "Insane"
image: "/images/blog/holmes-s09.svg"
tags:
  - "DFIR"
  - "Memory Forensics"
  - "Active Directory"
  - "Kerberos"
  - "Golden Ticket"
  - "Holmes CTF 2026"
---

> **Reto:** Holmes CTF 2026 — Sherlock 09 "Last Light" (final) · Forense de memoria Windows: golden ticket, RBCD y robo de token en el bosque DIOGENES. Parte del arco *The Reichenbach Directive*.
>
> **Navegación:** [🇪🇸 Español](#es) · [🇬🇧 English](#en)

<a id="es"></a>

## 🇪🇸 Español

### Escenario

Última luz sobre DIOGENES. Tras la intrusión de **S08 "Borrowed Name"**, el APT **NAPOLEON** (desde `192.168.56.1`) ya ha pivotado al controlador de dominio hijo **DC02** (`core.diogenes.htb`, `192.168.56.11`) y ha dejado un implante persistente. Lo único que nos entregan es un **volcado de memoria completo** de DC02 tomado con QEMU: `memory.elf`. Junto a él viajan `ntds.dit`, las *hives* de registro (`SYSTEM`, `SECURITY`, `SAM`) y logs `.evtx` (`Security.evtx`, `Microsoft-Windows-Sysmon%4Operational.evtx`).

El bosque tiene dos dominios en relación **padre-hijo** dentro del mismo bosque, unidos por una confianza transitiva bidireccional:

- **Raíz `diogenes.htb`** — DC **DIOCORE**, SID de dominio `S-1-5-21-3066635835-107521988-671693545`. Aquí viven los grupos de mayor poder del bosque: **Enterprise Admins** (`…-519`) y **Schema Admins** (`…-518`).
- **Hijo `core.diogenes.htb`** — DC **DC02** (`192.168.56.11`), SID de dominio `S-1-5-21-2253468260-689643353-167204612`. Es el dominio donde NAPOLEON tiene el pie: comprometerlo **no** basta para poseer el bosque; hay que cruzar la frontera de confianza hacia la raíz.

Cuentas relevantes: **afenwick** y **jreed** (comprometidas en la cadena previa, S08) y **rfairfax**, un **Domain/Enterprise Admin de la raíz** con una **sesión RDP viva** en DC02. El objetivo del reto es reconstruir, **solo desde RAM**, cómo NAPOLEON pasó de tener un implante en un DC hijo a ser **dueño de todo el bosque**. Dificultad: **insane**.

La consigna clave del enunciado — *"sin volcar LSASS"* — no es decorativa: obliga a extraer los tickets Kerberos leyendo las estructuras del propio `lsass.exe` **dentro de la imagen**, y no generando un minidump con `comsvcs.dll`/`procdump`. Es un guiño al operador OPSEC-aware: en 2026 volcar LSASS es de los eventos más vigilados (Sysmon EID 10 sobre `lsass.exe`, WDAC, PPL). El reto pide reproducir la misma lectura **fría**, sobre bytes ya congelados.

> **Por qué un dominio hijo no es el bosque.** El límite de seguridad real de Active Directory es el **bosque**, no el dominio. Comprometer el `krbtgt` del hijo te da control total del hijo, pero la raíz **no confía** en los SIDs que el hijo emita dentro del rango de la propia raíz salvo excepciones. Para saltar de hijo a raíz hay exactamente dos raíles clásicos, y NAPOLEON usó **los dos a la vez** (redundancia de operador): (a) un **golden ticket con SID-history de cruce de dominio** que inyecta el RID `-519` (Enterprise Admins) de la **raíz**, y (b) **RBCD** más **robo del token vivo** de un admin de la raíz que estaba logueado en el hijo. Este reto es, en el fondo, la anatomía de ese doble salto vista desde la memoria.

### Artefacto y herramientas

- **Volcado:** `memory.elf` — *ELF core* de QEMU de DC02 (Windows Server, build **17763** / 1809 LTSC). No es un `raw`/DumpIt clásico: es el formato *core* de QEMU, con segmentos `PT_LOAD` que mapean la RAM invitada. Volatility 3 lo trata como layer física; MemProcFS lo abre nativo con `-device`.
- **Volatility 3** para el triage: `windows.pslist`, `windows.pstree`, `windows.dlllist`, `windows.registry.hivelist`, `windows.filescan`, `windows.netscan`.
- **pypykatz vía Volatility 3** — la técnica *"without dumping LSASS"*: un plugin vol3 que llama a `pypykatz.go_volatility3` y lee las structs `KERB_TICKET_CACHE_ENTRY` de `lsass.exe` (**PID 604**) **directamente del `memory.elf`**, sin generar minidump. Usé el script **`scripts/vol3_pypykatz_kerberos.py`** de la skill `htb-sherlock-diogenes` (**crédito al autor de la skill**; internamente se apoya en `pypykatz` de Tamas Jos / @skelsec y en el reader `volatility3.volreader`). El plugin **parchea `KerberosTicket.aparse`** para capturar, junto a cada *kirbi*, tanto la **VA del buffer del ticket** como la **`struct_loc`** (la base del objeto en LSASS) y las serializa a `addr.json`. **34 *kirbis*** exportados a `KDIR`.
- **MemProcFS** (`memprocfs -device memory.elf -mount /mnt`) para traducir **VA↔físico**, y para enumerar `_TOKEN`, *threads* e *impersonation levels* del proceso del implante. En Parrot/py3.13 la API Python de MemProcFS puede segfaultar → usar el **binario + FUSE** y navegar el árbol `/mnt/pid/<pid>/`.
- **impacket-ticketConverter** (kirbi→ccache) y **`describeTicket.py --rc4/--aes`** (Impacket) para leer el **PAC** y sus checksums.
- **Sysmon** (`Microsoft-Windows-Sysmon%4Operational.evtx`) y **Security.evtx** para PID/TID del implante y para los eventos de reset de contraseña (4723/4724) y de configuración de RBCD (4662/5136).
- Apoyo: `evtx_dump` / `python-evtx`, `pypykatz` standalone para reconstruir la *session key* y `xxd`/`radare2` para confirmar cabeceras ASN.1 (`0x76 0x82` = `KRB-CRED`, `0x61 0x82` = `Ticket`) sobre las VAs candidatas.

### Metodología (paso a paso)

#### 1. El implante — servicio `defragsvc` secuestrado (Q1)

**El porqué.** La cadena de S08 termina con NAPOLEON subiendo un agente a `\\dc02\ADMIN$\svc_bkup` y **secuestrando el servicio de desfragmentación** `defragsvc` (que se hospeda en `svchost.exe -k defragsvc`). Es un clásico de persistencia: en lugar de crear un servicio nuevo (ruidoso), reescribe el `ServiceDll`/`ImagePath` de uno legítimo poco vigilado. El proceso resultante corre como **svc_bkup**, cuenta de máquina/servicio del propio implante.

En `windows.pslist`/`pstree` y en Sysmon **EventID 1 (Process Create)** aparece el `svchost.exe -k defragsvc` colgando del árbol de servicios, con **PID 3376** y línea de comandos coherente con el hijack:

```bash
# Triage de procesos y localización del svchost del servicio secuestrado
vol -f memory.elf windows.pstree | grep -Ei 'svchost|defrag|svc_bkup'
vol -f memory.elf windows.pslist | grep -i 3376

# Confirmación por Sysmon EID1 (creación del proceso implante)
evtx_dump Microsoft-Windows-Sysmon%4Operational.evtx \
  | grep -A30 -i defragsvc | grep -Ei 'ProcessId|Image|Hashes|User'
```

Volcando el binario del implante desde disco (`C:\Windows\...`, referenciado por el servicio) y hasheándolo:

```bash
sha256sum agent.bin
# 1e44c63950dd4fe1ffcc955c08d509132bcaddf87bbb08f5ea622d0533625274
```

Ese SHA256 identifica el *service agent* (**Q1**). Sysmon EID 1 suele traer ya el hash en `Hashes:` si `HashAlgorithms` incluye SHA256, con lo que se puede corroborar sin re-hashear. **PID 3376 será el proceso pivote de todo lo que sigue** (Q4–Q7): el token robado cuelga de uno de sus *threads* y su cuenta de máquina `svc_bkup$` es la beneficiaria del RBCD.

#### 2. Los tickets Kerberos — sin tocar LSASS (base de Q2/Q3)

**El porqué.** Un golden ticket es un **TGT forjado** cifrado con la clave del `krbtgt`: quien tiene el hash del `krbtgt` puede fabricar un TGT para cualquier usuario, con cualquier pertenencia de grupo, sin pasar por el KDC. En memoria, esos TGT viven en la **caché de tickets de LSASS**, como structs `KERB_TICKET_CACHE_ENTRY`. La técnica "sin volcar LSASS" es leer esas structs directamente de la imagen.

Inyecto `pypykatz` en volatility3 y lanzo el plugin de la skill, que recorre las sesiones de logon y los *orphaned creds* de `lsass.exe` y serializa cada ticket a `.kirbi` **con su dirección**:

```bash
# Preparar el entorno y ejecutar el plugin (crédito: skill htb-sherlock-diogenes)
pipx inject volatility3 pypykatz
export KDIR=out
vol -f memory.elf -p scripts vol3_pypykatz_kerberos.PpkKerb   # → 34 kirbis + addr.json

# El plugin escribe, por cada ticket: {idx, fn, ticket_va, struct_loc}
jq '.[] | select(.fn|test("Administrator"))' out/addr.json
```

Entre los 34 *kirbis* hay **varios golden**. Aquí está la primera trampa del reto:

**El del enunciado — "con el extra SID" — NO es el que primero parece.** El golden de **DC02$** (`krbtgt/CORE.DIOGENES.HTB`) lleva `S-1-5-9` (Enterprise Domain Controllers), pero **ese SID es normal en cualquier ticket de un DC** (lo lleva todo controlador de dominio para DCSync/replicación): es ruido, no la respuesta. El ticket con el *extra SID* que importa es el **golden TGT de `Administrator`** (también `krbtgt/CORE.DIOGENES.HTB`, cifrado **RC4/etype23**): es el único con un SID inyectado por **SID-history de cruce de dominio**:

```text
Extra SID (Count 1) = S-1-5-21-3066635835-107521988-671693545-519   # Enterprise Admins de la RAÍZ
                      └────────── SID del dominio RAÍZ ───────────┘ └519┘
```

Es decir: forjaron un TGT de `Administrator` del **dominio hijo** y le inyectaron, vía el campo `ExtraSids` del `KERB_VALIDATION_INFO` del PAC (flag `LOGON_EXTRA_SIDS`), los **Enterprise Admins de la raíz**. Como el **SID filtering** entre dominios *del mismo bosque* no filtra por defecto el rango de la raíz, ese TGT presentado a DIOCORE concede **EA del bosque**. Descifra con la **RC4/NT del krbtgt hijo** (`e812d14a9c390f7400549593fc98a2c2`), **no** con la clave AES: es la firma inequívoca de un golden de `impacket-ticketer` en modo RC4.

```bash
# Confirmar el cipher del ticket sobre su VA (cabecera ASN.1 61 82 = Ticket / 76 82 = KRB-CRED)
# usando MemProcFS para traducir VA→offset físico del memory.elf
xxd -s <phys_off> -l 16 memory.elf     # → 76 82 05 ..  (KRB-CRED) / 61 82 ..  (Ticket)

# Descifrar/inspeccionar el golden de Administrator con la RC4 del krbtgt hijo
describeTicket.py Administrator.ccache --rc4 e812d14a9c390f7400549593fc98a2c2 \
  | grep -Ei 'ExtraSids|UserName|LogonDomainName|GroupIds|UserFlags'
```

#### 3. Q2 — la dirección del ticket + el md5 del ccache

**El porqué (la segunda trampa).** *"Memory address of the ticket"* **no** es el offset físico dentro del `memory.elf`, ni el `fileoff`, ni el puntero al **buffer de datos** del ticket. Es la **base de la struct `KERB_TICKET_CACHE_ENTRY`** — el "objeto ticket" — sobre el **eje de VAs de LSASS** (`0x227...`), exactamente el mismo criterio que se aplica al `_TOKEN` de Q4 (un objeto, referido por la base de su struct). Ese objeto está en `Ticket-member − 0xd0`: el miembro `Ticket` de la entrada apunta al buffer, y la base de la struct queda `0xd0` bytes por debajo.

```text
KERB_TICKET_CACHE_ENTRY @ 0x227473721b0   ← base de la struct  = "the ticket address" (Q2)
                        + 0xd0
        .Ticket (member) @ 0x227473722e0   ← puntero al buffer del kirbi/KRB-CRED
```

Convierto el kirbi (ya con la *session key* descifrada por pypykatz — importante, porque el `KRB-CRED` **en crudo en memoria** trae la `enc-part` **cifrada**, y convertir *eso* da un ccache falso) a ccache y saco su md5:

```bash
impacket-ticketConverter out/0xx_Administrator@CORE.DIOGENES.HTB.kirbi Administrator.ccache
md5sum Administrator.ccache
```

Respuesta **Q2** (grader OK): **`0x227473721b0:dcf56965eee82fff4d381c6127834d72`**.

> **Nota honesta de proceso (varias iteraciones reales).** El md5 del ccache **depende de la herramienta** (impacket ≠ minikerberos ≠ el formato exacto que valida el grader) y el eje de la dirección tuvo tres candidatos falsos antes del bueno:
> - `88512e19…` — venía del `KRB-CRED` **en memoria con la `enc-part` cifrada** → ccache falso. Descartado.
> - El golden de **DC02$** (extra SID `S-1-5-9`) con md5 `558c8077…` / addr `0x2274733d37c` → era el ticket *equivocado* (S-1-5-9 es ruido). Descartado por el grader.
> - Direcciones tipo `file-off` y `guest-phys` → **rechazadas**; el eje correcto es la **VA de LSASS**.
>
> El válido es el golden de **Administrator**, tomando la **VA base de la struct** (`0x227473721b0`, no la del miembro `Ticket` ni la del buffer) y el md5 `dcf56965…`.

#### 4. Q3 — el KDCChecksum

**El porqué.** El **PAC** (Privilege Attribute Certificate) dentro del TGT lleva varias firmas. Un golden de `impacket-ticketer` genera un PAC mínimo con buffers `[1, 10, 12, 6, 7]` y **sin *Ticket Signature*** (type 16), lo que ya delata que es forjado (un TGT legítimo de un KDC moderno la incluye). Las dos firmas presentes son:

- **ServerChecksum** (PAC buffer **type 6**) — firma con la clave del servicio (aquí el `krbtgt`).
- **KDCChecksum** (PAC buffer **type 7**) — firma del KDC sobre el ServerChecksum.

Como el ticket es **RC4/etype23**, ambos checksums usan **`hmac_md5`** (un ticket AES256 usaría `hmac_sha1_96`, y el KDCChecksum sería de 12 bytes en vez de 16). Leyendo el PAC del **mismo** golden de Administrator:

```bash
describeTicket.py Administrator.ccache --rc4 e812d14a9c390f7400549593fc98a2c2 \
  | grep -Ei 'Checksum|Signature|PAC_'
# ServerChecksum (type 6, hmac_md5) = 5cc2da157cb1c50b8f555401bea362af
# KDCChecksum    (type 7, hmac_md5) = b63742148ab83e91d38dd632b5b1fb99
```

Respuesta **Q3**: **`b63742148ab83e91d38dd632b5b1fb99`** (KDCChecksum, PAC type 7, `hmac_md5`). Ojo: no confundir con el KDCChecksum del golden de **DC02$** (`1438cc04…`, ese era el ticket equivocado, y además AES → `hmac_sha1_96`).

#### 5. Q4–Q6 — robo de token de una sesión de Domain Admin

**El porqué.** NAPOLEON **no crackeó** la contraseña de rfairfax. rfairfax (DA/EA de la raíz) tenía una **sesión RDP viva** en DC02; su `_TOKEN` de impersonación estaba residente en memoria. El implante, corriendo como SYSTEM, **duplicó/robó** ese token y lo asoció a uno de sus *threads* (patrón `SeImpersonatePrivilege` → `ImpersonateLoggedOnUser`/`DuplicateTokenEx`). Con ese token, cualquier acción de red del thread se autentica **como rfairfax** → EA de la raíz, sin tocar una contraseña.

Con MemProcFS monto la imagen y examino el proceso del implante (**svc_bkup, PID 3376**), enumerando *threads* y el `_TOKEN` de cada uno:

```bash
memprocfs -device memory.elf -mount /mnt
# Threads del implante y su token
ls  /mnt/pid/3376/threads/
cat /mnt/pid/3376/threads/4968/*        # TID 4968 porta el token robado
cat /mnt/pid/3376/token/*               # _TOKEN, SID, ImpersonationLevel, LogonId

# Alternativa vol3
vol -f memory.elf windows.threads --pid 3376
```

Uno de sus *threads* (**TID 4968**) porta un **`_TOKEN` robado**:

```text
_TOKEN (truncado)  = 0xca8ddc130830          # completo: 0xffffca8ddc130830
ImpersonationLevel : LogonID = 2 : 0xa616a   # 2 = SecurityImpersonation
ThreadId           = 4968
```

`ImpersonationLevel 2` = **SecurityImpersonation** (el nivel que permite actuar en red en nombre del titular; `1` = Identification no bastaría). El `LogonID 0xa616a` es el **AuthenticationId** que **liga el token a la sesión de logon de rfairfax**: se puede cruzar con `windows.getsids`/eventos 4624 para confirmar que ese LUID pertenece a la sesión RDP (LogonType 10) del DA de la raíz. El `_TOKEN` completo se reconstruye con el prefijo canónico de kernel `0xffff…` sobre los 48 bits bajos.

- **Q4** (`_TOKEN` completo): **`0xffffca8ddc130830`**
- **Q5** (`ImpersonationLevel:LogonID`): **`2:0xa616a`**
- **Q6** (`ThreadId` que porta el token): **`4968`**

#### 6. Q7–Q9 — el abuso de RBCD

**El porqué.** **RBCD** (Resource-Based Constrained Delegation) es delegación configurada **en el recurso destino**: si escribes en `msDS-AllowedToActOnBehalfOfOtherIdentity` de una máquina el SID de una cuenta que controlas, esa cuenta puede pedir `S4U2Self`+`S4U2Proxy` y **suplantar a cualquier usuario** contra ese recurso. NAPOLEON pobló ese atributo en la cuenta de máquina de su implante, `svc_bkup$`, dándose un segundo raíl de suplantación además del golden ticket.

En `ntds.dit` / las *hives* (`SECURITY`), la cuenta de máquina del implante tiene poblado `msDS-AllowedToActOnBehalfOfOtherIdentity`:

```bash
# Volcar ntds y leer el atributo RBCD de svc_bkup$
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL -just-dc-user 'CORE\svc_bkup$'
# o con dsInternals/ldbsearch offline:
Get-BootKey / Get-ADDBAccount -SamAccountName 'svc_bkup$' -DBPath ntds.dit \
  | select msDS-AllowedToActOnBehalfOfOtherIdentity
```

```text
Cuenta máquina RBCD (SAM:SID) = svc_bkup$ : S-1-5-21-2253468260-689643353-167204612-1140
SID del dominio HIJO (deriva)  = S-1-5-21-2253468260-689643353-167204612
SID del dominio RAÍZ           = S-1-5-21-3066635835-107521988-671693545
```

El evento que **configuró** el RBCD (la escritura del atributo, visible como **4662** *"An operation was performed on an object"* / **5136** *"A directory service object was modified"* sobre `msDS-AllowedToActOnBehalfOfOtherIdentity`) aparece en `Security.evtx` a nombre de **jreed**, autenticado con **LogonType 3 (Network/NTLM)** desde `192.168.56.1`:

```bash
evtx_dump Security.evtx | grep -B2 -A25 -i 'AllowedToActOnBehalf' \
  | grep -Ei 'SubjectUserName|SubjectLogonId|LogonType|IpAddress'
# SubjectUserName: jreed  SubjectLogonId: 0x3f213b  LogonType: 3  IpAddress: 192.168.56.1
```

- **Q7** (cuenta máquina RBCD, `SAM:SID`): **`svc_bkup$:S-1-5-21-2253468260-689643353-167204612-1140`**
- **Q8** (SID del dominio **raíz**): **`S-1-5-21-3066635835-107521988-671693545`**
- **Q9** (`SubjectLogonId:LogonType` del RBCD): **`0x3f213b:3`**

#### 7. Q10 — el ataque a la contraseña (prepare:reset)

**El porqué.** La cadena de S08 (ResetNightmare / **CVE-2026-27912**, un downgrade de Kerberos estilo Semperis) vive todavía en los eventos de Security. NAPOLEON, teniendo `WriteProperty` sobre el `userPrincipalName` de **afenwick**, hizo un **swap del UPN** (afenwick → `"jreed"` y de vuelta) para *preparar* un AS-REQ que le entregara un TGT emitido para jreed; con él pasó por `kadmin/changepw` y **reseteó la contraseña de jreed** (Security **EventID 4723** *"An attempt was made to change an account's password"* / **4724** *"An attempt was made to reset an account's password"*). Los **Record IDs** (`EventRecordID`) de ambos eventos son el par pedido:

```bash
evtx_dump Security.evtx \
  | grep -Ei 'EventRecordID|EventID|4723|4724|TargetUserName|userPrincipalName'
# prepare (UPN swap sobre afenwick)  → EventRecordID 0x17c514
# reset   (4723 password de jreed)   → EventRecordID 0x17c569
```

```text
prepare (UPN swap) : reset (4723) = 0x17c514 : 0x17c569
```

Respuesta **Q10**: **`0x17c514:0x17c569`**. Con ello se cierra el reto y cae la **flag: `HTB{3v3n_Th3_F0g_Kn0ws_D10g3n3s}`**.

### Cronología

| Momento | Evento | Evidencia |
|---|---|---|
| T0 (S08) | UPN swap sobre **afenwick** (`WriteProperty` sobre su UPN) para preparar el AS-REQ enterprise | `Security.evtx` — EventRecordID `0x17c514` |
| T0+ | Reset de contraseña de **jreed** (ResetNightmare / CVE-2026-27912) | `Security.evtx` — **4723**, EventRecordID `0x17c569` |
| T1 | **jreed** (NTLM/LogonType 3) desde `192.168.56.1` escribe el RBCD sobre `svc_bkup$` | `Security.evtx` — **4662/5136**, SubjectLogonId `0x3f213b` |
| T2 | Despliegue del implante: hijack de **`defragsvc`**, `svchost.exe -k defragsvc` como **svc_bkup PID 3376** | Sysmon **EID 1**; SHA256 `1e44c639…` |
| T3 | Forja del **golden TGT de Administrator** con extra SID `…-519` (EA raíz), RC4 del krbtgt hijo | `KERB_TICKET_CACHE_ENTRY` @ `0x227473721b0` en LSASS |
| T4 | **Robo del `_TOKEN`** de la sesión RDP viva de **rfairfax** (DA/EA raíz), SecurityImpersonation | `_TOKEN` `0xffffca8ddc130830`, TID **4968**, LogonID `0xa616a` |
| T5 | Ejecución con privilegios de la raíz → **toma total del bosque DIOGENES** | golden + RBCD + token, todos convergiendo sobre `diogenes.htb` |

### IOCs

- **Hash del implante (SHA256):** `1e44c63950dd4fe1ffcc955c08d509132bcaddf87bbb08f5ea622d0533625274` (service agent `svc_bkup`).
- **Servicio secuestrado:** `defragsvc` (`svchost.exe -k defragsvc`), proceso **PID 3376**, thread malicioso **TID 4968**.
- **Cuenta de implante:** `svc_bkup` / `svc_bkup$` — SID `S-1-5-21-2253468260-689643353-167204612-1140`.
- **IP del atacante (NAPOLEON):** `192.168.56.1`; **DC02** víctima `192.168.56.11` (`core.diogenes.htb`).
- **Cuentas comprometidas:** afenwick, jreed (pivote NTLM), rfairfax (DA/EA raíz, token robado).
- **Artefacto Kerberos:** golden TGT de `Administrator` con `ExtraSids = S-1-5-21-3066635835-107521988-671693545-519`, RC4/etype23, **PAC sin Ticket Signature (type 16)** — firma inequívoca de golden forjado.
- **RBCD:** `msDS-AllowedToActOnBehalfOfOtherIdentity` poblado en `svc_bkup$`.
- **SID dominio raíz:** `S-1-5-21-3066635835-107521988-671693545` · **SID dominio hijo:** `S-1-5-21-2253468260-689643353-167204612`.

### Mapeo MITRE ATT&CK

| Técnica | ID | Dónde aparece en el reto |
|---|---|---|
| **Steal or Forge Kerberos Tickets: Golden Ticket** | **T1558.001** | Golden TGT de Administrator con SID-history de EA raíz (Q2/Q3) |
| SID-History Injection | **T1134.005** | Extra SID `…-519` inyectado para cruzar de dominio hijo a raíz |
| **Access Token Manipulation: Token Impersonation/Theft** | **T1134.001** | Robo del `_TOKEN` SecurityImpersonation de la sesión RDP de rfairfax (Q4–Q6) |
| Domain Policy Modification / RBCD abuse (delegación) | **T1484 / T1550.003** | Escritura de `msDS-AllowedToActOnBehalfOfOtherIdentity` en `svc_bkup$` (Q7–Q9) |
| Account Manipulation / credential access (reset de pass) | **T1098 / T1556** | ResetNightmare: UPN swap + reset de jreed (Q10) |
| Create or Modify System Process: Windows Service (hijack) | **T1543.003** | Secuestro del servicio `defragsvc` como persistencia (Q1) |
| OS Credential Dumping (contra-lectura fría, "without dumping LSASS") | **T1003.001** | Lectura de `KERB_TICKET_CACHE_ENTRY` desde la imagen, sin minidump |
| Use Alternate Authentication Material: Pass the Ticket | **T1550.003** | Uso del golden TGT para autenticarse contra la raíz |

### Detección y remediación

**Detección.**
- **Golden ticket / PAC forjado:** un TGT cuyo PAC **carece de Ticket Signature (type 16)** o cuyos checksums no cuadran es golden por definición. Alertar sobre TGT de larga duración, `ExtraSids` con RID `-519`/`-518` del dominio **raíz** presentados a un DC, y TGS sin AS previo. Vigilar **4769** con encryption type `0x17` (RC4) para cuentas que deberían ir AES.
- **SID-History de cruce de dominio:** habilitar y auditar **SID filtering / quarantine** en confianzas donde aplique; cualquier SID del rango de la raíz en un ticket originado en el hijo es sospechoso.
- **Robo de token:** correlacionar **4624 LogonType 10** (RDP de un DA) seguido de acciones de red con ese LUID desde un proceso de servicio (SYSTEM). Sysmon **EID 10** (ProcessAccess sobre `lsass.exe`/procesos de sesión) y accesos con `SeImpersonatePrivilege`.
- **RBCD:** **4662/5136** sobre `msDS-AllowedToActOnBehalfOfOtherIdentity`; alertar en **cualquier** escritura de ese atributo, especialmente sobre cuentas de máquina.
- **Reset/abuse de contraseña:** **4723/4724** sobre cuentas de admin, cambios de **`userPrincipalName`** (correlacionar el "prepare" UPN swap con el reset), y logins **NTLM (LogonType 3)** de cuentas que deberían usar Kerberos.
- **Persistencia por servicio:** cambios en `ImagePath`/`ServiceDll` de servicios legítimos (`defragsvc`), Sysmon EID 1/7/13 sobre `svchost -k`.

**Remediación.**
- **Rotar dos veces el hash del `krbtgt`** de **ambos** dominios (hijo y raíz) — es lo único que invalida los golden tickets existentes; una sola rotación no basta.
- **Resetear** las cuentas comprometidas (afenwick, jreed, `svc_bkup$`, y **rfairfax** por robo de token) y **cerrar sus sesiones** (los tokens vivos sobreviven a un cambio de contraseña hasta el logoff).
- **Limpiar** el RBCD (`msDS-AllowedToActOnBehalfOfOtherIdentity` vacío) y eliminar la cuenta/servicio `svc_bkup`/`defragsvc` secuestrado.
- **Endurecer confianzas:** SID filtering, mínimo privilegio en EA/DA, tiering de administración (no RDP de cuentas de bosque a DCs hijos), PPL + WDAC en LSASS, y AES-only para cuentas sensibles.

### Respuestas / flags

| # | Pregunta | Respuesta |
|---|----------|-----------|
| 1 | SHA256 del *service agent* (implante `svc_bkup`, servicio `defragsvc`, PID 3376) | `1e44c63950dd4fe1ffcc955c08d509132bcaddf87bbb08f5ea622d0533625274` |
| 2 | Dirección del golden ticket (VA base de `KERB_TICKET_CACHE_ENTRY`) : md5 del ccache | `0x227473721b0:dcf56965eee82fff4d381c6127834d72` |
| 3 | KDCChecksum del mismo ticket (PAC type 7, hmac_md5) | `b63742148ab83e91d38dd632b5b1fb99` |
| 4 | `_TOKEN` robado (completo) | `0xffffca8ddc130830` |
| 5 | `ImpersonationLevel:LogonID` del token robado | `2:0xa616a` |
| 6 | `ThreadId` que porta el token | `4968` |
| 7 | Cuenta máquina RBCD (`SAM:SID`) | `svc_bkup$:S-1-5-21-2253468260-689643353-167204612-1140` |
| 8 | SID del dominio **raíz** | `S-1-5-21-3066635835-107521988-671693545` |
| 9 | RBCD `SubjectLogonId:LogonType` (jreed, NTLM desde 192.168.56.1) | `0x3f213b:3` |
| 10 | Ataque a contraseña (`prepare:reset`, UPN swap : 4723) | `0x17c514:0x17c569` |

**Flag final:** `HTB{3v3n_Th3_F0g_Kn0ws_D10g3n3s}`

### Lecciones

- **"Sin volcar LSASS" = pypykatz sobre la imagen, no minidump.** El plugin vol3 que lee `KERB_TICKET_CACHE_ENTRY` del `memory.elf` recupera los kirbis con su VA real y descifra la *session key*; un minidump de LSASS falla aquí por páginas paginadas y, además, el `KRB-CRED` en crudo trae la `enc-part` cifrada → ccache falso.
- **El "extra SID" que importa no es `S-1-5-9`.** En un ticket de DC, Enterprise Domain Controllers es ruido. El SID que delata la toma del bosque es el **SID-history de cruce de dominio** (`…-519`, Enterprise Admins de la raíz) inyectado en el golden de **Administrator**, descifrable con la **RC4 del krbtgt hijo**.
- **"Dirección del ticket" = base de la struct, no el buffer ni el offset físico.** El eje siempre es la **VA de LSASS** (`0x227…`), y la base está en `Ticket-member − 0xd0`, como el `_TOKEN`.
- **El md5 del ccache depende de la herramienta.** impacket ≠ minikerberos; itera hasta el formato exacto que valida el grader (aquí `dcf56965…`).
- **RC4 → hmac_md5; AES256 → hmac_sha1_96.** El etype del ticket determina el algoritmo (y la longitud) de los checksums del PAC. No confundir el KDCChecksum del ticket correcto con el del ticket señuelo.
- **Robo de token > cracking.** Suplantar el `_TOKEN` vivo de una sesión RDP de un DA (`SecurityImpersonation`) da EA de la raíz sin tocar una sola contraseña; **RBCD** y **golden ticket con SID-history** son los dos raíles para saltar de dominio hijo a raíz, y NAPOLEON usó los dos.

> **Cierre del arco.** "Last Light" es el **escenario final** de *The Reichenbach Directive*: el objetivo era siempre **DIOGENES**, y aquí se demuestra en RAM cómo el APT NAPOLEON convirtió un implante en DC02 en **control total del bosque raíz**. De S01 a S09, cada Sherlock añadió una pieza — el dividendo silencioso, la cadena de susurros, el fantasma de papel, el nombre prestado — y todas convergen en esta última luz. Fin del arco. Fin de la luz.

### Serie · The Reichenbach Directive

| Sherlock | Escenario | Enlace |
|---|---|---|
| S01 | Silent Dividend | [../2026-09-15-holmes2026-s01-silent-dividend/](../2026-09-15-holmes2026-s01-silent-dividend/) |
| S02 | Bottle Out | [../2026-09-16-holmes2026-s02-bottle-out/](../2026-09-16-holmes2026-s02-bottle-out/) |
| S03 | Whisper Chain | [../2026-09-17-holmes2026-s03-whisper-chain/](../2026-09-17-holmes2026-s03-whisper-chain/) |
| S04 | Paper Ghost | [../2026-09-18-holmes2026-s04-paper-ghost/](../2026-09-18-holmes2026-s04-paper-ghost/) |
| S05 | Poisoned Branch | [../2026-09-19-holmes2026-s05-poisoned-branch/](../2026-09-19-holmes2026-s05-poisoned-branch/) |
| S06 | Silent Passenger | [../2026-09-20-holmes2026-s06-silent-passenger/](../2026-09-20-holmes2026-s06-silent-passenger/) |
| S07 | Iron Feather | [../2026-09-21-holmes2026-s07-iron-feather/](../2026-09-21-holmes2026-s07-iron-feather/) |
| S08 | Borrowed Name | [../2026-09-22-holmes2026-s08-borrowed-name/](../2026-09-22-holmes2026-s08-borrowed-name/) |
| **S09** | **Last Light** *(este · final)* | [../2026-09-23-holmes2026-s09-last-light/](../2026-09-23-holmes2026-s09-last-light/) |

---

<a id="en"></a>

## 🇬🇧 English

### Scenario

Last light over DIOGENES. After the **S08 "Borrowed Name"** intrusion, APT **NAPOLEON** (from `192.168.56.1`) has already pivoted to the **child** domain controller **DC02** (`core.diogenes.htb`, `192.168.56.11`) and dropped a persistent implant. All we get is a **full memory dump** of DC02 captured with QEMU: `memory.elf`, alongside `ntds.dit`, the registry hives (`SYSTEM`, `SECURITY`, `SAM`) and `.evtx` logs (`Security.evtx`, `Microsoft-Windows-Sysmon%4Operational.evtx`).

The forest has two domains in a **parent-child** relationship inside the same forest, joined by a transitive two-way trust:

- **Root `diogenes.htb`** — DC **DIOCORE**, domain SID `S-1-5-21-3066635835-107521988-671693545`. Home of the forest's most powerful groups: **Enterprise Admins** (`…-519`) and **Schema Admins** (`…-518`).
- **Child `core.diogenes.htb`** — DC **DC02** (`192.168.56.11`), domain SID `S-1-5-21-2253468260-689643353-167204612`. This is where NAPOLEON has a foothold: owning it is **not** enough to own the forest — you must cross the trust boundary into the root.

Relevant accounts: **afenwick** and **jreed** (compromised earlier in the chain, S08) and **rfairfax**, a **root Domain/Enterprise Admin** with a **live RDP session** on DC02. The challenge: reconstruct, **from RAM alone**, how NAPOLEON went from a child-DC implant to **owning the entire forest**. Difficulty: **insane**.

The key wording — *"without dumping LSASS"* — is not cosmetic: it forces you to extract Kerberos tickets by reading `lsass.exe`'s structures **inside the image**, not by producing a minidump with `comsvcs.dll`/`procdump`. It is a nod to the OPSEC-aware operator: in 2026 dumping LSASS is one of the most watched events (Sysmon EID 10 on `lsass.exe`, WDAC, PPL). The challenge asks you to reproduce that same **cold** read, over already-frozen bytes.

> **Why a child domain is not the forest.** Active Directory's real security boundary is the **forest**, not the domain. Compromising the child's `krbtgt` gives you full control of the child, but the root **does not honor** SIDs the child mints inside the root's own range, save exceptions. To jump from child to root there are exactly two classic rails, and NAPOLEON used **both at once** (operator redundancy): (a) a **golden ticket with cross-domain SID-history** injecting the **root's** `-519` RID (Enterprise Admins), and (b) **RBCD** plus **theft of the live token** of a root admin logged into the child. At heart, this challenge is the anatomy of that double jump seen from memory.

### Artifact and tools

- **Dump:** `memory.elf` — QEMU *ELF core* of DC02 (Windows Server, build **17763** / 1809 LTSC). Not a classic `raw`/DumpIt: it is QEMU's *core* format, with `PT_LOAD` segments mapping guest RAM. Volatility 3 treats it as a physical layer; MemProcFS opens it natively with `-device`.
- **Volatility 3** for triage: `windows.pslist`, `windows.pstree`, `windows.dlllist`, `windows.registry.hivelist`, `windows.filescan`, `windows.netscan`.
- **pypykatz via Volatility 3** — the *"without dumping LSASS"* technique: a vol3 plugin that calls `pypykatz.go_volatility3` and reads the `KERB_TICKET_CACHE_ENTRY` structs of `lsass.exe` (**PID 604**) **straight from `memory.elf`**, with no minidump. I used **`scripts/vol3_pypykatz_kerberos.py`** from the `htb-sherlock-diogenes` skill (**credit to the skill's author**; internally it builds on `pypykatz` by Tamas Jos / @skelsec and the `volatility3.volreader` reader). The plugin **patches `KerberosTicket.aparse`** to capture, for each *kirbi*, both the **ticket buffer VA** and the **`struct_loc`** (the object's base in LSASS), serializing them to `addr.json`. **34 *kirbis*** exported to `KDIR`.
- **MemProcFS** (`memprocfs -device memory.elf -mount /mnt`) for **VA↔physical** translation and to enumerate the implant process's `_TOKEN`, threads and impersonation levels. On Parrot/py3.13 MemProcFS's Python API may segfault → use the **binary + FUSE** and walk the `/mnt/pid/<pid>/` tree.
- **impacket-ticketConverter** (kirbi→ccache) and **`describeTicket.py --rc4/--aes`** (Impacket) to read the **PAC** and its checksums.
- **Sysmon** (`Microsoft-Windows-Sysmon%4Operational.evtx`) and **Security.evtx** for the implant's PID/TID and the password-reset events (4723/4724) and RBCD configuration (4662/5136).
- Support: `evtx_dump` / `python-evtx`, standalone `pypykatz` to rebuild the *session key*, and `xxd`/`radare2` to confirm ASN.1 headers (`0x76 0x82` = `KRB-CRED`, `0x61 0x82` = `Ticket`) over the candidate VAs.

### Methodology (step by step)

#### 1. The implant — hijacked `defragsvc` service (Q1)

**The why.** The S08 chain ends with NAPOLEON uploading an agent to `\\dc02\ADMIN$\svc_bkup` and **hijacking the defrag service** `defragsvc` (hosted in `svchost.exe -k defragsvc`). A persistence classic: instead of creating a noisy new service, it rewrites the `ServiceDll`/`ImagePath` of a legitimate, lightly-watched one. The resulting process runs as **svc_bkup**, the implant's own machine/service account.

In `windows.pslist`/`pstree` and in Sysmon **EventID 1 (Process Create)** there is a `svchost.exe -k defragsvc` hanging off the service tree, with **PID 3376** and a command line consistent with the hijack:

```bash
# Process triage and locating the hijacked-service svchost
vol -f memory.elf windows.pstree | grep -Ei 'svchost|defrag|svc_bkup'
vol -f memory.elf windows.pslist | grep -i 3376

# Confirm via Sysmon EID1 (implant process creation)
evtx_dump Microsoft-Windows-Sysmon%4Operational.evtx \
  | grep -A30 -i defragsvc | grep -Ei 'ProcessId|Image|Hashes|User'
```

Carving the implant binary from disk (`C:\Windows\...`, referenced by the service) and hashing it:

```bash
sha256sum agent.bin
# 1e44c63950dd4fe1ffcc955c08d509132bcaddf87bbb08f5ea622d0533625274
```

That SHA256 identifies the *service agent* (**Q1**). Sysmon EID 1 usually already carries the hash in `Hashes:` when `HashAlgorithms` includes SHA256, so it can be corroborated without re-hashing. **PID 3376 is the pivot process for everything that follows** (Q4–Q7): the stolen token hangs off one of its threads and its machine account `svc_bkup$` is the RBCD beneficiary.

#### 2. The Kerberos tickets — without touching LSASS (basis for Q2/Q3)

**The why.** A golden ticket is a **forged TGT** encrypted with the `krbtgt` key: whoever holds the `krbtgt` hash can fabricate a TGT for any user, with any group membership, bypassing the KDC. In memory, those TGTs live in LSASS's **ticket cache**, as `KERB_TICKET_CACHE_ENTRY` structs. The "without dumping LSASS" technique is reading those structs straight from the image.

Inject `pypykatz` into volatility3 and run the skill's plugin, which walks `lsass.exe`'s logon sessions and *orphaned creds* and serializes each ticket to `.kirbi` **with its address**:

```bash
# Prepare the environment and run the plugin (credit: htb-sherlock-diogenes skill)
pipx inject volatility3 pypykatz
export KDIR=out
vol -f memory.elf -p scripts vol3_pypykatz_kerberos.PpkKerb   # → 34 kirbis + addr.json

# For each ticket the plugin writes: {idx, fn, ticket_va, struct_loc}
jq '.[] | select(.fn|test("Administrator"))' out/addr.json
```

Among the 34 *kirbis* there are **several golden tickets**. Here is the challenge's first trap:

**The one the prompt means — "with the extra SID" — is NOT the obvious one.** The **DC02$** golden (`krbtgt/CORE.DIOGENES.HTB`) carries `S-1-5-9` (Enterprise Domain Controllers), but **that SID is normal in any DC ticket** (every domain controller carries it for DCSync/replication): noise, not the answer. The ticket with the *extra SID* that matters is the **golden TGT for `Administrator`** (also `krbtgt/CORE.DIOGENES.HTB`, encrypted **RC4/etype23**): it is the only one with a **cross-domain SID-history** injection:

```text
Extra SID (Count 1) = S-1-5-21-3066635835-107521988-671693545-519   # ROOT Enterprise Admins
                      └─────────── ROOT domain SID ─────────────┘ └519┘
```

In other words: they forged a **child-domain** `Administrator` TGT and, via the `ExtraSids` field of the PAC's `KERB_VALIDATION_INFO` (flag `LOGON_EXTRA_SIDS`), stuffed in the **root Enterprise Admins**. Because **SID filtering** between domains *of the same forest* does not by default filter the root's own range, that TGT presented to DIOCORE grants **forest EA**. It decrypts with the child **krbtgt RC4/NT** (`e812d14a9c390f7400549593fc98a2c2`), **not** the AES key: the unmistakable signature of an `impacket-ticketer` golden in RC4 mode.

```bash
# Confirm the ticket cipher over its VA (ASN.1 header 61 82 = Ticket / 76 82 = KRB-CRED)
# using MemProcFS to translate VA→physical offset in memory.elf
xxd -s <phys_off> -l 16 memory.elf     # → 76 82 05 ..  (KRB-CRED) / 61 82 ..  (Ticket)

# Inspect/decrypt the Administrator golden with the child krbtgt RC4
describeTicket.py Administrator.ccache --rc4 e812d14a9c390f7400549593fc98a2c2 \
  | grep -Ei 'ExtraSids|UserName|LogonDomainName|GroupIds|UserFlags'
```

#### 3. Q2 — the ticket address + the ccache md5

**The why (the second trap).** *"Memory address of the ticket"* is **not** the physical offset in `memory.elf`, nor the `fileoff`, nor the pointer to the ticket's **data buffer**. It is the **base of the `KERB_TICKET_CACHE_ENTRY` struct** — the "ticket object" — on **LSASS's VA axis** (`0x227...`), exactly the same criterion applied to Q4's `_TOKEN` (an object, referred to by its struct base). That object sits at `Ticket-member − 0xd0`: the entry's `Ticket` member points to the buffer, and the struct base is `0xd0` bytes below it.

```text
KERB_TICKET_CACHE_ENTRY @ 0x227473721b0   ← struct base = "the ticket address" (Q2)
                        + 0xd0
        .Ticket (member) @ 0x227473722e0   ← pointer to the kirbi/KRB-CRED buffer
```

I convert the kirbi (already with the *session key* decrypted by pypykatz — crucial, because the **raw `KRB-CRED` in memory** carries an **encrypted** `enc-part`, and converting *that* yields a bogus ccache) to ccache and take its md5:

```bash
impacket-ticketConverter out/0xx_Administrator@CORE.DIOGENES.HTB.kirbi Administrator.ccache
md5sum Administrator.ccache
```

Answer **Q2** (grader OK): **`0x227473721b0:dcf56965eee82fff4d381c6127834d72`**.

> **Honest process note (several real iterations).** The ccache md5 is **tool-dependent** (impacket ≠ minikerberos ≠ the exact format the grader validates), and the address axis had three false candidates before the right one:
> - `88512e19…` — came from the **raw `KRB-CRED` in memory with an encrypted `enc-part`** → bogus ccache. Rejected.
> - The **DC02$** golden (extra SID `S-1-5-9`) with md5 `558c8077…` / addr `0x2274733d37c` → the *wrong* ticket (S-1-5-9 is noise). Rejected by the grader.
> - `file-off` and `guest-phys` style addresses → **rejected**; the correct axis is the **LSASS VA**.
>
> The valid answer is the **Administrator** golden, taking the **struct base VA** (`0x227473721b0`, not the `Ticket` member's nor the buffer's) and md5 `dcf56965…`.

#### 4. Q3 — the KDCChecksum

**The why.** The **PAC** (Privilege Attribute Certificate) inside the TGT carries several signatures. An `impacket-ticketer` golden generates a minimal PAC with buffers `[1, 10, 12, 6, 7]` and **no *Ticket Signature*** (type 16), which already betrays it as forged (a legit TGT from a modern KDC includes it). The two present signatures are:

- **ServerChecksum** (PAC buffer **type 6**) — signed with the service key (here the `krbtgt`).
- **KDCChecksum** (PAC buffer **type 7**) — the KDC's signature over the ServerChecksum.

Since the ticket is **RC4/etype23**, both checksums use **`hmac_md5`** (an AES256 ticket would use `hmac_sha1_96`, and the KDCChecksum would be 12 bytes instead of 16). Reading the PAC of the **same** Administrator golden:

```bash
describeTicket.py Administrator.ccache --rc4 e812d14a9c390f7400549593fc98a2c2 \
  | grep -Ei 'Checksum|Signature|PAC_'
# ServerChecksum (type 6, hmac_md5) = 5cc2da157cb1c50b8f555401bea362af
# KDCChecksum    (type 7, hmac_md5) = b63742148ab83e91d38dd632b5b1fb99
```

Answer **Q3**: **`b63742148ab83e91d38dd632b5b1fb99`** (KDCChecksum, PAC type 7, `hmac_md5`). Do not confuse it with the DC02$ golden's KDCChecksum (`1438cc04…`, the wrong ticket, and AES → `hmac_sha1_96`).

#### 5. Q4–Q6 — token theft from a Domain Admin session

**The why.** NAPOLEON **did not crack** rfairfax's password. rfairfax (root DA/EA) had a **live RDP session** on DC02; its impersonation `_TOKEN` was resident in memory. The implant, running as SYSTEM, **duplicated/stole** that token and attached it to one of its threads (`SeImpersonatePrivilege` → `ImpersonateLoggedOnUser`/`DuplicateTokenEx` pattern). With that token, any network action of the thread authenticates **as rfairfax** → root EA, without touching a password.

With MemProcFS I mount the image and inspect the implant process (**svc_bkup, PID 3376**), enumerating threads and each thread's `_TOKEN`:

```bash
memprocfs -device memory.elf -mount /mnt
# Implant threads and their token
ls  /mnt/pid/3376/threads/
cat /mnt/pid/3376/threads/4968/*        # TID 4968 carries the stolen token
cat /mnt/pid/3376/token/*               # _TOKEN, SID, ImpersonationLevel, LogonId

# vol3 alternative
vol -f memory.elf windows.threads --pid 3376
```

One of its threads (**TID 4968**) carries a **stolen `_TOKEN`**:

```text
_TOKEN (truncated) = 0xca8ddc130830          # full: 0xffffca8ddc130830
ImpersonationLevel : LogonID = 2 : 0xa616a   # 2 = SecurityImpersonation
ThreadId           = 4968
```

`ImpersonationLevel 2` = **SecurityImpersonation** (the level that lets you act on the network on behalf of the holder; `1` = Identification would not suffice). The `LogonID 0xa616a` is the **AuthenticationId** that **ties the token to rfairfax's logon session**: cross-reference with `windows.getsids`/4624 events to confirm that LUID belongs to the root DA's RDP session (LogonType 10). The full `_TOKEN` is reconstructed with the canonical kernel prefix `0xffff…` over the low 48 bits.

- **Q4** (full `_TOKEN`): **`0xffffca8ddc130830`**
- **Q5** (`ImpersonationLevel:LogonID`): **`2:0xa616a`**
- **Q6** (`ThreadId` carrying the token): **`4968`**

#### 6. Q7–Q9 — the RBCD abuse

**The why.** **RBCD** (Resource-Based Constrained Delegation) is delegation configured **on the target resource**: if you write the SID of an account you control into a machine's `msDS-AllowedToActOnBehalfOfOtherIdentity`, that account can request `S4U2Self`+`S4U2Proxy` and **impersonate any user** against that resource. NAPOLEON populated that attribute on its implant's machine account, `svc_bkup$`, giving itself a second impersonation rail besides the golden ticket.

In `ntds.dit` / the hives (`SECURITY`), the implant's machine account has `msDS-AllowedToActOnBehalfOfOtherIdentity` populated:

```bash
# Dump ntds and read svc_bkup$'s RBCD attribute
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL -just-dc-user 'CORE\svc_bkup$'
# or with dsInternals/ldbsearch offline:
Get-BootKey / Get-ADDBAccount -SamAccountName 'svc_bkup$' -DBPath ntds.dit \
  | select msDS-AllowedToActOnBehalfOfOtherIdentity
```

```text
RBCD machine account (SAM:SID) = svc_bkup$ : S-1-5-21-2253468260-689643353-167204612-1140
CHILD domain SID (derives)     = S-1-5-21-2253468260-689643353-167204612
ROOT domain SID                = S-1-5-21-3066635835-107521988-671693545
```

The event that **configured** the RBCD (the attribute write, visible as **4662** *"An operation was performed on an object"* / **5136** *"A directory service object was modified"* on `msDS-AllowedToActOnBehalfOfOtherIdentity`) shows up in `Security.evtx` under **jreed**, authenticated with **LogonType 3 (Network/NTLM)** from `192.168.56.1`:

```bash
evtx_dump Security.evtx | grep -B2 -A25 -i 'AllowedToActOnBehalf' \
  | grep -Ei 'SubjectUserName|SubjectLogonId|LogonType|IpAddress'
# SubjectUserName: jreed  SubjectLogonId: 0x3f213b  LogonType: 3  IpAddress: 192.168.56.1
```

- **Q7** (RBCD machine account, `SAM:SID`): **`svc_bkup$:S-1-5-21-2253468260-689643353-167204612-1140`**
- **Q8** (**root** domain SID): **`S-1-5-21-3066635835-107521988-671693545`**
- **Q9** (RBCD `SubjectLogonId:LogonType`): **`0x3f213b:3`**

#### 7. Q10 — the password attack (prepare:reset)

**The why.** The S08 chain (ResetNightmare / **CVE-2026-27912**, a Semperis-style Kerberos downgrade) still lives in the Security events. NAPOLEON, holding `WriteProperty` over **afenwick**'s `userPrincipalName`, did a **UPN swap** (afenwick → `"jreed"` and back) to *prepare* an AS-REQ that would hand it a TGT issued for jreed; with it, it went through `kadmin/changepw` and **reset jreed's password** (Security **EventID 4723** *"An attempt was made to change an account's password"* / **4724** *"…to reset an account's password"*). The **Record IDs** (`EventRecordID`) of both events are the requested pair:

```bash
evtx_dump Security.evtx \
  | grep -Ei 'EventRecordID|EventID|4723|4724|TargetUserName|userPrincipalName'
# prepare (UPN swap on afenwick)   → EventRecordID 0x17c514
# reset   (4723 jreed password)    → EventRecordID 0x17c569
```

```text
prepare (UPN swap) : reset (4723) = 0x17c514 : 0x17c569
```

Answer **Q10**: **`0x17c514:0x17c569`**. That closes the challenge and drops the **flag: `HTB{3v3n_Th3_F0g_Kn0ws_D10g3n3s}`**.

### Timeline

| Moment | Event | Evidence |
|---|---|---|
| T0 (S08) | UPN swap on **afenwick** (`WriteProperty` over her UPN) to prepare the enterprise AS-REQ | `Security.evtx` — EventRecordID `0x17c514` |
| T0+ | **jreed** password reset (ResetNightmare / CVE-2026-27912) | `Security.evtx` — **4723**, EventRecordID `0x17c569` |
| T1 | **jreed** (NTLM/LogonType 3) from `192.168.56.1` writes the RBCD on `svc_bkup$` | `Security.evtx` — **4662/5136**, SubjectLogonId `0x3f213b` |
| T2 | Implant deployed: **`defragsvc`** hijack, `svchost.exe -k defragsvc` as **svc_bkup PID 3376** | Sysmon **EID 1**; SHA256 `1e44c639…` |
| T3 | Forge of the **Administrator golden TGT** with extra SID `…-519` (root EA), child krbtgt RC4 | `KERB_TICKET_CACHE_ENTRY` @ `0x227473721b0` in LSASS |
| T4 | **`_TOKEN` theft** of **rfairfax**'s live RDP session (root DA/EA), SecurityImpersonation | `_TOKEN` `0xffffca8ddc130830`, TID **4968**, LogonID `0xa616a` |
| T5 | Execution with root privileges → **total takeover of the DIOGENES forest** | golden + RBCD + token, all converging on `diogenes.htb` |

### IOCs

- **Implant hash (SHA256):** `1e44c63950dd4fe1ffcc955c08d509132bcaddf87bbb08f5ea622d0533625274` (service agent `svc_bkup`).
- **Hijacked service:** `defragsvc` (`svchost.exe -k defragsvc`), process **PID 3376**, malicious thread **TID 4968**.
- **Implant account:** `svc_bkup` / `svc_bkup$` — SID `S-1-5-21-2253468260-689643353-167204612-1140`.
- **Attacker IP (NAPOLEON):** `192.168.56.1`; victim **DC02** `192.168.56.11` (`core.diogenes.htb`).
- **Compromised accounts:** afenwick, jreed (NTLM pivot), rfairfax (root DA/EA, stolen token).
- **Kerberos artifact:** Administrator golden TGT with `ExtraSids = S-1-5-21-3066635835-107521988-671693545-519`, RC4/etype23, **no Ticket Signature (type 16)** — unmistakable forged-golden signature.
- **RBCD:** `msDS-AllowedToActOnBehalfOfOtherIdentity` populated on `svc_bkup$`.
- **Root domain SID:** `S-1-5-21-3066635835-107521988-671693545` · **Child domain SID:** `S-1-5-21-2253468260-689643353-167204612`.

### MITRE ATT&CK mapping

| Technique | ID | Where it appears in the challenge |
|---|---|---|
| **Steal or Forge Kerberos Tickets: Golden Ticket** | **T1558.001** | Administrator golden TGT with root-EA SID-history (Q2/Q3) |
| SID-History Injection | **T1134.005** | Extra SID `…-519` injected to cross from child to root domain |
| **Access Token Manipulation: Token Impersonation/Theft** | **T1134.001** | Theft of rfairfax's RDP `_TOKEN` (SecurityImpersonation) (Q4–Q6) |
| Domain Policy Modification / RBCD abuse (delegation) | **T1484 / T1550.003** | Write of `msDS-AllowedToActOnBehalfOfOtherIdentity` on `svc_bkup$` (Q7–Q9) |
| Account Manipulation / credential access (password reset) | **T1098 / T1556** | ResetNightmare: UPN swap + jreed reset (Q10) |
| Create or Modify System Process: Windows Service (hijack) | **T1543.003** | `defragsvc` service hijack as persistence (Q1) |
| OS Credential Dumping (cold-read counter, "without dumping LSASS") | **T1003.001** | Reading `KERB_TICKET_CACHE_ENTRY` from the image, no minidump |
| Use Alternate Authentication Material: Pass the Ticket | **T1550.003** | Using the golden TGT to authenticate against the root |

### Detection and remediation

**Detection.**
- **Golden ticket / forged PAC:** a TGT whose PAC **lacks the Ticket Signature (type 16)** or whose checksums do not match is golden by definition. Alert on long-lived TGTs, `ExtraSids` carrying the **root** domain's `-519`/`-518` RIDs presented to a DC, and TGS with no preceding AS. Watch **4769** with encryption type `0x17` (RC4) for accounts that should be AES.
- **Cross-domain SID-History:** enable and audit **SID filtering / quarantine** on trusts where applicable; any SID from the root's range in a ticket originating in the child is suspicious.
- **Token theft:** correlate **4624 LogonType 10** (a DA's RDP) followed by network actions with that LUID from a service (SYSTEM) process. Sysmon **EID 10** (ProcessAccess on `lsass.exe`/session processes) and `SeImpersonatePrivilege` use.
- **RBCD:** **4662/5136** on `msDS-AllowedToActOnBehalfOfOtherIdentity`; alert on **any** write of that attribute, especially onto machine accounts.
- **Password reset/abuse:** **4723/4724** on admin accounts, changes to **`userPrincipalName`** (correlate the "prepare" UPN swap with the reset), and **NTLM (LogonType 3)** logons from accounts that should use Kerberos.
- **Service persistence:** changes to `ImagePath`/`ServiceDll` of legit services (`defragsvc`), Sysmon EID 1/7/13 on `svchost -k`.

**Remediation.**
- **Rotate the `krbtgt` hash twice** for **both** domains (child and root) — the only thing that invalidates existing golden tickets; a single rotation is not enough.
- **Reset** the compromised accounts (afenwick, jreed, `svc_bkup$`, and **rfairfax** for the token theft) and **kill their sessions** (live tokens survive a password change until logoff).
- **Clean** the RBCD (empty `msDS-AllowedToActOnBehalfOfOtherIdentity`) and remove the hijacked `svc_bkup`/`defragsvc` account/service.
- **Harden trusts:** SID filtering, least privilege on EA/DA, admin tiering (no forest-account RDP to child DCs), PPL + WDAC on LSASS, and AES-only for sensitive accounts.

### Answers / flags

| # | Question | Answer |
|---|----------|--------|
| 1 | SHA256 of the *service agent* (implant `svc_bkup`, `defragsvc` service, PID 3376) | `1e44c63950dd4fe1ffcc955c08d509132bcaddf87bbb08f5ea622d0533625274` |
| 2 | Golden ticket address (base VA of `KERB_TICKET_CACHE_ENTRY`) : ccache md5 | `0x227473721b0:dcf56965eee82fff4d381c6127834d72` |
| 3 | KDCChecksum of that ticket (PAC type 7, hmac_md5) | `b63742148ab83e91d38dd632b5b1fb99` |
| 4 | Stolen `_TOKEN` (full) | `0xffffca8ddc130830` |
| 5 | `ImpersonationLevel:LogonID` of the stolen token | `2:0xa616a` |
| 6 | `ThreadId` carrying the token | `4968` |
| 7 | RBCD machine account (`SAM:SID`) | `svc_bkup$:S-1-5-21-2253468260-689643353-167204612-1140` |
| 8 | **Root** domain SID | `S-1-5-21-3066635835-107521988-671693545` |
| 9 | RBCD `SubjectLogonId:LogonType` (jreed, NTLM from 192.168.56.1) | `0x3f213b:3` |
| 10 | Password attack (`prepare:reset`, UPN swap : 4723) | `0x17c514:0x17c569` |

**Final flag:** `HTB{3v3n_Th3_F0g_Kn0ws_D10g3n3s}`

### Lessons

- **"Without dumping LSASS" = pypykatz over the image, not a minidump.** The vol3 plugin that reads `KERB_TICKET_CACHE_ENTRY` from `memory.elf` recovers kirbis with their real VA and decrypts the *session key*; a LSASS minidump fails here because of paged-out pages and, moreover, the raw `KRB-CRED` carries an encrypted `enc-part` → bogus ccache.
- **The "extra SID" that matters is not `S-1-5-9`.** In a DC ticket, Enterprise Domain Controllers is noise. The SID that betrays the forest takeover is the **cross-domain SID-history** (`…-519`, root Enterprise Admins) injected into the **Administrator** golden, decryptable with the **child krbtgt RC4**.
- **"Ticket address" = struct base, not the buffer or the physical offset.** The axis is always the **LSASS VA** (`0x227…`), and the base is at `Ticket-member − 0xd0`, like the `_TOKEN`.
- **ccache md5 is tool-dependent.** impacket ≠ minikerberos; iterate to the exact format the grader validates (here `dcf56965…`).
- **RC4 → hmac_md5; AES256 → hmac_sha1_96.** The ticket's etype determines the algorithm (and length) of the PAC checksums. Don't confuse the correct ticket's KDCChecksum with the decoy ticket's.
- **Token theft beats cracking.** Impersonating a DA's live RDP `_TOKEN` (`SecurityImpersonation`) yields root EA without touching a single password; **RBCD** and a **golden ticket with SID-history** are the two rails to jump from child to root domain, and NAPOLEON used both.

> **Arc finale.** "Last Light" is the **final scenario** of *The Reichenbach Directive*: the objective was always **DIOGENES**, and here — in RAM — we see how APT NAPOLEON turned a DC02 implant into **total control of the root forest**. From S01 to S09, each Sherlock added a piece — the silent dividend, the whisper chain, the paper ghost, the borrowed name — and they all converge on this last light. End of the arc. The light goes out.

### Series · The Reichenbach Directive

| Sherlock | Scenario | Link |
|---|---|---|
| S01 | Silent Dividend | [../2026-09-15-holmes2026-s01-silent-dividend/](../2026-09-15-holmes2026-s01-silent-dividend/) |
| S02 | Bottle Out | [../2026-09-16-holmes2026-s02-bottle-out/](../2026-09-16-holmes2026-s02-bottle-out/) |
| S03 | Whisper Chain | [../2026-09-17-holmes2026-s03-whisper-chain/](../2026-09-17-holmes2026-s03-whisper-chain/) |
| S04 | Paper Ghost | [../2026-09-18-holmes2026-s04-paper-ghost/](../2026-09-18-holmes2026-s04-paper-ghost/) |
| S05 | Poisoned Branch | [../2026-09-19-holmes2026-s05-poisoned-branch/](../2026-09-19-holmes2026-s05-poisoned-branch/) |
| S06 | Silent Passenger | [../2026-09-20-holmes2026-s06-silent-passenger/](../2026-09-20-holmes2026-s06-silent-passenger/) |
| S07 | Iron Feather | [../2026-09-21-holmes2026-s07-iron-feather/](../2026-09-21-holmes2026-s07-iron-feather/) |
| S08 | Borrowed Name | [../2026-09-22-holmes2026-s08-borrowed-name/](../2026-09-22-holmes2026-s08-borrowed-name/) |
| **S09** | **Last Light** *(this · finale)* | [../2026-09-23-holmes2026-s09-last-light/](../2026-09-23-holmes2026-s09-last-light/) |
