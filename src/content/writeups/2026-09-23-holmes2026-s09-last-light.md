---
title: "Holmes CTF 2026 — S09 Last Light"
date: 2026-09-23
description: "Forense de un volcado de memoria Windows (DC02, bosque DIOGENES): reconstruir un golden ticket con extra-SID, un abuso de RBCD y un robo de token, sin volcar LSASS."
excerpt: "El escenario final del arco. Un memory.elf de QEMU esconde la toma total del bosque DIOGENES: implante svc_bkup, golden ticket de Administrator con SID-history de Enterprise Admins raíz, RBCD y robo de _TOKEN de una sesión RDP de un Domain Admin."
platform: "HTB"
difficulty: "Insane"
image: "/images/ctf.svg"
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

Última luz sobre DIOGENES. Tras la intrusión de **S08 "Borrowed Name"**, el APT **NAPOLEON** (desde `192.168.56.1`) ya ha pivotado al controlador de dominio hijo **DC02** (`core.diogenes.htb`, `192.168.56.11`) y ha dejado un implante persistente. Lo único que nos entregan es un **volcado de memoria completo** de DC02 tomado con QEMU: `memory.elf`. Junto a él viajan `ntds.dit`, las *hives* de registro y logs `.evtx`.

El bosque tiene dos dominios: la **raíz `diogenes.htb`** (DC **DIOCORE**, SID `S-1-5-21-3066635835-107521988-671693545`) y el **hijo `core.diogenes.htb`** (DC02). Cuentas relevantes: **afenwick** y **jreed** (comprometidas en la cadena previa) y **rfairfax**, un **Domain/Enterprise Admin de la raíz** con una sesión RDP viva en DC02. El objetivo del reto es reconstruir, solo desde RAM, cómo NAPOLEON pasó de DC02 a **dueño de todo el bosque**. Dificultad: **insane**.

La consigna clave del enunciado — *"sin volcar LSASS"* — no es decorativa: obliga a extraer los tickets Kerberos leyendo las estructuras del propio `lsass.exe` dentro de la imagen, no con un minidump.

### Artefacto y herramientas

- **Volcado:** `memory.elf` — *ELF core* de QEMU de DC02 (Windows Server, build **17763**).
- **Volatility 3** para el triage: `windows.pslist`, `windows.dlllist`, `windows.registry.hivelist`, `windows.filescan`.
- **pypykatz vía Volatility 3** — la técnica *"without dumping LSASS"*: un plugin vol3 que llama a `pypykatz.go_volatility3` y lee las structs `KERB_TICKET_CACHE_ENTRY` de `lsass.exe` **directamente del `memory.elf`**, sin generar minidump. Usé el script **`scripts/vol3_pypykatz_kerberos.py`** de la skill `htb-sherlock-diogenes` (crédito al autor de la skill); parchea `KerberosTicket.aparse` para mapear cada *kirbi* a su **VA en LSASS**. 34 *kirbis* exportados.
- **MemProcFS** (`memprocfs -device memory.elf -mount /mnt`) para traducir **VA↔físico**, y para enumerar `_TOKEN`, *threads* e *impersonation levels* del proceso del implante. En Parrot/py3.13 la API Python puede segfaultar → usar el binario + FUSE.
- **impacket-ticketConverter** (kirbi→ccache) y **`describeTicket.py --rc4/--aes`** para leer el PAC.
- **Sysmon** y **Security.evtx** para PID/TID del implante y para los eventos de reset de contraseña.

### Metodología (paso a paso)

**1. El implante — servicio `defragsvc` secuestrado.** En `windows.pslist`/Sysmon aparece un `svchost.exe -k defragsvc` (servicio de desfragmentación **`defragfs`/`defragsvc`** secuestrado) lanzado como el implante de NAPOLEON, ejecutándose como **svc_bkup** con **PID 3376** (Sysmon **EventID 1**). Volcando el binario del disco (`C:\Windows\...`) y hasheándolo:

```
sha256sum agent.bin
# 1e44c63950dd4fe1ffcc955c08d509132bcaddf87bbb08f5ea622d0533625274
```

Ese SHA256 identifica el *service agent* (**Q1**). PID 3376 será el proceso pivote de todo lo que sigue.

**2. Los tickets Kerberos — sin tocar LSASS.** Inyecto `pypykatz` en volatility3 y lanzo el plugin de la skill, que lee las cachés de tickets de `lsass.exe` desde la imagen:

```
pipx inject volatility3 pypykatz
vol -f memory.elf -p scripts vol3_pypykatz_kerberos.PpkKerb   # KDIR=out → 34 kirbis
```

Entre los 34 *kirbis* hay varios golden. **El del enunciado — "con el extra SID"— NO es el que primero parece.** El golden de **DC02$** (`krbtgt/CORE.DIOGENES.HTB`) lleva `S-1-5-9` (Enterprise Domain Controllers), pero **ese SID es normal en cualquier ticket de un DC**. El ticket con el *extra SID* que importa es el **golden TGT de `Administrator`** (también `krbtgt/CORE.DIOGENES.HTB`, **RC4/etype23**): es el único con un SID inyectado por **SID-history de cruce de dominio** →

```
Extra SID (Count 1) = S-1-5-21-3066635835-107521988-671693545-519   # Enterprise Admins de la RAÍZ
```

Es decir: forjaron un TGT de Administrator del dominio hijo y le metieron los **Enterprise Admins de la raíz** para saltar de `core` a `diogenes.htb`. Descifra con la **RC4/NT del krbtgt hijo** (`e812d14a9c390f7400549593fc98a2c2`), no con la AES.

**3. Q2 — la dirección del ticket + el md5 del ccache.** El segundo escollo: *"memory address of the ticket"* **no** es el offset físico ni el puntero al buffer de datos, sino la **base de la struct `KERB_TICKET_CACHE_ENTRY`** (el "objeto ticket", exactamente igual que el `_TOKEN` de Q4), sobre el **eje VA de LSASS** (`0x227...`). Ese objeto está en `Ticket-member − 0xd0`. Convierto el kirbi a ccache y saco su md5:

```
impacket-ticketConverter Administrator.kirbi Administrator.ccache
md5sum Administrator.ccache
```

Respuesta **Q2** (grader OK): **`0x227473721b0:dcf56965eee82fff4d381c6127834d72`**.

> Nota honesta de proceso: el md5 del ccache **depende de la herramienta** (impacket ≠ minikerberos ≠ el que espera el grader), y este reto costó varias iteraciones. Los primeros candidatos `88512e19…` (KRB-CRED con enc-part **cifrado** → ccache falso) y luego los del golden de **DC02$** fueron **rechazados**; el válido es el del golden de **Administrator** sobre la **VA base de la struct**.

**4. Q3 — el KDCChecksum.** Leyendo el PAC del mismo ticket (`describeTicket.py --rc4`), el golden de impacket trae un PAC mínimo sin *Ticket Signature*; el **KDCChecksum** (PAC buffer type 7) de un ticket RC4 usa **hmac_md5**:

```
KDCChecksum  = b63742148ab83e91d38dd632b5b1fb99   # (ServerChecksum type6 = 5cc2da157cb1c50b8f555401bea362af)
```

Respuesta **Q3**: **`b63742148ab83e91d38dd632b5b1fb99`**.

**5. Q4–Q6 — robo de token de una sesión de Domain Admin.** Con MemProcFS monto la imagen y examino el proceso del implante (**svc_bkup, PID 3376**). Uno de sus *threads* porta un **`_TOKEN` robado**:

```
_TOKEN (truncado) = 0xca8ddc130830        # completo: 0xffffca8ddc130830
ImpersonationLevel : LogonID = 2:0xa616a  # 2 = SecurityImpersonation
ThreadId = 4968
```

El token robado es el de la **sesión RDP viva de `rfairfax`** (DA/EA de la raíz): NAPOLEON no crackeó nada, **suplantó** el token de un admin que estaba logueado. `ImpersonationLevel 2` = **SecurityImpersonation** y `LogonID 0xa616a` liga el token a esa sesión. El *thread* que lo lleva es el **TID 4968**.

- **Q4** (`_TOKEN` completo): **`0xffffca8ddc130830`**
- **Q5** (`ImpersonationLevel:LogonID`): **`2:0xa616a`**
- **Q6** (`ThreadId`): **`4968`**

**6. Q7–Q9 — el abuso de RBCD.** En `ntds.dit` / las *hives*, la cuenta de máquina del implante tiene poblado `msDS-AllowedToActOnBehalfOfOtherIdentity` (**Resource-Based Constrained Delegation**):

```
Cuenta máquina RBCD (SAM:SID) = svc_bkup$ : S-1-5-21-2253468260-689643353-167204612-1140
SID del dominio RAÍZ           = S-1-5-21-3066635835-107521988-671693545
```

El evento que **configuró** el RBCD (escritura del atributo) aparece en Security.evtx a nombre de **jreed**, con **LogonType 3 (NTLM)** desde `192.168.56.1`:

```
SubjectLogonId : LogonType = 0x3f213b : 3
```

- **Q7** (cuenta máquina RBCD, `SAM:SID`): **`svc_bkup$:S-1-5-21-2253468260-689643353-167204612-1140`**
- **Q8** (SID del dominio **raíz**): **`S-1-5-21-3066635835-107521988-671693545`**
- **Q9** (`SubjectLogonId:LogonType` del RBCD): **`0x3f213b:3`**

**7. Q10 — el ataque a la contraseña (prepare:reset).** La cadena de S08 vive todavía en los eventos: NAPOLEON hizo un **swap del UPN de afenwick** (afenwick → "jreed" y reverso) para *preparar* el AS-REQ, y luego un **cambio de contraseña de jreed** (Security **EventID 4723**). Los *Record IDs* de ambos eventos son el par pedido:

```
prepare (UPN swap) : reset (4723) = 0x17c514 : 0x17c569
```

Respuesta **Q10**: **`0x17c514:0x17c569`**. Con ello se cierra el reto y cae la **flag: `HTB{3v3n_Th3_F0g_Kn0ws_D10g3n3s}`**.

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

- **"Sin volcar LSASS" = pypykatz sobre la imagen, no minidump.** El plugin vol3 que lee `KERB_TICKET_CACHE_ENTRY` del `memory.elf` recupera los kirbis con su VA real; un minidump de LSASS falla aquí por páginas paginadas.
- **El "extra SID" que importa no es `S-1-5-9`.** En un ticket de DC, Enterprise Domain Controllers es ruido. El SID que delata la toma del bosque es el **SID-history de cruce de dominio** (`…-519`, Enterprise Admins de la raíz) inyectado en el golden de **Administrator**, descifrable con la **RC4 del krbtgt hijo**.
- **"Dirección del ticket" = base de la struct, no el buffer ni el offset físico.** El eje siempre es la **VA de LSASS** (`0x227…`), como el `_TOKEN`.
- **El md5 del ccache depende de la herramienta.** impacket ≠ minikerberos; itera hasta el formato que espera el grader.
- **Robo de token > cracking.** Suplantar el `_TOKEN` vivo de una sesión RDP de un DA (`SecurityImpersonation`) da EA de la raíz sin tocar una sola contraseña; **RBCD** y **golden ticket con SID-history** son los dos raíles para saltar de dominio hijo a raíz.

> **Cierre del arco.** "Last Light" es el **escenario final** de *The Reichenbach Directive*: el objetivo era siempre **DIOGENES**, y aquí se demuestra en RAM cómo el APT NAPOLEON convirtió un implante en DC02 en control total del bosque raíz. Fin de la luz.

---

<a id="en"></a>

## 🇬🇧 English

### Scenario

Last light over DIOGENES. After the **S08 "Borrowed Name"** intrusion, APT **NAPOLEON** (from `192.168.56.1`) has already pivoted to the **child** domain controller **DC02** (`core.diogenes.htb`, `192.168.56.11`) and dropped a persistent implant. All we get is a **full memory dump** of DC02 captured with QEMU: `memory.elf`, alongside `ntds.dit`, the registry hives and `.evtx` logs.

The forest has two domains: the **root `diogenes.htb`** (DC **DIOCORE**, SID `S-1-5-21-3066635835-107521988-671693545`) and the **child `core.diogenes.htb`** (DC02). Relevant accounts: **afenwick** and **jreed** (compromised earlier in the chain) and **rfairfax**, a **root Domain/Enterprise Admin** with a live RDP session on DC02. The challenge: reconstruct, from RAM alone, how NAPOLEON went from DC02 to **owning the entire forest**. Difficulty: **insane**.

The key wording — *"without dumping LSASS"* — is not cosmetic: it forces you to extract Kerberos tickets by reading `lsass.exe`'s structures inside the image itself, not from a minidump.

### Artifact and tools

- **Dump:** `memory.elf` — QEMU *ELF core* of DC02 (Windows Server, build **17763**).
- **Volatility 3** for triage: `windows.pslist`, `windows.dlllist`, `windows.registry.hivelist`, `windows.filescan`.
- **pypykatz via Volatility 3** — the *"without dumping LSASS"* technique: a vol3 plugin that calls `pypykatz.go_volatility3` and reads the `KERB_TICKET_CACHE_ENTRY` structs of `lsass.exe` **straight from `memory.elf`**, with no minidump. I used **`scripts/vol3_pypykatz_kerberos.py`** from the `htb-sherlock-diogenes` skill (credit to the skill's author); it patches `KerberosTicket.aparse` to map each *kirbi* to its **LSASS VA**. 34 *kirbis* exported.
- **MemProcFS** (`memprocfs -device memory.elf -mount /mnt`) for **VA↔physical** translation and to enumerate the implant process's `_TOKEN`, threads and impersonation levels. On Parrot/py3.13 the Python API may segfault → use the binary + FUSE.
- **impacket-ticketConverter** (kirbi→ccache) and **`describeTicket.py --rc4/--aes`** to read the PAC.
- **Sysmon** and **Security.evtx** for the implant's PID/TID and the password-reset events.

### Methodology (step by step)

**1. The implant — hijacked `defragsvc` service.** In `windows.pslist`/Sysmon there is a `svchost.exe -k defragsvc` (hijacked **`defragfs`/`defragsvc`** defrag service) launched as NAPOLEON's implant, running as **svc_bkup** with **PID 3376** (Sysmon **EventID 1**). Carving the binary from disk (`C:\Windows\...`) and hashing it:

```
sha256sum agent.bin
# 1e44c63950dd4fe1ffcc955c08d509132bcaddf87bbb08f5ea622d0533625274
```

That SHA256 identifies the *service agent* (**Q1**). PID 3376 is the pivot process for everything that follows.

**2. The Kerberos tickets — without touching LSASS.** Inject `pypykatz` into volatility3 and run the skill's plugin, which reads `lsass.exe`'s ticket caches from the image:

```
pipx inject volatility3 pypykatz
vol -f memory.elf -p scripts vol3_pypykatz_kerberos.PpkKerb   # KDIR=out → 34 kirbis
```

Among the 34 *kirbis* there are several golden tickets. **The one the prompt means — "with the extra SID" — is NOT the obvious one.** The **DC02$** golden (`krbtgt/CORE.DIOGENES.HTB`) carries `S-1-5-9` (Enterprise Domain Controllers), but **that SID is normal in any DC ticket**. The ticket with the *extra SID* that matters is the **golden TGT for `Administrator`** (also `krbtgt/CORE.DIOGENES.HTB`, **RC4/etype23**): it is the only one with a **cross-domain SID-history** injection →

```
Extra SID (Count 1) = S-1-5-21-3066635835-107521988-671693545-519   # ROOT Enterprise Admins
```

In other words: they forged a child-domain Administrator TGT and stuffed in the **root Enterprise Admins** to jump from `core` to `diogenes.htb`. It decrypts with the child **krbtgt RC4/NT** (`e812d14a9c390f7400549593fc98a2c2`), not the AES key.

**3. Q2 — the ticket address + the ccache md5.** The second trap: *"memory address of the ticket"* is **not** the physical offset nor the pointer to the data buffer, but the **base of the `KERB_TICKET_CACHE_ENTRY` struct** (the "ticket object", exactly like Q4's `_TOKEN`), on the **LSASS VA axis** (`0x227...`). That object sits at `Ticket-member − 0xd0`. Convert the kirbi to ccache and take its md5:

```
impacket-ticketConverter Administrator.kirbi Administrator.ccache
md5sum Administrator.ccache
```

Answer **Q2** (grader OK): **`0x227473721b0:dcf56965eee82fff4d381c6127834d72`**.

> Honest process note: the ccache md5 is **tool-dependent** (impacket ≠ minikerberos ≠ whatever the grader expects), and this one took several iterations. Early candidates `88512e19…` (KRB-CRED with an **encrypted** enc-part → bogus ccache) and then the **DC02$** golden's were **rejected**; the valid answer is the **Administrator** golden on the **struct base VA**.

**4. Q3 — the KDCChecksum.** Reading the PAC of the same ticket (`describeTicket.py --rc4`), the impacket golden ships a minimal PAC with no *Ticket Signature*; the **KDCChecksum** (PAC buffer type 7) of an RC4 ticket uses **hmac_md5**:

```
KDCChecksum  = b63742148ab83e91d38dd632b5b1fb99   # (ServerChecksum type6 = 5cc2da157cb1c50b8f555401bea362af)
```

Answer **Q3**: **`b63742148ab83e91d38dd632b5b1fb99`**.

**5. Q4–Q6 — token theft from a Domain Admin session.** With MemProcFS I mount the image and inspect the implant process (**svc_bkup, PID 3376**). One of its threads carries a **stolen `_TOKEN`**:

```
_TOKEN (truncated) = 0xca8ddc130830        # full: 0xffffca8ddc130830
ImpersonationLevel : LogonID = 2:0xa616a   # 2 = SecurityImpersonation
ThreadId = 4968
```

The stolen token belongs to **`rfairfax`'s live RDP session** (root DA/EA): NAPOLEON cracked nothing — it **impersonated** a logged-in admin's token. `ImpersonationLevel 2` = **SecurityImpersonation** and `LogonID 0xa616a` ties the token to that session. The carrying thread is **TID 4968**.

- **Q4** (full `_TOKEN`): **`0xffffca8ddc130830`**
- **Q5** (`ImpersonationLevel:LogonID`): **`2:0xa616a`**
- **Q6** (`ThreadId`): **`4968`**

**6. Q7–Q9 — the RBCD abuse.** In `ntds.dit` / the hives, the implant's machine account has `msDS-AllowedToActOnBehalfOfOtherIdentity` populated (**Resource-Based Constrained Delegation**):

```
RBCD machine account (SAM:SID) = svc_bkup$ : S-1-5-21-2253468260-689643353-167204612-1140
ROOT domain SID                = S-1-5-21-3066635835-107521988-671693545
```

The event that **configured** the RBCD (the attribute write) shows up in Security.evtx under **jreed**, with **LogonType 3 (NTLM)** from `192.168.56.1`:

```
SubjectLogonId : LogonType = 0x3f213b : 3
```

- **Q7** (RBCD machine account, `SAM:SID`): **`svc_bkup$:S-1-5-21-2253468260-689643353-167204612-1140`**
- **Q8** (**root** domain SID): **`S-1-5-21-3066635835-107521988-671693545`**
- **Q9** (RBCD `SubjectLogonId:LogonType`): **`0x3f213b:3`**

**7. Q10 — the password attack (prepare:reset).** The S08 chain still lives in the events: NAPOLEON did a **UPN swap on afenwick** (afenwick → "jreed" and back) to *prepare* the AS-REQ, then a **jreed password change** (Security **EventID 4723**). The *Record IDs* of both events are the requested pair:

```
prepare (UPN swap) : reset (4723) = 0x17c514 : 0x17c569
```

Answer **Q10**: **`0x17c514:0x17c569`**. That closes the challenge and drops the **flag: `HTB{3v3n_Th3_F0g_Kn0ws_D10g3n3s}`**.

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

- **"Without dumping LSASS" = pypykatz over the image, not a minidump.** The vol3 plugin that reads `KERB_TICKET_CACHE_ENTRY` from `memory.elf` recovers kirbis with their real VA; a LSASS minidump fails here because of paged-out pages.
- **The "extra SID" that matters is not `S-1-5-9`.** In a DC ticket, Enterprise Domain Controllers is noise. The SID that betrays the forest takeover is the **cross-domain SID-history** (`…-519`, root Enterprise Admins) injected into the **Administrator** golden, decryptable with the **child krbtgt RC4**.
- **"Ticket address" = struct base, not the buffer or the physical offset.** The axis is always the **LSASS VA** (`0x227…`), like the `_TOKEN`.
- **ccache md5 is tool-dependent.** impacket ≠ minikerberos; iterate to the format the grader expects.
- **Token theft beats cracking.** Impersonating a DA's live RDP `_TOKEN` (`SecurityImpersonation`) yields root EA without touching a single password; **RBCD** and a **golden ticket with SID-history** are the two rails to jump from child to root domain.

> **Arc finale.** "Last Light" is the **final scenario** of *The Reichenbach Directive*: the objective was always **DIOGENES**, and here — in RAM — we see how APT NAPOLEON turned a DC02 implant into total control of the root forest. The light goes out.
