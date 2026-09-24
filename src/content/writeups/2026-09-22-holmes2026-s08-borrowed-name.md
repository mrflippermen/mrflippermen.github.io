---
title: "Holmes CTF 2026 — S08 Borrowed Name"
date: 2026-09-22
description: "DFIR de un incidente Active Directory: agente AdaptixC2 vía DLL sideloading, tráfico NTLM descifrado y privesc ResetNightmare (CVE-2026-27912)."
excerpt: "USB con DLL sideloading despliega AdaptixC2; se descifra el PCAP RC4 y se reconstruye la cadena Internal Monologue → ResetNightmare → movimiento lateral a DC02."
platform: "HTB"
difficulty: "Insane"
image: "/images/ctf.svg"
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

Tras la recuperación de un dron (Sherlock anterior), Eleanor Mercer detecta una **sesión saliente no autorizada** desde una estación de trabajo protegida (WS02) del bosque **DIOGENES**. La actividad no coincide con ningún software aprobado y continúa después de retirar un objeto físico. El origen es un **USB** dejado con apariencia de documento de RRHH ("Q3 Salary Review").

El bosque objetivo:

- Raíz **`diogenes.htb`** → DC **DIOCORE**
- Hijo **`core.diogenes.htb`** → DC **DC02** (`192.168.56.11`)
- Usuarios implicados: **afenwick** (comprometido inicial, WS02), **jreed** (objetivo del privesc), rfairfax.
- Implante final desplegado en DC02: **`svc_bkup`**.

El objetivo del análisis es reconstruir toda la cadena: cómo entró el operador, qué C2 usó, cómo escaló privilegios y cómo se movió lateralmente hasta el DC hijo.

### Artefacto y herramientas

**Evidencia entregada (`BorrowedName/`):**

| Artefacto | Descripción |
|-----------|-------------|
| `evidence/capture.pcapng` | Tráfico C2 (HTTP con cifrado RC4 propietario) |
| `evidence/usb/` | Contenido del USB: `docviewer.exe`, `version.dll`, `winupdate.exe`, `Salary_Review_Q3_2026.pdf.lnk`, `README.txt` |
| `evidence/Q3_Salary_Review.img` | Imagen FAT32 del USB (`.lnk` → `docviewer.exe`) |
| `evidence/C/Windows` + EVTX | Logs NTLM del host (EventID 4021 / NTLM) |
| PDF narrativo (Chapters 10-12) | Contexto del arco *The Reichenbach Directive* |

**Herramientas:** análisis PE (`file`, `strings`, Ghidra/radare2), extractor de config **AdaptixC2** (Unit42), scripts RC4 en Python para descifrar el PCAP, `hashcat` (mode 5600) para el NetNTLMv2, parseo de EVTX, y montaje de la imagen de disco.

Hashes de los binarios del USB:

```
aca111935d339b17544ead3e8c2c8831  docviewer.exe   (host legítimo del sideload)
6e787589a69ce783b0380b0de86a2d68  version.dll     (DLL maliciosa sideloaded)
b1c8c95d3bfa22780076084377584739  winupdate.exe   (agente AdaptixC2)
```

### Metodología (paso a paso)

1. **USB drop → DLL sideloading.** El `.lnk` del USB lanza `docviewer.exe` (binario firmado/legítimo). En el mismo directorio se coloca `version.dll` maliciosa: al arrancar, `docviewer.exe` resuelve `version.dll` por orden de búsqueda y **carga la DLL del atacante** (DLL search-order hijacking / sideloading). La DLL despliega `winupdate.exe`, el agente C2.

2. **Identificación del C2.** `winupdate.exe` contiene la clase `ConnectorHTTP`, header **`X-Beacon-Id`**, named pipe `\\.\pipe\%08lx`, perfil RC4 embebido con URIs rotando y respuestas JSON `{"status":"ok","data":"...","metrics":"sync"}`. La terminología BeaconID / SessionKey / EncryptionKey + BOF apunta a **AdaptixC2** (extractor de config de Unit42).

3. **Extracción de claves.** En la sección `.rdata` del agente: `[4 bytes tamaño][config RC4][16 bytes encrypt_key]`. Se recupera la **EncryptionKey** `4580221ac3fe51be1797524a048e552d`. Con ella se descifra `X-Beacon-Id = base64(RC4(beat, encrypt_key))`, y del beat sale **BeaconID `be4c0149`** + **SessionKey `53fc4c03c7b461befe5dcb268e3d9208`** (campo de 16 bytes con prefijo de longitud). El beat confirma host `WS02`, user `afenwick`, dominio `core.diogenes.htb`, proceso `winupdate.exe`.

4. **Descifrado del PCAP.** Con la SessionKey (RC4) se descifran todas las tareas/outputs del C2. Aparecen: `whoami` → `DIOCORE\afenwick` (SID `...-1125`), recon LDAP de usuarios/equipos, e info de dominio (`core.diogenes.htb` + padre `diogenes.htb`).

5. **Lectura del DACL.** Un BOF enumera el descriptor de seguridad de afenwick y descubre que **afenwick tiene `WriteProperty` sobre su propio `userPrincipalName`** (ACE con `ObjectAceType = 28630ebb-41d5-11d1-a9c1-0000f80367c1`, el schemaIDGUID de `userPrincipalName`). Ese permiso es el requisito de **ResetNightmare**.

6. **Internal Monologue.** BOF de captura de credenciales (frame 609) fuerza autenticación NTLM local con challenge fijo `1122334455667788` y `SessionKeyStatus: Missing`, capturando el **NetNTLMv2 de afenwick**. Correlacionado con el EVTX (EventID 4021, `ProcessName: winupdate`, `NtlmUsageReason: NTLM was called directly`) → timestamp **2026-09-09 20:44:11**. El hash se crackea con hashcat (5600 + rockyou) → **`*Seash5lls*`**.

7. **ResetNightmare (CVE-2026-27912).** BOF custom (`RESET_NIGHTMARE_RUN`, `LdapSetUPN`, `ResetTargetPassword`, md5 `583236cc3ef2488fb133385bcd75825e`). Con el `WriteProperty` sobre UPN, escribe un UPN falso en afenwick → solicita un AS-REQ *enterprise* → obtiene un TGT que resuelve a **jreed** → vía kadmin/changepw (Kerberos, puerto 464) **resetea el password de jreed** a **`Aigohng8vai0seish4zi`**. Output: `[+] ResetNightmare succeeded! jreed's password is now: Aigohng8vai0seish4zi`.

8. **Impersonación de token.** `LogonUser(jreed)` genera un token con **LogonType 9 (NewCredentials)** — equivalente a `runas /netonly`. Output: `The user impersonated successfully: DIOCORE\jreed (logon: 9)`.

9. **Movimiento lateral.** Se sube un nuevo agente (103936 bytes) a **`\\dc02\ADMIN$\svc_bkup`** y se secuestra el service group **`defragsvc`** (path original `svchost.exe -k defragsvc`). Nace un **segundo beacon en DC02 como SYSTEM** (proceso `svc_bkup`): **BeaconID `ddc68fa7`** + **SessionKey `289122cf1ec91c67eb89c30642adfea4`**.

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

### Lecciones

- **DLL sideloading** con binario legítimo (`docviewer.exe` + `version.dll`) es un vector de entrega sigiloso vía USB que evade allowlisting basado en firmas.
- El tráfico de **AdaptixC2** es descifrable si se extrae la `encrypt_key` del `.rdata` del agente: cadena `EncryptionKey → beat → SessionKey → todo el C2`. La reconstrucción del PCAP es la clave que desbloquea casi todas las respuestas.
- **ResetNightmare (CVE-2026-27912)** encadena `WriteProperty` sobre `userPrincipalName` + AS-REQ enterprise + kadmin/changepw para tomar el password de otro usuario sin DCSync — un abuso de identidad Kerberos peligroso y silencioso.
- **Internal Monologue** captura NetNTLMv2 sin tocar LSASS; el challenge fijo `1122334455667788` en EVTX (EventID 4021) es una firma detectable.
- **LogonType 9 (NewCredentials)** es la huella de impersonación tipo `runas /netonly`, útil para threat hunting.

<a id="en"></a>

## 🇬🇧 English

### Escenario

After the drone recovery (previous Sherlock), Eleanor Mercer spots an **unauthorized outbound session** from a protected workstation (WS02) inside the **DIOGENES** forest. The activity matches no approved software and continues after a physical object is removed. The source is a **USB drop** disguised as an HR document ("Q3 Salary Review").

Target forest:

- Root **`diogenes.htb`** → DC **DIOCORE**
- Child **`core.diogenes.htb`** → DC **DC02** (`192.168.56.11`)
- Users involved: **afenwick** (initial compromise, WS02), **jreed** (privesc target), rfairfax.
- Final implant deployed on DC02: **`svc_bkup`**.

The goal is to reconstruct the full chain: how the operator got in, which C2 was used, how privileges were escalated, and how lateral movement reached the child DC.

### Artefacto y herramientas

**Provided evidence (`BorrowedName/`):**

| Artifact | Description |
|----------|-------------|
| `evidence/capture.pcapng` | C2 traffic (HTTP with proprietary RC4 encryption) |
| `evidence/usb/` | USB contents: `docviewer.exe`, `version.dll`, `winupdate.exe`, `Salary_Review_Q3_2026.pdf.lnk`, `README.txt` |
| `evidence/Q3_Salary_Review.img` | FAT32 USB image (`.lnk` → `docviewer.exe`) |
| `evidence/C/Windows` + EVTX | Host NTLM logs (EventID 4021 / NTLM) |
| Narrative PDF (Chapters 10-12) | *The Reichenbach Directive* arc context |

**Tools:** PE analysis (`file`, `strings`, Ghidra/radare2), the **AdaptixC2** config extractor (Unit42), Python RC4 scripts to decrypt the PCAP, `hashcat` (mode 5600) for the NetNTLMv2, EVTX parsing, and disk-image mounting.

USB binary hashes:

```
aca111935d339b17544ead3e8c2c8831  docviewer.exe   (legitimate sideload host)
6e787589a69ce783b0380b0de86a2d68  version.dll     (malicious sideloaded DLL)
b1c8c95d3bfa22780076084377584739  winupdate.exe   (AdaptixC2 agent)
```

### Metodología (paso a paso)

1. **USB drop → DLL sideloading.** The USB `.lnk` launches `docviewer.exe` (signed/legitimate). A malicious `version.dll` sits in the same folder: on start, `docviewer.exe` resolves `version.dll` by search order and **loads the attacker DLL** (DLL search-order hijacking / sideloading). The DLL drops `winupdate.exe`, the C2 agent.

2. **C2 identification.** `winupdate.exe` contains a `ConnectorHTTP` class, an **`X-Beacon-Id`** header, named pipe `\\.\pipe\%08lx`, an embedded RC4 profile with rotating URIs, and JSON responses `{"status":"ok","data":"...","metrics":"sync"}`. The BeaconID / SessionKey / EncryptionKey + BOF terminology points to **AdaptixC2** (Unit42 config extractor).

3. **Key extraction.** In the agent's `.rdata`: `[4-byte size][RC4 config][16-byte encrypt_key]`. The **EncryptionKey** `4580221ac3fe51be1797524a048e552d` is recovered. With it, `X-Beacon-Id = base64(RC4(beat, encrypt_key))` decrypts, yielding **BeaconID `be4c0149`** + **SessionKey `53fc4c03c7b461befe5dcb268e3d9208`** (16-byte length-prefixed field). The beat confirms host `WS02`, user `afenwick`, domain `core.diogenes.htb`, process `winupdate.exe`.

4. **PCAP decryption.** Using the SessionKey (RC4), all C2 tasks/outputs decrypt. We see `whoami` → `DIOCORE\afenwick` (SID `...-1125`), LDAP user/computer recon, and domain info (`core.diogenes.htb` + parent `diogenes.htb`).

5. **DACL read.** A BOF enumerates afenwick's security descriptor and finds that **afenwick holds `WriteProperty` over its own `userPrincipalName`** (ACE with `ObjectAceType = 28630ebb-41d5-11d1-a9c1-0000f80367c1`, the `userPrincipalName` schemaIDGUID). That right is the prerequisite for **ResetNightmare**.

6. **Internal Monologue.** A credential-capture BOF (frame 609) coerces local NTLM authentication with a fixed challenge `1122334455667788` and `SessionKeyStatus: Missing`, capturing afenwick's **NetNTLMv2**. Correlated with EVTX (EventID 4021, `ProcessName: winupdate`, `NtlmUsageReason: NTLM was called directly`) → timestamp **2026-09-09 20:44:11**. The hash is cracked with hashcat (5600 + rockyou) → **`*Seash5lls*`**.

7. **ResetNightmare (CVE-2026-27912).** Custom BOF (`RESET_NIGHTMARE_RUN`, `LdapSetUPN`, `ResetTargetPassword`, md5 `583236cc3ef2488fb133385bcd75825e`). Using `WriteProperty` on the UPN, it writes a spoofed UPN on afenwick → requests an *enterprise* AS-REQ → obtains a TGT that resolves to **jreed** → via kadmin/changepw (Kerberos, port 464) it **resets jreed's password** to **`Aigohng8vai0seish4zi`**. Output: `[+] ResetNightmare succeeded! jreed's password is now: Aigohng8vai0seish4zi`.

8. **Token impersonation.** `LogonUser(jreed)` yields a token with **LogonType 9 (NewCredentials)** — equivalent to `runas /netonly`. Output: `The user impersonated successfully: DIOCORE\jreed (logon: 9)`.

9. **Lateral movement.** A new agent (103936 bytes) is uploaded to **`\\dc02\ADMIN$\svc_bkup`** and the **`defragsvc`** service group is hijacked (original path `svchost.exe -k defragsvc`). A **second beacon spawns on DC02 as SYSTEM** (process `svc_bkup`): **BeaconID `ddc68fa7`** + **SessionKey `289122cf1ec91c67eb89c30642adfea4`**.

### Respuestas / flags

| # | Pregunta | Respuesta |
|---|----------|-----------|
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

### Lecciones

- **DLL sideloading** with a legitimate binary (`docviewer.exe` + `version.dll`) is a stealthy USB delivery vector that evades signature-based allowlisting.
- **AdaptixC2** traffic is decryptable once you extract the `encrypt_key` from the agent's `.rdata`: the chain `EncryptionKey → beat → SessionKey → whole C2` reconstructs the PCAP, which unlocks nearly every answer.
- **ResetNightmare (CVE-2026-27912)** chains `WriteProperty` over `userPrincipalName` + an enterprise AS-REQ + kadmin/changepw to take over another user's password without DCSync — a dangerous, quiet Kerberos identity abuse.
- **Internal Monologue** captures NetNTLMv2 without touching LSASS; the fixed challenge `1122334455667788` in EVTX (EventID 4021) is a detectable signature.
- **LogonType 9 (NewCredentials)** is the fingerprint of `runas /netonly`-style impersonation, a useful threat-hunting pivot.

---

*Créditos: técnica ResetNightmare documentada por [Semperis](https://www.semperis.com/blog/identity-crisis-novel-vulnerabilities-leading-to-kerberos-downgrade-dos-and-full-domain-takeover/); análisis de AdaptixC2 por [Unit42 (Palo Alto Networks)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/).*
