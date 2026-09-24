---
title: "Holmes CTF 2026 — S05 Poisoned Branch"
date: 2026-09-19
description: "Cadena de suministro en Gitea: paquete Python con backdoor Meterpreter, LFI en Flask y recuperación de LOOT.zip con bkcrack."
excerpt: "DFIR sobre triage UAC de Linux e infra del atacante: paquete Python envenenado en Gitea, implante Meterpreter XOR, LFI en Flask y bkcrack contra ZipCrypto."
platform: "HTB"
difficulty: "Medium"
image: "/images/ctf.svg"
tags:
  - "DFIR"
  - "Linux"
  - "Supply Chain"
  - "Gitea"
  - "Meterpreter"
  - "Holmes CTF 2026"
---

> **Reto:** Holmes CTF 2026 — Sherlock 05 "Poisoned Branch" · Triage UAC Linux + cadena de suministro Gitea. Parte del arco *The Reichenbach Directive*.
>
> **Navegación:** [🇪🇸 Español](#es) · [🇬🇧 English](#en)

<a id="es"></a>

## 🇪🇸 Español

### Escenario

Tom Ainsworth, contratista del gobierno que da soporte a una aplicación de RRHH en Whitehall, clona un paquete Python envenenado (`diogenes-ticket-parser`) desde una instancia interna de **Gitea**. El paquete contenía un módulo de telemetría que decodificaba por **XOR** un implante Meterpreter reverse-TCP, lo plantaba en `~/.cache/.ticket-parser/.integrity` y lo lanzaba contra la infra C2 del atacante en `BlackPearl2026.htb:31337`.

A través de la sesión Meterpreter, el atacante (operando como el APT **NAPOLEON**, alias **Sebastian Moran**) exfiltró un roster de emergencia de RRHH clasificado, borró evidencia del host de la víctima y empaquetó el botín en un ZIP protegido por contraseña en su servidor de staging. La evidencia es un **triage UAC** (`uac_output/*.tar.gz`) más la infraestructura del atacante, accesible por VPN.

- **Víctima:** Tom Ainsworth · **Atacante:** Sebastian Moran (APT NAPOLEON)
- **Target:** `10.129.3.29` · **Dificultad:** Medium · **15/15 flags**

### Artefacto y herramientas

| Recurso | Detalle |
|---------|---------|
| Triage UAC | `uac-LT-TAinsworth-linux-20260915155349.tar.gz` (UAC 3.3.0) |
| Log clave | `/var/log/audit/audit.log` (2.472 líneas, 189 registros EXECVE) |
| Repo malicioso | `http://devforge.internal:3000/diogenes/diogenes-ticket-parser.git` |
| Infra atacante | File exchange Flask `BlackPearl2026.htb:9999`; MSF DB PostgreSQL en `localhost:5433` |
| Botín | `LOOT.zip` (38.934 bytes, cifrado ZipCrypto) |

Herramientas: análisis de auditd EXECVE y decodificado de argumentos hex, forense de metadatos Git, LFI (path traversal) sobre Flask, SSH con clave exfiltrada, forense de la tabla `session_events` de la base MSF, y ataque de texto plano conocido con **bkcrack** sobre ZipCrypto.

### Metodología (paso a paso)

1. **Repo envenenado (Gitea).** El paquete `diogenes-ticket-parser` fue creado en `devforge.internal:3000` por el autor `Sebastain Moran <cbass.Moran@blackpearl2026.htb>` (nótese el typo intencional "Sebastain"). El dropper es `src/ticket_parser/telemetry.py`, que hace **XOR** de `diogenes.jpg` con `calibration.bin` para reconstruir el ELF Meterpreter.
2. **Trigger de ejecución.** La constante base64 `_CALIBRATION` decodifica a `chmod +x ~/.cache/.ticket-parser/.integrity; ~/.cache/.ticket-parser/.integrity 2>&1 &`. Al ejecutar `ticket_parser.py`, se escribe el implante en `/home/Tom/.cache/.ticket-parser/.integrity` y se lanza.
3. **C2 establecido (PID 1514).** El reverse shell Meterpreter (`linux/x64/meterpreter_reverse_tcp`) conecta a `BlackPearl2026.htb:31337`. El atacante confirma identidad (`getuid` → Tom) y despliega persistencia SSH plantando su clave pública vía `wget` a través del file exchange Flask.
4. **Reconstrucción por audit.log.** Correlacionando `audit.log` con la tabla `session_events` de la MSF DB (102 eventos): PID 1516 y 1521 son intentos fallidos de `wget` de la clave SSH (typo en la cookie de auth; falta el puerto en la URL); PID 1525 es el `wget` exitoso desde `203.0.113.10:9999`.
5. **Exfiltración.** El atacante navega a `~/Work_Stuff/ONBOARDING/`, localiza el PDF clasificado con `search -d ONBOARDING -f *.pdf` y descarga `Gov_HR_Continuity_Emergency_Callout_Roster.pdf` a su staging.
6. **Anti-forense (PID 1549).** Shell (channel 5) que borra el PDF de la víctima con `rm Gov_HR_Continuity_Emergency_Callout_Roster.pdf`, seguido de `ls -la` para confirmar. Después limpia `.bash_history`.
7. **LFI en Flask.** `/home/moran/Flask_server/app.py` tenía path-traversal LFI en `/download?file=`: tras satisfacer la cookie `X-Operator-Auth=napoleon_moran_1894`, un `../../` permitía leer ficheros arbitrarios del staging server. Así se recuperó `LOOT.zip`.
8. **bkcrack (known-plaintext).** La contraseña no estaba en rockyou. `LOOT.zip` usa ZipCrypto; se ataca con texto plano conocido contra la entrada `README.txt` (SOP genérico, CRC32 `e4d5acac`) para derivar las 3 internal keys `85b6bbc1 27824945 ce665bee` y descifrar sin la contraseña.
9. **Contenido del botín:** el PDF clasificado; `cvoss_exfil` (41 bytes) con la credencial `tainsworth:d10g3n3s_T1ck3ts#2026:forever`; y `README.txt` (SOP: "Package into a password protected zip. Remove remnants.").
10. **Hallazgo clave.** El roster lista 12 empleados del gobierno; un registro tiene el campo `Position` marcado como REDACTED y clasificación CONFIDENTIAL: **Sarah Kemp** (ID `DIO-1648`, Identity Operations), con dirección `Flat 6, Ashdown House, Palace Court, London W2 4LS`.

### Respuestas / flags

| # | Pregunta | Respuesta |
|---|----------|-----------|
| 1 | Nombre del repositorio malicioso | `diogenes-ticket-parser` |
| 2 | Email del atacante | `cbass.Moran@blackpearl2026.htb` |
| 3 | Fichero clave XOR usado para decodificar el payload | `calibration.bin` |
| 4 | Ruta completa del implante depositado | `/home/Tom/.cache/.ticket-parser/.integrity` |
| 5 | Puerto de callback C2 | `31337` |
| 6 | PID del proceso del implante | `1514` |
| 7 | File server del atacante (host:puerto) | `BlackPearl2026.htb:9999` |
| 8 | Cookie de autenticación | `X-Operator-Auth=napoleon_moran_1894` |
| 9 | Comando anti-forense | `rm Gov_HR_Continuity_Emergency_Callout_Roster.pdf` |
| 10 | PID del shell anti-forense | `1549` |
| 11 | Comando de setup del payload en MSF | `set payload linux/x64/meterpreter_reverse_tcp` |
| 12 | Comando de búsqueda de fichero | `search -d ONBOARDING -f *.pdf` |
| 13 | Nombre del archivo de exfiltración | `LOOT.zip` |
| 14 | Persona con la posición redactada | Sarah Kemp |
| 15 | Dirección de esa persona | Flat 6, Ashdown House, Palace Court, London W2 4LS |

### Lecciones

- **Cadena de suministro interna:** un typo en el nombre del autor de un commit (`Sebastain`) y un módulo "de telemetría" bastan para colar un dropper. Auditar dependencias internas de Gitea/Git como si fueran externas.
- **auditd es oro forense:** con `history -c` borrando la evidencia obvia, `/var/log/audit/audit.log` (EXECVE con argumentos hex) reconstruye toda la actividad del atacante a nivel de proceso.
- **Correlación cross-artefacto:** la MSF DB (`session_events` en PostgreSQL:5433) del propio atacante da la timeline canónica; cruzarla con los PID del triage de la víctima confirma cada acción.
- **XOR "en plena vista":** ocultar el ELF como `calibration.bin` XOR `diogenes.jpg` evade el escaneo estático; reproducir el XOR en Python revela el Meterpreter real.
- **ZipCrypto sigue siendo débil:** con una sola entrada de texto plano conocido (un README de SOP), bkcrack recupera las internal keys y descifra el ZIP sin la contraseña.

<a id="en"></a>

## 🇬🇧 English

### Scenario

Tom Ainsworth, a government contractor supporting an HR application across Whitehall, cloned a poisoned Python package (`diogenes-ticket-parser`) from an internal **Gitea** instance. The package shipped a telemetry module that **XOR**-decoded a Meterpreter reverse-TCP implant, planted it at `~/.cache/.ticket-parser/.integrity`, and called back to the attacker's C2 at `BlackPearl2026.htb:31337`.

Through the Meterpreter session, the attacker (operating as APT **NAPOLEON**, alias **Sebastian Moran**) exfiltrated a classified HR emergency callout roster, deleted evidence from the victim host, and packaged the loot into a password-protected ZIP on their staging server. Evidence is a **UAC triage** (`uac_output/*.tar.gz`) plus the attacker's live infrastructure over VPN.

- **Victim:** Tom Ainsworth · **Attacker:** Sebastian Moran (APT NAPOLEON)
- **Target:** `10.129.3.29` · **Difficulty:** Medium · **15/15 flags**

### Artifact and tools

| Resource | Detail |
|----------|--------|
| UAC triage | `uac-LT-TAinsworth-linux-20260915155349.tar.gz` (UAC 3.3.0) |
| Key log | `/var/log/audit/audit.log` (2,472 lines, 189 EXECVE records) |
| Malicious repo | `http://devforge.internal:3000/diogenes/diogenes-ticket-parser.git` |
| Attacker infra | Flask file exchange `BlackPearl2026.htb:9999`; MSF PostgreSQL DB at `localhost:5433` |
| Loot | `LOOT.zip` (38,934 bytes, ZipCrypto encryption) |

Tools: auditd EXECVE analysis and hex-argument decoding, Git metadata forensics, LFI (path traversal) on Flask, SSH with the exfiltrated key, MSF `session_events` table forensics, and a **bkcrack** known-plaintext attack on ZipCrypto.

### Methodology (step by step)

1. **Poisoned repo (Gitea).** `diogenes-ticket-parser` was created on `devforge.internal:3000` by author `Sebastain Moran <cbass.Moran@blackpearl2026.htb>` (note the intentional typo "Sebastain"). The dropper `src/ticket_parser/telemetry.py` XORs `diogenes.jpg` with `calibration.bin` to reconstruct the ELF Meterpreter.
2. **Execution trigger.** The base64 constant `_CALIBRATION` decodes to `chmod +x ~/.cache/.ticket-parser/.integrity; ~/.cache/.ticket-parser/.integrity 2>&1 &`. Running `ticket_parser.py` writes the implant to `/home/Tom/.cache/.ticket-parser/.integrity` and launches it.
3. **C2 established (PID 1514).** The Meterpreter reverse shell (`linux/x64/meterpreter_reverse_tcp`) connects to `BlackPearl2026.htb:31337`. The attacker confirms identity (`getuid` → Tom) and deploys SSH persistence by planting their public key via `wget` through the Flask file exchange.
4. **audit.log reconstruction.** Correlating `audit.log` with the MSF DB `session_events` table (102 events): PID 1516 and 1521 are failed `wget` attempts for the SSH key (typo in the auth cookie; missing port in the URL); PID 1525 is the successful `wget` from `203.0.113.10:9999`.
5. **Exfiltration.** The attacker navigates to `~/Work_Stuff/ONBOARDING/`, locates the classified PDF with `search -d ONBOARDING -f *.pdf`, and downloads `Gov_HR_Continuity_Emergency_Callout_Roster.pdf` to their staging server.
6. **Anti-forensics (PID 1549).** A shell (channel 5) deletes the PDF from the victim with `rm Gov_HR_Continuity_Emergency_Callout_Roster.pdf`, followed by `ls -la` to confirm. The attacker then clears `.bash_history`.
7. **Flask LFI.** `/home/moran/Flask_server/app.py` had a path-traversal LFI in `/download?file=`: once the `X-Operator-Auth=napoleon_moran_1894` cookie gate was satisfied, `../../` allowed reading arbitrary files off the staging server — this is how `LOOT.zip` was recovered.
8. **bkcrack (known-plaintext).** The password was not in rockyou. `LOOT.zip` uses ZipCrypto; a known-plaintext attack against the `README.txt` entry (generic SOP, CRC32 `e4d5acac`) derives the three internal keys `85b6bbc1 27824945 ce665bee` and decrypts without the password.
9. **Loot contents:** the classified PDF; `cvoss_exfil` (41 bytes) with credential `tainsworth:d10g3n3s_T1ck3ts#2026:forever`; and `README.txt` (SOP: "Package into a password protected zip. Remove remnants.").
10. **Key finding.** The roster lists 12 government employees; one record has its `Position` field marked REDACTED and classification CONFIDENTIAL: **Sarah Kemp** (ID `DIO-1648`, Identity Operations), home address `Flat 6, Ashdown House, Palace Court, London W2 4LS`.

### Answers / flags

| # | Question | Answer |
|---|----------|--------|
| 1 | Malicious repository name | `diogenes-ticket-parser` |
| 2 | Attacker email address | `cbass.Moran@blackpearl2026.htb` |
| 3 | XOR key file used to decode the payload | `calibration.bin` |
| 4 | Full path of the dropped implant | `/home/Tom/.cache/.ticket-parser/.integrity` |
| 5 | C2 callback port | `31337` |
| 6 | Implant process PID | `1514` |
| 7 | Attacker file server host:port | `BlackPearl2026.htb:9999` |
| 8 | Authentication cookie | `X-Operator-Auth=napoleon_moran_1894` |
| 9 | Anti-forensics command | `rm Gov_HR_Continuity_Emergency_Callout_Roster.pdf` |
| 10 | Anti-forensics shell PID | `1549` |
| 11 | MSF payload setup command | `set payload linux/x64/meterpreter_reverse_tcp` |
| 12 | File search command | `search -d ONBOARDING -f *.pdf` |
| 13 | Exfiltration archive name | `LOOT.zip` |
| 14 | Person with the redacted position | Sarah Kemp |
| 15 | Address of that person | Flat 6, Ashdown House, Palace Court, London W2 4LS |

### Lessons

- **Internal supply chain:** a typo in a commit author's name (`Sebastain`) and a "telemetry" module are enough to smuggle in a dropper. Audit internal Gitea/Git dependencies as if they were external.
- **auditd is forensic gold:** with `history -c` wiping the obvious evidence, `/var/log/audit/audit.log` (EXECVE with hex arguments) reconstructs the entire attack at process level.
- **Cross-artifact correlation:** the attacker's own MSF DB (`session_events` in PostgreSQL:5433) provides the canonical timeline; cross-referencing it with the victim triage PIDs confirms every action.
- **XOR "in plain sight":** hiding the ELF as `calibration.bin` XOR `diogenes.jpg` evades static scanning; replaying the XOR in Python reveals the real Meterpreter.
- **ZipCrypto is still weak:** with a single known-plaintext entry (a SOP README), bkcrack recovers the internal keys and decrypts the ZIP without the password.
