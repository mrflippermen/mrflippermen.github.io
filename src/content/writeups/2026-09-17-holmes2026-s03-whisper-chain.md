---
title: "Holmes CTF 2026 — S03 Whisper Chain"
date: 2026-09-17
description: "Forense de un servidor XMPP/Prosody vivo (MurkNet): del certificado TLS al descifrado de las órdenes, encadenando registro in-band, metadatos PDF, pubsub AES y un pivote OSINT a la Wayback Machine."
excerpt: "Susurro a susurro: cada eslabón entrega la clave del siguiente. Cert TLS → canales → email en metadatos → password en #infra → pubsub cifrado → decryptor archivado en la Wayback → wallet XMR y el objetivo DIOGENES."
platform: "HTB"
difficulty: "Medium"
image: "/images/ctf.svg"
tags:
  - "DFIR"
  - "XMPP"
  - "OSINT"
  - "Crypto"
  - "Forensics"
  - "Holmes CTF 2026"
---

> **Reto:** Holmes CTF 2026 — Sherlock 03 "Whisper Chain" · Forense de XMPP/Prosody + OSINT. Parte del arco *The Reichenbach Directive*.
>
> **Navegación:** [🇪🇸 Español](#es) · [🇬🇧 English](#en)

<a id="es"></a>

## 🇪🇸 Español

### Escenario

Watson sobrevive. En Silvertown queda un portátil con un intento apresurado de borrar la actividad reciente; solo persiste un cliente de comunicaciones cuyo servidor, cuenta y propósito son desconocidos. El operador hablaba a través de una red privada (**MurkNet**) bajo un alias.

El reto solo entrega un **PDF con la historia** — **toda la evidencia está en el objetivo vivo**: un servidor XMPP (**Prosody**) sobre `10.129.x.x`. Hay que recuperar lo que sobrevivió al wipe, entender qué voces pertenecían juntas y adónde viajaban las órdenes cuando la conversación pública se detenía. Dificultad: **medium**.

### Artefacto y herramientas

- **Objetivo vivo:** servidor XMPP/Prosody (`murknet.htb`) detrás de nginx.
- **Recon:** `nmap`, `openssl s_client` (certificado TLS y SANs).
- **Acceso:** `slixmpp` con registro in-band (XEP-0077) y verificación TLS desactivada (cert autofirmado).
- **Enumeración/lectura:** disco#items (XEP-0030), MAM (XEP-0313), MUC (XEP-0045), pubsub (XEP-0060), file share HTTP Upload (XEP-0363).
- **Metadatos:** `exiftool` sobre los PDFs subidos a `upload.murknet.htb`.
- **Cripto:** `openssl enc -d -aes-256-cbc -pbkdf2 -iter 120000 -md sha256` (payloads en base64).
- **OSINT:** Wayback Machine / CDX (`web.archive.org`) para recuperar un blog de threat-intel borrado.

### Metodología (paso a paso)

**1. Recon — un Prosody detrás de nginx.** El `nmap` de puertos comunes revela el stack XMPP:

```
22/tcp   open  ssh       OpenSSH 9.6p1
443/tcp  open  ssl/http  nginx 1.24.0
5222/tcp open  xmpp-client   # cliente (STARTTLS)
5269/tcp open  xmpp-server   # s2s
5281/tcp open  ssl/http      # Prosody mod_http
```

El certificado autofirmado (443/5222) revela la identidad del despliegue y da directamente la primera flag:

```
# openssl s_client -connect 10.129.x.x:443 | openssl x509 -noout -ext subjectAltName
DNS:murknet.htb, DNS:groups.murknet.htb, DNS:command.murknet.htb, DNS:upload.murknet.htb
```

Subdominios clave: **groups** (MUC/salas), **command** (dispatcher pubsub) y **upload** (file share XEP-0363). → **Q1**.

**2. Acceso — registro in-band y enumeración de canales.** El servidor tiene **registro in-band habilitado** (`<register/>` en las stream features) y el certificado es autofirmado, así que con `slixmpp` (verificación TLS desactivada) se crea una cuenta y se enumeran componentes. *Nota crítica:* las cuentas nuevas se **purgan casi al instante** — hay que **registrar y trabajar en la misma sesión**. Un `disco#items` sobre `groups.murknet.htb` lista los canales:

```
resources@groups.murknet.htb  | Resources
rules@groups.murknet.htb      | Rules
random@groups.murknet.htb     | Random
infra@groups.murknet.htb      | Infrastructure
```

→ **Q2** (orden alfabético).

**3. El primer susurro — email en metadatos, password en #infra.** Leyendo el historial (MAM) de las salas aparecen PDFs subidos a `upload.murknet.htb`. El *Operational Onboarding Guide* filtra la identidad de un miembro en sus metadatos:

```
# exiftool Operational_Onboarding_Guide_v3.2.pdf
Author  : zytglogge88@murknet.htb
Creator : swissclock          # Zytglogge = torre del reloj de Berna
```

La contraseña estaba a la vista: en el canal **#infra**, *rattlesnake* pega por error las "contraseñas temporales" antiguas. La temática canta — **TickTock** ↔ reloj ↔ swissclock:

```
# passwords filtradas en #infra
KillBill2025!  K4w4Bong424!  Northwind225!  TickTock24!   <-- válida
```

→ **Q3**: `zytglogge88@murknet.htb:TickTock24!`. Con esta cuenta (**swissclock**, miembro real) se accede a los chats privados 1-a-1 y a las salas de operación.

**4. Dentro de la célula — tres operaciones y un dispatcher cifrado.** Autenticado como swissclock, el archivo MAM personal y las salas privadas revelan la estructura. El componente `command.murknet.htb` es un servicio **pubsub** (XEP-0060) con las órdenes de cada operación cifradas (OpenSSL `Salted__` / AES-256-CBC):

- `op_sparkling` → robo cripto (1ª op)
- `op_snatch` → secuestro de Watson
- `op_dominance` → "next operation"

En un DM, *rattlesnake* entrega a swissclock la clave rotada: `The new key is SHALLOWBLUE`. Pero **SHALLOWBLUE no descifra los comandos ya publicados** — son de **antes** de la rotación. La clave *vieja* no está en el XMPP: hay que recuperarla del decryptor filtrado (pivote OSINT).

En la sala `op_snatch` se reparten roles (colonel): *"Dynamite handles transport. Spur handles custody after delivery"* y `dynamite: "I'm starting the operation now"`. → **Q6**: `dynamite`.

En la sala privada `op_dominance`, el briefing de *doctor*: *"The next operation is unlike anything we've handled before… Our objective has a name: DIOGENES"*. → **Q8**: `Dominance,DIOGENES`.

**5. El pivote OSINT — "nothing is ever truly deleted once enough eyes have seen it".** La sala `op_sparkling` guarda la reacción de la célula a un informe de threat-intel que les atribuyó el malware **BalanceRAT**. *rattlesnake* presume de haber borrado el blog — *"I personally nuked it. It's gone. try opening it now"* — y *doctor* le corrige con la frase que es la pista literal del reto. *timothy* pega la URL (host caído a propósito):

```
http://security.billblog.co.uk/threat/BalanceRAT-analysis-and-attribution
```

El host real está muerto, pero la copia vive en la **Wayback Machine**. El CDX confirma el snapshot y una imagen delatora (`porlock.png`):

```
# curl "http://web.archive.org/cdx/search/cdx?url=security.billblog.co.uk*&output=text"
20260805 .../threat/BalanceRAT-analysis-and-attribution/          200
20260805 .../threat/BalanceRAT-analysis-and-attribution/porlock.png 200
```

El artículo (*"Ghost Balance"*) mapea las identidades online del alias **Porlock** (= rattlesnake) e incluye el **decryptor completo**. La cuenta de RRSS del miembro → **Q4**: `https://stonedforums.htb/@porlock`.

El `decrypt_command.sh` recuperado del blog archivado:

```bash
#!/usr/bin/env bash
KEY='BLACKFENLOTTE'                # clave ANTIGUA (pre-rotación)
printf '%s' "$1" | base64 -d |
  openssl enc -d -aes-256-cbc -pbkdf2 -iter 120000 -md sha256 -pass "pass:${KEY}"
```

Cada operación usa **su propia clave** con el mismo método: **op_sparkling → BLACKFENLOTTE**, **op_snatch → SHALLOWBLUE**. El detalle que rompía todo antes: faltaba `-iter 120000`.

**6. Descifrado — las órdenes en claro.** Con BLACKFENLOTTE se descifra `op_sparkling` (robo de criptoactivos):

```
cmd-02 Evilginx server: 185.203.11.109
cmd-03 BTC: 1BfQc4twbZrUSrtKdwW8TtSN6o1SUezWkX · 1BcanTJp… · 1BHoNZGG…
cmd-04 XMR Address: 429x3WVq1ucARGXx6NEwL4Sg4iowfW5ZWMAqEDErLxrWdg4ffkonB5tNxg85BKGjDqDQRfBERANhgf6DnGjjFyDR5L7uwye
cmd-05 Bank creds -> https://submit-creds.murknet.htb:9099
cmd-06 New C2 (BalanceRAT): 34.54.165.186
```

→ **Q5** (wallet XMR de la 1ª operación). Con SHALLOWBLUE se descifra `op_snatch` (secuestro de Watson):

```
cmd-02 Watson… red Ford Fiesta, matrícula WT609DXT
cmd-03 He just stopped at Pembridge Square
cmd-04 …turned onto Bayswater Road. Stay right on his heels!
cmd-05 He's about to enter Victoria Station. He must not reach the tracks. Act NOW
cmd-06 Heading toward Silvertown — 51°30'17.6"N, 0°02'05.1"E
cmd-08 Sector B. Row 6. Container 75JM77. Watchword: Chaos Is Order
cmd-09 Take the car to the junkyard in Walton-on-Thames. Ask for Richard.
cmd-10 Start cleanup process IMMEDIATELY
```

El agarre se ejecuta en **Victoria Station** (cmd-05); luego lo trasladan a la guarida de **Silvertown** (contenedor 75JM77), que es donde aparecen los objetos del PDF de la historia. → **Q7**: `Victoria Station` (no confundir captura vs cautiverio).

### Respuestas / flags

| # | Pregunta | Respuesta |
|---|----------|-----------|
| Q1 | SANs del certificado TLS (hostname principal primero, resto alfabético) | `murknet.htb,command.murknet.htb,groups.murknet.htb,upload.murknet.htb` |
| Q2 | Canales públicos del servidor XMPP (orden alfabético) | `Infrastructure,Random,Resources,Rules` |
| Q3 | Credenciales de un miembro del APT (email:password) | `zytglogge88@murknet.htb:TickTock24!` |
| Q4 | URL de la cuenta de RRSS de un miembro del APT | `https://stonedforums.htb/@porlock` |
| Q5 | Wallet XMR usada en la primera operación | `429x3WVq1ucARGXx6NEwL4Sg4iowfW5ZWMAqEDErLxrWdg4ffkonB5tNxg85BKGjDqDQRfBERANhgf6DnGjjFyDR5L7uwye` |
| Q6 | Apodo del afiliado que secuestró a Watson | `dynamite` |
| Q7 | Dónde ha sido secuestrado Watson | `Victoria Station` |
| Q8 | Última operación planeada y su objetivo | `Dominance,DIOGENES` |

### Lecciones

- **Cada eslabón entrega la clave del siguiente** — de ahí "Whisper Chain": Cert TLS → SANs; registro XMPP → canales; metadatos PDF → email; canal infra → password; login swissclock → pubsub; DM rattlesnake → SHALLOWBLUE; Wayback → decryptor + BLACKFENLOTTE + Porlock; openssl → wallet + ubicación.
- **La trampa central de cripto:** los comandos publicados usan la clave **vieja** (BLACKFENLOTTE, del blog), no la rotada del DM (SHALLOWBLUE). Si la clave nueva da basura, el mensaje es pre-rotación.
- **Registrar y trabajar en la misma sesión:** las cuentas IBR se purgan casi al instante en este Prosody.
- **Metadatos = OSINT gratis:** `exiftool` sobre un PDF subido filtró Author/Creator y desbloqueó una cuenta real.
- **"Nada se borra del todo":** un host caído a propósito seguía vivo en la Wayback Machine (CDX), que guardaba el decryptor completo y la imagen delatora.
- **Distinguir captura vs cautiverio:** a Watson lo **capturan** en Victoria Station y lo **retienen** en Silvertown; la pregunta pedía el lugar del secuestro.

<a id="en"></a>

## 🇬🇧 English

### Scenario

Watson survives. In Silvertown a laptop is left behind with a hasty attempt to wipe recent activity; only a comms client persists, its server, account and purpose unknown. The operator spoke through a private network (**MurkNet**) under an alias.

The challenge ships only a **story PDF** — **all the evidence lives on the live target**: an XMPP (**Prosody**) server on `10.129.x.x`. You must recover what survived the wipe, work out which voices belonged together, and where the orders travelled once the public conversation stopped. Difficulty: **medium**.

### Artifact and tooling

- **Live target:** XMPP/Prosody server (`murknet.htb`) behind nginx.
- **Recon:** `nmap`, `openssl s_client` (TLS certificate and SANs).
- **Access:** `slixmpp` with in-band registration (XEP-0077) and TLS verification disabled (self-signed cert).
- **Enumeration/reading:** disco#items (XEP-0030), MAM (XEP-0313), MUC (XEP-0045), pubsub (XEP-0060), HTTP File Upload (XEP-0363).
- **Metadata:** `exiftool` on the PDFs uploaded to `upload.murknet.htb`.
- **Crypto:** `openssl enc -d -aes-256-cbc -pbkdf2 -iter 120000 -md sha256` (base64 payloads).
- **OSINT:** Wayback Machine / CDX (`web.archive.org`) to recover a deleted threat-intel blog.

### Methodology (step by step)

**1. Recon — a Prosody behind nginx.** An `nmap` of common ports reveals the XMPP stack:

```
22/tcp   open  ssh       OpenSSH 9.6p1
443/tcp  open  ssl/http  nginx 1.24.0
5222/tcp open  xmpp-client   # client (STARTTLS)
5269/tcp open  xmpp-server   # s2s
5281/tcp open  ssl/http      # Prosody mod_http
```

The self-signed certificate (443/5222) reveals the deployment's identity and gives the first flag directly:

```
# openssl s_client -connect 10.129.x.x:443 | openssl x509 -noout -ext subjectAltName
DNS:murknet.htb, DNS:groups.murknet.htb, DNS:command.murknet.htb, DNS:upload.murknet.htb
```

Key subdomains: **groups** (MUC/rooms), **command** (pubsub dispatcher) and **upload** (file share, XEP-0363). → **Q1**.

**2. Access — in-band registration and channel enumeration.** The server has **in-band registration enabled** (`<register/>` in the stream features) and the cert is self-signed, so with `slixmpp` (TLS verification disabled) you create an account and enumerate components. *Critical note:* new accounts are **purged almost instantly** — you must **register and work in the same session**. A `disco#items` against `groups.murknet.htb` lists the channels:

```
resources@groups.murknet.htb  | Resources
rules@groups.murknet.htb      | Rules
random@groups.murknet.htb     | Random
infra@groups.murknet.htb      | Infrastructure
```

→ **Q2** (alphabetical order).

**3. The first whisper — email in metadata, password in #infra.** Reading the room history (MAM) surfaces PDFs uploaded to `upload.murknet.htb`. The *Operational Onboarding Guide* leaks a member's identity in its metadata:

```
# exiftool Operational_Onboarding_Guide_v3.2.pdf
Author  : zytglogge88@murknet.htb
Creator : swissclock          # Zytglogge = clock tower of Bern
```

The password was in plain sight: in **#infra**, *rattlesnake* mistakenly pastes the old "temporary passwords". The theme sings — **TickTock** ↔ clock ↔ swissclock:

```
# passwords leaked in #infra
KillBill2025!  K4w4Bong424!  Northwind225!  TickTock24!   <-- valid
```

→ **Q3**: `zytglogge88@murknet.htb:TickTock24!`. This account (**swissclock**, a real member) unlocks the 1-to-1 private chats and the operation rooms.

**4. Inside the cell — three operations and an encrypted dispatcher.** Authenticated as swissclock, the personal MAM archive and private rooms reveal the structure. The `command.murknet.htb` component is a **pubsub** service (XEP-0060) with each operation's orders encrypted (OpenSSL `Salted__` / AES-256-CBC):

- `op_sparkling` → crypto theft (1st op)
- `op_snatch` → Watson's kidnapping
- `op_dominance` → "next operation"

In a DM, *rattlesnake* hands swissclock the rotated key: `The new key is SHALLOWBLUE`. But **SHALLOWBLUE does not decrypt the already-published commands** — they predate the rotation. The *old* key is not in the XMPP: it must be recovered from the leaked decryptor (OSINT pivot).

In the `op_snatch` room, roles are assigned (colonel): *"Dynamite handles transport. Spur handles custody after delivery"* and `dynamite: "I'm starting the operation now"`. → **Q6**: `dynamite`.

In the private `op_dominance` room, *doctor*'s briefing: *"The next operation is unlike anything we've handled before… Our objective has a name: DIOGENES"*. → **Q8**: `Dominance,DIOGENES`.

**5. The OSINT pivot — "nothing is ever truly deleted once enough eyes have seen it".** The `op_sparkling` room stores the cell's reaction to a threat-intel report attributing the **BalanceRAT** malware to them. *rattlesnake* brags about deleting the blog — *"I personally nuked it. It's gone. try opening it now"* — and *doctor* corrects him with the line that is the challenge's literal hint. *timothy* pastes the URL (host down on purpose):

```
http://security.billblog.co.uk/threat/BalanceRAT-analysis-and-attribution
```

The real host is dead, but the copy lives in the **Wayback Machine**. The CDX confirms the snapshot and a giveaway image (`porlock.png`):

```
# curl "http://web.archive.org/cdx/search/cdx?url=security.billblog.co.uk*&output=text"
20260805 .../threat/BalanceRAT-analysis-and-attribution/          200
20260805 .../threat/BalanceRAT-analysis-and-attribution/porlock.png 200
```

The article (*"Ghost Balance"*) maps the online identities of the alias **Porlock** (= rattlesnake) and includes the **full decryptor**. The member's social account → **Q4**: `https://stonedforums.htb/@porlock`.

The `decrypt_command.sh` recovered from the archived blog:

```bash
#!/usr/bin/env bash
KEY='BLACKFENLOTTE'                # OLD key (pre-rotation)
printf '%s' "$1" | base64 -d |
  openssl enc -d -aes-256-cbc -pbkdf2 -iter 120000 -md sha256 -pass "pass:${KEY}"
```

Each operation uses **its own key** with the same method: **op_sparkling → BLACKFENLOTTE**, **op_snatch → SHALLOWBLUE**. The detail that broke everything before: `-iter 120000` was missing.

**6. Decryption — the orders in the clear.** BLACKFENLOTTE decrypts `op_sparkling` (crypto-asset theft):

```
cmd-02 Evilginx server: 185.203.11.109
cmd-03 BTC: 1BfQc4twbZrUSrtKdwW8TtSN6o1SUezWkX · 1BcanTJp… · 1BHoNZGG…
cmd-04 XMR Address: 429x3WVq1ucARGXx6NEwL4Sg4iowfW5ZWMAqEDErLxrWdg4ffkonB5tNxg85BKGjDqDQRfBERANhgf6DnGjjFyDR5L7uwye
cmd-05 Bank creds -> https://submit-creds.murknet.htb:9099
cmd-06 New C2 (BalanceRAT): 34.54.165.186
```

→ **Q5** (XMR wallet of the 1st operation). SHALLOWBLUE decrypts `op_snatch` (Watson's kidnapping):

```
cmd-02 Watson… red Ford Fiesta, plate WT609DXT
cmd-03 He just stopped at Pembridge Square
cmd-04 …turned onto Bayswater Road. Stay right on his heels!
cmd-05 He's about to enter Victoria Station. He must not reach the tracks. Act NOW
cmd-06 Heading toward Silvertown — 51°30'17.6"N, 0°02'05.1"E
cmd-08 Sector B. Row 6. Container 75JM77. Watchword: Chaos Is Order
cmd-09 Take the car to the junkyard in Walton-on-Thames. Ask for Richard.
cmd-10 Start cleanup process IMMEDIATELY
```

The grab happens at **Victoria Station** (cmd-05); he is then moved to the **Silvertown** hideout (container 75JM77), where the story-PDF objects appear. → **Q7**: `Victoria Station` (don't confuse capture vs captivity).

### Answers / flags

| # | Question | Answer |
|---|----------|--------|
| Q1 | TLS certificate SANs (main hostname first, rest alphabetical) | `murknet.htb,command.murknet.htb,groups.murknet.htb,upload.murknet.htb` |
| Q2 | Public XMPP channels (alphabetical order) | `Infrastructure,Random,Resources,Rules` |
| Q3 | Credentials of an APT member (email:password) | `zytglogge88@murknet.htb:TickTock24!` |
| Q4 | URL of an APT member's social account | `https://stonedforums.htb/@porlock` |
| Q5 | XMR wallet used in the first operation | `429x3WVq1ucARGXx6NEwL4Sg4iowfW5ZWMAqEDErLxrWdg4ffkonB5tNxg85BKGjDqDQRfBERANhgf6DnGjjFyDR5L7uwye` |
| Q6 | Nickname of the affiliate who kidnapped Watson | `dynamite` |
| Q7 | Where Watson was kidnapped | `Victoria Station` |
| Q8 | Last operation planned and its objective | `Dominance,DIOGENES` |

### Lessons

- **Each link hands you the next key** — hence "Whisper Chain": TLS cert → SANs; XMPP registration → channels; PDF metadata → email; infra channel → password; swissclock login → pubsub; rattlesnake DM → SHALLOWBLUE; Wayback → decryptor + BLACKFENLOTTE + Porlock; openssl → wallet + location.
- **The core crypto trap:** the published commands use the **old** key (BLACKFENLOTTE, from the blog), not the rotated DM key (SHALLOWBLUE). If the new key yields garbage, the message is pre-rotation.
- **Register and work in the same session:** IBR accounts are purged almost instantly on this Prosody.
- **Metadata = free OSINT:** `exiftool` on an uploaded PDF leaked Author/Creator and unlocked a real account.
- **"Nothing is ever truly deleted":** a deliberately down host was still alive in the Wayback Machine (CDX), which kept the full decryptor and the giveaway image.
- **Capture vs captivity:** Watson is **captured** at Victoria Station and **held** in Silvertown; the question asked for the kidnapping location.
