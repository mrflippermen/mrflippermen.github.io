---
title: "Holmes CTF 2026 — S03 Whisper Chain"
date: 2026-09-17
description: "Forense de un servidor XMPP/Prosody vivo (MurkNet): del certificado TLS al descifrado de las órdenes, encadenando registro in-band, metadatos PDF, pubsub AES y un pivote OSINT a la Wayback Machine."
excerpt: "Susurro a susurro: cada eslabón entrega la clave del siguiente. Cert TLS → canales → email en metadatos → password en #infra → pubsub cifrado → decryptor archivado en la Wayback → wallet XMR y el objetivo DIOGENES."
platform: "HTB"
difficulty: "Medium"
image: "/images/blog/holmes-s03.svg"
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
> **Dificultad:** Medium · **Flags:** 8/8 · **Disciplinas:** DFIR de servicio vivo · XMPP/Prosody · metadatos · criptografía simétrica · OSINT de archivo web.
>
> **Navegación:** [🇪🇸 Español](#es) · [🇬🇧 English](#en)

<a id="es"></a>

## 🇪🇸 Español

### Escenario

Watson sobrevive. En Silvertown queda un portátil con un intento apresurado de borrar la actividad reciente; solo persiste un cliente de comunicaciones cuyo servidor, cuenta y propósito son desconocidos. El operador hablaba a través de una red privada (**MurkNet**) bajo un alias.

El reto solo entrega un **PDF con la historia** — **toda la evidencia está en el objetivo vivo**: un servidor XMPP (**Prosody**) sobre `10.129.x.x`. No hay disco, ni memoria, ni pcap: hay que recuperar lo que sobrevivió al wipe *hablando con el servicio*, entender qué voces pertenecían juntas y adónde viajaban las órdenes cuando la conversación pública se detenía. Dificultad: **medium**.

La metáfora del título es literal y es la clave del reto. **Cada eslabón de la investigación entrega la clave del siguiente**: el certificado nombra los subdominios, los subdominios abren los canales, los canales filtran un email, el email pide una password que está pegada por error en otro canal, la cuenta abre el pubsub cifrado, el pubsub exige una clave que solo vive en un blog borrado, y el blog resucita en la Wayback Machine con el descifrador que finalmente revela la wallet y el objetivo final. Un susurro tras otro.

> **Encuadre.** Todo el trabajo se hace contra una infraestructura de laboratorio de HTB, autorizada y efímera. El objetivo es **defensivo/didáctico**: reconstruir la operación de un APT ficticio (Napoleon/MurkNet) para entender su cadena de mando y sus fallos de OPSEC, no atacar sistemas de terceros.

### Artefacto y herramientas

- **Objetivo vivo:** servidor XMPP/Prosody (`murknet.htb`) detrás de nginx, con tres componentes: `groups` (MUC), `command` (pubsub) y `upload` (HTTP File Upload).
- **Recon:** `nmap`, `openssl s_client` (certificado TLS y SANs vía STARTTLS y vía 443).
- **Acceso:** `slixmpp` con registro in-band (XEP-0077) y verificación TLS desactivada (cert autofirmado).
- **Enumeración/lectura:** disco#items (XEP-0030), MAM (XEP-0313), MUC (XEP-0045), pubsub (XEP-0060), HTTP File Upload (XEP-0363).
- **Metadatos:** `exiftool` sobre los PDFs subidos a `upload.murknet.htb`.
- **Cripto:** `openssl enc -d -aes-256-cbc -pbkdf2 -iter 120000 -md sha256` sobre payloads base64 con cabecera `Salted__`.
- **OSINT:** Wayback Machine / API CDX (`web.archive.org`) para recuperar un blog de threat-intel borrado y su `decrypt_command.sh`.

**Preparativos.** Antes de tocar nada, fijamos los nombres en `/etc/hosts` para que STARTTLS y la subida HTTP resuelvan bien el SNI/Host y el certificado valide contra el hostname esperado:

```bash
# 10.129.x.x es la IP del target del lab
echo "10.129.x.x murknet.htb groups.murknet.htb command.murknet.htb upload.murknet.htb submit-creds.murknet.htb" | sudo tee -a /etc/hosts
```

### Metodología (paso a paso)

#### 1. Recon — un Prosody detrás de nginx

**Por qué.** No sabemos ni el dominio XMPP ni los componentes. Un servidor Prosody típico expone un cuarteto de puertos muy reconocible; el certificado TLS, aunque sea autofirmado, está obligado a declarar en sus *Subject Alternative Names* todos los hostnames virtuales que atiende — es decir, nos regala el mapa del despliegue **y** la primera flag.

```bash
# barrido completo + versión sobre puertos abiertos
nmap -Pn -p- --min-rate 2000 10.129.x.x -oA whisper_allports
nmap -Pn -p22,443,5222,5269,5281 -sV -sC 10.129.x.x -oA whisper_svc
```

```
22/tcp   open  ssh       OpenSSH 9.6p1
443/tcp  open  ssl/http  nginx 1.24.0
5222/tcp open  xmpp-client   # cliente (STARTTLS)
5269/tcp open  xmpp-server   # s2s (server-to-server)
5281/tcp open  ssl/http      # Prosody mod_http (BOSH/WebSocket/Upload)
```

La firma es inequívoca: **5222** (c2s con STARTTLS), **5269** (federación s2s) y **5281** (el HTTP interno de Prosody). El **443/nginx** es el *reverse proxy* que publica los vhosts HTTP (entre ellos `upload`). El certificado autofirmado, presentado en 443 y en 5222, revela la identidad del despliegue y da directamente **Q1**.

**El truco del SANs.** Se puede leer el certificado de dos maneras — desde el 443 con SNI, o directamente del puerto XMPP negociando STARTTLS; ambas devuelven el mismo cert:

```bash
# vía 443 con SNI
echo | openssl s_client -connect 10.129.x.x:443 -servername murknet.htb 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName

# vía XMPP c2s negociando STARTTLS (útil si el 443 está filtrado)
echo | openssl s_client -connect 10.129.x.x:5222 -starttls xmpp -xmpphost murknet.htb 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName
```

```
X509v3 Subject Alternative Name:
    DNS:murknet.htb, DNS:groups.murknet.htb, DNS:command.murknet.htb, DNS:upload.murknet.htb
```

Subdominios clave: **groups** (MUC/salas de chat multiusuario), **command** (el *dispatcher* pubsub por donde viajan las órdenes) y **upload** (el file share XEP-0363 donde se cuelgan los PDFs). El orden pedido por la pregunta es *hostname principal primero, resto alfabético*.

> **Q1 — SANs del certificado TLS:** `murknet.htb,command.murknet.htb,groups.murknet.htb,upload.murknet.htb`

#### 2. Acceso — registro in-band y enumeración de canales

**Por qué.** No tenemos credenciales, pero el servidor anuncia `<register/>` en sus *stream features*: **registro in-band habilitado** (XEP-0077, IBR). Podemos crearnos una cuenta desechable y, ya autenticados, preguntarle al servidor por sus componentes (disco#items) y por los canales del MUC. El certificado es autofirmado, así que hay que **desactivar la verificación TLS** en el cliente.

*Nota crítica de OPSEC del lab:* las cuentas nuevas (burner) se **purgan casi al instante** — hay un job que las limpia. Por eso hay que **registrar y trabajar en la misma sesión**: en cuanto tienes stream, enumeras y lees; no cierres y vuelvas.

Confirmamos primero que el IBR está anunciado:

```bash
# las stream features anuncian <register/> si el IBR está activo
echo "<stream:stream to='murknet.htb' xmlns='jabber:client' \
xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>" \
  | openssl s_client -connect 10.129.x.x:5222 -starttls xmpp -xmpphost murknet.htb -quiet 2>/dev/null \
  | grep -o 'register'
```

Y lo automatizamos con `slixmpp`, que trae plugins para todos los XEP que necesitamos:

```python
#!/usr/bin/env python3
import asyncio, ssl, slixmpp

class Burner(slixmpp.ClientXMPP):
    def __init__(self, jid, pwd):
        super().__init__(jid, pwd)
        for x in ('xep_0030','xep_0045','xep_0060','xep_0077','xep_0313','xep_0363'):
            self.register_plugin(x)          # disco, MUC, pubsub, IBR, MAM, HTTP Upload
        self['xep_0077'].force_registration = True
        self.add_event_handler('register', self._register)
        self.add_event_handler('session_start', self._start)

    async def _register(self, iq):
        resp = self.Iq(); resp['type'] = 'set'
        resp['register']['username'] = self.boundjid.user
        resp['register']['password'] = self.password
        await resp.send()                     # crea la cuenta burner

    async def _start(self, _):
        self.send_presence(); await self.get_roster()
        # disco#items sobre el componente de salas
        items = await self['xep_0030'].get_items(jid='groups.murknet.htb')
        for it in items['disco_items']['items']:
            print(it[0], '|', it[2])          # JID | nombre del canal
        self.disconnect()

x = Burner('burner01@murknet.htb', 'Burner!2026')
x.ssl_context.check_hostname = False          # cert autofirmado
x.ssl_context.verify_mode   = ssl.CERT_NONE
x.connect(('10.129.x.x', 5222))
x.process(forever=False)
```

El `disco#items` sobre `groups.murknet.htb` — equivalente al stanza crudo `<iq type='get' to='groups.murknet.htb'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>` — lista los canales públicos:

```
resources@groups.murknet.htb  | Resources
rules@groups.murknet.htb      | Rules
random@groups.murknet.htb     | Random
infra@groups.murknet.htb      | Infrastructure
```

La pregunta pide los **nombres** en orden alfabético.

> **Q2 — Canales públicos del XMPP (alfabético):** `Infrastructure,Random,Resources,Rules`

#### 3. El primer susurro — email en metadatos, password en #infra

**Por qué.** Los canales públicos son historia viva: Prosody guarda **MAM** (Message Archive Management, XEP-0313), así que podemos rebobinar todo lo dicho. Entre los mensajes hay enlaces a PDFs colgados en `upload.murknet.htb` (XEP-0363). Los documentos ofimáticos casi siempre filtran quién los creó en sus metadatos: es OSINT gratis que nos da el **email** de un miembro real. Con el email, solo falta la password — y alguien la pegó por error en un canal.

Consultamos el archivo de una sala con MAM. En `slixmpp`:

```python
# dentro de _start(): recupera el historial completo de #infra
async for msg in self['xep_0313'].iterate(jid='infra@groups.murknet.htb',
                                           amount=200, rsm={'max': 200}):
    body = msg['mam_result']['forwarded']['stanza']['body']
    if body: print(body)
```

…que por debajo emite el stanza estándar de MAM:

```xml
<iq type='set' to='infra@groups.murknet.htb' id='mam1'>
  <query xmlns='urn:xmpp:mam:2'>
    <set xmlns='http://jabber.org/protocol/rsm'><max>200</max></set>
  </query>
</iq>
```

En el historial aparecen las URLs de los PDFs. Los descargamos del file share y les pasamos `exiftool`:

```bash
# el enlace HTTP Upload lleva un UUID de un solo uso
curl -sk "https://upload.murknet.htb/<uuid>/Operational_Onboarding_Guide_v3.2.pdf" -o guide.pdf
exiftool -Author -Creator -Producer -CreateDate guide.pdf
```

```
Author  : zytglogge88@murknet.htb
Creator : swissclock          # Zytglogge = torre del reloj de Berna
```

El *Operational Onboarding Guide* filtra la identidad de un miembro: el email **zytglogge88@murknet.htb** y el alias **swissclock**. `Zytglogge` es la torre del reloj medieval de Berna — un guiño temático (reloj) que enseguida encaja con la password.

La contraseña estaba a la vista: en el canal **#infra**, *rattlesnake* pega por error las "contraseñas temporales" antiguas de un lote de altas. En vez de forzar login por login, dejamos que la **temática** desempate — **swissclock** ↔ reloj ↔ **TickTock**:

```
# passwords filtradas en #infra (lote de altas antiguo)
KillBill2025!   K4w4Bong424!   Northwind225!   TickTock24!   <-- válida
```

Autenticando `zytglogge88@murknet.htb:TickTock24!` entramos como **swissclock**, un miembro *real* de la célula — no un burner —, lo que desbloquea los chats privados 1-a-1 y las salas de operación que a un desconocido le están vedadas.

> **Q3 — Credenciales de un miembro del APT:** `zytglogge88@murknet.htb:TickTock24!`

#### 4. Dentro de la célula — tres operaciones y un dispatcher cifrado

**Por qué.** Como swissclock ya no somos observadores: tenemos MAM personal, DMs y acceso a las salas privadas donde se coordina de verdad. Aquí aparece el corazón del reto: el componente `command.murknet.htb` es un servicio **pubsub** (XEP-0060) que funciona como *dead drop* — cada operación tiene su nodo con las órdenes publicadas **cifradas** (OpenSSL `Salted__` / AES-256-CBC, payload en base64). Enumerar los nodos y sus items nos da el mapa de operaciones.

```python
# nodos del dispatcher pubsub
nodes = await self['xep_0060'].get_nodes('command.murknet.htb')
for n in nodes['disco_items']['items']:
    print('NODE', n[1])
    items = await self['xep_0060'].get_items('command.murknet.htb', n[1])
    for it in items['pubsub']['items']:
        print('  ', it['id'], it['payload'].text[:60], '...')   # base64 cifrado
```

Aparecen tres operaciones:

- `op_sparkling` → robo de criptoactivos (la **1ª** operación)
- `op_snatch` → secuestro de Watson
- `op_dominance` → *"next operation"*

**La trampa central.** En un DM, *rattlesnake* entrega a swissclock la clave rotada: `The new key is SHALLOWBLUE`. Es tentador usarla para todo — pero **SHALLOWBLUE no descifra los comandos ya publicados** de `op_sparkling`/`op_snatch`, porque esos items son **anteriores** a la rotación. La clave *vieja* con la que se cifraron **no está en el XMPP**: hay que recuperarla del descifrador filtrado (el pivote OSINT del paso 5). Regla mental: *si la clave nueva da basura, el mensaje es pre-rotación.*

Mientras tanto, las salas de operación reparten roles y objetivos. En `op_snatch`, el *colonel* asigna la logística del secuestro:

```
# sala op_snatch — reparto de roles (colonel)
"Dynamite handles transport. Spur handles custody after delivery"
dynamite: "I'm starting the operation now"
```

Quien ejecuta el traslado/agarre de Watson es **dynamite** (Spur solo se encarga de la custodia *después* de la entrega).

> **Q6 — Apodo del afiliado que secuestró a Watson:** `dynamite`

Y en la sala privada `op_dominance`, el briefing de *doctor* nombra la operación final y su objetivo:

```
# sala privada op_dominance — briefing de doctor
"The next operation is unlike anything we've handled before…
 Our objective has a name: DIOGENES"
```

> **Q8 — Última operación planeada y su objetivo:** `Dominance,DIOGENES`

#### 5. El pivote OSINT — "nothing is ever truly deleted once enough eyes have seen it"

**Por qué.** Los comandos publicados están cifrados con una clave que no vive en el chat. La sala `op_sparkling` guarda la reacción de la célula a un informe de threat-intel externo que les atribuyó el malware **BalanceRAT**. *rattlesnake* (alias **Porlock**) presume de haber borrado el blog — *"I personally nuked it. It's gone. try opening it now"* — y *doctor* le corrige con la frase que es la **pista literal** del reto: *"nothing is ever truly deleted once enough eyes have seen it"*. *timothy* pega la URL, con el host caído a propósito:

```
http://security.billblog.co.uk/threat/BalanceRAT-analysis-and-attribution
```

El host real está muerto, pero la copia vive en la **Wayback Machine**. Consultamos la API **CDX** para listar snapshots y descubrir recursos asociados (una imagen delatora y el script):

```bash
# lista de capturas y recursos bajo ese host
curl -s "http://web.archive.org/cdx/search/cdx?url=security.billblog.co.uk*&output=text&collapse=urlkey"
```

```
20260805 .../threat/BalanceRAT-analysis-and-attribution/                200
20260805 .../threat/BalanceRAT-analysis-and-attribution/porlock.png     200
20260805 .../threat/BalanceRAT-analysis-and-attribution/decrypt_command.sh  200
```

Recuperamos el artículo y sus recursos por el proxy de la Wayback. El sufijo `id_` sirve el objeto **crudo**, sin la barra de navegación de archive.org:

```bash
BASE="https://web.archive.org/web/20260805000000id_/http://security.billblog.co.uk/threat/BalanceRAT-analysis-and-attribution"
curl -s "$BASE/"                 -o article.html
curl -s "$BASE/porlock.png"      -o porlock.png
curl -s "$BASE/decrypt_command.sh" -o decrypt_command.sh
```

El artículo (*"Ghost Balance"*) mapea las identidades online del alias **Porlock** (= rattlesnake), incluida su cuenta de foros, y adjunta el **descifrador completo**. La cuenta de RRSS del miembro es la respuesta a **Q4**.

> **Q4 — URL de la cuenta de RRSS de un miembro del APT:** `https://stonedforums.htb/@porlock`

El `decrypt_command.sh` recuperado del blog archivado revela **la clave vieja** y, sobre todo, **los parámetros exactos** de OpenSSL:

```bash
#!/usr/bin/env bash
KEY='BLACKFENLOTTE'                # clave ANTIGUA (pre-rotación)
printf '%s' "$1" | base64 -d |
  openssl enc -d -aes-256-cbc -pbkdf2 -iter 120000 -md sha256 -pass "pass:${KEY}"
```

Cada operación usa **su propia clave** con el mismo método: **op_sparkling → BLACKFENLOTTE**, **op_snatch → SHALLOWBLUE** (la rotada). El detalle que rompía el descifrado a mano antes de tener el script: faltaban **`-pbkdf2 -iter 120000 -md sha256`**. Sin esa derivación de clave idéntica, OpenSSL produce basura aunque la contraseña sea correcta.

#### 6. Descifrado — las órdenes en claro

**Por qué.** Con el método exacto y las dos claves, ya podemos convertir cada payload base64 del pubsub en texto plano. Conviene verificar primero la cabecera `Salted__` (así confirmamos que es un blob de `openssl enc` con sal, no otra cosa):

```bash
# 1) inspección: los primeros 8 bytes deben ser "Salted__"
echo -n "$PAYLOAD_B64" | base64 -d | head -c 16 | xxd
# 00000000: 5361 6c74 6564 5f5f ....  Salted__....

# 2) descifrado de op_sparkling con la clave VIEJA
echo -n "$PAYLOAD_B64" | base64 -d \
  | openssl enc -d -aes-256-cbc -pbkdf2 -iter 120000 -md sha256 -pass pass:BLACKFENLOTTE
```

Con **BLACKFENLOTTE** se descifra `op_sparkling` (robo de criptoactivos):

```
cmd-02 Evilginx server: 185.203.11.109
cmd-03 BTC: 1BfQc4twbZrUSrtKdwW8TtSN6o1SUezWkX · 1BcanTJp… · 1BHoNZGG…
cmd-04 XMR Address: 429x3WVq1ucARGXx6NEwL4Sg4iowfW5ZWMAqEDErLxrWdg4ffkonB5tNxg85BKGjDqDQRfBERANhgf6DnGjjFyDR5L7uwye
cmd-05 Bank creds -> https://submit-creds.murknet.htb:9099
cmd-06 New C2 (BalanceRAT): 34.54.165.186
```

La wallet Monero de `cmd-04` es la de la **primera** operación.

> **Q5 — Wallet XMR usada en la primera operación:** `429x3WVq1ucARGXx6NEwL4Sg4iowfW5ZWMAqEDErLxrWdg4ffkonB5tNxg85BKGjDqDQRfBERANhgf6DnGjjFyDR5L7uwye`

Con **SHALLOWBLUE** (misma línea, cambiando solo `-pass pass:SHALLOWBLUE`) se descifra `op_snatch` (secuestro de Watson):

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

La secuencia narra el operativo minuto a minuto: siguen a Watson desde Pembridge Square por Bayswater Road; el **agarre se ejecuta en Victoria Station** (`cmd-05`, *"He must not reach the tracks. Act NOW"*); después lo **trasladan** a la guarida de **Silvertown** (`cmd-06`/`cmd-08`, contenedor 75JM77), que es exactamente donde el PDF de la historia sitúa los objetos recuperados. La pregunta pide **dónde lo secuestran**, no dónde lo retienen.

> **Q7 — Dónde ha sido secuestrado Watson:** `Victoria Station` (captura ≠ cautiverio)

### Cronología

| Fase | Hito de la investigación | Artefacto / técnica |
|------|--------------------------|----------------------|
| T0 | Portátil incautado en Silvertown; solo un cliente XMPP superviviente | PDF de historia |
| T1 | `nmap` → stack Prosody (5222/5269/5281 + nginx 443) | recon de puertos |
| T2 | SANs del cert autofirmado → 4 hostnames (**Q1**) | `openssl s_client` / `x509` |
| T3 | IBR activo → cuenta burner con `slixmpp`; `disco#items` → 4 canales (**Q2**) | XEP-0077 / XEP-0030 |
| T4 | MAM de las salas → PDFs en `upload`; `exiftool` filtra email+alias | XEP-0313 / XEP-0363 / metadatos |
| T5 | Password temática pegada en `#infra` → login como swissclock (**Q3**) | reutilización/fuga de credenciales |
| T6 | Pubsub `command.*` → 3 operaciones cifradas; DM entrega SHALLOWBLUE | XEP-0060 |
| T7 | Roles en `op_snatch` → **dynamite** (**Q6**); briefing `op_dominance` → **DIOGENES** (**Q8**) | lectura de MUC |
| T8 | Pista *"nothing is ever truly deleted"* → CDX/Wayback recupera el blog | OSINT de archivo |
| T9 | Blog archivado → cuenta **@porlock** (**Q4**) + `decrypt_command.sh` (BLACKFENLOTTE, `-iter 120000`) | Wayback + análisis del script |
| T10 | Descifrado: `op_sparkling` → wallet XMR (**Q5**); `op_snatch` → **Victoria Station** (**Q7**) | `openssl enc -d` |

### IOCs

| Tipo | Indicador | Contexto |
|------|-----------|----------|
| Dominio | `murknet.htb`, `groups.murknet.htb`, `command.murknet.htb`, `upload.murknet.htb` | Infra XMPP/Prosody de la célula (SANs del cert) |
| Dominio/puerto | `submit-creds.murknet.htb:9099` | Colector de credenciales bancarias robadas (`op_sparkling` cmd-05) |
| Dominio | `security.billblog.co.uk` | Blog de threat-intel borrado; recuperable en Wayback |
| Dominio | `stonedforums.htb/@porlock` | Cuenta de foros del alias Porlock (= rattlesnake) |
| IPv4 | `185.203.11.109` | Servidor **Evilginx** (phishing AiTM) — `op_sparkling` cmd-02 |
| IPv4 | `34.54.165.186` | Nuevo C2 de **BalanceRAT** — `op_sparkling` cmd-06 |
| Wallet BTC | `1BfQc4twbZrUSrtKdwW8TtSN6o1SUezWkX`, `1BcanTJp…`, `1BHoNZGG…` | Destino del robo cripto |
| Wallet XMR | `429x3WVq1ucARGXx6NEwL4Sg4iowfW5ZWMAqEDErLxrWdg4ffkonB5tNxg85BKGjDqDQRfBERANhgf6DnGjjFyDR5L7uwye` | Wallet Monero de la 1ª operación |
| Malware | `BalanceRAT` | RAT atribuido a la célula en el informe "Ghost Balance" |
| Clave cripto | `BLACKFENLOTTE` (op_sparkling), `SHALLOWBLUE` (op_snatch, rotada) | AES-256-CBC / PBKDF2 iter 120000 |
| Credencial | `zytglogge88@murknet.htb:TickTock24!` (alias swissclock) | Cuenta comprometida de la célula |
| Alias | swissclock, rattlesnake/Porlock, doctor, colonel, dynamite, spur, timothy | Miembros de la célula |
| Vehículo | Ford Fiesta rojo, matrícula `WT609DXT` | Coche de Watson (`op_snatch`) |
| Geo | `51°30'17.6"N, 0°02'05.1"E` — Silvertown; Contenedor `75JM77`, watchword `Chaos Is Order` | Guarida/cautiverio |

### Mapeo MITRE ATT&CK

TTPs del adversario observadas al reconstruir la operación:

| Táctica | Técnica | Evidencia en el reto |
|---------|---------|----------------------|
| Resource Development | **T1583.001** Acquire Infrastructure: Domains | `murknet.htb` + subdominios propios |
| Resource Development | **T1587.001** Develop Capabilities: Malware | BalanceRAT |
| Resource Development | **T1585.001** Establish Accounts: Social Media | `@porlock` en stonedforums.htb |
| Command and Control | **T1071.001** Application Layer Protocol: Web/Messaging | XMPP (Prosody) como canal de mando |
| Command and Control | **T1102** Web Service (dead drop) | pubsub XEP-0060 como buzón de órdenes |
| Command and Control | **T1573.001** Encrypted Channel: Symmetric Cryptography | órdenes en AES-256-CBC / PBKDF2 |
| Command and Control | **T1573.002** + rotación de claves | rotación BLACKFENLOTTE → SHALLOWBLUE |
| Credential Access | **T1557** Adversary-in-the-Middle | servidor **Evilginx** (185.203.11.109) |
| Collection / Initial Access | **T1566** Phishing / **T1598** Phishing for Information | robo de credenciales bancarias → `submit-creds:9099` |
| Impact | **T1657** Financial Theft | robo de criptoactivos (op_sparkling), wallets BTC/XMR |
| Defense Evasion | **T1070** Indicator Removal | *"I personally nuked it"* — borrado del blog de atribución |
| — (mundo físico) | Secuestro de Watson (op_snatch) | fuera del alcance ATT&CK; incluido por contexto narrativo |

### Detección y remediación

**Para el operador del servidor XMPP (lecciones de OPSEC del APT, aplicables a un defensor):**

- **Desactivar el registro in-band** en Prosody (`allow_registration = false`) o exigir aprobación de admin (`mod_register_web`). Un IBR abierto permitió el burner y toda la enumeración.
- **Certificados propios de una CA**, no autofirmados: el autofirmado no aporta seguridad y sus SANs filtraron el mapa completo del despliegue. Al menos, no listar todos los vhosts sensibles en un único cert público.
- **Retención de MAM mínima** y por defecto desactivada en salas sensibles: el archivo completo dejó reconstruir meses de coordinación. Purgar y limitar `max_archive_query_results`.
- **Higiene de credenciales:** nunca pegar lotes de "contraseñas temporales" en un canal (`#infra`), no usar passwords temáticas/adivinables (`TickTock24!` ↔ swissclock), y rotar de verdad revocando las cuentas afectadas.
- **Scrubbing de metadatos** antes de subir documentos: `exiftool -all= guide.pdf` habría evitado filtrar `Author`/`Creator`. Un pipeline de subida debería normalizar metadatos.
- **Cifrado en reposo tras rotación:** rotar la clave (SHALLOWBLUE) sin **re-cifrar los items antiguos** dejó los comandos previos descifrables con la clave vieja recuperable por OSINT. Al rotar, re-encriptar o borrar el histórico.
- **El borrado no es borrado:** un host caído sigue vivo en la Wayback Machine / cachés. Para infra propia filtrada, solicitar la exclusión del archivo *y* asumir que la copia ya circula.

**Para el equipo de detección (blue team) que vigila una red parecida:**

- Alertar sobre **XMPP c2s/s2s** (5222/5269/5281) hacia destinos no corporativos, y sobre **s2s federado** con dominios desconocidos.
- Inspeccionar payloads de **pubsub/MUC** en busca de **blobs base64 con cabecera `Salted__`** (`U2FsdGVk` en base64): indicador fuerte de comandos cifrados con `openssl enc`.
- Correlacionar los **IOCs de red** (Evilginx `185.203.11.109`, C2 `34.54.165.186`, `submit-creds.murknet.htb:9099`) contra logs de proxy/DNS/firewall.
- Vigilar **wallets** BTC/XMR conocidas en fuentes de inteligencia y monitorizar la creación de **cuentas de foros/RRSS** asociadas a alias del actor.

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
- **Los parámetros de KDF son parte de la clave:** sin `-pbkdf2 -iter 120000 -md sha256` idénticos, la contraseña correcta produce basura. El script archivado no solo daba la clave: daba el *método*.
- **Registrar y trabajar en la misma sesión:** las cuentas IBR se purgan casi al instante en este Prosody.
- **Metadatos = OSINT gratis:** `exiftool` sobre un PDF subido filtró Author/Creator y desbloqueó una cuenta real.
- **"Nada se borra del todo":** un host caído a propósito seguía vivo en la Wayback Machine (CDX), que guardaba el decryptor completo y la imagen delatora.
- **Distinguir captura vs cautiverio:** a Watson lo **capturan** en Victoria Station y lo **retienen** en Silvertown; la pregunta pedía el lugar del secuestro.

### Serie · The Reichenbach Directive

| Sherlock | Título | Enlace |
|----------|--------|--------|
| S01 | Silent Dividend | [../2026-09-15-holmes2026-s01-silent-dividend/](../2026-09-15-holmes2026-s01-silent-dividend/) |
| S02 | Bottle Out | [../2026-09-16-holmes2026-s02-bottle-out/](../2026-09-16-holmes2026-s02-bottle-out/) |
| **S03** | **Whisper Chain — este writeup** | [../2026-09-17-holmes2026-s03-whisper-chain/](../2026-09-17-holmes2026-s03-whisper-chain/) |
| S04 | Paper Ghost | [../2026-09-18-holmes2026-s04-paper-ghost/](../2026-09-18-holmes2026-s04-paper-ghost/) |
| S05 | Poisoned Branch | [../2026-09-19-holmes2026-s05-poisoned-branch/](../2026-09-19-holmes2026-s05-poisoned-branch/) |
| S06 | Silent Passenger | [../2026-09-20-holmes2026-s06-silent-passenger/](../2026-09-20-holmes2026-s06-silent-passenger/) |
| S07 | Iron Feather | [../2026-09-21-holmes2026-s07-iron-feather/](../2026-09-21-holmes2026-s07-iron-feather/) |
| S08 | Borrowed Name | [../2026-09-22-holmes2026-s08-borrowed-name/](../2026-09-22-holmes2026-s08-borrowed-name/) |
| S09 | Last Light | [../2026-09-23-holmes2026-s09-last-light/](../2026-09-23-holmes2026-s09-last-light/) |

<a id="en"></a>

## 🇬🇧 English

### Scenario

Watson survives. In Silvertown a laptop is left behind with a hasty attempt to wipe recent activity; only a comms client persists, its server, account and purpose unknown. The operator spoke through a private network (**MurkNet**) under an alias.

The challenge ships only a **story PDF** — **all the evidence lives on the live target**: an XMPP (**Prosody**) server on `10.129.x.x`. There is no disk image, no memory dump, no pcap: you must recover what survived the wipe *by talking to the service itself*, work out which voices belonged together, and where the orders travelled once the public conversation stopped. Difficulty: **medium**.

The title is literal and it is the whole point. **Every link of the investigation hands you the key to the next**: the certificate names the subdomains, the subdomains open the channels, a channel leaks an email, the email needs a password that someone pasted by mistake into another channel, the account opens the encrypted pubsub, the pubsub demands a key that only lives on a deleted blog, and the blog comes back to life in the Wayback Machine carrying the decryptor that finally reveals the wallet and the final objective. One whisper after another.

> **Framing.** All work is done against authorized, ephemeral HTB lab infrastructure. The goal is **defensive/educational**: reconstruct a fictional APT's operation (Napoleon/MurkNet) to understand its chain of command and its OPSEC failures, not to attack third-party systems.

### Artifact and tooling

- **Live target:** XMPP/Prosody server (`murknet.htb`) behind nginx, with three components: `groups` (MUC), `command` (pubsub) and `upload` (HTTP File Upload).
- **Recon:** `nmap`, `openssl s_client` (TLS certificate and SANs via STARTTLS and via 443).
- **Access:** `slixmpp` with in-band registration (XEP-0077) and TLS verification disabled (self-signed cert).
- **Enumeration/reading:** disco#items (XEP-0030), MAM (XEP-0313), MUC (XEP-0045), pubsub (XEP-0060), HTTP File Upload (XEP-0363).
- **Metadata:** `exiftool` on the PDFs uploaded to `upload.murknet.htb`.
- **Crypto:** `openssl enc -d -aes-256-cbc -pbkdf2 -iter 120000 -md sha256` on base64 payloads with a `Salted__` header.
- **OSINT:** Wayback Machine / CDX API (`web.archive.org`) to recover a deleted threat-intel blog and its `decrypt_command.sh`.

**Setup.** Before touching anything, pin the names in `/etc/hosts` so STARTTLS and the HTTP upload resolve SNI/Host correctly and the cert validates against the expected hostname:

```bash
# 10.129.x.x is the lab target IP
echo "10.129.x.x murknet.htb groups.murknet.htb command.murknet.htb upload.murknet.htb submit-creds.murknet.htb" | sudo tee -a /etc/hosts
```

### Methodology (step by step)

#### 1. Recon — a Prosody behind nginx

**Why.** We know neither the XMPP domain nor the components. A typical Prosody server exposes a very recognizable quartet of ports; the TLS certificate, self-signed or not, is obliged to declare in its *Subject Alternative Names* every virtual hostname it serves — so it hands us the deployment map **and** the first flag.

```bash
# full sweep + version detection on open ports
nmap -Pn -p- --min-rate 2000 10.129.x.x -oA whisper_allports
nmap -Pn -p22,443,5222,5269,5281 -sV -sC 10.129.x.x -oA whisper_svc
```

```
22/tcp   open  ssh       OpenSSH 9.6p1
443/tcp  open  ssl/http  nginx 1.24.0
5222/tcp open  xmpp-client   # client (STARTTLS)
5269/tcp open  xmpp-server   # s2s (server-to-server)
5281/tcp open  ssl/http      # Prosody mod_http (BOSH/WebSocket/Upload)
```

The signature is unmistakable: **5222** (c2s with STARTTLS), **5269** (s2s federation) and **5281** (Prosody's internal HTTP). **443/nginx** is the reverse proxy publishing the HTTP vhosts (`upload` among them). The self-signed cert, presented on 443 and 5222, reveals the deployment's identity and gives **Q1** directly.

**The SANs trick.** You can read the cert two ways — from 443 with SNI, or straight off the XMPP port negotiating STARTTLS; both return the same cert:

```bash
# via 443 with SNI
echo | openssl s_client -connect 10.129.x.x:443 -servername murknet.htb 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName

# via XMPP c2s negotiating STARTTLS (useful if 443 is filtered)
echo | openssl s_client -connect 10.129.x.x:5222 -starttls xmpp -xmpphost murknet.htb 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName
```

```
X509v3 Subject Alternative Name:
    DNS:murknet.htb, DNS:groups.murknet.htb, DNS:command.murknet.htb, DNS:upload.murknet.htb
```

Key subdomains: **groups** (MUC/multi-user chat rooms), **command** (the pubsub *dispatcher* the orders travel through) and **upload** (the XEP-0363 file share where the PDFs are dropped). The order the question wants is *main hostname first, rest alphabetical*.

> **Q1 — TLS certificate SANs:** `murknet.htb,command.murknet.htb,groups.murknet.htb,upload.murknet.htb`

#### 2. Access — in-band registration and channel enumeration

**Why.** We have no credentials, but the server advertises `<register/>` in its *stream features*: **in-band registration enabled** (XEP-0077, IBR). We can create a burner account and, once authenticated, ask the server for its components (disco#items) and the MUC channels. The cert is self-signed, so we must **disable TLS verification** in the client.

*Critical lab OPSEC note:* new (burner) accounts are **purged almost instantly** — a job cleans them up. So you must **register and work in the same session**: as soon as you have a stream, enumerate and read; don't disconnect and come back.

First confirm IBR is advertised:

```bash
# stream features advertise <register/> if IBR is on
echo "<stream:stream to='murknet.htb' xmlns='jabber:client' \
xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>" \
  | openssl s_client -connect 10.129.x.x:5222 -starttls xmpp -xmpphost murknet.htb -quiet 2>/dev/null \
  | grep -o 'register'
```

And automate with `slixmpp`, which ships plugins for every XEP we need:

```python
#!/usr/bin/env python3
import asyncio, ssl, slixmpp

class Burner(slixmpp.ClientXMPP):
    def __init__(self, jid, pwd):
        super().__init__(jid, pwd)
        for x in ('xep_0030','xep_0045','xep_0060','xep_0077','xep_0313','xep_0363'):
            self.register_plugin(x)          # disco, MUC, pubsub, IBR, MAM, HTTP Upload
        self['xep_0077'].force_registration = True
        self.add_event_handler('register', self._register)
        self.add_event_handler('session_start', self._start)

    async def _register(self, iq):
        resp = self.Iq(); resp['type'] = 'set'
        resp['register']['username'] = self.boundjid.user
        resp['register']['password'] = self.password
        await resp.send()                     # create the burner account

    async def _start(self, _):
        self.send_presence(); await self.get_roster()
        # disco#items against the rooms component
        items = await self['xep_0030'].get_items(jid='groups.murknet.htb')
        for it in items['disco_items']['items']:
            print(it[0], '|', it[2])          # JID | channel name
        self.disconnect()

x = Burner('burner01@murknet.htb', 'Burner!2026')
x.ssl_context.check_hostname = False          # self-signed cert
x.ssl_context.verify_mode   = ssl.CERT_NONE
x.connect(('10.129.x.x', 5222))
x.process(forever=False)
```

The `disco#items` against `groups.murknet.htb` — equivalent to the raw stanza `<iq type='get' to='groups.murknet.htb'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>` — lists the public channels:

```
resources@groups.murknet.htb  | Resources
rules@groups.murknet.htb      | Rules
random@groups.murknet.htb     | Random
infra@groups.murknet.htb      | Infrastructure
```

The question wants the **names** in alphabetical order.

> **Q2 — Public XMPP channels (alphabetical):** `Infrastructure,Random,Resources,Rules`

#### 3. The first whisper — email in metadata, password in #infra

**Why.** The public channels are living history: Prosody keeps **MAM** (Message Archive Management, XEP-0313), so we can rewind everything said. Among the messages are links to PDFs dropped on `upload.murknet.htb` (XEP-0363). Office documents almost always leak their creator in the metadata: free OSINT that hands us a real member's **email**. With the email, we only lack the password — and someone pasted it by mistake into a channel.

Query a room's archive via MAM. In `slixmpp`:

```python
# inside _start(): pull the full #infra history
async for msg in self['xep_0313'].iterate(jid='infra@groups.murknet.htb',
                                           amount=200, rsm={'max': 200}):
    body = msg['mam_result']['forwarded']['stanza']['body']
    if body: print(body)
```

…which underneath emits the standard MAM stanza:

```xml
<iq type='set' to='infra@groups.murknet.htb' id='mam1'>
  <query xmlns='urn:xmpp:mam:2'>
    <set xmlns='http://jabber.org/protocol/rsm'><max>200</max></set>
  </query>
</iq>
```

The PDF URLs show up in the history. Download them from the file share and run `exiftool`:

```bash
# the HTTP Upload link carries a one-time UUID
curl -sk "https://upload.murknet.htb/<uuid>/Operational_Onboarding_Guide_v3.2.pdf" -o guide.pdf
exiftool -Author -Creator -Producer -CreateDate guide.pdf
```

```
Author  : zytglogge88@murknet.htb
Creator : swissclock          # Zytglogge = clock tower of Bern
```

The *Operational Onboarding Guide* leaks a member's identity: the email **zytglogge88@murknet.htb** and the alias **swissclock**. `Zytglogge` is Bern's medieval clock tower — a thematic nudge (clock) that immediately fits the password.

The password was in plain sight: in **#infra**, *rattlesnake* mistakenly pastes the old "temporary passwords" from an onboarding batch. Instead of brute-forcing login by login, let the **theme** break the tie — **swissclock** ↔ clock ↔ **TickTock**:

```
# passwords leaked in #infra (old onboarding batch)
KillBill2025!   K4w4Bong424!   Northwind225!   TickTock24!   <-- valid
```

Authenticating `zytglogge88@murknet.htb:TickTock24!` gets us in as **swissclock**, a *real* cell member — not a burner — which unlocks the private 1-to-1 chats and the operation rooms an outsider can't see.

> **Q3 — Credentials of an APT member:** `zytglogge88@murknet.htb:TickTock24!`

#### 4. Inside the cell — three operations and an encrypted dispatcher

**Why.** As swissclock we are no longer observers: we have a personal MAM archive, DMs and access to the private rooms where the real coordination happens. Here lies the heart of the challenge: the `command.murknet.htb` component is a **pubsub** service (XEP-0060) acting as a *dead drop* — each operation has its node with the orders published **encrypted** (OpenSSL `Salted__` / AES-256-CBC, base64 payload). Enumerating the nodes and their items gives us the operations map.

```python
# pubsub dispatcher nodes
nodes = await self['xep_0060'].get_nodes('command.murknet.htb')
for n in nodes['disco_items']['items']:
    print('NODE', n[1])
    items = await self['xep_0060'].get_items('command.murknet.htb', n[1])
    for it in items['pubsub']['items']:
        print('  ', it['id'], it['payload'].text[:60], '...')   # encrypted base64
```

Three operations appear:

- `op_sparkling` → crypto-asset theft (the **1st** operation)
- `op_snatch` → Watson's kidnapping
- `op_dominance` → *"next operation"*

**The core trap.** In a DM, *rattlesnake* hands swissclock the rotated key: `The new key is SHALLOWBLUE`. It's tempting to use it for everything — but **SHALLOWBLUE does not decrypt the already-published commands** of `op_sparkling`/`op_snatch`, because those items **predate** the rotation. The *old* key they were encrypted with **is not in the XMPP**: it must be recovered from the leaked decryptor (the OSINT pivot in step 5). Mental rule: *if the new key yields garbage, the message is pre-rotation.*

Meanwhile the operation rooms assign roles and objectives. In `op_snatch`, the *colonel* assigns the kidnapping logistics:

```
# op_snatch room — role assignment (colonel)
"Dynamite handles transport. Spur handles custody after delivery"
dynamite: "I'm starting the operation now"
```

Whoever executes Watson's grab/transport is **dynamite** (Spur only handles custody *after* delivery).

> **Q6 — Nickname of the affiliate who kidnapped Watson:** `dynamite`

And in the private `op_dominance` room, *doctor*'s briefing names the final operation and its objective:

```
# private op_dominance room — doctor's briefing
"The next operation is unlike anything we've handled before…
 Our objective has a name: DIOGENES"
```

> **Q8 — Last operation planned and its objective:** `Dominance,DIOGENES`

#### 5. The OSINT pivot — "nothing is ever truly deleted once enough eyes have seen it"

**Why.** The published commands are encrypted with a key that doesn't live in the chat. The `op_sparkling` room stores the cell's reaction to an external threat-intel report attributing the **BalanceRAT** malware to them. *rattlesnake* (alias **Porlock**) brags about deleting the blog — *"I personally nuked it. It's gone. try opening it now"* — and *doctor* corrects him with the line that is the challenge's **literal hint**: *"nothing is ever truly deleted once enough eyes have seen it"*. *timothy* pastes the URL, host down on purpose:

```
http://security.billblog.co.uk/threat/BalanceRAT-analysis-and-attribution
```

The real host is dead, but the copy lives in the **Wayback Machine**. We query the **CDX** API to list snapshots and discover associated resources (a giveaway image and the script):

```bash
# list of captures and resources under that host
curl -s "http://web.archive.org/cdx/search/cdx?url=security.billblog.co.uk*&output=text&collapse=urlkey"
```

```
20260805 .../threat/BalanceRAT-analysis-and-attribution/                200
20260805 .../threat/BalanceRAT-analysis-and-attribution/porlock.png     200
20260805 .../threat/BalanceRAT-analysis-and-attribution/decrypt_command.sh  200
```

Recover the article and its resources through the Wayback proxy. The `id_` suffix serves the **raw** object, without archive.org's navigation bar:

```bash
BASE="https://web.archive.org/web/20260805000000id_/http://security.billblog.co.uk/threat/BalanceRAT-analysis-and-attribution"
curl -s "$BASE/"                 -o article.html
curl -s "$BASE/porlock.png"      -o porlock.png
curl -s "$BASE/decrypt_command.sh" -o decrypt_command.sh
```

The article (*"Ghost Balance"*) maps the online identities of the alias **Porlock** (= rattlesnake), including his forum account, and attaches the **full decryptor**. The member's social account is the answer to **Q4**.

> **Q4 — URL of an APT member's social account:** `https://stonedforums.htb/@porlock`

The `decrypt_command.sh` recovered from the archived blog reveals **the old key** and, above all, the **exact** OpenSSL parameters:

```bash
#!/usr/bin/env bash
KEY='BLACKFENLOTTE'                # OLD key (pre-rotation)
printf '%s' "$1" | base64 -d |
  openssl enc -d -aes-256-cbc -pbkdf2 -iter 120000 -md sha256 -pass "pass:${KEY}"
```

Each operation uses **its own key** with the same method: **op_sparkling → BLACKFENLOTTE**, **op_snatch → SHALLOWBLUE** (the rotated one). The detail that broke manual decryption before we had the script: `-pbkdf2 -iter 120000 -md sha256` was missing. Without that identical key derivation, OpenSSL produces garbage even with the correct passphrase.

#### 6. Decryption — the orders in the clear

**Why.** With the exact method and both keys, we can turn each base64 pubsub payload into plaintext. First verify the `Salted__` header (confirming it's an `openssl enc` blob with a salt, not something else):

```bash
# 1) inspection: the first 8 bytes must be "Salted__"
echo -n "$PAYLOAD_B64" | base64 -d | head -c 16 | xxd
# 00000000: 5361 6c74 6564 5f5f ....  Salted__....

# 2) decrypt op_sparkling with the OLD key
echo -n "$PAYLOAD_B64" | base64 -d \
  | openssl enc -d -aes-256-cbc -pbkdf2 -iter 120000 -md sha256 -pass pass:BLACKFENLOTTE
```

**BLACKFENLOTTE** decrypts `op_sparkling` (crypto-asset theft):

```
cmd-02 Evilginx server: 185.203.11.109
cmd-03 BTC: 1BfQc4twbZrUSrtKdwW8TtSN6o1SUezWkX · 1BcanTJp… · 1BHoNZGG…
cmd-04 XMR Address: 429x3WVq1ucARGXx6NEwL4Sg4iowfW5ZWMAqEDErLxrWdg4ffkonB5tNxg85BKGjDqDQRfBERANhgf6DnGjjFyDR5L7uwye
cmd-05 Bank creds -> https://submit-creds.murknet.htb:9099
cmd-06 New C2 (BalanceRAT): 34.54.165.186
```

The Monero wallet in `cmd-04` is the one from the **first** operation.

> **Q5 — XMR wallet used in the first operation:** `429x3WVq1ucARGXx6NEwL4Sg4iowfW5ZWMAqEDErLxrWdg4ffkonB5tNxg85BKGjDqDQRfBERANhgf6DnGjjFyDR5L7uwye`

**SHALLOWBLUE** (same line, only changing `-pass pass:SHALLOWBLUE`) decrypts `op_snatch` (Watson's kidnapping):

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

The sequence narrates the operation minute by minute: they tail Watson from Pembridge Square along Bayswater Road; the **grab happens at Victoria Station** (`cmd-05`, *"He must not reach the tracks. Act NOW"*); he is then **moved** to the **Silvertown** hideout (`cmd-06`/`cmd-08`, container 75JM77), which is exactly where the story PDF places the recovered objects. The question asks **where he was kidnapped**, not where he was held.

> **Q7 — Where Watson was kidnapped:** `Victoria Station` (capture ≠ captivity)

### Timeline

| Phase | Investigation milestone | Artifact / technique |
|-------|-------------------------|----------------------|
| T0 | Laptop seized in Silvertown; only a surviving XMPP client | story PDF |
| T1 | `nmap` → Prosody stack (5222/5269/5281 + nginx 443) | port recon |
| T2 | Self-signed cert SANs → 4 hostnames (**Q1**) | `openssl s_client` / `x509` |
| T3 | IBR on → burner account via `slixmpp`; `disco#items` → 4 channels (**Q2**) | XEP-0077 / XEP-0030 |
| T4 | Rooms' MAM → PDFs on `upload`; `exiftool` leaks email+alias | XEP-0313 / XEP-0363 / metadata |
| T5 | Themed password pasted in `#infra` → login as swissclock (**Q3**) | credential reuse/leak |
| T6 | Pubsub `command.*` → 3 encrypted operations; DM hands over SHALLOWBLUE | XEP-0060 |
| T7 | Roles in `op_snatch` → **dynamite** (**Q6**); `op_dominance` briefing → **DIOGENES** (**Q8**) | MUC reading |
| T8 | Hint *"nothing is ever truly deleted"* → CDX/Wayback recovers the blog | archive OSINT |
| T9 | Archived blog → account **@porlock** (**Q4**) + `decrypt_command.sh` (BLACKFENLOTTE, `-iter 120000`) | Wayback + script analysis |
| T10 | Decryption: `op_sparkling` → XMR wallet (**Q5**); `op_snatch` → **Victoria Station** (**Q7**) | `openssl enc -d` |

### IOCs

| Type | Indicator | Context |
|------|-----------|---------|
| Domain | `murknet.htb`, `groups.murknet.htb`, `command.murknet.htb`, `upload.murknet.htb` | Cell's XMPP/Prosody infra (cert SANs) |
| Domain/port | `submit-creds.murknet.htb:9099` | Stolen banking credentials collector (`op_sparkling` cmd-05) |
| Domain | `security.billblog.co.uk` | Deleted threat-intel blog; recoverable in Wayback |
| Domain | `stonedforums.htb/@porlock` | Forum account of alias Porlock (= rattlesnake) |
| IPv4 | `185.203.11.109` | **Evilginx** server (AiTM phishing) — `op_sparkling` cmd-02 |
| IPv4 | `34.54.165.186` | New **BalanceRAT** C2 — `op_sparkling` cmd-06 |
| BTC wallet | `1BfQc4twbZrUSrtKdwW8TtSN6o1SUezWkX`, `1BcanTJp…`, `1BHoNZGG…` | Crypto theft destination |
| XMR wallet | `429x3WVq1ucARGXx6NEwL4Sg4iowfW5ZWMAqEDErLxrWdg4ffkonB5tNxg85BKGjDqDQRfBERANhgf6DnGjjFyDR5L7uwye` | Monero wallet of the 1st operation |
| Malware | `BalanceRAT` | RAT attributed to the cell in the "Ghost Balance" report |
| Crypto key | `BLACKFENLOTTE` (op_sparkling), `SHALLOWBLUE` (op_snatch, rotated) | AES-256-CBC / PBKDF2 iter 120000 |
| Credential | `zytglogge88@murknet.htb:TickTock24!` (alias swissclock) | Compromised cell account |
| Alias | swissclock, rattlesnake/Porlock, doctor, colonel, dynamite, spur, timothy | Cell members |
| Vehicle | Red Ford Fiesta, plate `WT609DXT` | Watson's car (`op_snatch`) |
| Geo | `51°30'17.6"N, 0°02'05.1"E` — Silvertown; Container `75JM77`, watchword `Chaos Is Order` | Hideout/captivity |

### MITRE ATT&CK mapping

Adversary TTPs observed while reconstructing the operation:

| Tactic | Technique | Evidence in the challenge |
|--------|-----------|---------------------------|
| Resource Development | **T1583.001** Acquire Infrastructure: Domains | `murknet.htb` + own subdomains |
| Resource Development | **T1587.001** Develop Capabilities: Malware | BalanceRAT |
| Resource Development | **T1585.001** Establish Accounts: Social Media | `@porlock` on stonedforums.htb |
| Command and Control | **T1071.001** Application Layer Protocol: Web/Messaging | XMPP (Prosody) as command channel |
| Command and Control | **T1102** Web Service (dead drop) | XEP-0060 pubsub as order mailbox |
| Command and Control | **T1573.001** Encrypted Channel: Symmetric Cryptography | orders in AES-256-CBC / PBKDF2 |
| Command and Control | **T1573.002** + key rotation | BLACKFENLOTTE → SHALLOWBLUE rotation |
| Credential Access | **T1557** Adversary-in-the-Middle | **Evilginx** server (185.203.11.109) |
| Collection / Initial Access | **T1566** Phishing / **T1598** Phishing for Information | banking credential theft → `submit-creds:9099` |
| Impact | **T1657** Financial Theft | crypto-asset theft (op_sparkling), BTC/XMR wallets |
| Defense Evasion | **T1070** Indicator Removal | *"I personally nuked it"* — deletion of the attribution blog |
| — (physical world) | Watson's kidnapping (op_snatch) | out of ATT&CK scope; included for narrative context |

### Detection and remediation

**For the XMPP server operator (the APT's OPSEC lessons, applicable to a defender):**

- **Disable in-band registration** in Prosody (`allow_registration = false`) or require admin approval (`mod_register_web`). Open IBR enabled the burner and all the enumeration.
- **Proper CA certificates**, not self-signed: the self-signed cert added no security and its SANs leaked the full deployment map. At minimum, don't list every sensitive vhost in a single public cert.
- **Minimal MAM retention**, off by default in sensitive rooms: the full archive let us reconstruct months of coordination. Purge and cap `max_archive_query_results`.
- **Credential hygiene:** never paste batches of "temporary passwords" into a channel (`#infra`), don't use themed/guessable passwords (`TickTock24!` ↔ swissclock), and rotate for real by revoking affected accounts.
- **Metadata scrubbing** before uploading documents: `exiftool -all= guide.pdf` would have avoided leaking `Author`/`Creator`. An upload pipeline should normalize metadata.
- **Encryption at rest after rotation:** rotating the key (SHALLOWBLUE) without **re-encrypting the old items** left the previous commands decryptable with the old, OSINT-recoverable key. On rotation, re-encrypt or delete the history.
- **Deletion isn't deletion:** a downed host stays alive in the Wayback Machine / caches. For your own leaked infra, request exclusion from the archive *and* assume the copy already circulates.

**For the detection team (blue team) watching a similar network:**

- Alert on **XMPP c2s/s2s** (5222/5269/5281) to non-corporate destinations, and on **federated s2s** with unknown domains.
- Inspect **pubsub/MUC** payloads for **base64 blobs with a `Salted__` header** (`U2FsdGVk` in base64): a strong indicator of commands encrypted with `openssl enc`.
- Correlate the **network IOCs** (Evilginx `185.203.11.109`, C2 `34.54.165.186`, `submit-creds.murknet.htb:9099`) against proxy/DNS/firewall logs.
- Watch known BTC/XMR **wallets** in intel feeds and monitor for the creation of **forum/social accounts** tied to the actor's aliases.

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
- **KDF parameters are part of the key:** without identical `-pbkdf2 -iter 120000 -md sha256`, the correct passphrase produces garbage. The archived script didn't just give the key: it gave the *method*.
- **Register and work in the same session:** IBR accounts are purged almost instantly on this Prosody.
- **Metadata = free OSINT:** `exiftool` on an uploaded PDF leaked Author/Creator and unlocked a real account.
- **"Nothing is ever truly deleted":** a deliberately down host was still alive in the Wayback Machine (CDX), which kept the full decryptor and the giveaway image.
- **Capture vs captivity:** Watson is **captured** at Victoria Station and **held** in Silvertown; the question asked for the kidnapping location.

### Series · The Reichenbach Directive

| Sherlock | Title | Link |
|----------|-------|------|
| S01 | Silent Dividend | [../2026-09-15-holmes2026-s01-silent-dividend/](../2026-09-15-holmes2026-s01-silent-dividend/) |
| S02 | Bottle Out | [../2026-09-16-holmes2026-s02-bottle-out/](../2026-09-16-holmes2026-s02-bottle-out/) |
| **S03** | **Whisper Chain — this writeup** | [../2026-09-17-holmes2026-s03-whisper-chain/](../2026-09-17-holmes2026-s03-whisper-chain/) |
| S04 | Paper Ghost | [../2026-09-18-holmes2026-s04-paper-ghost/](../2026-09-18-holmes2026-s04-paper-ghost/) |
| S05 | Poisoned Branch | [../2026-09-19-holmes2026-s05-poisoned-branch/](../2026-09-19-holmes2026-s05-poisoned-branch/) |
| S06 | Silent Passenger | [../2026-09-20-holmes2026-s06-silent-passenger/](../2026-09-20-holmes2026-s06-silent-passenger/) |
| S07 | Iron Feather | [../2026-09-21-holmes2026-s07-iron-feather/](../2026-09-21-holmes2026-s07-iron-feather/) |
| S08 | Borrowed Name | [../2026-09-22-holmes2026-s08-borrowed-name/](../2026-09-22-holmes2026-s08-borrowed-name/) |
| S09 | Last Light | [../2026-09-23-holmes2026-s09-last-light/](../2026-09-23-holmes2026-s09-last-light/) |
