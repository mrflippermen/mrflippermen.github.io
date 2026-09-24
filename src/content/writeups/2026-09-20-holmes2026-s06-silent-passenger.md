---
title: "Holmes CTF 2026 — S06 Silent Passenger"
date: 2026-09-20
description: "Forense de firmware de head-unit Android: del updater privilegiado TWCore a un implante C2 multi-stage que convierte el coche en nodo proxy de salida."
excerpt: "Un system.img de infoentretenimiento oculta una cadena de suministro: TWCore push por MQTT → loader reflexivo com.tw.jar1 → stage DexClassLoader → framework C2 sdk.jar → módulo relay com.miyc.transfer. 20 flags, del APK a las coordenadas del relay aparcado."
platform: "HTB"
difficulty: "Hard"
image: "/images/ctf.svg"
tags:
  - "DFIR"
  - "Firmware"
  - "Android"
  - "Reverse Engineering"
  - "IoT"
  - "Holmes CTF 2026"
---

> **Reto:** Holmes CTF 2026 — Sherlock 06 "Silent Passenger" · Forense de firmware de head-unit de coche. Parte del arco *The Reichenbach Directive*.
>
> **Navegación:** [🇪🇸 Español](#es) · [🇬🇧 English](#en)

<a id="es"></a>

## 🇪🇸 Español

### Escenario

Un vehículo aparcado sirvió como **relay desechable** en la operación. Su unidad de infoentretenimiento (*head unit*, Android Automotive embebido) fue comprometida no por un exploit ruidoso, sino por una **cadena de suministro de software**: un updater legítimo del fabricante empujó una app maliciosa, y ésta descargó stage tras stage hasta plantar un implante que convierte el coche en un **nodo proxy de salida** para el C2.

El reto entrega el firmware ya volcado: una imagen `fw/system.img` (ext4, ~944 MB), varios **blobs** de partición `fw/<uuid>.N`, un `fw/History.txt` (changelog en chino del integrador) y un PDF que solo aporta narrativa. Toda la evidencia está en el firmware. Dificultad: **hard**.

> El reto replica de cerca el caso real documentado por Securelist sobre la **botnet DoFun / head-units** (TWCore/钛马星, `cardoor.cn`, JarService, familia *zhima*, relación con *MoYu*/BADBOX). Los IOCs del writeup coinciden con ese informe.

### Artefacto y herramientas

- **`fw/system.img`** — partición `/system` en ext4. Se explora **sin root ni re-montar los 3 GB**:
  - `debugfs -R "ls -l /system/priv-app" system.img` para navegar.
  - `debugfs -R "dump /system/priv-app/TWCore/TWCore.apk out.apk" system.img` para extraer.
  - Alternativas: `mount -o ro,loop` o `binwalk -e`.
- **`fw/History.txt`** — changelog del integrador (`strings` / lectura directa): confirma el ecosistema chino (钛马星/TWCore, temas "兜风"/DoFun, adb-carnet, ID100).
- **Análisis de APK/DEX:** `jadx`, `apktool`, `dex2jar`, `baksmali` — el núcleo es seguir **reflexión** y **DexClassLoader** stage a stage.
- **Hashing:** `sha256sum` sobre cada objeto extraído/reconstruido.
- **Red/C2:** lectura estática de las cadenas MQTT y los endpoints HTTP (`/api/rsaUpdate`, `/api/init`, `/cpc/api/*`).

### Metodología (paso a paso)

1. **Punto de entrada — el updater privilegiado.** En `/system/priv-app/` aparece `TWCore/TWCore.apk` (钛马星, updater con permisos de sistema). Es el responsable de la entrega no autorizada de aplicaciones. Su hash SHA-256 identifica el APK (flag 1).

2. **Selección de región.** Al decidir su *service region*, TWCore evalúa el locale del dispositivo **junto a** la propiedad Android `ro.com.google.gmsversion` (flag 2). Eso encamina a los coches afectados hacia una infraestructura concreta.

3. **Canal de tasking — MQTT.** TWCore se conecta a `tcp://mqtt.car.cardoor.cn:1883` con credenciales `dofun:dofun666666` (flag 3) y se suscribe al *topic filter* `dofun/car/config/#` (flag 4), por donde llegan las instrucciones de actualización a toda la flota.

4. **App entregada.** El updater instala una app antes ausente: `com.tw.jar1` (flag 5), un **loader reflexivo**.

5. **Entry point reflexivo + canal de campaña.** Dentro de `com.tw.jar1` el punto de entrada reflexivo es `com.c.j.qbh.wa` y el *campaign channel* es `2039` → `com.c.j.qbh.wa:2039` (flag 6). Su descriptor de método DEX (solo tipos de parámetro y retorno) es `(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IIII)V` (flag 17).

6. **Siguiente stage.** De la app entregada se reconstruye el siguiente ejecutable; su SHA-256 es la flag 7. El stage se identifica ante su infraestructura como versión `1.7` (flag 8).

7. **Update request oculto.** El stage reconstruido (`com.c.j`, que usa **DexClassLoader**) genera un update request con el endpoint oculto `/api/rsaUpdate` (flag 9). La respuesta apunta al siguiente objeto por el path *host-independent* `/vr34der34/dex3.68.png` (flag 10) — extensión `.png` falsa que en realidad es un archivo ejecutable, cuyo SHA-256 es la flag 11.

8. **Control stage / framework C2.** Ese objeto (`sdk.jar`, framework C2 `com.a.b.a`) genera como primer *request-target* de configuración `/api/init?configVersion=3.8&rsa=1&channelId=2039` (flag 12) y se registra en `/cpc/api/*`. El servicio de registro le asigna el **UID de implante** `00005bp` (flag 13) y la tupla `product:task:version` = `4532:34337681:1787907664` (flag 14).

9. **Entrega del módulo final.** El framework ejecuta una operación de script `loadlib2` cuyo campo `url` suministra la ubicación del módulo → `loadlib2:url` (flag 15). El módulo final descargado tiene SHA-256 flag 16.

10. **Módulo relay.** El módulo final es `com.miyc.transfer` (proxy HTTP/SOCKS reverso). A su entry point se le pasan cuatro enteros en orden: `9999,7777,8888,20000` (flag 18). Al abrir su canal de comando primario envía el **auth frame** `33000000420000000730303030356270` (flag 19) — nótese el sufijo `30303030356270` = ASCII `00005bp`, el UID del implante.

11. **Uso operativo.** La tarea de proxy reutiliza el vehículo comprometido como salida para una operación *follow-on*. El relay estaba aparcado en las coordenadas `51.4997000,-0.1608000` (flag 20) — Pavilion Road car park, que ata la ventana operativa con el activo aéreo del siguiente escenario (S07 *Iron Feather*).

**Cadena completa:** `TWCore` (updater priv.) → push MQTT (`cardoor.cn`) → `com.tw.jar1` (loader reflexivo, canal 2039) → stage `com.c.j` (DexClassLoader, `/api/rsaUpdate`) → `sdk.jar` (framework C2 `com.a.b.a`, `/cpc/api/*`) → `com.miyc.transfer` (proxy reverso, nodo de salida).

### Respuestas / flags

| # | Pregunta | Respuesta |
|---|---|---|
| 1 | ¿Qué paquete Android privilegiado es responsable de la entrega no autorizada de apps? | `/system/priv-app/TWCore/TWCore.apk:d7569563cd0491e76d28a1c6a9929234ffffcf035194d2288d888dced7aa11c2` |
| 2 | ¿Qué propiedad del sistema Android se evalúa junto al locale para elegir región? | `ro.com.google.gmsversion` |
| 3 | ¿Qué servicio MQTT y credenciales usa TWCore en la región afectada? | `tcp://mqtt.car.cardoor.cn:1883\|dofun:dofun666666` |
| 4 | ¿Qué topic filter MQTT expone las instrucciones de update de la flota? | `dofun/car/config/#` |
| 5 | ¿Qué aplicación antes ausente entregó el updater? | `com.tw.jar1:12:6c2e34b30da42085240ede53ab6107d4` |
| 6 | ¿Qué entry point reflexivo y canal de campaña se recuperan de la app entregada? | `com.c.j.qbh.wa:2039` |
| 7 | SHA-256 del siguiente stage ejecutable reconstruido de la app entregada | `cf5c8c624967775230573a5a552e2e4e2b3653f2362e8c9b66a801e3b251f37c` |
| 8 | ¿Qué versión declara el stage reconstruido ante su infraestructura? | `1.7` |
| 9 | ¿Qué endpoint API se oculta en el update request generado por el stage? | `/api/rsaUpdate` |
| 10 | Path host-independent del siguiente objeto devuelto por el update service | `/vr34der34/dex3.68.png` |
| 11 | SHA-256 del archivo ejecutable recuperado de ese objeto | `79e01a591c81554b57e0baaf877ca0a1a1f86f39d38973faa1580089b675838d` |
| 12 | Primer request-target de configuración generado por el control stage | `/api/init?configVersion=3.8&rsa=1&channelId=2039` |
| 13 | ¿Qué UID asigna al implante el servicio de registro? | `00005bp` |
| 14 | Tupla product:task:version asignada al implante | `4532:34337681:1787907664` |
| 15 | Operación de script que entrega el módulo final + campo con su ubicación | `loadlib2:url` |
| 16 | SHA-256 del módulo final descargado | `906734ebb9a274c5c83a22a4475e27354857d7b5b62a4ab6bb5d8d365692e963` |
| 17 | Descriptor DEX del método entry point invocado por el control stage | `(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IIII)V` |
| 18 | Cuatro enteros pasados al entry point del módulo final (en orden) | `9999,7777,8888,20000` |
| 19 | Auth frame que envía el módulo al abrir su canal de comando primario | `33000000420000000730303030356270` |
| 20 | Coordenadas donde estaba aparcado el relay | `51.4997000,-0.1608000` |

### Lecciones

- **La cadena de suministro es el exploit.** No hay 0-day: un updater OEM firmado y privilegiado (`TWCore`) es el vector. En Android embebido, `/system/priv-app` merece la misma sospecha que un binario en `System32`.
- **DexClassLoader stage a stage.** El patrón defensivo clave: cada stage descarga el siguiente y lo carga reflexivamente, a menudo con extensión falsa (`.png` que es un JAR/DEX). Seguir la cadena requiere reconstruir cada objeto y volver a `jadx`.
- **Los hashes son la evidencia.** Seis flags son SHA-256 de stages/módulos: hay que extraer y hashear cada artefacto reconstruido, no solo leer strings.
- **Correlación entre casos.** El auth frame (`...30303030356270` = `00005bp`) enlaza el módulo relay con el UID del implante, y las coordenadas del relay atan S06 con el activo aéreo de S07.
- **Explorar ext4 sin re-montar.** `debugfs -R "ls/dump"` sobre `system.img` evita montar 3 GB y da acceso de solo lectura suficiente para extraer los APK.

<a id="en"></a>

## 🇬🇧 English

### Scenario

A parked vehicle served as a **disposable relay** in the operation. Its infotainment head unit (embedded Android Automotive) was compromised not by a noisy exploit but by a **software supply chain**: a legitimate OEM updater pushed a malicious app, which then pulled stage after stage until it planted an implant that turns the car into an **egress proxy node** for the C2.

The challenge ships the dumped firmware: an `fw/system.img` (ext4, ~944 MB), several partition **blobs** `fw/<uuid>.N`, an `fw/History.txt` (the integrator's Chinese changelog) and a PDF that only carries narrative. All the evidence lives in the firmware. Difficulty: **hard**.

> The challenge closely replicates the real Securelist case on the **DoFun / head-unit botnet** (TWCore/钛马星, `cardoor.cn`, JarService, the *zhima* family, links to *MoYu*/BADBOX). The writeup's IOCs match that report.

### Artifact and tools

- **`fw/system.img`** — the `/system` ext4 partition. Explored **without root and without re-mounting 3 GB**:
  - `debugfs -R "ls -l /system/priv-app" system.img` to navigate.
  - `debugfs -R "dump /system/priv-app/TWCore/TWCore.apk out.apk" system.img` to extract.
  - Alternatives: `mount -o ro,loop` or `binwalk -e`.
- **`fw/History.txt`** — the integrator changelog (`strings` / direct read): confirms the Chinese ecosystem (钛马星/TWCore, "兜风"/DoFun themes, adb-carnet, ID100).
- **APK/DEX analysis:** `jadx`, `apktool`, `dex2jar`, `baksmali` — the core work is following **reflection** and **DexClassLoader** stage by stage.
- **Hashing:** `sha256sum` on every extracted/reconstructed object.
- **Network/C2:** static reading of the MQTT strings and HTTP endpoints (`/api/rsaUpdate`, `/api/init`, `/cpc/api/*`).

### Methodology (step by step)

1. **Entry point — the privileged updater.** Under `/system/priv-app/` sits `TWCore/TWCore.apk` (钛马星, a system-privileged updater). It is responsible for the unauthorized app delivery; its SHA-256 identifies the APK (flag 1).

2. **Region selection.** When choosing its *service region*, TWCore evaluates the device locale **alongside** the Android property `ro.com.google.gmsversion` (flag 2), routing affected cars to a specific infrastructure.

3. **Tasking channel — MQTT.** TWCore connects to `tcp://mqtt.car.cardoor.cn:1883` with credentials `dofun:dofun666666` (flag 3) and subscribes to the topic filter `dofun/car/config/#` (flag 4), through which fleet-wide update instructions arrive.

4. **Delivered app.** The updater installs a previously absent app: `com.tw.jar1` (flag 5), a **reflective loader**.

5. **Reflective entry point + campaign channel.** Inside `com.tw.jar1` the reflective entry point is `com.c.j.qbh.wa` and the campaign channel is `2039` → `com.c.j.qbh.wa:2039` (flag 6). Its DEX method descriptor (parameter and return types only) is `(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IIII)V` (flag 17).

6. **Next stage.** The next executable is reconstructed from the delivered app; its SHA-256 is flag 7. The stage identifies itself to its infrastructure as version `1.7` (flag 8).

7. **Concealed update request.** The reconstructed stage (`com.c.j`, using **DexClassLoader**) generates an update request with the concealed endpoint `/api/rsaUpdate` (flag 9). The response points to the next object via the host-independent path `/vr34der34/dex3.68.png` (flag 10) — a fake `.png` extension that is actually an executable archive, whose SHA-256 is flag 11.

8. **Control stage / C2 framework.** That object (`sdk.jar`, C2 framework `com.a.b.a`) generates as its first configuration request-target `/api/init?configVersion=3.8&rsa=1&channelId=2039` (flag 12) and registers at `/cpc/api/*`. The registration service assigns the **implant UID** `00005bp` (flag 13) and the `product:task:version` tuple `4532:34337681:1787907664` (flag 14).

9. **Final-module delivery.** The framework runs a `loadlib2` script operation whose `url` field supplies the module location → `loadlib2:url` (flag 15). The downloaded final module has SHA-256 flag 16.

10. **Relay module.** The final module is `com.miyc.transfer` (a reverse HTTP/SOCKS proxy). Its entry point is invoked with four integers in order: `9999,7777,8888,20000` (flag 18). When opening its primary command channel it sends the **auth frame** `33000000420000000730303030356270` (flag 19) — note the suffix `30303030356270` = ASCII `00005bp`, the implant UID.

11. **Operational use.** The proxy task repurposes the compromised vehicle as egress for a follow-on operation. The relay was parked at coordinates `51.4997000,-0.1608000` (flag 20) — Pavilion Road car park, tying the operational window to the aerial asset of the next scenario (S07 *Iron Feather*).

**Full chain:** `TWCore` (priv. updater) → MQTT push (`cardoor.cn`) → `com.tw.jar1` (reflective loader, channel 2039) → stage `com.c.j` (DexClassLoader, `/api/rsaUpdate`) → `sdk.jar` (C2 framework `com.a.b.a`, `/cpc/api/*`) → `com.miyc.transfer` (reverse proxy, egress node).

### Answers / flags

| # | Question | Answer |
|---|---|---|
| 1 | Which privileged Android package is responsible for the unauthorized application delivery? | `/system/priv-app/TWCore/TWCore.apk:d7569563cd0491e76d28a1c6a9929234ffffcf035194d2288d888dced7aa11c2` |
| 2 | Which Android system property is evaluated alongside the device locale when TWCore selects its service region? | `ro.com.google.gmsversion` |
| 3 | Which MQTT service and credentials does TWCore use for the affected service region? | `tcp://mqtt.car.cardoor.cn:1883\|dofun:dofun666666` |
| 4 | Which MQTT topic filter exposes update instructions shared with the affected fleet? | `dofun/car/config/#` |
| 5 | Which previously absent application was delivered through the updater? | `com.tw.jar1:12:6c2e34b30da42085240ede53ab6107d4` |
| 6 | What reflective entry point and campaign channel are recovered from the delivered application? | `com.c.j.qbh.wa:2039` |
| 7 | What is the SHA-256 of the next executable stage reconstructed from the delivered application? | `cf5c8c624967775230573a5a552e2e4e2b3653f2362e8c9b66a801e3b251f37c` |
| 8 | Which version does the reconstructed stage identify itself as when contacting its update infrastructure? | `1.7` |
| 9 | Which API endpoint is concealed in the reconstructed stage's generated update request? | `/api/rsaUpdate` |
| 10 | What host-independent path identifies the next object returned by the update service? | `/vr34der34/dex3.68.png` |
| 11 | What is the SHA-256 of the executable archive recovered from that object? | `79e01a591c81554b57e0baaf877ca0a1a1f86f39d38973faa1580089b675838d` |
| 12 | What is the first configuration request-target generated by the recovered control stage? | `/api/init?configVersion=3.8&rsa=1&channelId=2039` |
| 13 | Which UID is assigned to the implant by the registration service? | `00005bp` |
| 14 | Which product, task, and version tuple is assigned to the implant? | `4532:34337681:1787907664` |
| 15 | Which script operation delivers the final module, and which field supplies its location? | `loadlib2:url` |
| 16 | What is the SHA-256 of the final downloaded module? | `906734ebb9a274c5c83a22a4475e27354857d7b5b62a4ab6bb5d8d365692e963` |
| 17 | What is the DEX method descriptor (parameter and return types only) of the module entry point invoked by the control stage? | `(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;IIII)V` |
| 18 | Which four integer values are passed to the final module entry point in invocation order? | `9999,7777,8888,20000` |
| 19 | What authentication frame does the module send when opening its primary command channel? | `33000000420000000730303030356270` |
| 20 | At what coordinates was the relay parked? | `51.4997000,-0.1608000` |

### Lessons

- **The supply chain is the exploit.** No 0-day: a signed, privileged OEM updater (`TWCore`) is the vector. In embedded Android, `/system/priv-app` deserves the same suspicion as a binary in `System32`.
- **DexClassLoader, stage by stage.** The key defensive pattern: each stage downloads the next and loads it reflectively, often with a fake extension (a `.png` that is really a JAR/DEX). Following the chain means reconstructing each object and re-running `jadx`.
- **Hashes are the evidence.** Six flags are SHA-256 of stages/modules: you must extract and hash each reconstructed artifact, not just read strings.
- **Cross-case correlation.** The auth frame (`...30303030356270` = `00005bp`) links the relay module to the implant UID, and the relay coordinates tie S06 to the aerial asset of S07.
- **Explore ext4 without re-mounting.** `debugfs -R "ls/dump"` on `system.img` avoids mounting 3 GB and gives enough read-only access to extract the APKs.
