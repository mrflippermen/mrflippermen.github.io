---
title: "Certified Active Directory Red Team Specialist (AD-RTS)"
date: 2026-02-01
level: "Intermediate"
platform: "Cyberwarfare Labs"
description: "30-Day intensive campaign simulating enterprise AD network exploitation, ESXi attacks, and advanced persistence techniques"
image: "/images/about/cwl-ad-rts.png"
---

<div align="center">

![Author](https://img.shields.io/badge/Author-Flippermen-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Cyberwarfare_Labs-darkred?style=for-the-badge)
![Cert](https://img.shields.io/badge/Cert-AD--RTS-red?style=for-the-badge)
![Level](https://img.shields.io/badge/Level-Intermediate-yellow?style=for-the-badge)
![Team](https://img.shields.io/badge/Team-CyberFlippers-blue?style=for-the-badge)

**Flippermen | CyberFlippers | UDLA-Cyber**

</div>

---

| Campo | Valor |
|-------|-------|
| Certificacion | Active Directory Red Team Specialist |
| Plataforma | Cyberwarfare Labs |
| Duracion | 30 dias de acceso al lab |
| Enfoque | Enterprise AD, ESXi, AD CS, Exchange |

## Sobre AD-RTS

**AD-RTS (Active Directory Red Team Specialist)** es una certificacion practica ofrecida por Cyberwarfare Labs, orientada a simular campanas ofensivas reales contra infraestructuras empresariales basadas en Active Directory. El lab expone un entorno corporativo completo con multiples componentes interconectados: controladores de dominio, servidores de certificados (AD CS), hipervisores VMware ESXi y servidores de correo Exchange.

A diferencia de laboratorios que presentan maquinas aisladas, AD-RTS obliga al operador a encadenar vectores de ataque a traves de toda la infraestructura, desde el acceso inicial hasta el compromiso total del dominio y la exfiltracion de datos, operando bajo las restricciones de un adversario real en un entorno con multiples capas de defensa.

**Vectores cubiertos:**
- **Active Directory Misconfiguration Abuse** — ACLs debiles, delegacion sin restricciones, relaciones de confianza mal configuradas
- **AD Certificate Services (AD CS)** — Plantillas de certificados vulnerables (ESC1-ESC8), enrollment abuse, NTLM relay a servicios de certificados
- **Virtualization & Hypervisor Attacks** — Compromiso de VMware ESXi, extraccion de VMs, persistencia a nivel de hipervisor
- **Exchange Server Exploitation** — ProxyLogon/ProxyShell style vectors, abuso de permisos de buzones para movimiento lateral

---

## 🔒 Confidential Assessment Profile

**Target Environment**: `Enterprise Grade AD Network`
**Simulated Threat**: `Insider Threat / APT`

---

## ⚔️ Tactical Competencies

### 1. Advanced AD Exploitation
*   **Misconfiguration Abuse**: Explotacion de ACLs debiles, Unconstrained Delegation y configuraciones erroneas en AD CS (Certificate Services).
*   **Kerberos Attacks**: Ejecucion de ataques Kerberoasting, AS-REP Roasting y manipulacion de tickets (Golden/Silver).
*   **AD CS Abuse**: Explotacion de plantillas de certificados vulnerables para obtener credenciales de cuentas privilegiadas, incluyendo ataques de tipo ESC1 (enrollment con SAN arbitrario) y relay NTLM contra el servicio de enrollment HTTP.
*   **Trust Exploitation**: Enumeracion y abuso de relaciones de confianza entre dominios para escalada de privilegios cross-domain.

### 2. Infrastructure & Virtualization
*   **ESXi & Hypervisor Attacks**: Compromiso de entornos de virtualizacion VMware ESXi para movimiento lateral y persistencia. Extraccion de discos virtuales (VMDK) para offline credential dumping.
*   **Exchange Exploitation**: Vectores de ataque contra servidores de correo corporativo, incluyendo abuso de permisos de buzon, SSRF interna y escalada de privilegios a traves de EWS (Exchange Web Services).
*   **Certificate Authority Compromise**: Compromiso de la CA raiz para emision de certificados arbitrarios y persistencia a largo plazo en el dominio.

### 3. Lateral Movement & Persistence
*   **Enterprise Attack Chains**: Movimiento lateral a traves de la red simulando tacticas de actores de amenazas avanzados (MITRE ATT&CK T1021, T1550).
*   **Data Exfiltration**: Tecnicas de extraccion de informacion critica sin levantar alertas, incluyendo canales encubiertos y staging de datos.
*   **Persistence Mechanisms**: Golden Tickets, Silver Tickets, certificados persistentes via AD CS, y modificacion de AdminSDHolder para acceso duradero.

## Metodologia Aplicada

### 1. Enumeracion de AD y Rutas de Ataque

```bash
# Enumeracion inicial con BloodHound
bloodhound-python -u <user> -p '<pass>' -d <domain> -c All -ns <DC_IP>

# Enumeracion de AD CS con Certipy
certipy find -u <user>@<domain> -p '<pass>' -dc-ip <DC_IP> -stdout

# Busqueda de plantillas vulnerables
certipy find -vulnerable -u <user>@<domain> -p '<pass>' -dc-ip <DC_IP>

# Enumeracion de delegacion
Get-ADComputer -Filter {TrustedForDelegation -eq $true}
Get-ADComputer -Filter {msds-AllowedToDelegateTo -ne "$null"}
```

### 2. Explotacion de AD CS

```bash
# Solicitar certificado con SAN arbitrario (ESC1)
certipy req -u <user>@<domain> -p '<pass>' -ca <CA_NAME> \
    -template <VULN_TEMPLATE> -upn administrator@<domain>

# Autenticacion con certificado obtenido
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

### 3. Compromiso de ESXi

```bash
# Enumeracion de hosts ESXi
nmap -sV -p 443,902,5989 <ESXi_RANGE>

# Acceso via credenciales obtenidas del dominio
ssh root@<ESXi_IP>
vim-cmd vmsvc/getallvms
```

### 4. Extraccion de Secretos del Dominio

```bash
# DCSync con credenciales de Domain Admin
secretsdump.py <domain>/<admin>:'<pass>'@<DC_IP> -just-dc

# Pass-the-Hash para acceso lateral
psexec.py -hashes :<NTLM_HASH> <domain>/administrator@<TARGET>
```

## Herramientas Utilizadas

| Herramienta | Proposito |
|-------------|-----------|
| `BloodHound / SharpHound` | Mapeo de rutas de ataque en AD |
| `Certipy` | Enumeracion y explotacion de AD CS |
| `Impacket (secretsdump, psexec, ntlmrelayx)` | Extraccion de credenciales y movimiento lateral |
| `Rubeus` | Ataques Kerberos (Kerberoasting, ticket forging) |
| `Mimikatz` | Extraccion de credenciales en memoria |
| `CrackMapExec / NetExec` | Enumeracion y ejecucion remota masiva |
| `Chisel / Ligolo-ng` | Pivoting y tunneling a traves de subredes |
| `PowerView` | Enumeracion avanzada de AD desde PowerShell |

## Key Takeaways

1. **AD CS es un vector critico subestimado** — Las plantillas de certificados mal configuradas proporcionan rutas directas hacia Domain Admin sin necesidad de exploits tradicionales.
2. **La virtualizacion amplia la superficie de ataque** — Un hipervisor ESXi comprometido da acceso a todos los discos virtuales, permitiendo credential dumping offline.
3. **La persistencia via certificados es extremadamente duradera** — Un certificado emitido por la CA interna puede ser valido durante anos, sobreviviendo a cambios de contrasena y rotaciones de credenciales.
4. **Los ataques de cadena son la norma en entornos reales** — El valor de AD-RTS reside en encadenar AD + ESXi + Exchange + AD CS, tal como lo haria un APT real.

---

## 🏆 Operational Impact

Haber completado **AD-RTS** certifica la capacidad de identificar y explotar vulnerabilidades criticas en infraestructuras modernas, demostrando un entendimiento profundo de la seguridad ofensiva en entornos hibridos y de alta complejidad. La certificacion valida competencia en ataques avanzados contra Active Directory, servicios de certificados, hipervisores y servidores de correo corporativo — vectores que representan las rutas de compromiso mas frecuentes en incidentes reales contra organizaciones empresariales.

---

<div align="center">

**Flippermen**
*CyberFlippers | UDLA-Cyber*

</div>
