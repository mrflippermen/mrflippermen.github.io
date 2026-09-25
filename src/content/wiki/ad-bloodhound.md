---
title: "BloodHound Cheat Sheet"
category: "AD"
description: "Mapeo de relaciones de confianza y caminos de ataque en Active Directory."
image: "/images/wiki/8.png"
---

# BloodHound: Mapeo de Attack Paths en Active Directory

**BloodHound** utiliza teoria de grafos para revelar las relaciones ocultas y, a menudo, no deseadas dentro de un entorno de Active Directory. Puede identificar rutas de ataque complejas que serian imposibles de ver manualmente. La herramienta modela el dominio como un grafo dirigido donde los **nodos** representan objetos de AD (usuarios, grupos, equipos, GPOs, OUs, dominios) y las **aristas** (edges) representan relaciones o permisos entre ellos (pertenencia a grupo, sesion activa, ACL, confianza de dominio, etc.).

[Repositorio Oficial - BloodHound CE](https://github.com/SpecterOps/BloodHound) | [Documentacion](https://support.bloodhoundenterprise.io/)

---

## Conceptos Fundamentales

### Teoria de Grafos Aplicada a AD

Active Directory es, en esencia, una base de datos de objetos con relaciones complejas entre ellos. BloodHound transforma estas relaciones en un grafo navegable:

| Concepto | En AD | En BloodHound |
|----------|-------|---------------|
| **Nodo** | Usuario, Grupo, Equipo, Dominio, GPO, OU | Entidad representada como circulo en el grafo |
| **Arista (Edge)** | Permiso, pertenencia, sesion, confianza | Flecha dirigida que conecta dos nodos |
| **Camino (Path)** | Cadena de relaciones explotables | Secuencia de aristas desde un nodo origen a un nodo objetivo |
| **Shortest Path** | Ruta de ataque mas directa | Camino con menor numero de saltos |

### Tipos de Nodos

| Tipo | Descripcion |
|------|-------------|
| `User` | Cuenta de usuario del dominio |
| `Group` | Grupo de seguridad o distribucion |
| `Computer` | Equipo unido al dominio |
| `Domain` | Dominio de AD |
| `GPO` | Group Policy Object |
| `OU` | Organizational Unit |
| `Container` | Contenedor de AD (CN=Users, CN=Computers, etc.) |

---

## Instalacion

### BloodHound Community Edition (CE) con Docker

BloodHound CE es la version moderna mantenida por SpecterOps. Usa una API REST, base de datos PostgreSQL y un frontend web.

```bash
# Clonar el repositorio
git clone https://github.com/SpecterOps/BloodHound.git
cd BloodHound

# Levantar con Docker Compose
docker compose up -d

# Obtener la contrasena inicial del admin
docker compose logs | grep "Initial Password Set To:"
```

Acceder a `http://localhost:8080` con usuario `admin` y la contrasena del log. Se recomienda cambiarla inmediatamente.

**Requisitos**: Docker Engine >= 20.10 y Docker Compose v2.

### BloodHound Legacy (Neo4j)

La version clasica usa Neo4j como base de datos de grafos y una aplicacion Electron como frontend.

```bash
# Instalar Neo4j (Debian/Ubuntu)
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable latest' | sudo tee /etc/apt/sources.list.d/neo4j.list
sudo apt update && sudo apt install neo4j

# Iniciar Neo4j (por defecto en puerto 7474/7687)
sudo systemctl start neo4j

# Descargar BloodHound GUI desde releases
# https://github.com/BloodHoundAD/BloodHound/releases
```

Credenciales por defecto de Neo4j: `neo4j:neo4j` (pide cambio en primer login).

---

## Recoleccion de Datos (Ingestion)

Para que BloodHound funcione, primero debes recolectar informacion del dominio usando un **ingestor**. Existen tres recolectores principales.

### SharpHound (Desde Windows)

Es el recolector oficial en C#/.NET. Se puede ejecutar como ejecutable standalone o como script de PowerShell importado en memoria.

```powershell
# Version EXE - recoleccion completa
.\SharpHound.exe --CollectionMethods All --Domain corp.local --ZipFileName loot.zip

# Version PowerShell
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethods All -OutputDirectory C:\Temp

# Especificar DC concreto
.\SharpHound.exe --CollectionMethods All --DomainController dc01.corp.local

# Excluir DCs de la enumeracion de sesiones (menos ruido)
.\SharpHound.exe --CollectionMethods All --ExcludeDomainControllers

# Loop de sesiones cada 10 minutos durante 2 horas
.\SharpHound.exe --CollectionMethods Session --Loop --LoopDuration 02:00:00 --LoopInterval 00:10:00
```

#### Metodos de Recoleccion de SharpHound

| Metodo | Descripcion | Protocolo / Ruido |
|--------|-------------|-------------------|
| `All` | Ejecuta todos los metodos (equivale a `Default` + `GPOLocalGroup` + `ObjectProps` + `ACL` + `SPNTargets`) | Alto |
| `Default` | `Group` + `LocalAdmin` + `Session` + `Trusts` + `ACL` + `ObjectProps` + `Container` | Medio-alto |
| `DCOnly` | Solo consulta al DC via LDAP/ADWS: grupos, ACLs, trusts, propiedades. No toca equipos clientes | Bajo |
| `Session` | Sesiones activas en equipos (NetSessionEnum via SMB/RPC) | Medio (conexion a cada equipo) |
| `LoggedOn` | Usuarios logueados via registry (requiere admin local en el equipo remoto) | Medio (requiere privilegios) |
| `Trusts` | Relaciones de confianza entre dominios y forests | Bajo (solo consulta al DC) |
| `ACL` | Listas de control de acceso (DACLs) de todos los objetos del dominio | Bajo (LDAP al DC) |
| `ObjectProps` | Propiedades de objetos: LastLogon, PwdLastSet, etc. | Bajo (LDAP al DC) |
| `Container` | Estructura de OUs/Containers y enlaces de GPO | Bajo (LDAP al DC) |
| `GPOLocalGroup` | Miembros de grupos locales definidos por GPO (Restricted Groups, GPP) | Bajo (LDAP al DC) |
| `DCOM` | Usuarios con acceso DCOM a equipos | Medio (conexion a cada equipo) |
| `RDP` | Usuarios con permiso de RDP a equipos | Medio (conexion a cada equipo) |
| `PSRemote` | Usuarios con acceso a PowerShell Remoting/WinRM | Medio (conexion a cada equipo) |
| `LocalAdmin` | Miembros del grupo Administrators local de cada equipo | Medio (conexion a cada equipo) |
| `SPNTargets` | Cuentas con SPN (potencialmente Kerberoastables) | Bajo (LDAP al DC) |
| `Stealth` | Recoleccion sigilosa: solo consulta DCs, servidores de Exchange y File Servers como fuentes de sesiones | Bajo |

### BloodHound-Python (Desde Linux/Remoto)

Ideal para atacantes que operan desde Linux o cuando no se tiene acceso directo a una maquina Windows unida al dominio. Solo necesita credenciales validas y conectividad de red al DC.

[Repositorio](https://github.com/dirkjanm/BloodHound.py)

```bash
# Instalacion
pip3 install bloodhound

# Recoleccion completa
bloodhound-python -u 'svc_audit' -p 'P@ssw0rd!' -ns 10.10.10.10 -d corp.local -c All

# Usando hash NTLM (pass-the-hash)
bloodhound-python -u 'svc_audit' --hashes aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f -ns 10.10.10.10 -d corp.local -c All

# Solo DCOnly (menos ruido)
bloodhound-python -u 'svc_audit' -p 'P@ssw0rd!' -ns 10.10.10.10 -d corp.local -c DCOnly

# Especificar DC manualmente
bloodhound-python -u 'svc_audit' -p 'P@ssw0rd!' -ns 10.10.10.10 -d corp.local -dc dc01.corp.local -c All

# Recolectar con Kerberos (no enviar password en texto)
bloodhound-python -u 'svc_audit' -p 'P@ssw0rd!' -ns 10.10.10.10 -d corp.local -c All -k

# Guardar en directorio especifico
bloodhound-python -u 'svc_audit' -p 'P@ssw0rd!' -ns 10.10.10.10 -d corp.local -c All --zip -o /tmp/loot/
```

#### Flags Importantes de bloodhound-python

| Flag | Descripcion |
|------|-------------|
| `-u` / `--username` | Usuario del dominio |
| `-p` / `--password` | Contrasena |
| `--hashes` | Hash NTLM (formato LM:NT) para pass-the-hash |
| `-ns` / `--nameserver` | IP del DNS (normalmente el DC) |
| `-d` / `--domain` | Nombre del dominio |
| `-dc` / `--domain-controller` | Hostname del DC (util si el DNS no resuelve) |
| `-c` / `--collectionmethod` | Metodos: `All`, `DCOnly`, `Group`, `LocalAdmin`, `Session`, `Trusts`, `ACL`, `ObjectProps`, `Container`, `DCOM`, `RDP`, `PSRemote`, `LoggedOn` |
| `-k` / `--kerberos` | Autenticacion Kerberos (requiere ccache o ticket) |
| `--zip` | Comprimir salida en ZIP |
| `-o` / `--outputdir` | Directorio de salida |
| `-w` / `--workers` | Numero de workers (por defecto 10) |
| `--dns-tcp` | Forzar DNS sobre TCP |
| `--dns-timeout` | Timeout de consultas DNS |
| `-v` | Modo verbose |

### RustHound (Alternativa en Rust)

[Repositorio](https://github.com/NH-RED-TEAM/RustHound)

Ingestor escrito en Rust, cross-platform. Soporta LDAPS, formato de salida compatible con BloodHound CE y Legacy, y GZIP. Util como alternativa cuando SharpHound es detectado por EDR.

```bash
# Desde Linux
rusthound -u 'svc_audit@corp.local' -p 'P@ssw0rd!' -d corp.local -i 10.10.10.10 --zip

# Con LDAPS
rusthound -u 'svc_audit@corp.local' -p 'P@ssw0rd!' -d corp.local -i 10.10.10.10 --ldaps --zip

# Formato para BloodHound CE
rusthound -u 'svc_audit@corp.local' -p 'P@ssw0rd!' -d corp.local -i 10.10.10.10 --zip --old-bloodhound
```

---

## Analisis en la Interfaz

### Importar Datos

**BloodHound CE**: Navegar a `http://localhost:8080` > File Ingest > subir el ZIP generado.

**BloodHound Legacy**: Arrastrar el ZIP directamente a la ventana de la aplicacion Electron o usar el boton "Upload Data".

### Consultas Predefinidas (Built-in Queries)

BloodHound incluye consultas predefinidas accesibles desde el panel lateral:

| Consulta | Descripcion |
|----------|-------------|
| Find all Domain Admins | Lista todos los miembros del grupo Domain Admins |
| Find Shortest Paths to Domain Admins | Muestra la ruta mas rapida desde cualquier nodo hacia DA |
| Find Principals with DCSync Rights | Usuarios/grupos que pueden ejecutar DCSync |
| List all Kerberoastable Accounts | Usuarios con SPN configurado |
| Find AS-REP Roastable Users | Usuarios con `DONT_REQUIRE_PREAUTH` habilitado |
| Find Computers with Unconstrained Delegation | Equipos con delegacion no restringida |
| Find Computers where Domain Users are Local Admin | Equipos donde `Domain Users` es admin local |
| Shortest Paths to High Value Targets | Rutas a todos los objetivos marcados como high-value |
| Find GPOs that modify local group memberships | GPOs que anadena usuarios a grupos locales |
| Find Users with Foreign Domain Group Membership | Usuarios con pertenencia a grupos de otros dominios |

### Navegacion del Grafo

- **Click en un nodo**: Muestra propiedades (SID, fechas, flags, grupo memberships).
- **Click en una arista**: Explica la relacion y muestra informacion de abuso (abuse info).
- **Click derecho en un nodo**: Opciones para marcarlo como owned, high value, o punto de inicio.
- **Marcar como Owned**: Fundamental para descubrir paths desde nodos que ya controlas.
- **Pathfinding**: Seleccionar nodo origen y destino para buscar caminos.

---

## Aristas Clave (Key Edges)

Cada arista representa un permiso o relacion que puede ser abusada. A continuacion las mas relevantes:

| Edge | Descripcion | Como se Abusa |
|------|-------------|---------------|
| **GenericAll** | Control total sobre el objeto | Cambiar password, modificar atributos, agregar a grupos, escribir SPN para Kerberoasting |
| **GenericWrite** | Escritura de cualquier atributo no protegido | Escribir `msDS-KeyCredentialLink` (Shadow Credentials), escribir `scriptPath`, modificar SPN |
| **WriteDACL** | Permiso para modificar la DACL del objeto | Otorgarse a uno mismo `GenericAll` u otros permisos y luego abusar de ellos |
| **WriteOwner** | Puede cambiar el propietario del objeto | Hacerse propietario (Owner) y luego modificar la DACL para darse permisos |
| **Owns** | Es propietario del objeto | El Owner puede modificar la DACL, equivale a control efectivo |
| **ForceChangePassword** | Puede resetear la password sin conocer la actual | `net user <target> <newpw> /domain` o `Set-ADAccountPassword` |
| **AddMember** | Puede agregar miembros a un grupo | `Add-ADGroupMember` para anadirse a si mismo o a otro usuario controlado |
| **AddSelf** | Puede agregarse a si mismo al grupo | Similar a AddMember pero restringido a la propia cuenta |
| **ReadLAPSPassword** | Puede leer la password de LAPS del equipo | `Get-ADComputer -Properties ms-Mcs-AdmPwd` para obtener la clave de admin local |
| **DCSync** | Derechos de replicacion (DS-Replication-Get-Changes + DS-Replication-Get-Changes-All) | `secretsdump.py` o `mimikatz lsadump::dcsync` para volcar hashes de todo el dominio |
| **AllExtendedRights** | Todos los derechos extendidos sobre el objeto | Incluye ForceChangePassword y ReadLAPSPassword entre otros |
| **GPLink** | Una GPO esta vinculada a una OU/dominio | Modificar la GPO para ejecutar codigo en equipos/usuarios afectados |
| **Contains** | Una OU contiene al objeto | No es directamente abusable pero muestra scope de GPOs |
| **HasSession** | El usuario tiene sesion activa en el equipo | Si eres admin local del equipo, puedes extraer credenciales de la sesion |
| **AdminTo** | Es administrador local del equipo | Ejecucion remota, extraccion de credenciales, movimiento lateral |
| **CanRDP** | Puede conectarse por RDP al equipo | Acceso interactivo al escritorio |
| **CanPSRemote** | Puede usar PowerShell Remoting/WinRM | Ejecucion remota de comandos |
| **ExecuteDCOM** | Puede ejecutar objetos DCOM en el equipo | Ejecucion remota via DCOM (MMC20, ShellWindows, etc.) |
| **AllowedToDelegate** | Delegacion restringida (constrained delegation) configurada | Impersonar usuarios ante el servicio delegado (S4U2Proxy) |
| **AllowedToAct** | Resource-Based Constrained Delegation (RBCD) | Configurar RBCD para impersonar usuarios ante el equipo |
| **SQLAdmin** | Administrador de SQL Server | Ejecucion de comandos via `xp_cmdshell` |

---

## Consultas Cypher Personalizadas

BloodHound usa **Cypher** (lenguaje de consultas de Neo4j) para hacer busquedas avanzadas. En BloodHound CE, estas consultas se ejecutan en la barra de busqueda o via API.

### Shortest Path al Grupo Domain Admins

```cypher
MATCH p=shortestPath((u:User {name:"SVCAUDIT@CORP.LOCAL"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}))
RETURN p
```

### Usuarios Kerberoastables con Path a Domain Admins

```cypher
MATCH (u:User {hasspn:true}),
      (g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}),
      p=shortestPath((u)-[*1..]->(g))
RETURN p
```

### Equipos con Unconstrained Delegation (excluyendo DCs)

```cypher
MATCH (c:Computer {unconstraineddelegation:true})
WHERE NOT c.name CONTAINS "DC"
RETURN c.name, c.operatingsystem
```

### Usuarios con DCSync Rights

```cypher
MATCH p=(u)-[:GetChanges|GetChangesAll*1..]->(d:Domain)
RETURN p
```

### Shortest Path desde Nodos Owned a Domain Admins

```cypher
MATCH p=shortestPath((u {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}))
RETURN p
```

### Encontrar Todos los Admin Locales de un Equipo Especifico

```cypher
MATCH p=(u)-[:AdminTo]->(c:Computer {name:"WS01.CORP.LOCAL"})
RETURN p
```

### Usuarios que Pueden Hacer ForceChangePassword

```cypher
MATCH p=(u:User)-[:ForceChangePassword]->(t:User)
RETURN u.name AS Atacante, t.name AS Victima
```

### Grupos con GenericAll sobre Otros Grupos

```cypher
MATCH p=(g1:Group)-[:GenericAll]->(g2:Group)
RETURN g1.name AS GrupoAtacante, g2.name AS GrupoVictima
```

### Equipos donde Domain Users Tiene Sesion (Hunting)

```cypher
MATCH (c:Computer)-[:HasSession]->(u:User)
WHERE u.name STARTS WITH "ADMIN"
RETURN c.name, u.name
```

### Encontrar AS-REP Roastable Users con Path a High Value

```cypher
MATCH (u:User {dontreqpreauth:true}),
      (h {highvalue:true}),
      p=shortestPath((u)-[*1..]->(h))
RETURN p
```

### Encontrar Cuentas con Constrained Delegation

```cypher
MATCH (c) WHERE c.allowedtodelegate IS NOT NULL
RETURN c.name, c.allowedtodelegate
```

### Usuarios que Nunca Han Cambiado su Password

```cypher
MATCH (u:User)
WHERE u.pwdlastset < (datetime().epochSeconds - 31536000)
  AND u.enabled = true
RETURN u.name, u.pwdlastset
ORDER BY u.pwdlastset ASC
```

---

## BloodHound CE API

BloodHound CE expone una API REST que permite automatizar tareas de importacion, consulta y gestion.

### Autenticacion

```bash
# Crear un token de API desde la interfaz web: Settings > API Tokens > Create Token

# Autenticarse con el token
export BH_TOKEN="<tu-token>"
export BH_URL="http://localhost:8080"
```

### Ejemplos de Uso con curl

```bash
# Listar dominios disponibles
curl -s -H "Authorization: Bearer $BH_TOKEN" "$BH_URL/api/v2/available-domains" | jq

# Ejecutar una consulta Cypher via API
curl -s -X POST -H "Authorization: Bearer $BH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"MATCH (u:User {enabled:true, hasspn:true}) RETURN u.name"}' \
  "$BH_URL/api/v2/graphs/cypher" | jq

# Subir datos de ingestor
curl -s -X POST -H "Authorization: Bearer $BH_TOKEN" \
  -F "file=@loot.zip" \
  "$BH_URL/api/v2/file-upload"

# Marcar un nodo como owned
curl -s -X PUT -H "Authorization: Bearer $BH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"owned":true}' \
  "$BH_URL/api/v2/asset-groups/<object-id>"
```

---

## Camino Tipico de Ataque

1. **Ingreso**: Tienes un usuario raso comprometido (`svc_audit`).
2. **Recoleccion**: Ejecutas SharpHound o bloodhound-python con `-c All`.
3. **Importar**: Subes el ZIP a BloodHound y marcas `svc_audit` como *owned*.
4. **Analizar**: "Shortest Paths from Owned Principals" revela que `svc_audit` tiene `GenericWrite` sobre `SVC_SQL`.
5. **Kerberoasting**: `SVC_SQL` tiene un SPN, asi que modificas su SPN (gracias a GenericWrite) y haces targeted Kerberoasting.
6. **Lateral Movement**: Crackeas el hash de `SVC_SQL`, que resulta ser `AdminTo` sobre `DB-SERVER01`.
7. **Credential Harvesting**: En `DB-SERVER01` hay una sesion de `ADMIN-TI`, miembro del grupo `IT-ADMINS`.
8. **Escalacion**: `IT-ADMINS` tiene `WriteDACL` sobre el grupo `Domain Admins`.
9. **Domain Admin**: Te otorgas `GenericAll` sobre `Domain Admins`, te agregas al grupo y comprometes el dominio.

---

## Consideraciones OPSEC

### Ruido de SharpHound

| Actividad | Nivel de Ruido | Detalle |
|-----------|----------------|---------|
| Consultas LDAP al DC | Bajo | Trafico normal, pero el volumen puede ser anomalo |
| Enumeracion de sesiones (`NetSessionEnum`) | Medio | Conexion SMB/RPC a cada equipo; genera eventos de red |
| Enumeracion de admins locales (`NetLocalGroupGetMembers`) | Medio | Similar a sesiones, conexion a cada equipo |
| Enumeracion de logons (`NetWkstaUserEnum`) | Alto | Requiere privilegios de admin local; intentos fallidos generan logs |

### Recomendaciones para Reducir Deteccion

- **Usar `-c DCOnly`** cuando no se necesitan sesiones ni admins locales: solo consulta LDAP al DC, trafico normal.
- **Evitar `--CollectionMethods All`** en la primera pasada: comenzar con `DCOnly`, luego sesiones selectivas.
- **Usar `--Stealth`**: Solo contacta DCs, Exchange y File Servers como fuentes de sesiones.
- **Loop de sesiones** en lugar de un escaneo masivo: `--Loop --LoopInterval 00:15:00` recoge sesiones incrementalmente.
- **Horario**: Ejecutar durante horario laboral cuando el trafico LDAP/SMB es normal.
- **BloodHound-python con `-w 1`**: Un solo worker para minimizar conexiones simultaneas.
- **Evitar re-escaneos frecuentes**: Guardar los datos y reutilizar; solo reescanear cuando se necesiten sesiones frescas.

### LDAP Queries Sospechosas

SharpHound genera consultas LDAP con filtros caracteristicos que pueden ser detectados:

```
# Filtro tipico de SharpHound para buscar cuentas con SPN
(&(samAccountType=805306368)(servicePrincipalName=*))

# Filtro para buscar equipos con delegacion no restringida
(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288))

# Filtro para buscar relaciones de confianza
(objectClass=trustedDomain)
```

---

## Deteccion

### Eventos de Windows Relevantes

| Event ID | Fuente | Descripcion |
|----------|--------|-------------|
| 4662 | Security | Acceso a objeto de AD (detecta consultas masivas de ACLs) |
| 5145 | Security | Acceso a share de red (detecta NetSessionEnum via IPC$) |
| 4624 (Type 3) | Security | Login de red (conexiones de enumeracion de sesiones) |
| 4661 | Security | Handle solicitado a objeto SAM (enumeracion de grupos locales) |

### Indicadores de Deteccion

- **Volumen anomalo de consultas LDAP** desde una sola IP en corto periodo.
- **Enumeracion masiva de sesiones**: Una maquina contactando muchos equipos via SMB en poco tiempo (port 445).
- **User-Agent o herramientas** conocidas: El binario de SharpHound puede ser detectado por firma (hash, YARA).
- **Nombres de archivo**: `BloodHound.bin`, `SharpHound.exe`, `*_BloodHound.zip` en disco o en trafico.

### Reglas de Deteccion

```yaml
# Ejemplo: Sigma rule para deteccion de enumeracion LDAP masiva
title: Potential BloodHound LDAP Reconnaissance
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    AccessMask: '0x100'
  filter:
    SubjectUserName|endswith: '$'
  timeframe: 5m
  condition: selection and not filter | count(SubjectUserName) > 100
level: medium
```

### Contramedidas Defensivas

- **Habilitar auditoria avanzada**: `DS Access > Audit Directory Service Access` para el evento 4662.
- **Restringir NetSessionEnum**: Modificar `SrvsvcSessionInfo` (via GPO o `NetCease`) para limitar quien puede enumerar sesiones.
- **Monitorizar LDAP**: Herramientas como MDI (Microsoft Defender for Identity) detectan reconocimiento LDAP anomalo.
- **Tiering model**: Separar cuentas de administracion en tiers para reducir paths transitivos.
- **Protected Users group**: Cuentas sensibles en este grupo no permiten delegacion ni caching de credenciales.
- **Eliminar ACLs excesivas**: Auditar y corregir ACLs que crean edges innecesarios (principal fuente de attack paths).

---

## Herramientas Complementarias

| Herramienta | Descripcion |
|-------------|-------------|
| [PlumHound](https://github.com/PlumHound/PlumHound) | Genera reportes HTML/CSV a partir de datos de BloodHound |
| [Cypheroth](https://github.com/seajaysec/cypheroth) | Coleccion de consultas Cypher utiles para pentest |
| [Max](https://github.com/knavesec/Max) | Herramienta para marcar nodos owned y analizar paths en masa |
| [BloodHound Notebook](https://github.com/ly4k/BloodHound-Notebooks) | Jupyter notebooks para analisis avanzado de datos de BloodHound |
| [BOFHound](https://github.com/fortalice/bofhound) | Genera datos de BloodHound a partir de logs de ldapsearch/BOF sin usar SharpHound |
| [ADExplorerSnapshot.py](https://github.com/c3c/ADExplorerSnapshot.py) | Convierte snapshots de AD Explorer (Sysinternals) a formato BloodHound |

---

## Entradas Relacionadas

- **Kerberoasting** - Ataque contra cuentas con SPN
- **AS-REP Roasting** - Ataque contra cuentas sin preautenticacion
- **DCSync** - Replicacion de hashes del dominio
- **DACL Abuse** - Abuso de listas de control de acceso
- **Constrained / Unconstrained Delegation** - Abuso de delegacion Kerberos
- **LAPS** - Local Administrator Password Solution
- **GPO Abuse** - Modificacion de Group Policy Objects para ejecucion de codigo
