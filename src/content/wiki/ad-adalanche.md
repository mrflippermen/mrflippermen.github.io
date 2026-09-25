---
title: "Adalanche Cheat Sheet"
category: "AD"
description: "Herramienta de análisis visual de ACLs y permisos en Active Directory."
image: "/images/wiki/11.png"
---

# Adalanche: Visualización de Permisos y ACLs

**Adalanche** es una herramienta open-source desarrollada por Lars Karlslund para visualizar y analizar permisos en Active Directory. Su objetivo es similar al de BloodHound — mapear relaciones de control entre objetos del dominio — pero con un enfoque distinto: un solo binario que recolecta, analiza y presenta los resultados en una interfaz web interactiva sin necesidad de bases de datos externas (Neo4j) ni ingestores separados (SharpHound).

[Repositorio Oficial](https://github.com/lkarlslund/Adalanche)

## Concepto y Comparación con BloodHound

Adalanche recorre el directorio mediante consultas LDAP y construye un grafo de relaciones de control basado en las ACLs (Access Control Lists) de cada objeto. A diferencia de BloodHound, que requiere un ingestor (SharpHound/AzureHound), una base de datos Neo4j y la aplicación Electron/web, Adalanche funciona como un **binario único y portable**.

| Característica | Adalanche | BloodHound CE |
|---|---|---|
| Arquitectura | Binario único (Go) | Ingestor + Neo4j + App web |
| Base de datos | Embebida en memoria | Neo4j (externa) |
| Lenguaje de consultas | Interfaz gráfica con filtros | Cypher (Neo4j) |
| Soporte Azure AD / Entra ID | Limitado | Completo (AzureHound) |
| Recolección | Integrada en el mismo binario | SharpHound (.exe / .ps1) separado |
| Consumo de recursos | Bajo-medio | Alto (Neo4j consume bastante RAM) |
| Curva de aprendizaje | Baja | Media-alta (Cypher, conceptos de grafo) |
| Detección por EDR | Menor (binario Go, sin .NET) | Mayor (SharpHound es .NET, muy firmado) |

Adalanche es especialmente útil en entornos donde no se quiere o no se puede instalar Neo4j, en evaluaciones rápidas, o como segunda opinión para contrastar con los resultados de BloodHound.

## Instalación

### Binarios Precompilados (Recomendado)

La forma más sencilla es descargar el binario correspondiente a tu plataforma desde la página de releases:

```bash
# Descargar la última release para Linux (amd64)
wget https://github.com/lkarlslund/Adalanche/releases/latest/download/adalanche-linux-amd64

# Dar permisos de ejecución
chmod +x adalanche-linux-amd64
mv adalanche-linux-amd64 adalanche

# Verificar
./adalanche --help
```

Para Windows, descargar `adalanche-windows-amd64.exe` desde la misma página de releases.

### Compilar desde el Código Fuente

Requiere Go 1.21 o superior:

```bash
git clone https://github.com/lkarlslund/Adalanche.git
cd Adalanche
go build -o adalanche ./cmd/adalanche
```

## Modos de Operación

Adalanche opera en dos fases principales: **recolección** (`collect`) y **análisis** (`analyze`). Cada fase es un subcomando independiente del binario.

### Fase 1: Recolección (collect)

El subcomando `collect` soporta varios modos de recolección:

| Modo | Descripción |
|---|---|
| `activedirectory` | Consulta un DC vía LDAP para extraer objetos, ACLs, GPOs, etc. |
| `local` | Recopila información del equipo local (usuarios, grupos, sesiones, servicios) |

#### Recolección Remota contra Active Directory

```bash
# Sintaxis completa
./adalanche collect activedirectory \
  --domain <FQDN> \
  --server <DC_IP_o_FQDN> \
  --username <usuario@dominio> \
  --password <contraseña> \
  [--tlsmode <modo>] \
  [--port <puerto>] \
  [--authmode <modo>] \
  [--searchbase <DN>]
```

Ejemplo práctico:

```bash
./adalanche collect activedirectory \
  --domain corp.local \
  --server 10.10.10.100 \
  --username auditor@corp.local \
  --password 'S3cur3P@ss!' \
  --tlsmode NoTLS \
  --port 389
```

#### Flags Importantes de Recolección

| Flag | Descripción | Valor por defecto |
|---|---|---|
| `--domain` | FQDN del dominio (ej: `corp.local`) | Detectado por DNS |
| `--server` | IP o FQDN del Domain Controller | Detectado por DNS SRV |
| `--username` | Usuario para autenticación LDAP (formato `user@domain`) | Sesión actual |
| `--password` | Contraseña del usuario | — |
| `--port` | Puerto LDAP | 636 (LDAPS) / 389 (LDAP) |
| `--tlsmode` | Modo TLS: `TLS`, `StartTLS`, `NoTLS` | `TLS` |
| `--authmode` | Modo de autenticación: `ntlm`, `basic`, `negotiate` | `negotiate` |
| `--searchbase` | DN base de búsqueda (ej: `DC=corp,DC=local`) | Raíz del dominio |
| `--datapath` | Directorio donde guardar los datos recolectados | `./data/` |

#### Recolección Local

Recopila información del equipo donde se ejecuta (útil para máquinas unidas al dominio):

```bash
./adalanche collect local
```

Este modo extrae usuarios locales, grupos, sesiones activas, servicios y tareas programadas. Se complementa con la recolección remota para obtener un panorama más completo del dominio.

### Solución de Problemas de Conexión

| Problema | Causa probable | Solución |
|---|---|---|
| Error de certificado TLS | DC con certificado auto-firmado o CA interna | `--tlsmode NoTLS --port 389` |
| Fallo de autenticación | NTLM no soportado o bloqueado | `--authmode basic` |
| Timeout de conexión | Puerto bloqueado o DC inaccesible | Verificar conectividad con `nmap -p 389,636 <DC>` |
| Resultados vacíos | SearchBase incorrecto o permisos insuficientes | Ajustar `--searchbase` o usar cuenta con más privilegios |
| Error "referral" | Dominio multibosque con referrals | Especificar `--server` apuntando al DC correcto del dominio |

### Fase 2: Análisis y Visualización (analyze)

Una vez recolectados los datos, se lanza el modo de análisis que levanta un servidor web local:

```bash
./adalanche analyze
```

Por defecto sirve en `http://127.0.0.1:8080`. Opciones útiles:

```bash
# Cambiar el puerto del servidor web
./adalanche analyze --bind 0.0.0.0:9090

# Especificar un directorio de datos distinto
./adalanche analyze --datapath ./datos-auditoria/
```

> **Nota de seguridad**: Si usas `--bind 0.0.0.0`, la interfaz será accesible desde toda la red. En un engagement real, limita la escucha a `127.0.0.1` o usa un túnel SSH.

## Interfaz Web y Consultas

La interfaz web presenta un grafo interactivo donde los nodos son objetos de AD (usuarios, grupos, equipos, OUs, GPOs) y las aristas representan relaciones de control o permisos.

### Funciones Principales de la UI

- **Barra de búsqueda**: Buscar cualquier objeto por nombre (sAMAccountName, DN, SID).
- **Filtros de relación**: Mostrar/ocultar tipos específicos de aristas (ej: solo `GenericAll`, solo `WriteDACL`).
- **Análisis de caminos**: Seleccionar un origen y un destino para ver todos los caminos de ataque posibles.
- **Expansión de nodos**: Click en un nodo para ver sus propiedades, membresías y permisos.

### Consultas Típicas en la Interfaz

| Objetivo | Qué buscar |
|---|---|
| Usuarios con DCSync | Buscar `Domain Controllers` → ver quién tiene `Replicating Directory Changes` y `Replicating Directory Changes All` |
| Kerberoastable accounts | Filtrar usuarios con SPN configurado |
| Cuentas con delegación sin restricción | Buscar equipos/usuarios con `TRUSTED_FOR_DELEGATION` |
| AdminSDHolder protegidos | Explorar grupo `Domain Admins` y objetos con `adminCount=1` |
| Permisos sobre GPOs | Buscar GPOs y ver quién tiene `WriteProperty` o `GenericWrite` |
| Rutas hacia Domain Admins | Seleccionar un usuario comprometido como origen y `Domain Admins` como destino |

## Interpretación del Grafo: Aristas y Relaciones

Cada arista (edge) del grafo representa un permiso o relación específica. Las más relevantes para un pentester:

### Aristas de Alto Impacto

| Arista | Significado | Impacto Ofensivo |
|---|---|---|
| `GenericAll` | Control total sobre el objeto | Cambiar contraseña, modificar membresías, Kerberoast forzado |
| `GenericWrite` | Escritura de cualquier atributo | Añadir SPN (Kerberoast), modificar `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) |
| `WriteDACL` | Modificar la ACL del objeto | Otorgarse a uno mismo `GenericAll` u otros permisos |
| `WriteOwner` | Cambiar el propietario del objeto | Tomar ownership y luego modificar la DACL |
| `ForceChangePassword` | Resetear contraseña sin conocer la actual | Takeover directo de la cuenta |
| `AddMember` | Agregar miembros a un grupo | Añadirse a grupos privilegiados |
| `Replicating Directory Changes` | Permiso de replicación de directorio | DCSync (junto con `Replicating Directory Changes All`) |
| `AllExtendedRights` | Todos los derechos extendidos | Incluye reset de contraseña y lectura de LAPS |
| `MemberOf` | Pertenencia a grupo (relación, no permiso) | Herencia transitiva de permisos |
| `GPLink` | GPO vinculada a una OU | Ejecución de código en todos los equipos de la OU |

### Relaciones de Delegación

| Arista | Descripción |
|---|---|
| `AllowedToDelegate` | Delegación restringida (Constrained Delegation) |
| `AllowedToActOnBehalfOf` | Delegación basada en recursos (RBCD) |
| `TrustedForDelegation` | Delegación sin restricción (Unconstrained) |

## Análisis Offline

Adalanche guarda los datos recolectados en el directorio `data/` (por defecto). Esto permite:

1. **Recolectar en el target y analizar fuera**: Copiar la carpeta `data/` a tu máquina de análisis y ejecutar `./adalanche analyze` allí.
2. **Compartir datos entre analistas**: Varios miembros del equipo pueden analizar los mismos datos sin volver a consultar el DC.
3. **Análisis histórico**: Mantener snapshots de distintos momentos para comparar cambios en los permisos del dominio.

```bash
# En la máquina objetivo (con acceso al DC)
./adalanche collect activedirectory --domain corp.local --server 10.10.10.100 \
  --username auditor@corp.local --password 'P@ss' --datapath ./recoleccion-sept/

# Comprimir y exfiltrar
tar czf adalanche-data.tar.gz ./recoleccion-sept/

# En tu máquina de análisis
tar xzf adalanche-data.tar.gz
./adalanche analyze --datapath ./recoleccion-sept/
```

## Integración con Otras Herramientas

Adalanche no opera en un vacío. Se complementa bien con otras herramientas del arsenal de AD:

| Herramienta | Complemento con Adalanche |
|---|---|
| **BloodHound** | Segunda opinión; Adalanche puede detectar relaciones que BloodHound no modela |
| **Impacket** | Usar `secretsdump.py` para explotar caminos de DCSync encontrados en Adalanche |
| **Certipy** | Analizar relaciones de AD CS (ESC1-ESC8) y cruzar con permisos vistos en Adalanche |
| **NetExec (nxc)** | Validar credenciales y acceso a máquinas identificadas como objetivos en el grafo |
| **PowerView** | Consultas LDAP manuales para verificar ACLs específicas que muestra Adalanche |
| **ldapdomaindump** | Recolección LDAP alternativa para contrastar datos |

### Flujo de Trabajo Típico en un Engagement

```
1. Recolección con Adalanche (collect activedirectory)
2. Recolección con SharpHound (para BloodHound)
3. Análisis paralelo en ambas herramientas
4. Identificar caminos de ataque convergentes
5. Validar permisos críticos con PowerView / ldapsearch
6. Explotar con Impacket / NetExec / Rubeus según el vector
```

## Consideraciones OPSEC

### Huella de Red

Adalanche genera tráfico **LDAP estándar** durante la recolección. Consideraciones:

- **Volumen de consultas**: Realiza consultas LDAP masivas para enumerar todos los objetos y sus ACLs. En dominios grandes, esto puede generar miles de consultas en poco tiempo.
- **Puerto utilizado**: 389 (LDAP) o 636 (LDAPS). El tráfico LDAPS está cifrado, lo que dificulta la inspección de contenido por parte del blue team.
- **User-Agent / identificación**: Al ser consultas LDAP nativas, no hay User-Agent como en HTTP. La conexión se identifica por la cuenta usada y la IP origen.
- **Logs generados**: Las consultas LDAP pueden registrarse si se habilita el diagnóstico LDAP en el DC (no habilitado por defecto).

### Recomendaciones para el Operador

- Ejecutar durante horario laboral para mezclarse con el tráfico LDAP legítimo.
- Usar una cuenta con permisos de lectura estándar (no necesita privilegios elevados para la recolección básica).
- Preferir LDAPS (`--tlsmode TLS`) para que el contenido de las consultas no sea visible en la red.
- Eliminar los datos recolectados del target tras la exfiltración.

## Detección desde la Perspectiva Defensiva

### Indicadores a Monitorizar

| Indicador | Fuente de Log | Detalle |
|---|---|---|
| Conexión LDAP desde IP inusual | Event ID 2889 (LDAP signing), logs de firewall | IP de origen no habitual realizando bind LDAP |
| Enumeración masiva de objetos | Diagnóstico LDAP (Field Engineering) | Gran volumen de búsquedas LDAP en poco tiempo |
| Lectura masiva de atributos de seguridad | Event ID 4662 (Directory Service Access) | Acceso a `nTSecurityDescriptor` de muchos objetos |
| Consulta de todos los objetos del dominio | Diagnóstico LDAP | Búsquedas con filtro `(objectClass=*)` en scope subtree |
| Bind LDAP con cuenta de servicio fuera de horario | Event ID 4624 (logon tipo 3) | Cuenta usada para la recolección en horario atípico |

### Reglas de Detección

Para detectar herramientas como Adalanche (y SharpHound), los defensores pueden:

1. **Habilitar el diagnóstico LDAP** en los Domain Controllers (registro `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics`, valor `15 Field Engineering` a nivel 5).
2. **Monitorizar Event ID 4662** filtrando por acceso al atributo `nTSecurityDescriptor` (GUID `{771727b1-31b8-4cdf-ae62-4fe39fadf89e}`).
3. **Establecer baselines** de volumen de consultas LDAP por usuario y alertar ante desviaciones.
4. **Auditar binds LDAP** sin firma (Event ID 2889) como indicador de herramientas que usan `--tlsmode NoTLS`.

## Ventajas de Adalanche sobre BloodHound

1. **Despliegue inmediato**: Un solo binario, sin dependencias. No requiere Neo4j, Java ni configuración de base de datos.
2. **Menor huella en disco y memoria**: No necesita instalar software adicional en la máquina de análisis.
3. **Recolección integrada**: El mismo binario recolecta y analiza, eliminando la transferencia de ficheros entre ingestor y frontend.
4. **Compilado en Go**: Menor tasa de detección por EDR/AV en comparación con SharpHound (.NET), especialmente en la fase de recolección.
5. **Visualización directa de ACLs**: Muestra las ACEs individuales de cada objeto, no solo las relaciones modeladas.
6. **Portabilidad**: Funciona en Linux, macOS y Windows sin modificaciones.

## Limitaciones

- **Comunidad más pequeña**: Menos documentación, menos consultas predefinidas y menos actualizaciones que BloodHound CE.
- **Sin soporte robusto de Azure AD / Entra ID**: Para entornos cloud o híbridos, BloodHound con AzureHound sigue siendo superior.
- **Sin API de consultas tipo Cypher**: Las búsquedas dependen de la interfaz gráfica; no hay un lenguaje de consulta programático.
- **Menos modelado de ataques**: BloodHound modela ataques como RBCD, Shadow Credentials y ADCS de forma más completa.

## Entradas Relacionadas

- **BloodHound** — Plataforma principal de análisis de caminos de ataque en AD.
- **PowerView** — Enumeración manual de AD vía PowerShell.
- **Impacket** — Suite de herramientas para interactuar con protocolos de Windows (secretsdump, GetUserSPNs, etc.).
- **Certipy** — Enumeración y explotación de AD CS (Active Directory Certificate Services).
- **ldapdomaindump** — Volcado de información LDAP en formatos legibles.
- **NetExec (nxc)** — Herramienta de post-explotación y movimiento lateral en redes Windows.
