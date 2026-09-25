---
title: "Certified Blue Teamer (CBTeamer)"
date: 2026-01-20
level: "Intermediate"
platform: "Blue Team Labs"
category: "Blue Team"
duration: "4h Exam"
image: "/images/about/cbteamer.png"
tags: ["Incident Response", "Digital Forensics", "Threat Hunting", "SIEM", "Active Directory"]
---

<div align="center">

![Author](https://img.shields.io/badge/Author-Flippermen-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Security_Blue_Team-blue?style=for-the-badge)
![Cert](https://img.shields.io/badge/Cert-CBTeamer-0066CC?style=for-the-badge)
![Level](https://img.shields.io/badge/Level-Intermediate-yellow?style=for-the-badge)
![Team](https://img.shields.io/badge/Team-CyberFlippers-blue?style=for-the-badge)

**Flippermen | CyberFlippers | UDLA-Cyber**

</div>

---

| Campo | Valor |
|-------|-------|
| Certificacion | Certified Blue Teamer (CBTeamer) |
| Plataforma | Security Blue Team / Blue Team Labs Online |
| Examen | 4 horas, 100% practico |
| Certificate ID | `10916716` |
| Enfoque | Incident Response, DFIR, Threat Hunting, SIEM |

## Sobre CBTeamer

**Certified Blue Teamer (CBTeamer)** es una certificacion practica ofrecida por Security Blue Team a traves de su plataforma Blue Team Labs Online. A diferencia de certificaciones defensivas basadas en teoria o preguntas de opcion multiple, CBTeamer es un examen **100% hands-on** de 4 horas que sumerge al analista en un escenario de compromiso activo dentro de un entorno corporativo Windows.

El examen evalua la capacidad del candidato para actuar como primer respondedor ante un incidente de seguridad real: investigar la intrusion, reconstruir la cadena de ataque completa (Cyber Kill Chain), identificar los indicadores de compromiso (IOCs), contener la amenaza y documentar los hallazgos. El entorno incluye estaciones de trabajo Windows comprometidas, servidores, logs de SIEM, capturas de red y volcados de memoria que deben ser analizados de forma integrada.

La certificacion cubre las seis areas fundamentales de la defensa corporativa:
- **Incident Response** — Manejo estructurado de incidentes siguiendo frameworks como NIST SP 800-61
- **Digital Forensics** — Analisis forense de disco, memoria y red para reconstruir la timeline de un ataque
- **Threat Hunting** — Busqueda proactiva de amenazas utilizando hipotesis basadas en TTPs de adversarios
- **SIEM & Log Analysis** — Correlacion de eventos de multiples fuentes para deteccion de actividad maliciosa
- **Network Forensics** — Analisis de capturas de red (PCAP) para identificar comunicaciones C2 y exfiltracion
- **Active Directory Defense** — Deteccion de ataques basados en identidad y persistencia en dominios Windows

---

## 🔒 Confidential Assessment Profile

**Role**: `Incident Responder / Threat Hunter`
**Scope**: `Full Kill-Chain Investigation`
**Certificate ID**: `10916716`

---

## ⚔️ Tactical Competencies

### 1. Incident Management & SIEM
*   **Event Correlation**: Vinculacion de logs dispares (Windows Event Logs, Sysmon, firewall, proxy) para reconstruir la *Cyber Kill Chain* completa — desde el acceso inicial hasta la exfiltracion de datos.
*   **Alert Triage**: Distincion rapida entre falsos positivos y actividad maliciosa critica. Priorizacion de alertas basada en contexto, criticidad de activos y fase de la cadena de ataque.
*   **SIEM Query Crafting**: Escritura de consultas avanzadas para busqueda de IOCs especificos, patrones de comportamiento anomalo y correlacion temporal de eventos.
*   **Incident Timeline Reconstruction**: Construccion de timelines detalladas que mapean cada accion del adversario con evidencia forense, estableciendo la cronologia exacta del compromiso.

### 2. Digital Forensics (DFIR)
*   **Disk Forensics**: Analisis de artefactos de disco — Prefetch files (evidencia de ejecucion de programas), Registry hives (configuracion y persistencia), Amcache, ShimCache, y archivos recientes (MRU/LNK files).
*   **Memory Forensics**: Analisis de volcados de memoria con Volatility para detectar inyecciones de codigo (process hollowing, reflective DLL injection), conexiones de red ocultas, y procesos maliciosos disfrazados.
*   **Network Analysis**: Diseccion de capturas PCAP para identificar trafico C2 (beaconing patterns, DNS tunneling, HTTPS anomalies) y exfiltracion de datos.
*   **Artifact Recovery**: Recuperacion de archivos eliminados, analisis de timestamps (MFT) y reconstruccion de actividad de usuario a partir de artefactos del sistema operativo.

### 3. Threat Hunting
*   **Hypothesis-Driven Hunting**: Formulacion de hipotesis basadas en inteligencia de amenazas (TTPs conocidos) y busqueda proactiva de evidencia en el entorno.
*   **MITRE ATT&CK Mapping**: Mapeo de actividad observada contra la matriz ATT&CK para identificar fases de la cadena de ataque completadas y predecir los proximos pasos del adversario.
*   **IOC Analysis**: Identificacion, documentacion y busqueda de indicadores de compromiso — hashes de archivos, dominios C2, direcciones IP, patrones de registro y artefactos de persistencia.
*   **Behavioral Detection**: Deteccion basada en comportamiento en lugar de firmas — patrones de acceso anomalos, movimiento lateral inusual, escalada de privilegios fuera de horario.

### 4. Active Directory Defense
*   **Identity Attack Detection**: Deteccion de ataques basados en identidad — Kerberoasting (Event ID 4769 con encryption type RC4), AS-REP Roasting, Pass-the-Hash (Event ID 4624 Logon Type 9), DCSync (replicacion de directorio no autorizada).
*   **Persistence Hunting**: Identificacion de mecanismos de permanencia ocultos en controladores de dominio — Golden Ticket artifacts, AdminSDHolder modifications, DCShadow traces, rogue Group Policy Objects.
*   **Privileged Account Monitoring**: Analisis de actividad de cuentas privilegiadas para deteccion de uso anormal, creacion de cuentas no autorizada y modificaciones de permisos sospechosas.

## Metodologia Aplicada

### 1. Triage Inicial y Recoleccion de Evidencia

```bash
# Analisis rapido de procesos sospechosos
Get-Process | Where-Object {$_.Path -notmatch "C:\\Windows|C:\\Program Files"} | 
    Select Name, Path, Id, StartTime

# Verificar conexiones de red activas
netstat -anob | findstr ESTABLISHED

# Recoleccion de Event Logs criticos
wevtutil qe Security /q:"*[System[(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4768 or EventID=4769)]]" /f:text

# Exportar logs de Sysmon
wevtutil epl "Microsoft-Windows-Sysmon/Operational" C:\Evidence\sysmon.evtx
```

### 2. Analisis Forense de Memoria

```bash
# Listar procesos y detectar anomalias
volatility -f memory.dmp --profile=<profile> pslist
volatility -f memory.dmp --profile=<profile> pstree

# Detectar inyeccion de codigo
volatility -f memory.dmp --profile=<profile> malfind

# Conexiones de red ocultas
volatility -f memory.dmp --profile=<profile> netscan

# Extraer strings de procesos sospechosos
volatility -f memory.dmp --profile=<profile> memdump -p <PID> -D ./dump/
strings ./dump/<PID>.dmp | grep -iE "(http|https|cmd|powershell|mimikatz)"
```

### 3. Analisis de Trafico de Red

```bash
# Identificar beaconing patterns en PCAP
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e frame.time_delta_displayed \
    -Y "ip.dst == <suspicious_ip>" | sort -t$'\t' -k3 -n

# Extraer objetos HTTP transferidos
tshark -r capture.pcap --export-objects http,./extracted_files/

# Buscar DNS tunneling
tshark -r capture.pcap -Y "dns.qry.name contains '<suspicious_domain>'" \
    -T fields -e dns.qry.name -e dns.resp.addr

# Estadisticas de comunicaciones
tshark -r capture.pcap -q -z conv,ip
```

### 4. Deteccion de Ataques AD

```powershell
# Detectar Kerberoasting (TGS requests con RC4)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} |
    Where-Object {$_.Properties[5].Value -eq '0x17'} |
    Select TimeCreated, @{N='Account';E={$_.Properties[0].Value}},
    @{N='Service';E={$_.Properties[2].Value}}

# Detectar DCSync (replicacion sospechosa)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4662} |
    Where-Object {$_.Properties[9].Value -match '1131f6aa-|1131f6ad-'}

# Buscar Golden Ticket artifacts
# TGTs con lifetime anomalo o emitidos por cuentas inusuales
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768} |
    Where-Object {$_.Properties[0].Value -ne $env:COMPUTERNAME}
```

## Herramientas Utilizadas

| Herramienta | Proposito |
|-------------|-----------|
| `Volatility / Volatility3` | Analisis forense de memoria |
| `Wireshark / tshark` | Analisis de capturas de red (PCAP) |
| `Splunk / ELK` | Correlacion de logs y busqueda de IOCs en SIEM |
| `Event Viewer / wevtutil` | Analisis de Windows Event Logs |
| `Sysmon` | Monitoreo avanzado de actividad del sistema |
| `Autopsy / FTK` | Analisis forense de disco |
| `KAPE` | Recoleccion rapida de artefactos forenses |
| `Eric Zimmerman Tools` | Analisis de artefactos Windows (Registry, Prefetch, MFT) |
| `CyberChef` | Decodificacion y analisis de datos ofuscados |
| `YARA` | Deteccion basada en reglas de malware |

## Key Takeaways

1. **La respuesta a incidentes es una carrera contra el reloj** — La velocidad de triage y contencion determina si un incidente queda en compromiso inicial o se convierte en brecha catastrofica.
2. **La memoria es el testigo mas fiable** — Los artefactos en disco pueden ser borrados, pero el volcado de memoria captura el estado exacto del sistema en el momento de la adquisicion, incluyendo procesos ocultos y conexiones activas.
3. **La correlacion de fuentes es lo que revela la historia completa** — Ningun log individual cuenta la historia. Solo la correlacion de Event Logs + Sysmon + PCAP + memoria forense reconstruye la cadena de ataque verdadera.
4. **El threat hunting complementa la deteccion reactiva** — Las alertas de SIEM son necesarias pero insuficientes. La busqueda proactiva basada en hipotesis y TTPs conocidos encuentra al adversario que evade las reglas de deteccion.
5. **Conocer el ataque habilita la defensa** — La experiencia ofensiva (pentesting, red team) es directamente transferible a la deteccion y respuesta, porque permite pensar como el adversario.

---

## 🏆 Operational Impact

Esta credencial certifica la capacidad para **"Cazar" (Hunt)** amenazas activas, validando no solo el uso de herramientas, sino la intuicion tactica necesaria para detener a un adversario humano en tiempo real. La perspectiva dual ofensiva/defensiva — habiendo completado tambien labs de Red Team — proporciona una ventaja operativa unica: entender los TTPs del atacante desde la experiencia directa para detectarlos y neutralizarlos desde el lado defensivo.

---

<div align="center">

**Flippermen**
*CyberFlippers | UDLA-Cyber*

</div>
