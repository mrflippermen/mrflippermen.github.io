---
title: "Digital Forensics & DFIR Tools"
description: "Colección exhaustiva de herramientas para análisis forense digital, respuesta a incidentes y malware analysis."
image: "/images/wiki/1.png"
---

# 🔬 Not The Hidden Wiki

## 📖 Portada

Bienvenido a la **colección más completa de herramientas forenses digitales y de respuesta a incidentes (DFIR)**. Este repositorio reúne más de **180+ herramientas especializadas** organizadas por funcionalidad, desde análisis de memoria y disco hasta forense móvil, análisis de malware y respuesta a incidentes en tiempo real.

> 💡 **Tip**: Usa `Ctrl+F` para buscar herramientas específicas o navega por el índice para encontrar la categoría que necesitas.

Ya seas un investigador forense, analista de seguridad, pentester o miembro de un equipo de respuesta a incidentes, encontrarás aquí las herramientas esenciales para tu arsenal.

---

## 📑 Índice Rápido

<details open>
<summary><strong>Click para expandir/contraer índice</strong></summary>

- [🧠 Memory Forensics](#-memory-forensics)
- [💿 Disk & Filesystem Forensics](#-disk--filesystem-forensics)
- [🪟 Windows Forensics](#-windows-forensics)
- [🍎 macOS Forensics](#-macos-forensics)
- [🐧 Linux Forensics](#-linux-forensics)
- [📱 Mobile Forensics](#-mobile-forensics-ios--android)
- [🌐 Network & PCAP](#-network--pcap-analysis)
- [🌍 Browser & Web](#-browser--web-forensics)
- [🦠 Malware Analysis](#-malware-analysis--sandboxing)
- [📄 File & Document](#-file--document-analysis)
- [🎨 Image & Media](#-image--media-forensics)
- [🔊 Audio & Stego](#-audio--steganography)
- [✉️ Email Forensics](#️-email-forensics)
- [⏱️ Timeline Analysis](#️-timeline-analysis)
- [🚨 Incident Response](#-incident-response--live-forensics)
- [🧰 DFIR Platforms](#-dfir-platforms--frameworks)
- [☁️ Cloud & Container](#️-cloud--container-forensics)
- [🔍 Data Utilities](#-data-identification--utilities)
- [📚 Resources](#-resources--collections)

</details>

---

## 🧠 Memory Forensics

> **Análisis de memoria volátil (RAM) para extraer artefactos digitales, procesos, credenciales y evidencia forense.**

### ⭐ Herramientas Principales

-  **[Volatility 3.0](https://github.com/volatilityfoundation/volatility3)** - Framework líder para análisis de memoria RAM (Python 3)
-  **[Volatility 2.0](https://github.com/volatilityfoundation/volatility)** - Versión legacy con plugins específicos
-  **[MemProcFS](https://github.com/ufrisk/MemProcFS)** - Visualiza memoria física como sistema de archivos virtual
-  **[OROCHI](https://github.com/LDO-CERT/orochi)** - GUI colaborativa para Volatility
-  **[rekall](https://github.com/google/rekall)** - Framework avanzado de análisis de memoria

### 🔧 Herramientas Auxiliares

-  [Volatility profiles](https://github.com/volatilityfoundation/profiles) - Perfiles para Linux y Mac OS X
-  [MemProcFS-Analyzer](https://github.com/evild3ad/MemProcFS-Analyzer) - Analizador automatizado
-  [Collect-MemoryDump](https://github.com/evild3ad/Collect-MemoryDump) - Recolector de dumps de memoria
-  [AutoVolatility](https://github.com/carlospolop/autoVolatility) - Ejecuta múltiples plugins de Vol

atility
-  [VolUtility](https://github.com/kevthehermit/VolUtility) - Interfaz web para Volatility

### 🎯 Adquisición de Memoria

-  **[LiME](https://github.com/504ensicsLabs/LiME)** - Linux Memory Extractor (módulo kernel)
-  **[avml](https://github.com/microsoft/avml)** - Adquisición de memoria para Linux (Microsoft)
-  **[LeechCore](https://github.com/ufrisk/LeechCore)** - Librería de adquisición de memoria física
-  **[PCILeech](https://github.com/ufrisk/pcileech)** - Direct Memory Access (DMA) Attack Software

### 🔍 Análisis Especializado

-  [KeeFarce](https://github.com/denandz/KeeFarce) - Extrae credenciales de KeePass 2.x desde memoria
-  [moneta](https://github.com/forrest-orr/moneta) - Escáner de memoria usermode para Windows
-  [swap_digger](https://github.com/sevagas/swap_digger) - Análisis de archivos swap en Linux
-  [tapir](https://github.com/tap-ir/tapir) - Herramienta de forense de memoria para Windows
-  [linux-explorer](https://github.com/intezer/linux-explorer) - Análisis de memoria para Linux

---

## 💿 Disk & Filesystem Forensics

> **Análisis y recuperación de sistemas de archivos, particiones y datos borrados.**

### 🔎 Análisis de Disco

-  **[Autopsy](https://www.autopsy.com/)** - Plataforma completa con GUI para análisis forense
-  **[Sleuth Kit (TSK)](https://github.com/sleuthkit/sleuthkit)** - Toolkit de línea de comandos para análisis de volúmenes
-  **[FTK Imager](https://www.r-studio.com/)** - Software profesional de recuperación de disco

### 📦 Recuperación de Archivos

-  **[Foremost](https://www.kali.org/tools/foremost/)** - File carving basado en headers y footers
-  **[PhotoRec](https://www.cgsecurity.org/wiki/PhotoRec)** - Recuperación de archivos eliminados
-  **[RecuperaBit](https://github.com/Lazza/RecuperaBit)** - Recuperación de sistemas de archivos
-  **[bulk_extractor](https://github.com/simsong/bulk_extractor)** - Extractor masivo de información

### 💾 Imaging & Montaje

-  [guymager](https://sourceforge.net/projects/guymager/) - Herramienta de imaging forense
-  [dcfldd](https://github.com/adulau/dcfldd) - Versión mejorada de `dd` para forense
-  [libewf](https://github.com/libyal/libewf) - Librería para imágenes forenses (E01)
-  [imagemounter](https://github.com/ralphje/imagemounter) - Montaje automático de imágenes forenses
-  [dissect](https://github.com/fox-it/dissect) - Conversor de formatos de imágenes de disco

---

## 🪟 Windows Forensics

> **Herramientas especializadas para análisis forense en sistemas Windows.**

### 🛠️ Suites Completas

-  **[Eric Zimmerman Tools (EZTools)](https://ericzimmerman.github.io/#!index.md)** - Suite esencial para Windows forense
-  **[WinFE](https://www.winfe.net/home)** - Windows Forensic Environment de arranque

### 📊 Event Logs & Registry

-  **[Hayabusa](https://github.com/Yamato-Security/hayabusa)** - Análisis rápido de logs EVTX
-  **[Chainsaw](https://github.com/WithSecureLabs/chainsaw)** - Búsqueda rápida en artefactos de Windows
-  **[RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)** - Parser de registro de Windows
-  **[evtx2json](https://github.com/Silv3rHorn/evtx2json)** - Convierte event logs a JSON
-  [python-evtx](https://github.com/williballenthin/python-evtx) - Parser Python para archivos EVTX
-  [python-evt](https://github.com/williballenthin/python-evt) - Parser Python para archivos EVT
-  [regrippy](https://github.com/airbus-cert/regrippy) - Análisis de registro en Python
-  [fred](https://www.pinguin.lu/fred) - Forensic Registry EDitor
-  [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - Análisis de sesiones de logon

### 💽 NTFS & Filesystem

-  **[PowerForensics](https://github.com/Invoke-IR/PowerForensics)** - Análisis forense de disco en PowerShell
-  [python-ntfs](https://github.com/williballenthin/python-ntfs) - Parser de NTFS en Python
-  [dfir_ntfs](https://github.com/msuhanov/dfir_ntfs) - Parser NTFS/FAT para DFIR
-  [USN-Journal-Parser](https://github.com/PoorBillionaire/USN-Journal-Parser) - Parser del USN journal
-  [mftmactime](https://github.com/kero99/mftmactime) - Generador de timeline desde MFT
-  [MFTExtractor](https://github.com/aarsakian/MFTExtractor) - Extractor de Master File Table
-  [pyshadow](https://github.com/alicangnll/pyshadow) - Parser de shadow copies en Python
-  [Hivetools](https://github.com/p0dalirius/hivetools) - Herramientas para registry hives

### 🔐 Credentials & Encryption

-  [ExtractBitlockerKeys](https://github.com/p0dalirius/ExtractBitlockerKeys) - Extrae claves de BitLocker del dominio
-  [bruteforce-luks](https://github.com/glv2/bruteforce-luks) - Recuperación de contenedores LUKS2
-  [pofr](https://github.com/gmagklaras/pofr) - Módulo PowerForensics PowerShell

### 📦 Artifact Collection

-  [Fastir_Collector](https://github.com/SekoiaLab/Fastir_Collector) - Recolector de memoria en Windows
-  [artifactcollector](https://github.com/forensicanalysis/artifactcollector) - Recolector de artefactos en vivo
-  [thor-lite](https://www.nextron-systems.com/thor-lite/) - HIDS para Windows
-  [PowerShell PE Parser](https://github.com/jsecurity101/PowerParse) - Parser de ejecutables en PowerShell

### 🌐 Online Tools

-  [Event log explorer](https://eventlogxp.com/) - Explorador de event logs
-  [squey.org](https://squey.org/) - Análisis de event logs
-  [computer_activity_view](https://www.nirsoft.net/utils/computer_activity_view.html) - Visor de actividad
-  [WinSearchDBAnalyzer](https://github.com/moaistory/WinSearchDBAnalyzer) - Analizador de Windows Search

---

## 🍎 macOS Forensics

> **Herramientas para análisis forense en sistemas macOS y análisis de APFS.**

-  **[mac_apt](https://github.com/ydkhatri/mac_apt)** - macOS Artifact Parsing Tool
-  **[MacForensics](https://github.com/ydkhatri/MacForensics)** - Scripts para artefactos de macOS
-  **[os

xcollector](https://github.com/Yelp/osxcollector)** - Recolector de evidencia forense
-  **[macos-UnifiedLogs](https://github.com/mandiant/macos-UnifiedLogs)** - Parser de Unified Logs
-  [OSXAuditor](https://github.com/jipegit/OSXAuditor) - Auditoría y análisis forense
-  [macMRU-Parser](https://github.com/mac4n6/macMRU-Parser) - Parser de archivos MRU
-  [Mac-Locations-Scraper](https://github.com/mac4n6/Mac-Locations-Scraper) - Scraper de ubicaciones
-  [apfs-fuse](https://github.com/sgan81/apfs-fuse) - Implementación FUSE de APFS
-  [Disk-Arbitrator](https://github.com/aburgh/Disk-Arbitrator) - Gestión de disk arbitration

---

## 🐧 Linux Forensics

> **Análisis forense para sistemas Linux y Unix.**

-  **[FastIR Collector Linux](https://github.com/SekoiaLab/Fastir_Collector_Linux)** - Recolector de artefactos
-  **[unix_collector](https://github.com/op7ic/unix_collector)** - Script shell para recolección forense
-  **[libelfmaster](https://github.com/elfmaster/libelfmaster)** - Librería de parsing ELF para forense
-  [linux-explorer](https://github.com/intezer/linux-explorer) - Análisis de memoria Linux

---

## 📱 Mobile Forensics (iOS & Android)

> **Extracción y análisis de dispositivos móviles iOS y Android.**

### 📲 Android

-  **[Andriller](https://github.com/den4uk/andriller)** - Colección de herramientas forenses para Android
-  **[Android-Forensics-References](https://github.com/RealityNet/Android-Forensics-References)** - Referencias de forense
-  [PancakeViewer](https://github.com/forensicmatt/PancakeViewer) - Visor de bases de datos SQLite

### 🍏 iOS

-  **[iLEAPP](https://github.com/abrignoni/iLEAPP)** - iOS Logs, Events, and Properties Parser
-  **[ALEAPP](https://github.com/abrignoni/ALEAPP)** - Advanced Logical Extraction and Analysis
-  **[OpenBackupExtractor](https://github.com/vgmoose/OpenBackupExtractor)** - Extractor de backups de iOS
-  [iOS-Frequent-Locations-Dumper](https://github.com/mac4n6/iOS-Frequent-Locations-Dumper) - Dumper de ubicaciones
-  [RLEAPP](https://github.com/abrignoni/RLEAPP) - Returns logs events and protobuf parser
-  [cLeapp](https://github.com/markmckinnon/cLeapp) - Chrome logs parser
-  [Signal Forensics](https://github.com/AvillaDaniel/Signal-Forensics) - Forense de Signal

### 📱 General Mobile

-  [MEAT](https://github.com/jfarley248/MEAT) - Mobile Evidence Acquisition Toolkit

---

## 🌐 Network & PCAP Analysis

> **Análisis de tráfico de red y archivos de captura PCAP.**

-  **[BruteShark](https://github.com/odedshimon/BruteShark)** - Analizador de red forense
-  **[NetworkMiner](https://www.netresec.com/?page=Networkminer)** - Network Forensic Analysis Tool
-  **[PcapXray](https://github.com/Srinivas11789/PcapXray)** - Visualización de PCAP
-  [apackets.com](https://apackets.com/) - Análisis online de PCAP
-  [lab.dynamite.ai](https://lab.dynamite.ai/) - Herramienta online de análisis
-  [kismet]( https://github.com/kismetwireless/kismet) - Detector de redes wireless
-  [O-Saft](https://github.com/OWASP/O-Saft) - OWASP SSL advanced forensic tool
-  [GreyNoise](https://viz.greynoise.io/) - Inteligencia de ruido de internet

---

## 🌍 Browser & Web Forensics

> **Análisis forense de navegadores y actividad web.**

-  **[Hindsight](https://github.com/obsidianforensics/hindsight)** - Análisis de Chrome/Chromium
-  **[ccl_chromium_reader](https://github.com/cclgroupltd/ccl_chromium_reader)** - Lector de datos de Chromium
-  [chrome-url-dumper](https://github.com/eLoopWoo/chrome-url-dumper) - Dumper de URLs
-  [chrome_cache_view](https://www.nirsoft.net/utils/chrome_cache_view.html) - Visor de caché
-  [cLeapp](https://github.com/markmckinnon/cLeapp) - Parser de logs de Chrome
-  [IE10Analyzer](https://github.com/moaistory/IE10Analyzer) - Analizador de IE10
-  [beagle](https://github.com/yampelo/beagle) - Análisis de información en servidores web

---

## 🦠 Malware Analysis & Sandboxing

> **Análisis de malware, sandboxing y detección de IOCs.**

### 🔬 Sandboxes Online

-  **[VirusTotal](https://www.virustotal.com/gui/home)** - Análisis multi-antivirus
-  **[Hybrid-Analysis](https://www.hybrid-analysis.com/)** - Sandbox gratuito de malware
-  **[Any.Run](https://app.any.run/)** - Sandbox interactivo en tiempo real

### 🛡️ Scanners & Detection

-  **[Loki](https://github.com/Neo23x0/Loki)** - Scanner simple de IOCs y YARA
-  **[unprotect.it](https://unprotect.it/)** - Base de datos de técnicas de evasión
-  **[EKFiddle](https://github.com/malwareinfosec/EKFiddle)** - Análisis de tráfico web malicioso
-  [ID Ransomware](https://id-ransomware.malwarehunterteam.com/index.php) - Identificador de ransomware

### 🔍 Analysis Tools

-  **[angr](https://github.com/angr/angr)** - Framework de análisis binario
-  [inVtero.net](https://github.com/ShaneK2/inVtero.net) - Análisis de aplicaciones .NET
-  [sherloq](https://github.com/GuidoBartoli/sherloq) - Clasificador de malware
-  [laikaboss](https://github.com/lmco/laikaboss) - Identificación de archivos
-  [Blauhaunt](https://github.com/cgosec/Blauhaunt) - Detector de herramientas anti-forenses

---

## 📄 File & Document Analysis

> **Análisis de metadatos, documentos Office y archivos PDF.**

### 📊 Metadata

-  **[ExifTool](https://github.com/exiftool/exiftool)** - Lectura/escritura de metadatos
-  **[FOCA](https://github.com/ElevenPaths/FOCA)** - Extracción de metadatos de documentos
-  [exifprobe](https://github.com/hfiguiere/exifprobe) - Parser de EXIF en línea de comandos
-  [exiv2](https://github.com/Exiv2/exiv2) - Librería de metadatos de imágenes

### 📝 Office & Documents

-  **[oletools](https://github.com/decalage2/oletools)** - Análisis de archivos MS OLE2
-  **[XLMMacroDeobfuscator](https://github.com/DissectMalware/XLMMacroDeobfuscator)** - Desofuscador de macros XLM
-  **[OfficeForensicTools](https://github.com/DissectMalware/OfficeForensicTools)** - Herramientas forenses para Office
-  [peepdf](https://github.com/jesparza/peepdf) - Analizador de PDFs maliciosos

### 🔧 Binary Analysis

-  **[binwalk](https://github.com/ReFirmLabs/binwalk)** - Análisis y extracción de firmware
-  **[bstrings](https://github.com/EricZimmerman/bstrings)** - Extractor de strings binarios
-  [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit) - Extracción de firmware Linux

---

## 🎨 Image & Media Forensics

> **Análisis forense de imágenes y medios digitales.**

-  **[IPED](https://github.com/sepinf-inc/IPED)** - Internet Picture Evidence Detector
-  **[imago-forensics](https://github.com/redaelli/imago-forensics)** - Extractor de evidencia de imágenes
-  [ghiro](https://github.com/Ghirensics/ghiro) - Herramienta de forense de imágenes

---

## 🔊 Audio & Steganography

> **Análisis de audio y detección de esteganografía.**

-  **[stegoVeritas](https://github.com/bannsec/stegoVeritas)** - Detector de esteganografía
-  **[stego-toolkit](https://github.com/DominicBreuker/stego-toolkit)** - Colección de herramientas stego
-  [zsteg](https://github.com/zed-0xff/zsteg) - Detector para PNG y BMP
-  [wavsteg](https://github.com/samolds/wavsteg) - Esteganografía en archivos WAV
-  [sonicvisualiser](https://www.sonicvisualiser.org/) - Software de análisis de audio

---

## ✉️ Email Forensics

> **Análisis de correos electrónicos y archivos EML.**

-  **[ThePhish](https://github.com/emalderson/ThePhish)** - Analizador de phishing
-  **[eml_analyzer](https://github.com/ninoseki/eml_analyzer)** - Analizador de archivos EML
-  [emailrep.io](https://emailrep.io/) - Verificación de reputación de email
-  [Sysinfo OST Viewer](https://www.sysinfotools.com/recovery/ost-file-viewer.php) - Visor de OST

---

## ⏱️ Timeline Analysis

> **Generación y análisis de líneas de tiempo forenses.**

-  **[Plaso](https://github.com/log2timeline/plaso)** - Motor backend para log2timeline
-  **[Timesketch](https://github.com/google/timesketch)** - Análisis colaborativo de timelines
-  **[dftimewolf](https://github.com/log2timeline/dftimewolf)** - Orquestador de workflows DFIR
-  [timeliner](https://github.com/airbus-cert/timeliner) - Generador de timeline
-  [Timeline Explorer](https://binaryforay.blogspot.com/2017/04/introducing-timeline-explorer-v0400.html) - Explorador de timelines

---

## 🚨 Incident Response & Live Forensics

> **Respuesta a incidentes y forense en vivo.**

### 🚀 Live Response

-  **[Velociraptor](https://github.com/Velocidex/velociraptor)** - Endpoint monitoring y respuesta
-  **[GRR Rapid Response](https://github.com/google/grr)** - Framework de respuesta remota
-  **[osquery](https://github.com/osquery/osquery)** - SQL para instrumentación de OS
-  [Invoke-LiveResponse](https://github.com/mgreen27/Powershell-IR) - PowerShell

 IR

### 📦 Artifact Collection

-  **[CHIRP](https://github.com/cisagov/CHIRP)** - Recolector forense en Python
-  **[FastIR Artifacts](https://github.com/SekoiaLab/fastir_artifacts)** - Recolector de artefactos
-  **[ArtifactExtractor](https://github.com/Silv3rHorn/ArtifactExtractor)** - Extractor de artefactos
-  **[acquire](https://github.com/fox-it/acquire)** - Herramienta de adquisición de evidencia
-  [ForensicMiner](https://github.com/securityjoes/ForensicMiner) - Recolector de evidencia
-  [uac](https://github.com/tclahr/uac) - Análisis de User Account Control

### 🔍 DFIR Platforms

-  **[SPECTR3](https://github.com/alpine-sec/SPECTR3)** - Plataforma de DFIR y threat hunting
-  [mig](https://github.com/mozilla/mig) - Mozilla Investigation Game
-  [intelmq](https://github.com/certtools/intelmq) - Framework de eventos de incidentes

---

## 🧰 DFIR Platforms & Frameworks

> **Plataformas completas y frameworks para DFIR.**

-  **[Turbinia](https://github.com/google/turbinia)** - Automatización y escalado de forense en la nube
-  **[Kuiper](https://github.com/DFIRKuiper/Kuiper)** - Plataforma de investigación forense
-  **[SIFT Workstation](https://github.com/teamdfir/sift)** - Toolkit forense completo de SANS
-  **[DFF](https://github.com/arxsys/dff)** - Digital Forensics Framework
-  **[iris-web](https://github.com/dfir-iris/iris-web)** - Interfaz web para forense
-  [dfirtrack](https://github.com/dfirtrack/dfirtrack) - Gestión de casos DFIR
-  [catalyst](https://github.com/SecurityBrewery/catalyst) - Framework de threat intelligence
-  [incidents](https://github.com/veeral-patel/incidents) - Automatización de respuesta
-  [DetectionLab](https://github.com/clong/DetectionLab) - Laboratorio de detección
-  [dexter](https://github.com/coinbase/dexter) - Forense automatizado
-  [fit](https://github.com/fit-project/fit) - Flexible and Intelligent Tracker
-  [recon](https://github.com/rusty-ferris-club/recon) - Investigación forense
-  [bitscout](https://github.com/vitaly-kamluk/bitscout) - Forense remoto

---

## ☁️ Cloud & Container Forensics

> **Análisis forense de contenedores Docker y infraestructura cloud.**

-  **[docker-explorer](https://github.com/google/docker-explorer)** - Análisis de contenedores Docker
-  **[docker-forensics-toolkit](https://github.com/docker-forensics-toolkit/toolkit)** - Toolkit de forense Docker
-  [tfsec](https://github.com/liamg/tfsec) - Scanner de seguridad para Terraform

---

## 🔍 Data Identification & Utilities

> **Herramientas de identificación de datos y utilidades generales.**

-  **[pyWhat](https://github.com/bee-san/pyWhat)** 🐸 - Identifica emails, IPs, hashes y más
-  **[lemmeknow](https://github.com/swanandx/lemmeknow)** - Identificación rápida de cualquier cosa
-  **[Brim (Zed)](https://www.brimdata.io/)** - Sistema de super-estructuración de datos
-  **[hashlookup-forensic-analyser](https://github.com/hashlookup/hashlookup-forensic-analyser)** - Analizador de hashes
-  [DCode](https://www.digital-detective.net/dcode/) - Decodificador de timestamps
-  [Autoaudit](https://github.com/a-mess-tech/autoaudit) - Detector de manipulación de logs
-  [CIRCLean](https://www.circl.lu/projects/CIRCLean/) - Sanitizador de USB

---

## 📚 Resources & Collections

> **Colecciones de recursos y repositorios de referencia.**

-  **[Awesome Forensics](https://github.com/cugu/awesome-forensics)** - Lista curada de recursos forenses
-  **[FireEye Market](https://fireeye.market/apps/211368)** - Repositorio de artefactos

---

## 📌 Notas Finales

> 💡 **Recuerda**: Siempre documenta tu cadena de custodia y mantén la integridad de la evidencia.

**Contribuciones**: Si conoces una herramienta que debería estar en esta lista, considera contribuir al repositorio.

**Licencias**: Verifica siempre las licencias de las herramientas antes de usarlas en entornos de producción o legales.

---

<div align="center">

**🔬 Happy Forensics! 🔍**

*Última actualización: 2026*

</div>