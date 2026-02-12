---
title: "Digital Forensics & DFIR Tools"
description: "Colección exhaustiva de herramientas para análisis forense digital, respuesta a incidentes y malware analysis."
image: "/images/wiki/forensics.png"
---

# Not The Hidden Wiki

## 📖 Portada

Bienvenido a la **colección más completa de herramientas forenses digitales y de respuesta a incidentes (DFIR)**. Este repositorio reúne más de **180+ herramientas especializadas** organizadas por funcionalidad, desde análisis de memoria y disco hasta forense móvil, análisis de malware y respuesta a incidentes en tiempo real.

Ya seas un investigador forense, analista de seguridad, pentester o miembro de un equipo de respuesta a incidentes, encontrarás aquí las herramientas esenciales para tu arsenal.

---

## 📑 Índice

- [🧠 Memory Forensics](#-memory-forensics)
- [💿 Disk & Filesystem Forensics](#-disk--filesystem-forensics)
- [🪟 Windows Forensics](#-windows-forensics)
- [🍎 macOS Forensics](#-macos-forensics)
- [🐧 Linux Forensics](#-linux-forensics)
- [📱 Mobile Forensics (iOS & Android)](#-mobile-forensics-ios--android)
- [🌐 Network & PCAP Analysis](#-network--pcap-analysis)
- [🌍 Browser & Web Forensics](#-browser--web-forensics)
- [🦠 Malware Analysis & Sandboxing](#-malware-analysis--sandboxing)
- [📄 File & Document Analysis](#-file--document-analysis)
- [🎨 Image & Media Forensics](#-image--media-forensics)
- [🔊 Audio & Steganography](#-audio--steganography)
- [✉️ Email Forensics](#️-email-forensics)
- [⏱️ Timeline Analysis](#️-timeline-analysis)
- [🚨 Incident Response & Live Forensics](#-incident-response--live-forensics)
- [🧰 DFIR Platforms & Frameworks](#-dfir-platforms--frameworks)
- [☁️ Cloud & Container Forensics](#️-cloud--container-forensics)
- [🔍 Data Identification & Utilities](#-data-identification--utilities)
- [📚 Resources & Collections](#-resources--collections)

---

## 🧠 Memory Forensics
-  Volatility 3.0 - [link](https://github.com/volatilityfoundation/volatility3)
-  Volatility 2.0 - [link](https://github.com/volatilityfoundation/volatility)
-  Volatility profiles for Linux and Mac OS X - [link](https://github.com/volatilityfoundation/profiles)
-  rekall - Memory analysis framework - [link](https://github.com/google/rekall)
-  MemProcFS: is an easy and convenient way of viewing physical memory as files in a virtual file system. - [link](https://github.com/ufrisk/MemProcFS)
-  MemProcFS-Analyzer - [link](https://github.com/evild3ad/MemProcFS-Analyzer)
-  Collect-MemoryDump - [link](https://github.com/evild3ad/Collect-MemoryDump)
-  LeechCore: Physical Memory Acquisition Library & The LeechAgent Remote Memory Acquisition Agent. - [link](https://github.com/ufrisk/LeechCore)
-  PCILeech: Direct Memory Access (DMA) Attack Software. - [link](https://github.com/ufrisk/pcileech)
-  LiME - Linux Memory Extractor - [link](https://github.com/504ensicsLabs/LiME)
-  avml - Memory analysis tool - [link](https://github.com/microsoft/avml)
-  VolUtility - Web interface for Volatility Memory Forensics - [link](https://github.com/kevthehermit/VolUtility)
-  OROCHI: The Volatility Collaborative GUI - [link](https://github.com/LDO-CERT/orochi)
-  AutoVolatility: Run several volatility plugins at the same time. - [link](https://github.com/carlospolop/autoVolatility)
-  usermode memory scanner for windows - [link](https://github.com/forrest-orr/moneta)
-  swap_digger - [link](https://github.com/sevagas/swap_digger)
-  KeeFarce - Extract KeePass 2.x credentials from memory - [link](https://github.com/denandz/KeeFarce)
-  tapir - Windows memory forensics tool - [link](https://github.com/tap-ir/tapir)
-  linux-explorer - Linux memory analysis tool - [link](https://github.com/intezer/linux-explorer)

## 💿 Disk & Filesystem Forensics
-  Autopsy - [link](https://www.autopsy.com/)
-  sleuthkit: Forensic toolkit to analyze volume and file system data - [link](https://github.com/sleuthkit/sleuthkit)
-  Foremost - [link](https://www.kali.org/tools/foremost/)
-  foremost: Foremost is a forensic tool for recovering files based on their data structures. - [link](https://doc.ubuntu-fr.org/foremost)
-  PhotoRec - File data recovery tool - [link](https://www.cgsecurity.org/wiki/PhotoRec)
-  Disk recovery software - [link](https://www.r-studio.com/)
-  RecuperaBit - filesystem recovery tool - [link](https://github.com/Lazza/RecuperaBit)
-  libewf - library for forensic disk images - [link](https://github.com/libyal/libewf)
-  imagemounter - tool for mounting forensic disk images - [link](https://github.com/ralphje/imagemounter)
-  guymager - Forensic imager - [link](https://sourceforge.net/projects/guymager/)
-  dcfldd - Enhanced version of dd for forensics and security - [link](https://github.com/adulau/dcfldd)
-  dcfldd.sourceforge.net - Enhanced version of dd for forensics and security - [link](https://dcfldd.sourceforge.net/)
-  dcfldd.sourceforge.net - Enhanced version of dd for forensics and security - [link](https://sourceforge.net/projects/dcfldd/)
-  dissect - Disk image format converter - [link](https://github.com/fox-it/dissect)
-  bulk_extractor - Forensic tool that scans a disk image,  file, or a directory of files and extracts information of interest - [link](https://github.com/simsong/bulk_extractor)

## 🪟 Windows Forensics
-  Eric Zimmerman Forensic Tools - [link](https://ericzimmerman.github.io/#!index.md)
-  chainsaw: Rapidly Search and Hunt through Windows Forensic Artefacts - [link](https://github.com/WithSecureLabs/chainsaw)
-  Event log explorer - [link](https://eventlogxp.com/)
-  evtx2json extracts events of interest from event logs, dedups them, and exports them to json. - [link](https://github.com/Silv3rHorn/evtx2json)
-  Pure Python parser for Windows Event Log files (.evtx) - [link](https://github.com/williballenthin/python-evtx)
-  python-evt - Python library for parsing Windows Event Log files (EVT) - [link](https://github.com/williballenthin/python-evt)
-  hayabusa - Binary analysis framework - [link](https://github.com/Yamato-Security/hayabusa)
-  LogonTracer - Logon and session timeline analysis tool - [link](https://github.com/JPCERTCC/LogonTracer)
-  computer_activity_view.html - Computer activity viewer - [link](https://www.nirsoft.net/utils/computer_activity_view.html)
-  squey.org - A tool for parsing and analyzing windows event logs - [link](https://squey.org/)
-  regrippy - Registry analysis tool - [link](https://github.com/airbus-cert/regrippy)
-  RegRipper3.0 - Registry analysis tool (RegRipper 3.0) - [link](https://github.com/keydet89/RegRipper3.0)
-  fred - Forensic Registry EDitor (FRED) - [link](https://www.pinguin.lu/fred)
-  Hivetools - [link](https://github.com/p0dalirius/hivetools)
-  python-ntfs - Python library for NTFS file system parsing - [link](https://github.com/williballenthin/python-ntfs)
-  dfir_ntfs: An NTFS/FAT parser for digital forensics & incident response. - [link](https://github.com/msuhanov/dfir_ntfs)
-  USN-Journal-Parser - USN (Update Sequence Number) journal parser - [link](https://github.com/PoorBillionaire/USN-Journal-Parser)
-  ntfs-linker - NTFS junction point creation tool - [link](https://strozfriedberg.github.io/ntfs-linker/)
-  mftmactime - MFT (Master File Table) MAC (Modification, Access, Change) timeline generator - [link](https://github.com/kero99/mftmactime)
-  MFTExtractor - MFT (Master File Table) extractor - [link](https://github.com/aarsakian/MFTExtractor)
-  pyshadow - Python library for NTFS shadow copy parsing - [link](https://github.com/alicangnll/pyshadow)
-  WinSearchDBAnalyzer - Windows Search database analysis tool - [link](https://github.com/moaistory/WinSearchDBAnalyzer)
-  PowerForensics: PowerForensics provides an all in one platform for live disk forensic analysis. [link](https://www.powershellgallery.com/packages/PowerForensics/1.1.1) - [link](https://github.com/Invoke-IR/PowerForensics)
-  pofr - PowerForensics PowerShell module - [link](https://github.com/gmagklaras/pofr)
-  PowerShell PE Parser - [link](https://github.com/jsecurity101/PowerParse)
-  ExtractBitlockerKeys: extract the bitlocker recovery keys from a domain. - [link](https://github.com/p0dalirius/ExtractBitlockerKeys)
-  bruteforce-luks: A tool to help recover encrypted LUKS2 containers - [link](https://github.com/glv2/bruteforce-luks)
-  Fastir_Collector - Windows forensic memory collection tool - [link](https://github.com/SekoiaLab/Fastir_Collector)
-  artifactcollector - Collects forensic artifacts on live Windows systems - [link](https://github.com/forensicanalysis/artifactcollector)
-  thor-lite - Host-based intrusion detection system (HIDS) for Windows - [link](https://www.nextron-systems.com/thor-lite/)
-  winfe.net - Windows Forensic Environment (WinFE) - [link](https://www.winfe.net/home)

## 🍎 macOS Forensics
-  mac_apt: macOS Artifact Parsing Tool - [link](https://github.com/ydkhatri/mac_apt/)
-  mac_apt - macOS artifact parsing toolkit (mac_apt) - [link](https://github.com/ydkhatri/mac_apt)
-  MacForensics: Repository of scripts for processing various artifacts from macOS (formerly OSX). - [link](https://github.com/ydkhatri/MacForensics)
-  osxcollector - OS X forensic evidence collection tool - [link](https://github.com/Yelp/osxcollector)
-  OSXAuditor - OS X auditor and forensic analysis tool - [link](https://github.com/jipegit/OSXAuditor)
-  macMRU-Parser - OS X Most Recently Used (MRU) file parser - [link](https://github.com/mac4n6/macMRU-Parser)
-  Mac-Locations-Scraper - OS X locations scraper tool - [link](https://github.com/mac4n6/Mac-Locations-Scraper)
-  apfs-fuse - APFS (Apple File System) FUSE implementation - [link](https://github.com/sgan81/apfs-fuse)
-  Disk-Arbitrator - tool for managing disk arbitration on macOS - [link](https://github.com/aburgh/Disk-Arbitrator)
-  parse the macOS Unified Log files - [link](https://github.com/mandiant/macos-UnifiedLogs)

## 🐧 Linux Forensics
-  FastIR Collector Linux - [link](https://github.com/SekoiaLab/Fastir_Collector_Linux)
-  unix_collector - Unix system memory and binary analysis tool - [link](https://github.com/op7ic/unix_collector)
-  unix_collector: elf-contained shell script designed for the forensic collection of various artifacts from Unix-based systems - [link](https://github.com/op7ic/unix_collector/tree/main)
-  libelfmaster: Secure ELF parsing/loading library for forensics reconstruction of malware, and robust reverse engineering tools - [link](https://github.com/elfmaster/libelfmaster)

## 📱 Mobile Forensics (iOS & Android)
-  Andriller - is software utility with a collection of forensic tools for smartphones - [link](https://github.com/den4uk/andriller)
-  Android Forensic - [link](https://github.com/RealityNet/Android-Forensics-References)
-  PancakeViewer - Android SQLite database viewer - [link](https://github.com/forensicmatt/PancakeViewer)
-  OpenBackupExtractor - iOS backup extractor - [link](https://github.com/vgmoose/OpenBackupExtractor)
-  MEAT - Mobile Evidence Acquisition Toolkit (MEAT) - [link](https://github.com/jfarley248/MEAT)
-  iOS-Frequent-Locations-Dumper - iOS frequent locations dumper - [link](https://github.com/mac4n6/iOS-Frequent-Locations-Dumper)
-  iLEAPP - iOS Logs, Events, and Properties Parser (iLEAPP) - [link](https://github.com/abrignoni/iLEAPP)
-  ALEAPP - Advanced iOS Logical Extraction and Analysis (ALEAPP) - [link](https://github.com/abrignoni/ALEAPP)
-  Returns logs events and protobuf parser - [link](https://github.com/abrignoni/RLEAPP)
-  Signal Forensics - [link](https://github.com/AvillaDaniel/Signal-Forensics)

## 🌐 Network & PCAP Analysis
-  PCAP Analysis - [link](https://apackets.com/)
-  PcapXray - [link](https://github.com/Srinivas11789/PcapXray)
-  online tool to analyse pcap files - [link](https://lab.dynamite.ai/)
-  BruteShark - [link](https://github.com/odedshimon/BruteShark)
-  ?page=Networkminer - A tool for parsing and analyzing windows event logs - [link](https://www.netresec.com/?page=Networkminer)
-  kismet - Wireless network and device detector, sniffer, wardriving tool - [link](https://github.com/kismetwireless/kismet)
-  O-Saft: OWASP SSL advanced forensic tool - [link](https://github.com/OWASP/O-Saft)
-  GreyNoise - [link](https://viz.greynoise.io/)

## 🌍 Browser & Web Forensics
-  hindsight - forensic analysis tool for browsers - [link](https://github.com/obsidianforensics/hindsight)
-  chrome-url-dumper - Chrome URL dumping tool - [link](https://github.com/eLoopWoo/chrome-url-dumper)
-  chrome_cache_view.html - Chrome cache viewer - [link](https://www.nirsoft.net/utils/chrome_cache_view.html)
-  Chrome logs events and protobufs parser - [link](https://github.com/markmckinnon/cLeapp)
-  ccl_chromium_reader: These libraries provide programmatic access to these data-stores with a digital forensics slant - [link](https://github.com/cclgroupltd/ccl_chromium_reader)
-  IE10Analyzer - Internet Explorer 10 history analysis tool - [link](https://github.com/moaistory/IE10Analyzer)
-  beagle - A tool for searching and analysing the information found on web servers - [link](https://github.com/yampelo/beagle)

## 🦠 Malware Analysis & Sandboxing
-  Virustotal - [link](https://www.virustotal.com/gui/home)
-  Hybrid-Analysis - [link](https://www.hybrid-analysis.com/)
-  Any-Run - [link](https://app.any.run/)
-  Loki - Simple IOC and YARA Scanner - [link](https://github.com/Neo23x0/Loki)
-  Your Swiss Army knife to analyze malicious web traffic - [link](https://github.com/malwareinfosec/EKFiddle)
-  Search Evasion Techniques - [link](https://unprotect.it/)
-  ID Ransomware - [link](https://id-ransomware.malwarehunterteam.com/index.php)
-  angr: a platform-agnostic binary analysis framework - [link](https://github.com/angr/angr)
-  inVtero.net - .NET application analysis - [link](https://github.com/ShaneK2/inVtero.net)
-  sherloq - malware classifier - [link](https://github.com/GuidoBartoli/sherloq)
-  laikaboss - File identification tool - [link](https://github.com/lmco/laikaboss)
-  Blauhaunt - Anti-forensic tool detector - [link](https://github.com/cgosec/Blauhaunt)

## 📄 File & Document Analysis
-  exif: Utility to read / write and edit metadata in image / audio and video files - [link](https://exiftool.org/)
-  exifprobe: Exifprobe is a command-line tool to parse EXIF data from image files. - [link](https://github.com/hfiguiere/exifprobe)
-  exiftool: writing and editing meta information in image / audio and video files. - [link](https://github.com/exiftool/exiftool)
-  exiv2: Image metadata library and toolset - [link](https://github.com/Exiv2/exiv2)
-  FOCA - metadata extraction tool for documents - [link](https://github.com/ElevenPaths/FOCA)
-  oletools - python tools to analyze MS OLE2 files - [link](https://github.com/decalage2/oletools)
-  Powerful Python tool to analyze PDF documents - [link](https://github.com/jesparza/peepdf)
-  Extract and Deobfuscate XLM macros - [link](https://github.com/DissectMalware/XLMMacroDeobfuscator)
-  OfficeForensicTools: A set of tools for collecting forensic information. - [link](https://github.com/DissectMalware/OfficeForensicTools)
-  bstrings - Binary strings analysis tool - [link](https://github.com/EricZimmerman/bstrings)
-  binwalk: Binwalk is a tool for analyzing / reverse engineering / and extracting firmware images. - [link](https://github.com/ReFirmLabs/binwalk)
-  collection of scripts and utilities to extract and rebuild linux based firmware images. - [link](https://github.com/rampageX/firmware-mod-kit)

## 🎨 Image & Media Forensics
-  imago-forensics: Imago is a python tool that extract digital evidences from images. - [link](https://github.com/redaelli/imago-forensics)
-  ghiro - digital image forensics tool - [link](https://github.com/Ghirensics/ghiro)
-  IPED - Internet Picture Evidence Detector (IPED) - [link](https://github.com/sepinf-inc/IPED)

## 🔊 Audio & Steganography
-  stegoVeritas - [link](https://github.com/bannsec/stegoVeritas)
-  Collection of steganography tools - [link](https://github.com/DominicBreuker/stego-toolkit)
-  zsteg - steganographic coder for WAV files - [link](https://github.com/zed-0xff/zsteg)
-  wavsteg - steganography tool for WAV files - [link](https://github.com/samolds/wavsteg)
-  sonicvisualiser - audio analysis software - [link](https://www.sonicvisualiser.org/)

## ✉️ Email Forensics
-  application to analyze the EML file - [link](https://github.com/ninoseki/eml_analyzer)
-  online tool for check email Reputation - [link](https://emailrep.io/)
-  ThePhish - [link](https://github.com/emalderson/ThePhish)
-  Sysinfo OST Viewer - [link](https://www.sysinfotools.com/recovery/ost-file-viewer.php)

## ⏱️ Timeline Analysis
-   timeliner - timeline generation tool for forensic investigations - [link](https://github.com/airbus-cert/timeliner)
-  introducing-timeline - timeline explorer tool - [link](https://binaryforay.blogspot.com/2017/04/introducing-timeline-explorer-v0400.html)
-  plaso - super timeline generation tool - [link](https://github.com/log2timeline/plaso)
-  dftimewolf - [link](https://github.com/log2timeline/dftimewolf)
-  timesketch - [link](https://github.com/google/timesketch)

## 🚨 Incident Response & Live Forensics
-  Remote Live Forensics - [link](https://github.com/google/grr)
-  Velociraptor - [link](https://github.com/Velocidex/velociraptor)
-  SPECTR3 - DFIR incident response and threat hunting platform - [link](https://github.com/alpine-sec/SPECTR3)
-  Invoke-LiveResponse - [link](https://github.com/mgreen27/Powershell-IR)
-  CHIRP: A forensic collection tool written in Python. - [link](https://github.com/cisagov/CHIRP)
-  FastIR Artifacts: Live forensic artifacts collector. - [link](https://github.com/SekoiaLab/fastir_artifacts)
-  ArtifactExtractor - Forensic artifact extraction tool - [link](https://github.com/Silv3rHorn/ArtifactExtractor)
-  acquire - Evidence acquisition tool - [link](https://github.com/fox-it/acquire)
-  ForensicMiner - Forensic incident response and intelligence gathering - [link](https://github.com/securityjoes/ForensicMiner)
-  osquery - SQL-powered operating system instrumentation, monitoring, and analytics - [link](https://github.com/osquery/osquery)
-  mig - MIG - Mozilla Investigation Game - [link](https://github.com/mozilla/mig)
-  intelmq - Incident and event processing framework - [link](https://github.com/certtools/intelmq)
-  uac - Forensic tool for the analysis of User Account Control (UAC) - [link](https://github.com/tclahr/uac)

## 🧰 DFIR Platforms & Frameworks
-  turbinia: Automation and Scaling of Digital Forensics Tools - [link](https://github.com/google/turbinia)
-  Kuiper: Digital Forensics Investigation Platform - [link](https://github.com/DFIRKuiper/Kuiper)
-  dff - Digital Forensics Framework (DFF) - [link](https://github.com/arxsys/dff)
-  sift - SANS Investigative Forensic Toolkit (SIFT) - [link](https://github.com/teamdfir/sift)
-  iris-web - web interface for digital forensics - [link](https://github.com/dfir-iris/iris-web)
-  dfirtrack - digital forensics and incident response (DFIR) case management tool - [link](https://github.com/dfirtrack/dfirtrack)
-  catalyst - incident response and threat intelligence framework - [link](https://github.com/SecurityBrewery/catalyst)
-  incidents - incident response automation tool - [link](https://github.com/veeral-patel/incidents)
-  DetectionLab - [link](https://github.com/clong/DetectionLab)
-  dexter - Automated digital forensics tool - [link](https://github.com/coinbase/dexter)
-  fit - Flexible and Intelligent Tracker - [link](https://github.com/fit-project/fit)
-  recon - Forensic investigation tool - [link](https://github.com/rusty-ferris-club/recon)
-  bitscout - Remote forensics tool - [link](https://github.com/vitaly-kamluk/bitscout)

## ☁️ Cloud & Container Forensics
-  docker-explorer - Docker container analysis tool - [link](https://github.com/google/docker-explorer)
-  toolkit - Docker forensics toolkit - [link](https://github.com/docker-forensics-toolkit/toolkit)
-  Static analysis powered security scanner for your terraform code - [link](https://github.com/liamg/tfsec)

## 🔍 Data Identification & Utilities
-  pyWhat -  🐸 Identify anything. pyWhat easily lets you identify emails, IP addresses, and more. Feed it a .pcap file or some text and it'll tell you what it is! 🧙‍♀️
Topics - [link](https://github.com/bee-san/pyWhat)
-  lemmeknow - The fastest way to identify anything! - [link](https://github.com/swanandx/lemmeknow)
-  Zed is a system that makes data easier by utilizing our new super-structured data model. - [link](https://www.brimdata.io/)
-  DCode - [link](https://www.digital-detective.net/dcode/)
-  hashlookup-forensic-analyser - Hashlookup forensic analyser - [link](https://github.com/hashlookup/hashlookup-forensic-analyser)
-  Autoaudit: A log tampering detection tool - [link](https://github.com/a-mess-tech/autoaudit)
-  CIRCLean - USB key sanitizer - [link](https://www.circl.lu/projects/CIRCLean/)

## 📚 Resources & Collections
-  Awesome Forensics - [link](https://github.com/cugu/awesome-forensics)
-  fireeye.market - Artifact repository - [link](https://fireeye.market/apps/211368)