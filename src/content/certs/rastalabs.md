---
title: "RastaLabs Red Team Operator"
date: 2025-03-25
level: "Hard"
platform: "Hack The Box"
category: "Pro Lab"
duration: "40h"
image: "/images/about/rastalab.jpg"
tags: ["Red Teaming", "Evasion", "Phishing", "Persistence"]
---

## Descripción del Laboratorio
RastaLabs es un entorno de simulación de **Red Team puro**. Inspirado en infraestructuras corporativas del mundo real, el laboratorio pone un énfasis masivo en el sigilo, la evasión de antivirus (AV/EDR) y la persistencia a largo plazo.

El objetivo no es solo obtener root, sino mantener el acceso sin ser detectado, emulando el comportamiento de un adversario sofisticado.

## Habilidades y Técnicas Dominadas

### 1. Evasión de Defensas (Defense Evasion)
*   **AMSI Patching**: Patching en memoria de `amsi.dll` para permitir la ejecución de scripts de PowerShell maliciosos.
*   **AppLocker Bypass**: Uso de reglas de ruta y editores de script permitidos para ejecutar código arbitrario.
*   **Payload Customization**: Compilación de herramientas propias para evitar firmas estáticas de antivirus.

### 2. Initial Access & Recon
*   **Open Source Intelligence (OSINT)**: Recolección de información pública (correos, nombres de usuario) para campañas de phishing dirigidas.
*   **Phishing Payloads**: Creación de documentos armados (HTA, Macros, OLE) para obtener el acceso inicial.

### 3. Active Directory Persistence
*   **DCSync**: Persistencia silenciosa mediante la replicación de secretos del dominio.
*   **Userland Persistence**: Persistencia a nivel de usuario (Run Keys, Startup folder) para sobrevivir a reinicios sin privilegios elevados inicialmente.

### 4. C2 Operations
*   **Beaconing Traffic**: Configuración de perfiles de tráfico C2 (jitter, sleep) para mezclarse con el ruido de la red.
*   **Domain Fronting**: Ocultamiento del tráfico de comando y control detrás de dominios legítimos de confianza.

## Logro Destacado
RastaLabs es la prueba definitiva de **paciencia y sigilo**. Certifica que el operador puede comprometer una red con defensas activas y listas blancas de aplicaciones, pensando "fuera de la caja" para lograr sus objetivos.
