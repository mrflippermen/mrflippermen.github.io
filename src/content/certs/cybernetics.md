---
title: "Cybernetics Certified Specialist"
date: 2025-04-15
level: "Insane"
platform: "Hack The Box"
category: "Pro Lab"
duration: "40h"
image: "/images/about/Cybernetics.jpg"
tags: ["AD Hardening", "DevOps Security", "Kerberos", "MS Security"]
---

## Descripción del Laboratorio
Cybernetics es un entorno de **Active Directory endurecido (Hardened AD)** que simula una organización moderna consciente de la seguridad. A diferencia de otros laboratorios, aquí las configuraciones por defecto han sido aseguradas, el monitoreo está activo y las rutas de ataque obvias han sido cerradas.

El desafío se centra en encontrar brechas en la implementación de **DevOps, CI/CD y automatización**, así como en la explotación avanzada de protocolos de autenticación como Kerberos en entornos restringidos.

## Habilidades y Técnicas Dominadas

### 1. Hardened AD Exploitation
*   **Kerberos Bronze Bit Attack**: Explotación de la extensión S4U2Self para impersonación.
*   **Resource-Based Constrained Delegation (RBCD)**: Abuso de delegación en objetos de computadora para escalada de privilegios.
*   **Protected Users Group Bypass**: Técnicas para operar contra cuentas protegidas que no cachean credenciales.

### 2. DevOps & Cloud Security
*   **Jenkins Exploitation**: Abuso de consolas de scripts y pipelines inseguros para ejecución remota de código.
*   **Gitlab/Gitea Abuse**: Extracción de secretos y credenciales hardcodeadas en repositorios de código.

### 3. Lateral Movement in Restricted Networks
*   **LAPS Bypass**: Métodos para recuperar contraseñas de administrador local incluso con LAPS implementado (si existen fallos de configuración).
*   **Windows Defender Evasion**: Creación de payloads en C# personalizados y ofuscación de PowerShell para eludir protecciones en tiempo real.

### 4. Advanced Persistence
*   **AdminSDHolder Abuse**: Persistencia a través de la modificación de la plantilla de seguridad para cuentas protegidas.
*   **Golden Ticket with SID History**: Mantenimiento de acceso de dominio cruzado.

## Logro Destacado
Cybernetics certifica la habilidad de **operar en entornos maduros**, donde la seguridad no es una ocurrencia tardía. Demuestra competencia en el ataque a infraestructuras modernas que combinan AD tradicional con prácticas de DevOps.
