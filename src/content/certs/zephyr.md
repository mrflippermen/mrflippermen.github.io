---
title: "Zephyr Certified Operator"
date: 2025-03-20
level: "Intermediate - Hard"
platform: "Hack The Box"
category: "Pro Lab"
duration: "40h"
image: "/images/about/Zephyr.jpg"
tags: ["Active Directory", "Reporting", "Pivoting", "GPO Abuse", "MSSQL"]
---

## Descripción del Laboratorio
Zephyr está diseñado para cerrar la brecha entre el pentesting básico de Active Directory y las operaciones de Red Team avanzadas. Simula una red corporativa realista con múltiples subredes y dominios, enfocándose en la **enumeración profunda y la explotación de malas configuraciones en Active Directory**.

A diferencia de otros laboratorios, Zephyr pone un fuerte énfasis en la **generación de reportes y la metodología**, requiriendo no solo la explotación técnica sino la comprensión del impacto empresarial de cada hallazgo.

## Habilidades y Técnicas Dominadas

### 1. Enumeración Avanzada de AD
*   **BloodHound & Sharphound**: Mapeo exhaustivo de relaciones de confianza, grupos y permisos en el dominio.
*   **LDAP Queries**: Consultas manuales para extraer información oculta sin alertar a los sistemas de monitoreo.

### 2. Ataques a Infraestructura Windows
*   **GPO Abuse**: Modificación de Políticas de Grupo para distribuir malware o crear usuarios administradores.
*   **MSSQL Exploitation**: Escalada de privilegios a través de servidores SQL mal configurados (xp_cmdshell, enlaces de servidores).
*   **DNS Adidnsdump**: Enumeración de registros DNS integrados en AD para descubrir nuevos objetivos.

### 3. Técnicas de Pivoting
*   **SOCKS Proxying**: Uso de Chisel y Proxychains para enrutar herramientas a través de máquinas comprometidas.
*   **Port Forwarding**: Acceso a servicios internos expuestos solo a la red local.

### 4. Credential Attacks
*   **Password Spraying**: Ataques de fuerza bruta inteligentes para evitar bloqueos de cuenta.
*   **DCSync**: Simulación de un controlador de dominio para volcar hashes de contraseñas de todos los usuarios (KRBTGT).
*   **Pass-the-Hash/Ticket**: Reutilización de credenciales robadas para autenticación lateral.

## Logro Destacado
La certificación de Zephyr valida una **metodología sólida de pentesting en Active Directory**, capaz de identificar y encadenar vulnerabilidades complejas que a menudo pasan desapercibidas en escaneos automatizados.
