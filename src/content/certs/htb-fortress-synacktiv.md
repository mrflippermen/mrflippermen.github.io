---
title: "HTB Fortress — Pwned by Synacktiv"
date: 2025-03-07
description: "Completion del Synacktiv Fortress en HackTheBox. Entorno diseñado por una de las consultoras de seguridad ofensiva más reconocidas de Europa. Rarity: 0.04% de usuarios."
level: "Hard"
platform: "Hack The Box"
category: "Fortress"
duration: "Multi-Flag Challenge"
image: "/images/about/ctf-blue.png"
certId: "synacktiv-fortress-2025"
tags: ["HTB", "Fortress", "Synacktiv", "Red Team", "Ofensivo", "Web", "Exploit Chain"]
---

<div align="center">

![Author](https://img.shields.io/badge/Author-Flippermen-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-HackTheBox-green?style=for-the-badge)
![Fortress](https://img.shields.io/badge/Fortress-Synacktiv-red?style=for-the-badge)
![Rarity](https://img.shields.io/badge/Rarity-0.04%25-black?style=for-the-badge)
![Team](https://img.shields.io/badge/Team-CyberFlippers-blue?style=for-the-badge)

**Flippermen | CyberFlippers | UDLA-Cyber**

</div>

---

| Campo | Valor |
|-------|-------|
| Fortress | Synacktiv |
| Badge | Pwned the Synacktiv Fortress |
| Completado | 07 Mar, 2025 |
| Rarity | **0.04%** de usuarios |

## Sobre Synacktiv

Synacktiv es una de las consultoras de seguridad ofensiva más reconocidas de Europa. Con sede en Francia, son conocidos por sus investigaciones en IoT, automotive hacking y red teaming avanzado a gran escala. Han publicado investigaciones sobre vulnerabilidades en Tesla, Apple y múltiples sistemas industriales.

## El Fortress

El entorno diseñado por Synacktiv refleja directamente el tipo de compromisos que realizan en sus engagements reales. Exige pensamiento lateral, encadenamiento de vulnerabilidades y la capacidad de mantener metodología cuando el camino no es obvio.

No hay hints. No hay foros de ayuda. Solo el entorno y lo que sabes.

## Metodología Aplicada

### 1. Reconocimiento y Enumeración

```bash
# Port scan inicial
nmap -sCV -p- --min-rate 5000 -oN nmap_synacktiv.txt <IP>

# Enum web con tecnología identificada
whatweb http://<IP> -v
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://<IP>/FUZZ -mc 200,301,302
```

### 2. Vectores de Ataque Identificados

**Categorías de vulnerabilidades encontradas:**

- **Authentication Bypass** — Mecanismos de autenticación con implementación deficiente
- **Logic Flaws** — Flujos de negocio con condiciones no contempladas por el diseñador
- **Privilege Escalation** — Escalación horizontal y vertical dentro del entorno
- **Information Disclosure** — Endpoints y rutas que exponían datos sensibles de configuración

### 3. Encadenamiento y Progresión

1. **Rango de exposición** — Mapeo completo de servicios HTTP/TCP disponibles
2. **Fuzzing de endpoints** — Descubrimiento de rutas ocultas y funcionalidades no documentadas
3. **Análisis de intercepción** — Revisión detallada de requests/responses con Burp Suite
4. **Explotación encadenada** — Combinación de hallazgos para escalar impacto sucesivamente

## Herramientas Utilizadas

| Herramienta | Propósito |
|-------------|-----------|
| `nmap` | Reconocimiento de puertos y servicios |
| `ffuf` | Fuzzing de endpoints web |
| `Burp Suite` | Interceptación y manipulación de tráfico HTTP |
| `curl` | Pruebas manuales de peticiones |
| `python3` | Scripts de explotación custom |

## Rarity

Con un **0.04%** de usuarios que lo han completado, este es uno de los Fortresses más exclusivos disponibles en HackTheBox — compartido en ese puesto con el Fortress de AWS.

## Key Takeaways

> **El sigilo importa.** Synacktiv diseña sus entornos para simular detección. Mantener las peticiones dentro de lo que parece tráfico legítimo es parte del reto.

1. La enumeración metódica es irremplazable — el 80% del tiempo debe invertirse aquí.
2. Cuando algo no funciona, la pregunta no es "¿por qué no funciona?" sino "¿qué me estoy perdiendo?".
3. Los Fortresses de vendors reales exponen la filosofía de seguridad del vendor — entenderla es ventaja táctica.

---

<div align="center">

**Flippermen**
*HackTheBox — Platinum Tier | #1 Ecuador | CyberFlippers | UDLA-Cyber*

</div>
