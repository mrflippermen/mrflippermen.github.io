---
title: "HTB Fortress — Respected by Akerva"
date: 2025-03-16
description: "Completion del Akerva Fortress en HackTheBox. Diseñado por la firma francesa de ciberseguridad Akerva, el entorno simula una red corporativa real con múltiples vectores de entrada. Rarity: 0.17% de usuarios."
level: "Hard"
platform: "Hack The Box"
category: "Fortress"
duration: "Multi-Flag Challenge"
image: "/images/about/ctf-blue.png"
certId: "akerva-fortress-2025"
tags: ["HTB", "Fortress", "Akerva", "Red Team", "Corporate Network", "Active Directory", "Credential Attacks"]
---

<div align="center">

![Author](https://img.shields.io/badge/Author-Flippermen-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-HackTheBox-green?style=for-the-badge)
![Fortress](https://img.shields.io/badge/Fortress-Akerva-green?style=for-the-badge)
![Rarity](https://img.shields.io/badge/Rarity-0.17%25-black?style=for-the-badge)
![Team](https://img.shields.io/badge/Team-CyberFlippers-blue?style=for-the-badge)

**Flippermen | CyberFlippers | UDLA-Cyber**

</div>

---

| Campo | Valor |
|-------|-------|
| Fortress | Akerva |
| Badge | Respected by Akerva |
| Completado | 16 Mar, 2025 |
| Rarity | **0.17%** de usuarios |

## Sobre Akerva

Akerva es una firma francesa de ciberseguridad especializada en auditorías técnicas, pruebas de intrusión y red teaming. Con una trayectoria sólida en compromisos para grandes organizaciones europeas, su enfoque combina rigor técnico con contexto de negocio real.

## El Fortress

El entorno diseñado por Akerva simula una **red corporativa con múltiples puntos de entrada**, replicando la complejidad de una infraestructura empresarial real. La clave no es encontrar una vulnerabilidad obvia, sino mapear correctamente la superficie de ataque y priorizar los vectores más prometedores.

## Metodología Aplicada

### 1. Mapeo de Infraestructura

```bash
# Scan completo de red
nmap -sCV -p- --min-rate 5000 <IP> -oA nmap_akerva

# Identificar servicios web
nmap -p 80,443,8080,8443,8888 --script=http-title,http-methods <IP>

# SMB enum (si disponible)
enum4linux-ng -A <IP>
```

### 2. Reconocimiento Web y Vhost Discovery

```bash
# Directory brute-force
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -u http://<IP>/FUZZ -mc 200,301,302,403 -t 50

# Vhost enumeration
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -H "Host: FUZZ.<domain>" -u http://<IP> -mc 200,301
```

### 3. Ataques de Credenciales

```bash
# Password spraying con Hydra contra SSH
hydra -L users.txt -P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt \
      ssh://<IP> -t 4

# Web login brute
hydra -L users.txt -P passwords.txt http-post-form \
      "/login:username=^USER^&password=^PASS^:Invalid credentials"
```

**Técnicas aplicadas:**
- Password spraying contra servicios de autenticación
- Credential stuffing con wordlists región-específicas
- Default credentials en servicios administrativos
- Credential reuse entre servicios

## Key Takeaways

1. **La infraestructura corporativa implica heterogeneidad** — Múltiples sistemas, tecnologías y versiones. Cada servicio es un vector potencial diferente.
2. **Password spraying > brute force** — En redes reales, lockout policies hacen el brute force inviable.
3. **El mapa importa** — En entornos multi-servicio, construir el mapa completo antes de atacar ahorra tiempo total.

---

<div align="center">

**Flippermen**
*HackTheBox — Platinum Tier | #1 Ecuador | CyberFlippers | UDLA-Cyber*

</div>
