---
title: "HTB Fortress — Respected by Faraday"
date: 2025-03-15
description: "Completion del Faraday Fortress en HackTheBox. Diseñado por la plataforma de gestión de vulnerabilidades Faraday, el entorno pone a prueba el entendimiento de flujos de trabajo de seguridad ofensiva. Rarity: 0.05% de usuarios."
level: "Hard"
platform: "Hack The Box"
category: "Fortress"
duration: "Multi-Flag Challenge"
image: "/images/about/ctf-blue.png"
certId: "faraday-fortress-2025"
tags: ["HTB", "Fortress", "Faraday", "Vulnerability Management", "Ofensivo", "Web", "SSTI", "Privilege Escalation"]
---

<div align="center">

![Author](https://img.shields.io/badge/Author-Flippermen-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-HackTheBox-green?style=for-the-badge)
![Fortress](https://img.shields.io/badge/Fortress-Faraday-blueviolet?style=for-the-badge)
![Rarity](https://img.shields.io/badge/Rarity-0.05%25-black?style=for-the-badge)
![Team](https://img.shields.io/badge/Team-CyberFlippers-blue?style=for-the-badge)

**Flippermen | CyberFlippers | UDLA-Cyber**

</div>

---

| Campo | Valor |
|-------|-------|
| Fortress | Faraday |
| Badge | Respected by Faraday |
| Completado | 15 Mar, 2025 |
| Rarity | **0.05%** de usuarios |

## Sobre Faraday

Faraday es una plataforma de gestión de vulnerabilidades utilizada por equipos de pentesting en entornos de producción real. Centraliza hallazgos, evidencias y reportes de engagements de seguridad ofensiva a escala empresarial.

## El Fortress — La Ironía

El Fortress de Faraday tiene una ironía bien ejecutada: **pone a prueba la capacidad de encontrar debilidades en un sistema diseñado específicamente para rastrear y gestionar vulnerabilidades**.

Completarlo implica pensar como alguien que conoce íntimamente el producto — y explotar exactamente eso.

## Metodología Aplicada

### 1. Fingerprinting de Faraday

```bash
# Reconocimiento de versión y componentes
curl -s http://<IP>/_api/info | python3 -m json.tool
curl -s http://<IP>/_api/v3/info

# Identificar versión específica para buscar CVEs
whatweb http://<IP> --log-verbose=whatweb.log
```

### 2. Análisis de la API REST

```bash
# Enumeración de workspaces
curl -s http://<IP>/_api/v3/ws

# Endpoints de usuarios
curl -s http://<IP>/_api/v3/users -H "Authorization: Bearer <token>"

# Vulns y evidencias
curl -s http://<IP>/_api/v3/ws/<workspace>/vulns
```

**Vectores investigados:**
- Acceso sin autenticación a workspaces de auditoría
- Escalación de privilegios entre roles (viewer → pentester → admin)
- Inyección en campos de reporte (SSTI potencial)
- Exposición de credentials almacenadas en evidencias

### 3. SSTI Testing en Campos de Reporte

```python
# Payload de prueba SSTI (Jinja2)
payload = "{{7*7}}"  # Si retorna 49, es vulnerable

# Escalación a RCE
ssti_rce = "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
```

### 4. Flags del Fortress

1. **Flag 1** — Acceso inicial a workspace de otro equipo (IDOR)
2. **Flag 2** — Escalación a rol de admin dentro de la plataforma
3. **Flag 3** — Acceso al servidor subyacente mediante explotación de funcionalidad avanzada

## Key Takeaways

1. **Conocer el producto es ventaja** — La documentación pública de Faraday es el mejor mapa del entorno.
2. **La superficie de ataque escala con la complejidad** — Sistemas sofisticados tienen más funcionalidad = más vectores posibles.
3. **Los roles importan** — La escalación horizontal (workspace a workspace) es tan crítica como la vertical.
4. **Los campos de texto son vectores** — Cualquier campo que renderice contenido merece atención especial.

---

<div align="center">

**Flippermen**
*HackTheBox — Platinum Tier | #1 Ecuador | CyberFlippers | UDLA-Cyber*

</div>
