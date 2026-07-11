---
title: "HTB Fortress — Respected by Context"
date: 2025-03-31
description: "Completion del Context Fortress en HackTheBox. Diseñado por Context Information Security, firma especializada en investigación de vulnerabilidades y red teaming. Rarity: 0.07% de usuarios."
level: "Hard"
platform: "Hack The Box"
category: "Fortress"
duration: "Multi-Flag Challenge"
image: "/images/about/ctf-blue.png"
certId: "context-fortress-2025"
tags: ["HTB", "Fortress", "Context", "Vulnerability Research", "Red Team", "Web", "Binary Exploitation"]
---

<div align="center">

![Author](https://img.shields.io/badge/Author-Flippermen-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-HackTheBox-green?style=for-the-badge)
![Fortress](https://img.shields.io/badge/Fortress-Context-teal?style=for-the-badge)
![Rarity](https://img.shields.io/badge/Rarity-0.07%25-black?style=for-the-badge)
![Team](https://img.shields.io/badge/Team-CyberFlippers-blue?style=for-the-badge)

**Flippermen | CyberFlippers | UDLA-Cyber**

</div>

---

| Campo | Valor |
|-------|-------|
| Fortress | Context |
| Badge | Respected by Context |
| Completado | 31 Mar, 2025 |
| Rarity | **0.07%** de usuarios |

## Sobre Context

Context Information Security es una firma con sede en el Reino Unido especializada en investigación de vulnerabilidades, red teaming y respuesta a incidentes. Han publicado investigaciones en vulnerabilidades críticas en software ampliamente usado y realizan compromisos para organizaciones de alto perfil en sectores regulados.

## El Fortress

El entorno diseñado por Context refleja su background en vulnerability research: **recompensa la enumeración exhaustiva y la explotación precisa**. Cada objetivo es independiente en apariencia pero conectado en la narrativa del compromiso.

## Metodología Aplicada

### 1. Reconocimiento Profundo

```bash
# Scan exhaustivo inicial
nmap -sCV -p- --min-rate 5000 <IP> -oA nmap_context
nmap -sU --top-ports 100 <IP>  # UDP también importa

# Web enum completo con múltiples extensiones
gobuster dir -u http://<IP> \
    -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt \
    -x php,html,js,txt,bak,old,backup \
    -t 50 -o gobuster_context.txt

# Buscar archivos de backup/config expuestos
curl http://<IP>/.git/HEAD
curl http://<IP>/.env
curl http://<IP>/config.php.bak
```

### 2. Análisis de Código Fuente y Lógica

```bash
# Extraer endpoints de JS client-side
curl -s http://<IP>/app.js | grep -oP '(api|endpoint|route)[\'"/]+[^\'"]+' | sort -u

# Análisis de binario si disponible
file ./target_binary
checksec --file=./target_binary
strings ./target_binary | grep -E '(password|key|secret|token|flag)'
```

**Técnicas aplicadas:**
- Lectura de código JavaScript para identificar endpoints ocultos
- Análisis de archivos de configuración expuestos
- Búsqueda de comentarios con información sensible
- Decompilación de binarios si hay ejecutables disponibles

### 3. Explotación por Fases

**Fase 1 — Acceso inicial:** Vulnerabilidad web con twist en implementación  
**Fase 2 — Escalación horizontal:** Acceso a datos de otros usuarios al mismo nivel  
**Fase 3 — Escalación vertical:** Comprometer funcionalidades administrativas

### 4. Documentación del Attack Path

```markdown
## Attack Path
- Servicio X → versión Z → CVE encontrado
- Credenciales en fuente A → reutilizadas en servicio B
- Permiso en recurso C → pivote a recurso D
```

## Key Takeaways

1. **La enumeración no termina** — En entornos de vulnerability research hay capas. Cuando sientes que terminaste, hay una más.
2. **El código fuente es un mapa de vectores** — Comentarios de desarrolladores son con frecuencia los más reveladores.
3. **Methodical > Fast** — El tiempo en enumeración completa siempre se recupera en la fase de explotación.
4. **Conectar los puntos** — Las flags no son independientes. La información de cada una es relevante para la siguiente.

---

<div align="center">

**Flippermen**
*HackTheBox — Platinum Tier | #1 Ecuador | CyberFlippers | UDLA-Cyber*

</div>
