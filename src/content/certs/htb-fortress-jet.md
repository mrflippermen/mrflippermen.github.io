---
title: "HTB Fortress — Respected by Jet"
date: 2025-03-11
description: "Completion del Jet Fortress en HackTheBox. Entorno que expone una superficie de ataque construida alrededor de aplicaciones modernas y pipelines de datos. Rarity: 0.13% de usuarios."
level: "Hard"
platform: "Hack The Box"
category: "Fortress"
duration: "Multi-Flag Challenge"
image: "/images/about/ctf-blue.png"
certId: "jet-fortress-2025"
tags: ["HTB", "Fortress", "Jet", "Web", "Pipelines", "API Abuse", "Data Exfiltration"]
---

<div align="center">

![Author](https://img.shields.io/badge/Author-Flippermen-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-HackTheBox-green?style=for-the-badge)
![Fortress](https://img.shields.io/badge/Fortress-Jet-orange?style=for-the-badge)
![Rarity](https://img.shields.io/badge/Rarity-0.13%25-black?style=for-the-badge)
![Team](https://img.shields.io/badge/Team-CyberFlippers-blue?style=for-the-badge)

**Flippermen | CyberFlippers | UDLA-Cyber**

</div>

---

| Campo | Valor |
|-------|-------|
| Fortress | Jet |
| Badge | Respected by Jet |
| Completado | 11 Mar, 2025 |
| Rarity | **0.13%** de usuarios |

## Sobre Jet

Jet es una plataforma de infraestructura y datos que diseñó su Fortress alrededor de los vectores de ataque más relevantes en entornos de aplicaciones modernas y pipelines de procesamiento de información.

El diseño refleja la realidad operacional de empresas que manejan flujos de datos masivos: APIs expuestas, tokens de autenticación con configuraciones incorrectas, y separación de privilegios insuficiente entre componentes de pipeline.

## El Fortress

El entorno expone múltiples capas de autenticación y autorización que deben ser navegadas metódicamente. La progresión es clara solo en retrospectiva — durante el proceso exige adaptarse constantemente a lo que el entorno revela.

## Metodología Aplicada

### 1. Reconocimiento de APIs y Servicios

```bash
# Descubrimiento inicial
nmap -sCV --open -p- <IP> -oN nmap_jet.txt

# API endpoint discovery
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -u http://<IP>/api/FUZZ -mc 200,201,400,401,403

# Swagger/OpenAPI check
curl -s http://<IP>/api/docs | python3 -m json.tool
curl -s http://<IP>/api/swagger.json
```

### 2. Análisis de JWT y Tokens de Autenticación

```python
import jwt, json

# Decodificar sin verificación para inspección
token = "eyJ..."
header = jwt.get_unverified_header(token)
payload = jwt.decode(token, options={"verify_signature": False})

print(f"Algorithm: {header['alg']}")
print(f"Payload: {json.dumps(payload, indent=2)}")
```

**Vectores de autenticación verificados:**
- Algoritmo `none` bypass
- Weak signing secret (crackeable con hashcat)
- Claims manipulation para escalación de rol

### 3. Abuso de Pipeline y Data Exfiltration

- **IDOR en endpoints de pipeline** — Acceso a jobs/results de otros usuarios modificando IDs
- **Parameter tampering** — Manipulación de parámetros de configuración de jobs
- **Batch operations abuse** — Uso de endpoints de operaciones en lote para maximizar extracción

## Herramientas Utilizadas

| Herramienta | Propósito |
|-------------|-----------|
| `nmap` | Enumeración de servicios |
| `ffuf` | Fuzzing de API endpoints |
| `Burp Suite` | Interceptación y manipulación |
| `hashcat` | Cracking de JWT secrets |
| `python3 / jwt` | Manipulación de tokens |
| `jq` | Procesamiento de respuestas JSON |

## Key Takeaways

1. **Las APIs son primera superficie de ataque** — El diseño de APIs modernas expone implícitamente lógica de negocio.
2. **JWT no es sinónimo de seguro** — Algoritmo, longitud de secret y validación de claims son tres capas independientes que pueden fallar separadamente.
3. **Los pipelines procesan datos sensibles** — En entornos de datos, el objetivo no siempre es RCE. Acceder a los datos procesados puede ser el verdadero impacto.

---

<div align="center">

**Flippermen**
*HackTheBox — Platinum Tier | #1 Ecuador | CyberFlippers | UDLA-Cyber*

</div>
