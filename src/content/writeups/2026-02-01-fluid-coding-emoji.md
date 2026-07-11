---
title: "Fluid Attacks CTF 2026: Coding - Emoji Classifier"
date: 2026-02-01
description: "Automatización y scripting para limpieza y validación de datasets corruptos."
tags: ["CTF", "Coding", "Scripting", "Python", "Data Analysis"]
image: "/images/blog/fluid-coding.png"
---

## 🎯 Objetivo

Se nos proporcionó un dataset CSV masivo (`emoji_dataset.csv`) conteniendo miles de entradas con IDs, caracteres Emoji y etiquetas de texto (ej. "cat", "dog"). El problema: muchas etiquetas eran incorrectas.

El reto exigía crear un script eficiente para **detectar todas las entradas mal etiquetadas** y devolver sus IDs ordenados.

## 💻 Solución

Dado el volumen de datos, la revisión manual era imposible. La solución requiere un enfoque de comparación contra una "fuente de verdad".

### 1. Definición de la Verdad

Primero, establecemos un diccionario que mapea cada caracter emoji a su etiqueta correcta e inmutable.

### Full Solver Script (`main.py`)

```python
import csv
from typing import List

# --- SOLUCIÓN PARA EL RETO CTF ---

def find_mislabelled() -> List[int]:
    # 1. Mapa de verdad (Emoji -> Etiqueta Correcta)
    truth = {
        '😺': 'cat',
        '🐶': 'dog',
        '🍎': 'apple',
        '🚗': 'car'
    }
    
    bad_ids = []
    
    # 2. Leemos el archivo asegurando la ruta correcta y codificación
    try:
        # Usamos ruta relativa estándar para el reto
        path = './data/emoji_dataset.csv'
        
        with open(path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                # Extraemos datos
                eid = int(row['id'])
                emoji = row['emoji'].strip()
                label = row['label'].strip()
                
                # 3. Verificamos si la etiqueta coincide con la realidad
                if emoji in truth:
                    expected = truth[emoji]
                    if label != expected:
                        bad_ids.append(eid)
                        
    except Exception as e:
        print(f"Error leyendo archivo: {e}")
        return []

    # 4. Retornamos la lista ordenada (Requisito del reto)
    return sorted(bad_ids)

# --- BLOQUE DE EJECUCIÓN ---
if __name__ == "__main__":
    resultado = find_mislabelled()
    print(f"IDs Encontrados ({len(resultado)}): {resultado}")
```

### 3. Optimización

El script debe ser rápido.
*   Usar diccionarios (`hash maps`) garantiza búsquedas O(1).
*   Leer el archivo línea por línea evita cargar todo el dataset en memoria RAM, lo cual es crucial para datasets gigantes.

## 🏆 Resultado

Al ejecutar el script, obtuvimos una lista precisa de IDs corruptos, permitiéndonos limpiar el dataset y obtener la flag del desafío de programación.
