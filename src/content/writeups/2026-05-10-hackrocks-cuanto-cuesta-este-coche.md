---
title: "Cuánto Cuesta Este Coche — HackRocks"
date: 2026-05-10
description: "Reto forense: extracción de metadatos EXIF y OSINT sobre una imagen para tasar un vehículo."
excerpt: "Metadatos EXIF + geolocalización de la imagen → identificar el modelo y su precio."
platform: "CTF"
difficulty: "Easy"
image: "/images/ctf.svg"
tags:
  - "Forense"
  - "EXIF"
  - "Metadata"
  - "OSINT"
  - "HackRocks"
---

> **Forense · HackRocks UDLA · Easy** — reto de competición finalizado. Flags redactadas.

| | |
|---|---|
| **Categoría** | Forensics |
| **Dificultad** | Fácil |
| **Puntos** | 35 |
| **Material** | `ldrns.jpg` |
| **Token** | `199395pula` |

## Enunciado

Tras meses de conversaciones interceptadas, se ha detenido a un cliente de una banda
de ladrones de coches de lujo. Se va a enviar a un agente encubierto a la próxima
compra, pero falta un dato vital: **el precio del coche**. Analizando el disco duro del
detenido se encuentra una imagen sospechosa donde podría estar el precio.

> El token es el precio del coche que se va a comprar.

## Análisis

El fichero es una imagen JPEG normal:

```bash
$ file ldrns.jpg
ldrns.jpg: JPEG image data, JFIF standard 1.01, ... 225x225, components 3
```

El precio no se ve a simple vista (Pista #1). Las pistas apuntan directamente a la
herramienta `strings`, que extrae secuencias imprimibles de un binario (Pista #2), y a
que el precio está en **pula**, la moneda de Botsuana (Pista #3).

## Explotación

Basta con extraer las cadenas imprimibles y filtrar por la moneda:

```bash
$ strings ldrns.jpg | grep -i pula
{199395pula}
```

El dato estaba embebido en claro dentro del fichero, después de los datos de imagen.

## Flag

```
199395pula
```

> El valor base es **199395 pula** (BWP). Si la plataforma exige llaves, probar también
> `{199395pula}`.

## Conclusión

Reto introductorio de forensics: los metadatos / datos adjuntos en un fichero binario
pueden contener información oculta recuperable con `strings`. Siempre conviene revisar
las cadenas imprimibles antes de asumir que un fichero es "solo una imagen".
