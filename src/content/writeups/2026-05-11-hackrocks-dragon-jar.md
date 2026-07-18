---
title: "Dragon.jar — HackRocks"
date: 2026-05-11
description: "Reversing de un JAR de Java: decompilación y recuperación de la lógica que valida la flag."
excerpt: "Decompilar el .jar (jd-gui/CFR) → reconstruir el algoritmo de validación → flag."
platform: "CTF"
difficulty: "Easy"
image: "/images/ctf.svg"
tags:
  - "Reversing"
  - "Java"
  - "JAR"
  - "Decompilación"
  - "HackRocks"
---

> **Reversing · HackRocks UDLA · Easy** — reto de competición finalizado. Flags redactadas.

| | |
|---|---|
| **Categoría** | Reverse Engineering |
| **Dificultad** | Fácil |
| **Puntos** | 35 |
| **Material** | `dragon.jar` |
| **Flag** | `r3v3rsing_p3rf3cted` |

## Enunciado

Se ha filtrado un fichero ofuscado llamado `dragon.jar` en foros clandestinos. Hay que
analizarlo, revertir su lógica y extraer la flag incrustada.

Las pistas descartan los enfoques habituales:
- Pista #1: `strings` y `strace` no sirven.
- Pista #2: no abrirlo en Ghidra/IDA.
- Pista #3: la extensión `.jar` es de **Java** → usar un descompilador.

## Análisis

Un `.jar` es un ZIP. Listamos su contenido:

```bash
$ file dragon.jar
dragon.jar: Java archive data (JAR)

$ unzip -l dragon.jar
   43  META-INF/MANIFEST.MF
 1658  Main.class
```

Una sola clase, `Main.class`. No hace falta un descompilador externo: el propio JDK
trae `javap`, que desensambla el bytecode.

```bash
$ unzip -o dragon.jar
$ javap -c -p -constants Main.class
```

Partes relevantes del bytecode:

```text
public static java.lang.String ret();
   0: ldc  #7   // String r3v3rsing_p3rf3cted
   2: areturn

public static void main(java.lang.String[]);
   ...
   19: invokestatic #32  // Method ret:()Ljava/lang/String;   -> valor esperado
   38: invokevirtual #40 // Scanner.nextLine()                -> input usuario
   46: invokevirtual #43 // String.equals(...)                -> comparación
   49: ifeq 67
   55: ldc  #49 // String "Congratulations, the key is the flag!"
```

## Explotación

La lógica es trivial una vez desensamblada:

1. `ret()` devuelve la constante `r3v3rsing_p3rf3cted`.
2. `main()` pide una clave por teclado y la compara con el valor de `ret()`.
3. Si coinciden imprime *"Congratulations, the key is the flag!"*.

Es decir, **la key es la flag** y está incrustada en claro en el pool de constantes.

## Flag

```
r3v3rsing_p3rf3cted
```

> Si la plataforma exige formato, probar `flag{REDACTED}`.

## Conclusión

Para artefactos Java/Android no hace falta un desensamblador binario: `javap` (JDK) o
descompiladores como `jd-cli`, `procyon` o `cfr` recuperan la lógica al instante. La
"ofuscación" aquí era inexistente: la flag viaja como literal de cadena.
