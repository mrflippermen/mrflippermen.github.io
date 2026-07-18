---
title: "Subdomain Takeover y Reconocimiento Web"
description: "El subdomain takeover ocurre cuando un subdominio apunta a un recurso cloud (S3, Heroku, Vercel, GitHub Pages) que ha sido eliminado, pero el registro DNS sigue…"
category: "Web"
date: 2026-07-18
---
# 🌐 Subdomain Takeover y Reconocimiento Web

El subdomain takeover ocurre cuando un subdominio apunta a un recurso cloud (S3, Heroku, Vercel, GitHub Pages) que ha sido eliminado, pero el **registro DNS sigue activo**. Cualquiera puede reclamar el recurso y tomar control del subdominio.

---

## ¿Por qué funciona?

```
dev.company.com  →  CNAME  →  ejemplo-app.vercel.app
                                          ↓
                              Vercel resource eliminado ❌
                                          ↓
                              Atacante registra ejemplo-app.vercel.app ✨
                                          ↓
                              Atacante controla dev.company.com 😈
```

El impacto incluye robo de cookies, phishing, bypass de CSP/CORS, y malware hosting.

---

## Fase 1: Enumeración de subdominios

### Pasivos (sin tráfico directo al target)

```bash
# Certificate Transparency (la fuente más completa)
curl -s 'https://crt.sh/?q=%25.target.com&output=json' | jq -r '.[].name_value' | sort -u

# Subfinder
subfinder -d target.com -all -silent -o subs.txt

# Assetfinder
assetfinder --subs-only target.com > assetfinder.txt

# Amass (modo pasivo)
amass enum -passive -d target.com -src

# GitHub
github-subdomains -d target.com -t <github_token>
```

### Activos

```bash
# Amass completo (incluye brute force)
amass enum -active -d target.com -brute -o subs.txt

# Resolución DNS y validación de alive
cat subs.txt | dnsx -silent -a -resp | tee ips.txt
cat subs.txt | httpx -silent -sc -title -tech-detect -o alive.txt
```

### Fuentes adicionales

```
# Wayback Machine
curl "https://web.archive.org/cdx/search/cdx?url=*.target.com&output=json" | jq

# SecurityTrails API
curl "https://api.securitytrails.com/v1/domain/target.com/subdomains" -H "APIKEY: x"

# DNS Dumpster (https://dnsdumpster.com)
# VirusTotal
https://virustotal.com/api/v3/domains/target.com/subdomains
```

---

## Fase 2: Detección de Takeover

```bash
# Subjack
subjack -w subs.txt -t 100 -timeout 30 -o takeover.txt

# Subzy
subzy run --targets subs.txt --timeout 5000 --hide_fails

# Nuclei
nuclei -l subs.txt -t ~/nuclei-templates/takeovers/

# httpx + fingerprints
httpx -l subs.txt -silent -ports 80,443 -cdn -cname -o cnames.txt
```

### Fingerprints por servicio

| Servicio | CNAME/Dominio | Fingerprint Response |
|----------|--------------|---------------------|
| **AWS S3** | `s3.amazonaws.com` | `NoSuchBucket` |
| **AWS CloudFront** | `cloudfront.net` | `x-amz-cf-id` |
| **Azure** | `azurewebsites.net` | `404 Not Found (Web App)` |
| **GitHub Pages** | `github.io` | `404 There isn't a GitHub Pages site here` |
| **Heroku** | `herokuapp.com` | `No such app` |
| **Vercel** | `vercel-dns.com` / `vercel.app` | `404: NOT_FOUND` |
| **Netlify** | `netlify.app` | `Not Found - Request ID:` |
| **Shopify** | `myshopify.com` | `Sorry, this shop is currently unavailable` |

---

## Fase 3: Content Discovery

```bash
# Directory fuzzing
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt

#JS endpoint extraction
cat alive.txt | katana -jc -js-crawl -o endpoints.txt

# Wayback URLs
gau --subs target.com | grep -E '\.js$|\.json$|\.yaml$|\.env$|\.git$'

# Parameter discovery
cat endpoints.txt | httpx -silent -path "/robots.txt" -path "/sitemap.xml" -path "/.well-known/"

# Secret scanning
cat all.js | grep -E '(aws|AKIA[A-Z0-9]{16}|ghp_|gho_|sk-[a-zA-Z0-9]{32})'
```

---

## Fase 4: Tecnología y fingerprinting

```bash
# Wappalyzer CLI
cat alive.txt | wappalyzer -o tech.json

# WhatWeb
whatweb -i alive.txt --log-verbose=tech.txt

# Nuclei tech detection
nuclei -l alive.txt -t ~/nuclei-templates/technologies/
```

---

## Automatización completa

```bash
#!/bin/bash
DOMAIN=$1
subfinder -d $DOMAIN -silent | tee subs.txt
assetfinder --subs-only $DOMAIN >> subs.txt
cat subs.txt | sort -u > all_subs.txt
httpx -l all_subs.txt -silent -sc -title -tech-detect -o alive.txt
subjack -w all_subs.txt -t 100 -ssl | tee takeover_results.txt
nuclei -l alive.txt -t ~/nuclei-templates/takeovers/ | tee nuclei_takeover.txt
```

## Chaining

Subdomain takeover + OAuth redirect_uri → ATO
Subdomain takeover + cookie injection → bypass doble-submit CSRF
Subdomain takeover + CSP trust → data exfiltration

## Relacionado
- **Cache Poisoning y Web Cache Deception** — WCD via subdomain paths
- **CORS Misconfiguration** — subdomain trust bypass
- **CSRF moderno** — SameSite=Lax bypass via sibling subdomain
- **Host Header Injection** — routing-based SSRF via Host
- **Metodologia Bug Bounty**
- **SSRF** — metadata discovery via subdomain enumeration
- **communitytools - Recon y Engagements**
- **Claude-BugHunter** (skill `bb-local-toolkit`)
- **Herramientas**
