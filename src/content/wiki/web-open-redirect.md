---
title: "Open Redirect"
description: "Redirección a un destino controlado por el atacante por validación débil del parámetro de retorno (?next=, ?url=, ?redirect=)."
category: "Web"
date: 2026-07-18
---
# ↪️ Open Redirect

Redirección a un destino controlado por el atacante por validación débil del parámetro de retorno (`?next=`, `?url=`, `?redirect=`).

## Bypasses típicos

```
//evil.com
https:evil.com
/\evil.com
@evil.com
trusted.com.evil.com      # Subdominio falso
trusted.com%23.evil.com   # Fragment confusion
trusted.com%2Feval        # Path traversal en redirect
trusted.com\@evil.com     # Credential confusion
```

## Chaining (por qué importa)

| Chain | Impacto |
|-------|---------|
| Open Redirect + OAuth → ATO | Robo de authorization code vía redirect_uri laxo |
| Open Redirect + Cache Poisoning | Cachea página con redirect malicioso |
| Open Redirect + Phishing | Página legítima redirige a login falso |
| Open Redirect + SSRF | Redirect de un server a metadata interno |

## Relacionado

- **Autenticacion Web** — OAuth redirect_uri manipulation
- **Cache Poisoning y Web Cache Deception** — redirect cache poisoning
- **CSRF moderno** — SameSite bypass via redirect
- **Host Header Injection** — redirect basado en Host
- **Metodologia Bug Bounty**
- **SSRF** — redirección a metadata endpoints
- **Claude-BugHunter** (skill `hunt-open-redirect`)
