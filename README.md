# FLIPPERMEN — Cyber Operations Portfolio

Offensive security portfolio documenting Red Team operations, Active Directory exploitation, CTF campaigns, certifications, and technical research. Dark terminal aesthetic, bilingual (ES/EN), deployed as static site.

## Tech Stack

- **Framework:** [Astro 4](https://astro.build) — static site generation
- **Styling:** SCSS + centralized design tokens (`_tokens.scss`)
- **Content:** Markdown collections with Zod-validated frontmatter
- **Icons:** Font Awesome 6 (CDN) + custom inline SVG components
- **Deployment:** GitHub Pages via GitHub Actions

## Quick Start

### Prerequisites

- Node.js 20.19.6 (see `.nvmrc`)
- npm

### Commands

```bash
npm install          # Install dependencies
npm run dev          # Dev server → http://localhost:4321
npm run build        # Static build to /dist
npm run preview      # Preview production build locally
```

## Project Structure

```
mrflippermen.github.io/
├── src/
│   ├── components/          # Astro components
│   │   ├── about/           # About page sections
│   │   ├── CommandHeader.astro
│   │   ├── Icon.astro       # Inline SVG icons
│   │   ├── SEOHead.astro
│   │   └── TimelineItem.astro
│   ├── layouts/
│   │   └── BaseLayout.astro # Global shell, CSP, fonts, FA CDN
│   ├── pages/
│   │   ├── index.astro      # Landing / redirect
│   │   └── [lang]/          # i18n routes (es/, en/)
│   │       ├── index.astro
│   │       ├── about.astro
│   │       ├── cyberflipper.astro
│   │       ├── contact.astro
│   │       ├── writeups/    # CTF log index + detail
│   │       ├── certs/       # Certifications index + detail
│   │       └── wiki/        # Technical wiki index + detail
│   ├── content/             # Markdown collections
│   │   ├── writeups/        # CTF and HTB machine writeups
│   │   ├── certs/           # Certifications and Pro Labs
│   │   ├── guides/          # Technical guides
│   │   ├── wiki/            # AD, forensics, exploitation wiki
│   │   └── config.ts        # Zod schemas for all collections
│   ├── i18n/
│   │   └── utils.ts         # Translations and locale routing
│   └── styles/
│       ├── _tokens.scss     # Design tokens — single source of truth
│       └── global.scss      # Base styles, animations, layout
├── public/
│   ├── images/              # Static images
│   ├── favicon.svg
│   ├── robots.txt
│   └── .nojekyll            # Required for GitHub Pages
├── .github/workflows/
│   └── deploy.yml           # CI/CD to GitHub Pages
└── astro.config.mjs
```

## Key Design Decisions

- **Design tokens** — all colors, spacing, typography defined once in `_tokens.scss`. Zero hardcoded values in components.
- **Bilingual** — Spanish default, English fallback. Path-prefixed i18n via Astro's built-in routing.
- **Content collections** — type-safe frontmatter with Zod schemas for writeups, certifications, guides, and wiki entries.
- **Dark terminal aesthetic** — circuit-grid background, scanline overlay, mono display font, faction-based color coding (red/blue/purple teams).
- **Performance** — inline SVG icons, preloaded Google Fonts, static assets via `public/`.

## Content Management

### Writeup

```yaml
---
title: "Machine Name - HTB"
date: 2024-01-15
excerpt: "Brief description"
tags: ["Web", "PrivEsc", "Linux"]
difficulty: "Medium"       # Easy | Medium | Hard | Insane
platform: "HTB"            # HTB | VulnHub | TryHackMe | CTF | Fluid | CWL | Custom
image: "/images/blog/file.png"
---
```

### Certification

```yaml
---
title: "Certification Name"
date: 2024-01-15
level: "Advanced"
platform: "Hack The Box"
image: "/images/about/file.png"
category: "Red Team"
tags: ["AD", "Exploitation"]
---
```

### Wiki entry

```yaml
---
title: "Attack Technique"
description: "Brief overview"
category: "AD"             # AD | Web | Forensics | Exploitation | Other
date: 2024-01-15
image: "/images/wiki/1.png"
---
```

## Styling

DO:
- Use CSS custom properties from `_tokens.scss` — `var(--red-team)`, `var(--text-muted)`, etc.
- Use faction colors semantically — red for offensive, blue for defensive, purple for hybrid.

DON'T:
- Hardcode raw color values in component styles.
- Use inline styles.

## Deployment

Push to `main` → GitHub Actions builds and deploys to:

```
https://mrflippermen.github.io/
```

Spanish default: `/es/` — English: `/en/` — Root redirects to `/es/`.

---

MIT © 2026 mrflippermen
