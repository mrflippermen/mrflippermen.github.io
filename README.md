# 🚀 Flippermen Portfolio

Personal cybersecurity portfolio showcasing Red Team operations, certifications, and technical writeups.

## 🛠️ Tech Stack

- **Framework:** [Astro 4.0](https://astro.build) - Modern static site generator
- **Styling:** SCSS with centralized design tokens
- **Content:** Markdown-based collections with frontmatter validation
- **Deployment:** GitHub Pages via GitHub Actions CI/CD
- **Icons:** Custom SVG components (replaced Font Awesome for performance)

## 🏃 Quick Start

### Prerequisites
- Node.js v20.19.6 (see `.nvmrc`)
- npm or yarn

### Development

```bash
# Install dependencies
npm install

# Start dev server (default: http://localhost:4321)
npm run dev
```

### Build

```bash
# Generate static site to /dist
npm run build

# Preview production build locally
npm run preview
```

## 📁 Project Architecture

```
mrflippermen.github.io/
├── src/
│   ├── components/          # Reusable Astro components
│   │   ├── SEOHead.astro   # Meta tags & OG
│   │   ├── CommandHeader.astro
│   │   └── ...
│   ├── layouts/             # Page layouts
│   │   └── BaseLayout.astro
│   ├── pages/               # Route endpoints
│   │   ├── index.astro     # Landing page
│   │   ├── about.astro
│   │   ├── writeups/
│   │   └── certs/
│   ├── content/             # Markdown collections
│   │   ├── writeups/       # CTF/HTB writeups
│   │   ├── certs/          # Certifications
│   │   ├── posts/          # Blog posts
│   │   └── config.ts       # Content schemas
│   └── styles/
│       ├── _tokens.scss    # **Single source of truth for design**
│       └── global.scss
├── public/                  # Static assets
│   ├──images/
│   └── robots.txt
└── astro.config.mjs         # Astro configuration
```

### Key Design Decisions

- **Design Tokens (`_tokens.scss`):** All colors, spacing, typography defined once. Zero hardcoded values in components.
- **Content Collections:** Type-safe frontmatter validation with Zod schemas.
- **Performance First:** Inline SVG icons, preloaded fonts, optimized images.

## 📝 Content Management

### Adding a New Writeup

1. Create file in `src/content/writeups/YYYY-MM-DD-machinename.md`
2. Add frontmatter:
```yaml
---
title: "Machine Name - HTB"
date: 2024-01-15
excerpt: "Brief description"
tags: ["Web", "PrivEsc", "Linux"]
difficulty: "Medium"  # Easy | Medium | Hard | Insane
platform: "HTB"       # HTB | VulnHub | TryHackMe
---
```
3. Write content in markdown
4. Build to validate: `npm run build`

### Adding a Certification

1. Create file in `src/content/certs/certname.md`
2. Add frontmatter:
```yaml
---
title: "Certification Name"
date: 2024-01-15
level: "Advanced"
platform: "Hack The Box"
image: "/images/certs/certname.jpg"
---
```

## 🎨 Styling Guide

**DO:**
- Use CSS custom properties from `_tokens.scss`
- Example: `color: var(--neon-green);`

**DON'T:**
- Hardcode colors: `color: #00ff41;` ❌
- Use inline styles

## 🚀 Deployment

Site automatically deploys to [mrflippermen.github.io](https://mrflippermen.github.io) on push to `main` via GitHub Actions.

Workflow: `.github/workflows/deploy.yml`

##License

MIT © 2026 mrflippermen

---

**Built with discipline. Deployed with precision.**
