import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';

// Custom sitemap: @astrojs/sitemap crashes with this version's i18n routing,
// so we enumerate the real routes (both locales) by hand. Keep in sync with
// src/pages/[lang]/** — only routes that actually render belong here.
const LOCALES = ['es', 'en'] as const;
const STATIC_PATHS = ['', 'about', 'contact', 'cyberflipper', 'osint', 'certs', 'wiki', 'writeups'];
const COLLECTIONS = ['writeups', 'certs', 'wiki'] as const;

export const GET: APIRoute = async ({ site }) => {
  const origin = (site?.toString() ?? 'https://mrflippermen.github.io/').replace(/\/$/, '');
  const today = new Date().toISOString().slice(0, 10);

  const paths = new Set<string>();
  for (const lang of LOCALES) {
    for (const p of STATIC_PATHS) paths.add(`/${lang}${p ? `/${p}` : '/'}`);
    for (const col of COLLECTIONS) {
      for (const entry of await getCollection(col)) {
        paths.add(`/${lang}/${col}/${entry.slug}`);
      }
    }
  }

  const urls = [...paths]
    .sort()
    .map((p) => `  <url><loc>${origin}${p}</loc><lastmod>${today}</lastmod></url>`)
    .join('\n');

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls}
</urlset>`;

  return new Response(xml, {
    headers: { 'Content-Type': 'application/xml; charset=utf-8' },
  });
};
