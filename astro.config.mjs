import { defineConfig } from 'astro/config';
// import sitemap from '@astrojs/sitemap';

// https://astro.build/config
export default defineConfig({
    site: 'https://mrflippermen.github.io',
    base: '/',
    output: 'static',
    // Sitemap temporalmente deshabilitado por error en build
    // Se reactivará después de investigar el problema
    integrations: [],
});
