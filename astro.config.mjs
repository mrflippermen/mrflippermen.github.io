import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

// https://astro.build/config
export default defineConfig({
    site: 'https://flippermen.github.io',
    base: '/',
    output: 'static',
    integrations: [sitemap()],
});
