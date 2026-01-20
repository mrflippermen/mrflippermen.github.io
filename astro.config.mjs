import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

// https://astro.build/config
export default defineConfig({
    site: 'https://mrflippermen.github.io',
    base: '/',
    output: 'static',
    integrations: [
        sitemap({
            filter: (page) => !page.includes('/draft/'),
            customPages: [],
            i18n: undefined,
        })
    ],
});
