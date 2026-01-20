import { defineConfig } from 'astro/config';
// import sitemap from '@astrojs/sitemap';

// https://astro.build/config
export default defineConfig({
    site: 'https://mrflippermen.github.io',
    base: '/',
    output: 'static',
    // Sitemap temporarily disabled due to persistent undefined reduce error
    // TODO: Investigate root cause - likely schema/frontmatter inconsistency
    // integrations: [
    //     sitemap({
    //         filter: (page) => !page.includes('/404'),
    //     })
    // ],
    integrations: [],
});
