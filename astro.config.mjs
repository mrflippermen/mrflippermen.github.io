import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

// https://astro.build/config
export default defineConfig({
    site: 'https://mrflippermen.github.io',
    base: '/',
    output: 'static',

    // Sitemap re-enabled with proper configuration
    integrations: [
        sitemap({
            filter: (page) => !page.includes('/404'),
            serialize(item) {
                // Ensure lastmod is always a valid date
                item.lastmod = new Date();
                return item;
            }
        })
    ],

    // Vite optimization for production builds
    vite: {
        build: {
            cssCodeSplit: true,
            minify: 'esbuild',
            rollupOptions: {
                output: {
                    manualChunks: undefined,
                }
            }
        }
    },
});
