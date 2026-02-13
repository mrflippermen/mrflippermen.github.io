import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

// https://astro.build/config
export default defineConfig({
    site: 'https://mrflippermen.github.io',
    base: '/',
    output: 'static',

    i18n: {
        defaultLocale: "es",
        locales: ["es", "en"],
        routing: {
            prefixDefaultLocale: true,
            strategy: 'pathname'
        }
    },

    // Sitemap re-enabled with proper configuration
    // sitemap()

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
