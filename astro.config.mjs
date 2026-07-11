import { defineConfig } from 'astro/config';

// https://astro.build/config
export default defineConfig({
    site: 'https://mrflippermen.github.io',
    base: '/',
    output: 'static',

    // Sitemap disabled — @astrojs/sitemap crashes with i18n routing in this version.
    // Re-enable after upgrading: npm update @astrojs/sitemap
    integrations: [],

    i18n: {
        defaultLocale: "es",
        locales: ["es", "en"],
        routing: {
            prefixDefaultLocale: true,
            strategy: 'pathname'
        }
    },

    markdown: {
        shikiConfig: {
            theme: 'github-dark',
            wrap: true,
        },
    },

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
