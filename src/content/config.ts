import { defineCollection, z } from 'astro:content';

const writeups = defineCollection({
    schema: z.object({
        title: z.string(),
        date: z.date().optional(),
        excerpt: z.string().optional(),
        tags: z.array(z.string()).optional(),
        // Allow loose schema to accommodate Jekyll legacy frontmatter
    }).passthrough(),
});

const certs = defineCollection({
    schema: z.object({
        title: z.string(),
        date: z.date().optional(),
        // Allow loose schema
    }).passthrough(),
});

const posts = defineCollection({
    schema: z.object({
        title: z.string(),
        date: z.date().optional(),
    }).passthrough(),
});

const wiki = defineCollection({
    schema: z.object({
        title: z.string(),
        description: z.string().optional(),
        image: z.string().optional(),
        date: z.date().optional(),
    }).passthrough(),
});

export const collections = {
    writeups,
    certs,
    wiki,
    posts,
};
