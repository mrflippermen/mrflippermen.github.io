import { defineCollection, z } from 'astro:content';

// Writeups Collection - Strict Schema
const writeups = defineCollection({
    schema: z.object({
        title: z.string(),
        date: z.coerce.date(), // Coerce string to Date for consistency
        description: z.string().optional(),
        excerpt: z.string().default(''),
        tags: z.array(z.string()).default([]),
        platform: z.enum(['HTB', 'VulnHub', 'TryHackMe', 'CTF', 'Other']).optional(),
        difficulty: z.enum(['Easy', 'Medium', 'Hard', 'Insane']).optional(),
        image: z.string().optional(),
    }).strict(), // NO passthrough - strict schema
});

// Certifications Collection - Strict Schema
const certs = defineCollection({
    schema: z.object({
        title: z.string(),
        date: z.coerce.date(),
        description: z.string().optional(),
        level: z.string().optional(),
        platform: z.string().optional(),
        image: z.string().optional(),
        certId: z.string().optional(),
    }).strict(),
});

// Blog Posts Collection - Strict Schema
const posts = defineCollection({
    schema: z.object({
        title: z.string(),
        date: z.coerce.date(),
        excerpt: z.string().default(''),
        tags: z.array(z.string()).default([]),
        author: z.string().default('Esteban Jimenez'),
    }).strict(),
});

// Wiki Collection - Strict Schema
const wiki = defineCollection({
    schema: z.object({
        title: z.string(),
        description: z.string().optional(),
        image: z.string().optional(),
        date: z.coerce.date().optional(),
        category: z.enum(['AD', 'Web', 'Forensics', 'Exploitation', 'Other']).optional(),
    }).strict(),
});

export const collections = {
    writeups,
    certs,
    wiki,
    posts,
};
