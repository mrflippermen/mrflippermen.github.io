import { defineCollection, z } from 'astro:content';

// Writeups Collection
const writeups = defineCollection({
    schema: z.object({
        title: z.string(),
        date: z.coerce.date(),
        description: z.string().optional(),
        excerpt: z.string().default(''),
        tags: z.array(z.string()).default([]),
        platform: z.enum([
            'HTB', 'VulnHub', 'TryHackMe', 'CTF',
            'Fluid', 'CWL', 'Custom', 'Other'
        ]).optional(),
        difficulty: z.enum(['Easy', 'Medium', 'Hard', 'Insane']).optional(),
        image: z.string().optional(),
    }).strict(),
});

// Certifications Collection — Solo certifications y Pro Labs completados
const certs = defineCollection({
    schema: z.object({
        title: z.string(),
        date: z.coerce.date(),
        description: z.string().optional(),
        level: z.string().optional(),
        platform: z.string().optional(),
        image: z.string().optional(),
        certId: z.string().optional(),
        category: z.string().optional(),
        duration: z.string().optional(),
        tags: z.array(z.string()).default([]),
    }).strict(),
});

// Guides Collection — Cheat sheets, guías técnicas, referencias de herramientas
const guides = defineCollection({
    schema: z.object({
        title: z.string(),
        date: z.coerce.date().optional(),
        description: z.string().optional(),
        category: z.enum([
            'Active Directory', 'Web', 'Pwn', 'Forensics',
            'OSINT', 'Cloud', 'Red Team', 'Blue Team', 'Other'
        ]).optional(),
        tags: z.array(z.string()).default([]),
        image: z.string().optional(),
    }),
});

// Wiki Collection
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
    guides,
    wiki,
};
