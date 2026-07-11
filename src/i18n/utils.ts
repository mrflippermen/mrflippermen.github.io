export const languages = {
    en: 'English',
    es: 'Español',
};

export const defaultLang = 'es';

export const ui = {
    en: {
        'nav.home': 'Home',
        'nav.about': 'Identity',
        'nav.writeups': 'Ops Log',
        'nav.certs': 'Credentials',
        'nav.wiki': 'Wiki',
        'nav.contact': 'Comms',
        'nav.cyberflipper': 'CyberFlipper',

        // Dashboard
        'role.red': 'RED TEAM OPERATOR',
        'role.blue': 'BLUE TEAM OPERATOR & SOC',
        'role.purple': 'PURPLE TEAM STRATEGIST',
        'system.status': 'SYSTEM OPERATIONAL',
        'card.identity': 'IDENTITY',
        'card.identity.desc': 'Executive Profile',
        'card.ops': 'OPERATIONS',
        'card.ops.desc': 'Mission Logs',
        'card.arsenal': 'ARSENAL',
        'card.arsenal.desc': 'Credentials',
        'card.intel': 'INTELLIGENCE',
        'card.intel.desc': 'Knowledge Base',
        'card.unit': 'CYBERFLIPPER',
        'card.unit.desc': 'Special Unit',
        'footer.encrypted': '> ENCRYPTED CONNECTION ESTABLISHED',

        // Writeup detail page
        'writeup.back': 'Back to Ops Log',
        'writeup.prev': 'Previous',
        'writeup.next': 'Next',
        'writeup.toc': 'Contents',
        'writeup.platform': 'Platform',
        'writeup.difficulty': 'Difficulty',
        'writeup.date': 'Date',
        'writeup.tags': 'Tags',
        'writeup.disclaimer': 'Performed in authorized environments. Educational purposes only.',

        // Contact
        'contact.channel': 'Secure channel open. Send your proposal.',
        'contact.email': 'EMAIL',
        'contact.github': 'GITHUB',
        'contact.linkedin': 'LINKEDIN',
        'contact.htb': 'HACK THE BOX',
    },
    es: {
        'nav.home': 'Inicio',
        'nav.about': 'Identidad',
        'nav.writeups': 'Registro Ops',
        'nav.certs': 'Credenciales',
        'nav.wiki': 'Wiki',
        'nav.contact': 'Comunicaciones',
        'nav.cyberflipper': 'CyberFlipper',

        // Dashboard
        'role.red': 'OPERADOR RED TEAM',
        'role.blue': 'OPERADOR BLUE TEAM & SOC',
        'role.purple': 'ESTRATEGA PURPLE TEAM',
        'system.status': 'SISTEMA OPERATIVO',
        'card.identity': 'IDENTIDAD',
        'card.identity.desc': 'Perfil Ejecutivo',
        'card.ops': 'OPERACIONES',
        'card.ops.desc': 'Bitácora de Misión',
        'card.arsenal': 'ARSENAL',
        'card.arsenal.desc': 'Credenciales',
        'card.intel': 'INTELIGENCIA',
        'card.intel.desc': 'Base de Conocimiento',
        'card.unit': 'CYBERFLIPPER',
        'card.unit.desc': 'Unidad Especial',
        'footer.encrypted': '> CONEXIÓN ENCRIPTADA ESTABLECIDA',

        // Writeup detail page
        'writeup.back': 'Volver al Registro',
        'writeup.prev': 'Anterior',
        'writeup.next': 'Siguiente',
        'writeup.toc': 'Contenido',
        'writeup.platform': 'Plataforma',
        'writeup.difficulty': 'Dificultad',
        'writeup.date': 'Fecha',
        'writeup.tags': 'Tags',
        'writeup.disclaimer': 'Realizado en entornos autorizados. Solo con fines educativos.',

        // Contact
        'contact.channel': 'Canal seguro abierto. Envía tu propuesta.',
        'contact.email': 'CORREO',
        'contact.github': 'GITHUB',
        'contact.linkedin': 'LINKEDIN',
        'contact.htb': 'HACK THE BOX',
    },
} as const;

export function getLangFromUrl(url: URL) {
    const [, lang] = url.pathname.split('/');
    if (lang in languages) return lang as keyof typeof languages;
    return defaultLang;
}

export function useTranslations(lang: keyof typeof ui) {
    return function t(key: keyof typeof ui[typeof defaultLang]) {
        return ui[lang][key] || ui[defaultLang][key];
    }
}
