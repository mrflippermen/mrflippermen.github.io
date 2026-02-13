import en from './en.json';
import es from './es.json';

export const languages = {
    en: 'English',
    es: 'Español',
};

export const defaultLang = 'es';

export const ui = {
    en,
    es,
} as const;
