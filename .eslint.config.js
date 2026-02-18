import js from '@eslint/js';
import globals from 'globals';

export default [
    js.configs.recommended,
    {
        ignores: ['html/**', 'docs/**'],
    },
    {
        files: ['**/*.js'],
        languageOptions: {
            ecmaVersion: 'latest',
            sourceType: 'module',
            globals: {
                ...globals.es2021,
                ...globals.node,
            }
        },
        rules: {
            'no-empty': ['error', { allowEmptyCatch: true }],
            'no-unused-vars': ['warn', { args: 'none' }],
            indent: ['error', 4, { SwitchCase: 1 }],
            'linebreak-style': ['error', 'unix'],
            quotes: ['error', 'single'],
            semi: ['error', 'always'],
        }
    },
];
