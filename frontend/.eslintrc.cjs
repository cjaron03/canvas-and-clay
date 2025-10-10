module.exports = {
  extends: ['eslint:recommended'],
  parserOptions: {
    ecmaVersion: 2020,
    sourceType: 'module'
  },
  env: {
    browser: true,
    es2017: true,
    node: true
  },
  overrides: [
    {
      files: ['**/*.svelte'],
      parser: 'svelte-eslint-parser',
      parserOptions: {
        parser: {
          js: 'espree',
          ts: '@typescript-eslint/parser'
        }
      }
    }
  ]
};
