export default {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: {
    project: './etc/tsconfig.eslint.json',
  },
  extends: ['eslint:recommended', 'plugin:@typescript-eslint/strict-type-checked', 'prettier'],
  plugins: ['import', '@typescript-eslint'],
  rules: {
    '@typescript-eslint/no-non-null-assertion': 0,
    '@typescript-eslint/no-unused-vars': [
      'error',
      {
        varsIgnorePattern: '^_',
        argsIgnorePattern: '^_',
        caughtErrors: 'all',
        caughtErrorsIgnorePattern: '^_',
        destructuredArrayIgnorePattern: '^_',
      },
    ],
  },
  ignorePatterns: ['pnpm-lock.yaml', 'dist/'],
  settings: {
    'import/parsers': {
      '@typescript-eslint/parser': ['.ts'],
    },
    'import/resolver': {
      typescript: {},
    },
  },
};
