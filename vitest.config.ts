import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.{ts,tsx}', 'tests/**/*.test.{ts,tsx}'],
    // The tests against the real relay server are opt-in: `npm run test:relay-real`.
    exclude: [...configDefaults.exclude, '**/*.real.test.ts'],
    environment: 'node',
    pool: 'forks',
    globals: true,
    // The seeded property and fuzz tests take a few seconds; a slow machine must not flake them.
    testTimeout: 30_000,
  },
});
