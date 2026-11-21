import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.{ts,tsx}', 'tests/**/*.test.{ts,tsx}'],
    environment: 'node',
    pool: 'forks',
    globals: true,
    // The seeded property and fuzz tests take a few seconds; a slow machine must not flake them.
    testTimeout: 30_000,
  },
});
