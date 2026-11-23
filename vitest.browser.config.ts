import { defineConfig } from 'vitest/config';

// Real-browser tests: `npm run test:browser`. Not part of `npm test` (see tests/real-browser/README.md).
export default defineConfig({
  test: {
    include: ['tests/real-browser/**/*.real.ts'],
    environment: 'node',
    pool: 'forks',
    globals: true,
    testTimeout: 60_000,
    hookTimeout: 60_000,
    fileParallelism: false,
  },
});
