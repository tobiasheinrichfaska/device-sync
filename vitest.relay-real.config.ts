import { defineConfig } from 'vitest/config';

// Opt-in: runs against the real relay server in RELAY_REAL_PATH (see tests/relay-real/).
export default defineConfig({
  test: {
    include: ['tests/relay-real/**/*.real.test.ts'],
    environment: 'node',
    pool: 'forks',
    globals: true,
    testTimeout: 120_000,
    fileParallelism: false,
  },
});
