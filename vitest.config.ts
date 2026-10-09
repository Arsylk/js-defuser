import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    // Two workers: each fixture suite runs whole programs through the engine
    // and a VM, and a laptop does not want a dozen of those at once.
    maxWorkers: 2,
  },
});
