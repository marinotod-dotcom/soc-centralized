import { resolve } from 'node:path';
import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    rollupOptions: {
      input: {
        main: resolve(import.meta.dirname, 'index.html'),
        sla_analytics: resolve(import.meta.dirname, 'sla_analytics.html'),
        coverage: resolve(import.meta.dirname, 'coverage.html'),
        action_plan: resolve(import.meta.dirname, 'action_plan.html'),
      },
    },
  },
});
