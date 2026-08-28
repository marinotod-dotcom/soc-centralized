import { resolve } from 'node:path';
import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        sla_analytics: resolve(__dirname, 'sla_analytics.html'),
        coverage: resolve(__dirname, 'coverage.html'),
        action_plan: resolve(__dirname, 'action_plan.html'),
      },
    },
  },
});
