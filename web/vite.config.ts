import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { federation } from '@module-federation/vite';

export default defineConfig({
  // Served under /ui/ by the Nexus daemon (see cmd/daemon.go). Using './'
  // keeps all asset references relative to index.html so they resolve
  // correctly under any mount prefix.
  base: './',
  plugins: [
    vue({
      template: {
        compilerOptions: {
          isCustomElement: (tag) => tag.startsWith('wf-'),
        },
      },
    }),
    federation({
      name: 'nexus',
      filename: 'remoteEntry.js',
      exposes: {
        './index': './src/index.ts',
      },
      shared: {
        '@workfort/ui': { singleton: true, import: false },
        '@workfort/auth': { singleton: true, import: false },
      },
    }),
  ],
  build: {
    target: 'esnext',
    outDir: 'dist',
  },
});
