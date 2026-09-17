import { defineConfig } from 'vite';

// Local assets only. No React/Babel plugin, project-selected config, or remote fonts.
export default defineConfig({
  clearScreen: false,
  envDir: false,
  envPrefix: 'VITE_MRK_',
  publicDir: false,
  esbuild: { jsx: 'automatic' },
  css: { postcss: { plugins: [] } },
  server: {
    host: '127.0.0.1',
    port: 1420,
    strictPort: true,
    fs: { strict: true },
  },
  build: {
    target: ['es2022', 'chrome110', 'safari16'],
    outDir: 'dist',
    emptyOutDir: false,
    sourcemap: false,
    reportCompressedSize: false,
  },
});
