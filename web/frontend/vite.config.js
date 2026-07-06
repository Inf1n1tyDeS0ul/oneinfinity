import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import compression from 'vite-plugin-compression'

const backendUrl = process.env.VITE_BACKEND_URL || 'http://localhost:8000';
const wsUrl = backendUrl.replace(/^http/, 'ws');

export default defineConfig({
  plugins: [
    react(),
    // Generate .gz alongside every asset — FastAPI StaticFiles serves them
    // automatically when the browser sends Accept-Encoding: gzip
    compression({ algorithm: 'gzip', ext: '.gz', threshold: 1024 }),
  ],
  server: {
    host: '0.0.0.0',
    port: 3000,
    proxy: {
      '/api': { target: backendUrl, changeOrigin: true },
      '/ws':  { target: wsUrl, ws: true },
    },
  },
  build: {
    chunkSizeWarningLimit: 1500,
    rollupOptions: {
      output: {
        manualChunks(id) {
          // React core — no circular deps, safe to isolate, cached forever
          if (id.includes('node_modules/react/') ||
              id.includes('node_modules/react-dom/') ||
              id.includes('node_modules/react-router') ||
              id.includes('node_modules/scheduler/')) {
            return 'vendor-react'
          }
          // All other node_modules → single vendor chunk (avoids circular splits)
          if (id.includes('node_modules/')) {
            return 'vendor'
          }
        },
      },
    },
  },
})
