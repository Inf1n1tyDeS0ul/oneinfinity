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
    // Raise the warning threshold — we're intentionally splitting
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        manualChunks(id) {
          // React core — tiny, cached forever
          if (id.includes('node_modules/react/') ||
              id.includes('node_modules/react-dom/') ||
              id.includes('node_modules/react-router')) {
            return 'vendor-react'
          }
          // 3-D graph + Three.js — large, rarely changes
          if (id.includes('node_modules/three') ||
              id.includes('node_modules/react-force-graph') ||
              id.includes('node_modules/three-spritetext')) {
            return 'vendor-three'
          }
          // Recharts — medium, rarely changes
          if (id.includes('node_modules/recharts') ||
              id.includes('node_modules/d3') ||
              id.includes('node_modules/victory')) {
            return 'vendor-charts'
          }
          // Everything else in node_modules → shared vendor chunk
          if (id.includes('node_modules/')) {
            return 'vendor-misc'
          }
        },
      },
    },
  },
})
