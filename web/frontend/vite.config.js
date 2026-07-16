import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import compression from 'vite-plugin-compression'

const backendUrl = process.env.VITE_BACKEND_URL || `http://localhost:${process.env.VITE_API_PORT || '47291'}`;
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
    port: parseInt(process.env.VITE_FRONTEND_PORT || '47292'),
    proxy: {
      '/api': { target: backendUrl, changeOrigin: true },
      '/ws':  { target: wsUrl, ws: true },
    },
  },
  build: {
    chunkSizeWarningLimit: 2000,
  },
})
