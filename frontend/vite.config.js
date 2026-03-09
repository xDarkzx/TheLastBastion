import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],
  server: {
    host: '0.0.0.0',
    port: 5173,
    watch: {
      usePolling: true,
    },
    allowedHosts: true,
    proxy: {
      '/m2m': 'http://api:8000',
      '/refinery': {
        target: 'http://api:8000',
        ws: true,
      },
      '/health': 'http://api:8000',
      '/sandbox': 'http://api:8000',
      '/anchoring': 'http://api:8000',
      '/demo-agent': 'http://api:8000',
      '/mcp': 'http://api:8000',
      '/ws': {
        target: 'http://api:8000',
        ws: true,
      },
    }
  }
})
