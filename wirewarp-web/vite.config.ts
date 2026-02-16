import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: process.env.BUILD_OUT || '../wirewarp-server/static',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/api': 'http://localhost:8100',
      '/ws': {
        target: 'ws://localhost:8100',
        ws: true,
      },
    },
  },
})
