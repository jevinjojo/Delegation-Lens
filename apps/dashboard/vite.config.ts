import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1', // MUST match the backend's allowed origin
    port: 5173,
    strictPort: true,  // fail loudly instead of silently picking another port
  },
})