/// <reference types="vitest" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Cabeceras solo de desarrollo. En produccion las pone `src/server/app.js`,
// que es quien sirve `web/dist`; estas solo protegen el origen del servidor de
// Vite mientras se desarrolla.
const headers = {
  'X-Content-Type-Options': 'nosniff',
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
}

export default defineConfig({
  plugins: [react()],
  server: {
    headers,
    proxy: { '/api': { target: 'http://127.0.0.1:4310', changeOrigin: true, secure: false } }
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}']
  }
})