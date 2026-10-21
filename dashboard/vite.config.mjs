import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Every API route is proxied through the dashboard's own port, so the browser only ever talks to
// :5173. This makes hosted sandboxes (Manus, Codespaces, a remote VM) work with ONE exposed port.
const API_TARGET = process.env.API_TARGET || 'http://127.0.0.1:8000'
const proxy = Object.fromEntries(
  ['/health', '/ready', '/graph', '/incidents', '/actions', '/metrics', '/llm'].map((p) => [p, { target: API_TARGET, changeOrigin: true }]),
)

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, host: true, allowedHosts: true, proxy },
  preview: { port: 5173, host: true, allowedHosts: true, proxy },
  build: { outDir: 'dist', emptyOutDir: true },
})
