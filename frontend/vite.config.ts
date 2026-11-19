import { defineConfig, Plugin } from 'vite';
import react from '@vitejs/plugin-react';

function strictCspPlugin(): Plugin {
  return {
    name: 'html-strict-csp',
    transformIndexHtml(html, ctx) {
      if (!ctx || !ctx.bundle) {
        // In dev mode, Vite uses inline module scripts and HMR websockets
        return html;
      }
      // Production build CSP: no 'unsafe-inline', no 'unsafe-eval'
      const cspMeta = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' http://127.0.0.1:* http://localhost:*; frame-ancestors 'none'; base-uri 'none'; form-action 'none';">`;
      return html.replace('<head>', `<head>\n    ${cspMeta}`);
    },
  };
}

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), strictCspPlugin()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    coverage: {
      provider: 'v8',
    },
  },
} as any);
