import { defineConfig, loadEnv, Plugin } from 'vite';
import react from '@vitejs/plugin-react';

function strictCspPlugin(apiOrigin: string): Plugin {
  return {
    name: 'html-strict-csp',
    transformIndexHtml(html, ctx) {
      if (!ctx || !ctx.bundle) {
        // In dev mode, Vite uses inline module scripts and HMR websockets
        return html;
      }
      // Production build CSP: no 'unsafe-inline', no 'unsafe-eval'
      const cspMeta = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' ${apiOrigin}; frame-ancestors 'none'; base-uri 'none'; form-action 'none';">`;
      return html.replace('<head>', `<head>\n    ${cspMeta}`);
    },
  };
}

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const apiOrigin = new URL(env.VITE_API_BASE_URL || 'http://127.0.0.1:8000').origin;
  return {
  plugins: [react(), strictCspPlugin(apiOrigin)],
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
  } as any;
});
