# Firewall Dashboard — Frontend (Day 14)

A read-only security review dashboard for the prompt-injection firewall.

## Security Design

| Property | Implementation |
|---|---|
| **Token storage** | Memory-only variable — never `localStorage`, `sessionStorage`, cookies, IndexedDB, or URL params |
| **Idle timeout** | 15-minute inactivity auto-logout (mouse/key/scroll/click resets the timer) |
| **XSS prevention** | Every API string passes through `SafeText` which replaces control chars, bidi overrides, zero-width chars with visible markers |
| **CSP** | Production build injects strict `Content-Security-Policy` (no `unsafe-inline`, no `unsafe-eval`) |
| **Network scope** | Loopback addresses only (`127.0.0.1`, `localhost`, `::1`) — enforced in `client.ts` before every request |
| **Fetch policy** | `credentials: "omit"`, `cache: "no-store"`, `referrerPolicy: "no-referrer"`, 10 s timeout, 5 MB body cap |
| **No CDN** | All assets are bundled locally by Vite — no remote fonts, icons, or analytics |

## Development

```bash
cd frontend
npm install

# Dev server  →  http://127.0.0.1:5173
npm run dev

# Full check: lint + typecheck + test + build
npm run check
```

## Generating Static Data

Run from the repo root (requires the Python venv active):

```bash
python scripts/export_openapi.py       # → frontend/src/api/openapi.json
python scripts/export_reason_codes.py  # → frontend/src/data/reason_codes.generated.json
```

## Token Roles

| Role | Access |
|---|---|
| `viewer` | Overview, Sessions list, Session detail, Audit chain verify |
| `reviewer` | All viewer endpoints plus approvals (Day 15) |

## Pages

| Route | Page |
|---|---|
| `/` | Overview — summary stats, top reason codes, audit chain verify |
| `/sessions` | Sessions — paginated table with Load more |
| `/sessions/:id` | Session detail — event timeline with event-type/action/tool filters |
| `/glossary` | Reason code glossary — searchable, categorised, plain-language descriptions |

## Project Structure

```
src/
├── api/          client.ts · token.ts · types.ts · openapi.json
├── context/      AuthContext.tsx
├── components/   SafeText · IdText · ActionBadge · ReasonCodeBadge
│                 Navbar · ErrorBanner · LoadingSpinner
├── pages/        Login · Overview · SessionsList · SessionDetail · Glossary
├── data/         reasonCodeDescriptions.ts · reason_codes.generated.json
├── styles/       global.css  (CSS variables, light/dark, all components)
├── test/         setup.ts
└── __tests__/    SafeText · token · client · sourceAudit · reasonCodeCoverage
```
