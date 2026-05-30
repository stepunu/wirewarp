# WireWarp Web Dashboard

React/Vite dashboard for the WireWarp control plane.

## Stack

- React 19 + TypeScript
- Vite 7
- React Router 7
- TanStack Query v5
- Zustand for small client-side state
- Plain CSS in `src/styles.css`

## Development

Start the backend on `localhost:8100`, then:

```bash
npm install
npm run dev
```

Vite proxies `/api` and `/ws` to `http://localhost:8100`.

## Build

```bash
npm run build
```

By default the production bundle is written to
`../wirewarp-server/static`, where FastAPI serves it. Set `BUILD_OUT` to
override the output directory.

## Important Files

- `src/App.tsx` - route tree, auth token handling, role guards.
- `src/components/Layout.tsx` - shell, navigation, theme, command palette, help overlay.
- `src/lib/api.ts` - typed REST client.
- `src/lib/realtime.ts` - dashboard WebSocket and query invalidation map.
- `src/lib/types.ts` - frontend domain types.
- `src/pages/Security*.tsx` - security edge console pages.

There are no frontend tests in the current tree; CI validates this app by
running `npm run build`.
