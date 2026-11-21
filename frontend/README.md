# ThreatSentinel console

React 18 and Vite frontend for the ThreatSentinel SOC agent. It uses a light terminal design: paper background, hairline rules, Archivo for headings and IBM Plex Mono for data.

## Run it

You need Node 20 and the API on `http://localhost:8000`.

```bash
npm ci
npm run dev      # http://localhost:3000, proxies /api and /health to :8000
npm run build    # static bundle in build/
```

`VITE_API_URL` sets the API base at build time and defaults to `http://localhost:8000/api/v1`.

## Authentication

The bundle contains no token. If the API answers 401, the console opens a token prompt, which you can also reach from Session / Token in the header. Paste the server's `SECRET_KEY`. It goes into `sessionStorage` for that tab and is sent as a Bearer header on every request. The console never writes it to `localStorage` or a URL. The live metrics WebSocket sends it as its first message.

`VITE_API_TOKEN` exists for build-time injection in private deployments. Don't set it for anything public, because every visitor can read it from the bundle.

## Layout

- `src/context/ThreatSentinelContext.jsx` holds the axios client, auth state, global counters and the shared mutations.
- `src/components/ui.jsx` has presentational pieces such as badges, stat strips, panels and formatters. It does no data fetching.
- `src/pages/` has one file per route. Each page fetches its own data, so it works on refresh or from a pasted link. Filters live in the query string.

Navigation is one flat level: Overview, Investigations, Reports, Monitoring, Integrations, Tasks, Audit. Detail pages are `/investigations/:id` and `/reports/:id?format=`.
