# Network Incident Diagnosis: frontend

Next.js 16 and Tailwind CSS 4 workspace for the FastAPI backend in `../backend`. It implements the
"Network diagnosis · Incident workspace" design and calls every backend operation.

## Run it

1. Start the backend (from `../backend`):

   ```bash
   AUTH_TOKENS_FILE=var/auth/tokens.json .venv/bin/uvicorn app.main:app --port 8000
   ```

2. Issue a token (shown once). Use `operator` to run diagnoses, `incident_manager` to also confirm, verify,
   close and update escalations, or `viewer` for read-only:

   ```bash
   AUTH_TOKENS_FILE=var/auth/tokens.json .venv/bin/python -m app.security.tokens issue \
     --subject noc.manager --kind human --role incident_manager --expires-hours 24
   ```

3. Start the frontend (from this folder):

   ```bash
   cp .env.example .env.local   # once
   npm install
   npm run dev                  # http://localhost:3000
   ```

4. Open http://localhost:3000 and paste the token. It is verified with `POST /auth/verify` and kept in
   session storage for this tab only.

The backend's `CORS_ORIGINS` defaults to `http://localhost:3000,http://127.0.0.1:3000`, so run the frontend on
port 3000 or add your origin there.

| Variable | Default | Used for |
| --- | --- | --- |
| `NEXT_PUBLIC_API_BASE_URL` | `http://127.0.0.1:8000` | Backend address (can also be changed on the sign-in page) |
| `NEXT_PUBLIC_WORKSPACE_NAME` | `HCL Tech` | Sidebar workspace card |
| `NEXT_PUBLIC_WORKSPACE_SCOPE` | `NOC · Production` | Sidebar workspace card |

## Scripts

| Command | What it does |
| --- | --- |
| `npm run dev` | Development server |
| `npm run build` / `npm start` | Production build and server |
| `npm run typecheck` | TypeScript, no emit |
| `npm run lint` | ESLint |
| `npm run gen:api` | Regenerates `src/lib/api/schema.ts` from the running backend's `/openapi.json` |

## Screens and the API behind them

| Screen | Endpoints |
| --- | --- |
| Sign in | `POST /auth/verify`, `GET /health` |
| Diagnose: open an incident | `POST /incidents` (with duplicate detection and `force_new`), `PATCH /incidents/{id}` (acknowledge), `POST /incidents/{id}/diagnosis`, `POST /diagnosis` (check without saving), `GET /dashboard/incidents` |
| Incident workspace | `GET /incidents/{id}`, `POST /diagnosis/advanced` (signals, path analysis, candidates, playbooks; only after **Analyse signals** is clicked, because it re-runs diagnostic tools), `GET /dashboard/network-health`, `GET /topology`, `GET /incidents/{id}/evidence`, `GET /incidents/{id}/timeline`, `GET /incidents/{id}/escalations`, `GET /diagnosis/{id}` and `GET /diagnosis/{id}/evidence` (superseded diagnoses) |
| Lifecycle actions | `PATCH /incidents/{id}` (details, severity, priority, status), `POST .../classification`, `POST .../escalations`, `PATCH .../escalations/{escalation_id}`, `POST .../resolution` (propose and verify), `POST .../close`, `POST .../reopen` |
| Diagnosis agent panel | `POST /conversations` (on the first message, not on open), `GET /conversations/{id}` (history after a reload), `POST /conversations/{id}/messages` streamed over SSE, `GET /conversations/{id}/events` (resume a dropped stream), `POST .../cancel`, `DELETE .../context`, `GET .../investigations/{id}`, `POST .../investigations/{id}/attach` (Save to incident, human click only). `POST /agent/diagnose` stays available for API clients but the UI no longer calls it. |
| Incidents | `GET /incidents` (status, severity, site and fault-domain filters, paging), `GET /dashboard/summary` |
| Network insights | `GET /dashboard/network-health`, `GET /topology/sites`, `GET /topology/sites/{id}`, `GET /topology/devices` (filters), `GET /topology/devices/{id}`, `GET /topology/devices/{id}/interfaces`, `GET /topology/links`, `GET /topology/services` |
| Knowledge base | `GET /knowledge/search`, `GET /knowledge/playbooks`, `GET /knowledge/playbooks/{id}`, `GET /knowledge/runbooks`, `GET /knowledge/procedures` |
| Reports | `GET /reports/summary`, `GET /reports/fault-domains`, `GET /reports/diagnosis`, `GET /reports/incidents` (CSV download) |
| Remote CLI | Read-only commands from the active diagnosis, open escalations and `GET /knowledge/procedures` |
| Sidebar | `GET /incidents` (recent diagnoses), `GET /reports/incidents` (notifications), `GET /health` |

## How it behaves

- **Optimistic concurrency.** Every write sends the incident's `expected_version`. A `409 INCIDENT_CONFLICT`
  reloads the incident and says so; nothing is retried silently.
- **Roles.** Actions the token can't perform are hidden or disabled with the reason. Viewers skip
  `POST /diagnosis/advanced`, which needs `run_diagnostics`, and see evidence counts instead.
- **Rate limit.** The backend allows 120 requests a minute per IP. Queries don't refetch on focus and don't
  retry 4xx responses; a `429` shows the `Retry-After` wait.
- **Times** show in the incident site's zone (IST, SGT, ET, UK time). Telemetry timestamps come from the
  synthetic datasets, so they carry their own date.

## The diagnosis agent

The panel is a conversation, not a form for `POST /agent/diagnose`. Opening it runs nothing. Greetings and questions
are answered without tools; describing symptoms gets a clarifying question; checks run only when you ask for them
("diagnose it", "check SIN-RTR-01 routing") or click a chip marked with an arrow. Tool progress, evidence ids,
clarification options, and the approvals a person must give (Save to incident, Review and confirm) appear in the
thread. Approval buttons open the workspace's existing dialogs; the agent never records anything itself. The Stop
button cancels a running investigation. The conversation id is kept per incident in session storage.

## What differs from the mock, and why

- **Confidence** is a level (high, medium, low, insufficient) with a three-step meter. The API doesn't return
  a percentage, so the UI doesn't invent one.
- **Signals** show measured anomalies (worst per category, with baseline and the asset) and the blast radius.
  There's no time-series endpoint, so there are no sparklines and no user counts.
- **Remote CLI** lists commands to copy. The backend never connects to devices, so neither does the page.
- **Sources connected** reports whether the diagnosis API answers `/health`.

## Layout

```
src/app/                 routes (thin server files; each page renders a client view)
src/components/shell     sidebar, top bar, command palette (⌘K), notifications
src/components/workspace incident workspace: model (lifecycle rules), panels, actions, export
src/components/agent     diagnosis agent panel
src/components/views     the other pages
src/components/ui        ui-sdk parts styled for this design (button, modal, fields, tabs, charts…)
src/lib/api              client, endpoints (one per operation), hooks, generated schema
```

See `DESIGN.md` for the design decisions.
