# Network Incident Diagnosis Assistant

TechBee Hackathon 2026 project. A read-only incident workspace for enterprise network operations: it diagnoses network
incidents from telemetry, explains the evidence behind each conclusion, and leaves every change to a person.

All network data in this repository is synthetic. Nothing connects to a real device.

## Objectives

- Find the likely root cause of an incident from read-only checks, with evidence and a calibrated confidence level.
- Keep people in charge: classification, escalation, resolution, closure and any configuration change are human actions.
- Explain findings in plain language, with the full evidence and provenance available for review and audit.

## Key features

- **Incident lifecycle.** Report, acknowledge, diagnose, confirm the fault domain, escalate, propose and verify a
  resolution, close and reopen. Duplicate detection on new reports and optimistic concurrency on every write.
- **Diagnosis engine.** 21 read-only diagnostic tools (reachability, interfaces, routing, firewall, DHCP/DNS, logs,
  change history, path health and more) under a 10-call budget, correlated into a hypothesis with supporting and
  contradicting evidence.
- **AI agent.** A Microsoft Agent Framework agent plans and calls the same tools. Without a configured model, or if the
  model fails, the rule-based engine produces the result and the reply says so.
- **Diagnostic reasoning.** Specialist agents, Bayesian hypothesis ranking, contradiction detection, causal and
  cross-layer analysis, temporal correlation, uncertainty, self-evaluation and investigation planning (`app/reasoning`).
- **Protocol and security analysis.** 17 engines (BGP, OSPF, STP, ARP, VLAN, NAT, IPsec, TCP, MTU, QoS, IPv6, Wi-Fi,
  multicast, TLS, suspicious traffic, lateral movement, threat correlation). Security findings are never stated as
  confirmed.
- **Observability.** SNMP, syslog, trap, NetFlow/IPFIX and OpenConfig decoders, baselines, health scores, capacity
  forecasts, configuration drift, dependency mapping and packet journeys over simulated telemetry.
- **Conversational agent.** Short plain answers by default, with reasons and technical detail on request. Checks run
  only when asked for or approved. Troubleshooting steps are based on the evidence and the user's report; when nothing
  justifies a step, the agent says more evidence is needed. Customer emails and updates are drafts that are never sent.
- **Knowledge base.** Playbooks, runbooks and procedures, used as guidance and never as evidence.
- **Web workspace.** Diagnose, incident workspace with the agent panel, incidents, network insights, observability,
  protocols and security, knowledge base, reports and a read-only command reference.

## Technology stack

| Layer | Technology |
| --- | --- |
| Backend | Python 3.12, FastAPI, Pydantic, Uvicorn |
| Agent | Microsoft Agent Framework (`agent-framework-core`, `agent-framework-openai`), OpenAI-compatible chat completions |
| Frontend | Next.js 16, React 19, TypeScript, Tailwind CSS 4, TanStack Query, `@ui-sdk/react`, lucide icons |
| Storage | JSON files on local disk (incidents, conversations, sessions); nothing external |
| Tests | pytest (backend), TypeScript and ESLint (frontend), a Postman collection for the API |

## Architecture

```
 Browser ──> Next.js workspace (frontend/) ──HTTPS/SSE──> FastAPI (backend/app)
                                                            │
        ┌───────────────────────┬───────────────────────────┼──────────────────────────┐
        │                       │                           │                          │
  security/ (auth, roles,  incidents/ (lifecycle,     conversation/ (intents,     api/ (REST + SSE,
  sessions, isolation)     concurrency, audit)        replies, approvals)         rate limits)
                                                            │
                         ┌──────────────────────────────────┼──────────────────────────────┐
                         │                                  │                              │
                 agent/ (Agent Framework,        engine/ (tool registry, executor,   reasoning/, protocols/,
                 rule-based fallback)            budget, safety, correlation)        observability/, knowledge/
                                                            │
                                         network/ (synthetic topology and scenario datasets)
```

Every tool call goes through `engine/executor.py`: allowlisted tools, validated arguments, a per-investigation budget,
bounded results and evidence records with provenance. The agent and the conversation layer cannot reach a device or
change an incident; writes happen only through the incident API after a person approves them.

## Getting started

Prerequisites: Python 3.12 and Node.js 20.9 or later.

```bash
# Backend
cd backend
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
cp .env.example .env                                              # placeholders only; see Configuration
.venv/bin/python -m app.security.users add --username <your.name> --role incident_manager   # prompts for a password
.venv/bin/uvicorn app.main:app --port 8000

# Frontend (second terminal)
cd frontend
cp .env.example .env.local
npm install
npm run dev                                                      # http://localhost:3000
```

Sign in with the account you created. The ten SCN demo incidents are seeded on first start (`DEMO_INCIDENTS=true`).

## Configuration

Settings come from `backend/.env` (Git-ignored); `backend/.env.example` lists every option with safe defaults.

| Setting | Purpose |
| --- | --- |
| `AI_PROVIDER` | `disabled` (default): rule-based diagnosis and replies. `openai`: enables the agent. |
| `AI_MODEL`, `AI_API_KEY` | Model name and key, set only when an approved model is available. Never commit them. |
| `AUTH_USERS_FILE`, `AUTH_TOKENS_FILE` | Accounts (scrypt-hashed passwords) and session tokens, under `var/auth/` |
| `INCIDENT_STORE_DIR`, `CONVERSATION_STORE_DIR` | Where incidents and conversations are stored (default under `var/`) |
| `CORS_ORIGINS` | Frontend origins allowed to call the API |
| `RATE_LIMIT_REQUESTS`, `SESSION_HOURS`, `LOGIN_MAX_FAILURES` | Request limits, session length and sign-in lockout |

The frontend reads `NEXT_PUBLIC_API_BASE_URL` (default `http://127.0.0.1:8000`) from `frontend/.env.local`.

## API and authentication

- Base path `/api/v1`. Interactive documentation is served at `/docs` outside production; `/openapi.json` has the schema.
- `POST /api/v1/auth/login` returns a bearer token for `SESSION_HOURS`; `POST /api/v1/auth/logout` revokes it.
- Roles: `viewer`, `operator`, `incident_manager`, `knowledge_manager`, `system_service`. Permissions are checked on
  every route. Operators see the incidents they reported or own; conversations are private to their creator. Anything
  outside a user's scope answers 404.
- Main areas: incidents and their lifecycle, diagnosis (`/agent/diagnose`, `/diagnosis`, `/diagnosis/multi-agent`),
  conversations (JSON or Server-Sent Events), topology, observability, protocols, knowledge and reports.

Endpoint details are in [backend/README.md](backend/README.md). A Postman collection is in [postman/](postman/README.md).

## AI agent workflow

1. A message is classified deterministically (`conversation/intents.py`). Greetings, questions and explanations never
   run a tool.
2. A diagnosis request runs the Agent Framework agent (or the rule-based planner) with the incident's validated sites,
   devices and services. It calls read-only tools one at a time within the 10-call budget.
3. The correlator turns the evidence into a hypothesis with supporting and contradicting evidence ids and a confidence
   level; the reasoning layer adds probabilities, contradictions, uncertainty and the next useful checks.
4. The reply is written from the turn's verified facts. A model-written reply is checked before use and replaced by the
   deterministic reply if it cites evidence that doesn't exist, names unknown devices, claims checks that didn't run,
   claims a confirmation nobody made, calls an alert an attack, drops a security warning, or offers a human-only action.
5. Every message records whether the reply and the result came from the model, the rules or a rule-based fallback.

## Security and human approval

- Read-only by design: tools read synthetic telemetry, and every command the assistant suggests passes a read-only
  check. Remediation requests are refused.
- Approval first: checks are offered and run only after the user approves; broad requests ("check every log") become a
  bounded plan to approve.
- Human-only actions: confirming the fault domain, saving a diagnosis, escalating, resolving and closing need a person
  with the right permission, through the workspace dialogs.
- Text from logs, documents and pasted output is treated as data; instructions inside it are ignored.
- Secrets stay out of the repository: `.env` files, `var/` (accounts, sessions, incidents, conversations) and build
  output are Git-ignored. Passwords are stored as scrypt hashes and session tokens as hashes.

## Synthetic data and demo scenarios

- **Topology:** 5 sites (New York, Singapore and Bengaluru branches, a London core, a Slough data centre), 17 devices
  and 17 links (`backend/app/network/data/topology.json`).
- **Core scenarios:** 15 failure scenarios and a healthy baseline (`backend/app/network/data/scenarios`).
- **Protocol scenarios:** 20 protocol and security cases, plus SCN-01 to SCN-10, ten multi-fault incidents with decoys
  (`backend/app/protocols/data/scenarios`). Expected outcomes for SCN-01 to SCN-10 live in separate cards that no
  diagnostic module reads.
- **Demo incidents:** SCN-01 to SCN-10 are seeded as incidents marked Demo, diagnosed by the rule-based engine and never
  pre-confirmed.

## Testing and benchmarks

```bash
cd backend
.venv/bin/python -m pytest -q                          # full backend suite, no model calls
.venv/bin/python -m verification.benchmark.run         # diagnosis, reasoning and protocol scoreboards

cd ../frontend
npm run typecheck && npm run lint && npm run build
```

`RUN_LIVE_AGENT_SPECS=1 .venv/bin/python -m pytest -q verification/agent/live_spec.py` exercises a configured model and
runs only when explicitly requested.

## Known limitations

- Synthetic data only. Live SNMP, gNMI, syslog and flow ingestion paths exist, but no device connection is bundled.
- The automated tests use a scripted model. The live model path runs only with an approved model and key.
- The specialist agents and the reasoning layer are deterministic rules, not separate model calls.
- Intent and symptom recognition is keyword-based, so unusual phrasing can be missed; the agent then asks for more
  evidence instead of guessing.
- Diagnosis accuracy on the hard SCN set is measured and reported by the benchmark, and is not perfect.
- Storage is local JSON on one machine, and rate limiting is in-process.

## Repository layout

```
backend/    FastAPI service, diagnosis engine, agent, reasoning, protocols, observability, tests (verification/)
frontend/   Next.js workspace (see frontend/README.md and frontend/DESIGN.md)
postman/    API collection and local environment
```

Component documentation: [backend/README.md](backend/README.md), [frontend/README.md](frontend/README.md),
[frontend/DESIGN.md](frontend/DESIGN.md), [postman/README.md](postman/README.md).
