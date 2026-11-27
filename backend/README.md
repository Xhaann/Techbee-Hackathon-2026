# Network Incident Diagnosis Assistant — Backend

Local FastAPI backend and Microsoft Agent Framework agent for diagnosing synthetic enterprise network incidents.

## Requirements

Python 3.12, one virtual environment.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
```

## Configuration

Copy `.env.example` to `.env` (Git-ignored) and set the model only when it is approved:

```env
AI_PROVIDER=openai
AI_MODEL=<organizer-approved-model>
AI_API_KEY=<replacement-organizer-key>
AUTH_TOKENS_FILE=var/auth/tokens.json
```

## Accounts and sign-in

Each person signs in with their own account. Accounts live in `var/auth/users.json` (`AUTH_USERS_FILE`; Git-ignored,
mode 600) with scrypt-hashed passwords. Passwords are prompted for and never printed:

```bash
.venv/bin/python -m app.security.users add --username jane.doe --role operator
.venv/bin/python -m app.security.users add --username sam.lee --role incident_manager --role knowledge_manager
.venv/bin/python -m app.security.users list
.venv/bin/python -m app.security.users passwd --username jane.doe     # also signs the account out everywhere
.venv/bin/python -m app.security.users disable --username jane.doe    # blocks sign-in and revokes sessions
```

`POST /api/v1/auth/login` issues a session token for `SESSION_HOURS` (default 12) under the account's own name, and
`POST /api/v1/auth/logout` revokes it. After `LOGIN_MAX_FAILURES` failed attempts (default 5) an account is refused for
`LOGIN_LOCKOUT_SECONDS` (default 300). Session writes are locked, so simultaneous sign-ins never lose a session.

Access is per user: operators see and act on the incidents they reported or own (`assigned_owner`), and conversations
are visible only to the person who started them. Incident managers, viewers and knowledge managers hold the
`view_all_incidents` permission; only incident managers can act on other people's incidents. Anything outside a
user's scope answers 404.

Service and test principals can still get a token directly (shown once; only its hash is stored):

```bash
.venv/bin/python -m app.security.tokens issue --subject diagnosis-service --kind system --role system_service --expires-hours 24
.venv/bin/python -m app.security.tokens revoke --subject diagnosis-service
```

## Run

```bash
.venv/bin/uvicorn app.main:app --port 8000
```

## Agent API

`POST /api/v1/agent/diagnose` with `Authorization: Bearer <token>`; requires the `run_diagnostics` permission
(roles `operator`, `incident_manager`, `system_service`).

```json
{
  "description": "Users at the Singapore branch cannot access internal applications.",
  "scenario_id": "WAN-FAILURE",
  "mode": "agent"
}
```

Optional fields: `site_ids`, `device_ids`, `services`, `incident_id`, `attach_to_incident` with `expected_version`,
and `mode: "rule_based"` to run without a model. The response contains `report` (the structured human-review
report), `execution` (request ID, mode, method, provider status, duration, tool calls, budget, fallback flag) and
`incident` (set only when the diagnosis was attached). Without a configured model, `mode: "agent"` returns
`503 AGENT_NOT_CONFIGURED`.

Command line: `.venv/bin/python -m app.agent --scenario WAN-FAILURE "<incident report>"` (add `--rule-based` to run without a model).

## Conversation API

A conversational layer (`app/conversation`) sits on top of the same engines. Each message is classified first
(`intents.py`, deterministic); tools run only for an explicit diagnosis request, a check request that names a target,
or a quick action the user clicked. Greetings, general questions, knowledge questions, symptom descriptions and
evidence explanations never call a diagnostic tool. Full diagnoses go through `DiagnosisAgent` (Microsoft Agent
Framework, rule-based fallback); targeted checks go through `ToolExecutor`. Both keep the 10-call budget, sequential
execution, the tool allowlist, argument/result limits and duplicate prevention. Replies are written by a tool-less
Agent Framework agent from the turn's facts and checked before use (evidence ids, device names, no claims of checks
that didn't run, no human actions, no remediation); otherwise the deterministic reply is used.

| Operation | Purpose |
| --- | --- |
| `POST /conversations` | Create (optional `incident_id`, `scenario_id`, `mode: auto \| rule_based`). Runs nothing. |
| `GET /conversations`, `GET /conversations/{id}`, `DELETE /conversations/{id}` | List, history (messages, context, investigations), delete |
| `POST /conversations/{id}/messages` | Send `content` or a clicked `action`. JSON `TurnResult`, or SSE with `stream: true` / `Accept: text/event-stream` |
| `GET /conversations/{id}/events?after=N` | Replay events after a sequence number and follow a running turn (SSE) |
| `POST /conversations/{id}/cancel` | Cancel the running turn; partial evidence is kept, no conclusion is drawn |
| `GET`/`DELETE /conversations/{id}/context` | Read or reset what the user has told the assistant (the incident link stays) |
| `GET /conversations/{id}/investigations/{investigation_id}` | Tool steps, evidence and report of one investigation |
| `POST /conversations/{id}/investigations/{investigation_id}/attach` | Human-approved save of a diagnosis to the incident (`expected_version`) |

`TurnResult` carries the intent, the response, any clarification, the investigation id, an execution summary (tool
calls, budget, mode, model, composer) and evidence references. SSE events: `turn.started`, `intent.classified`,
`investigation.started`, `tool.started`, `tool.completed` / `tool.failed` / `tool.skipped`, `knowledge.searched`,
`investigation.progress`, `evidence.correlated`, `investigation.completed` / `failed` / `cancelled`,
`human_confirmation.required`, `assistant.typing`, `assistant.delta`, `assistant.message`, `turn.cancelling`, and the
terminal `turn.completed` (or `turn.failed`). Conversations are private to the principal that created them (other
users get 404) and are held in memory, so they don't survive a backend restart.

## Observability API

`app/observability` adds network intelligence on top of the same topology and scenario data, under
`/api/v1/observability` (tag `observability`). Reads need `view_diagnostics`; ingestion needs `ingest_telemetry`, which
only the `system_service` role holds. Everything is computed in code (no model calls) and nothing contacts a device.

| Area | Operations |
| --- | --- |
| Sources and ingestion | `GET /sources`; `POST /ingest/telemetry`, `/ingest/streaming` (OpenConfig paths), `/ingest/syslog`, `/ingest/traps`, `/ingest/flows` (records or base64 NetFlow v5 / IPFIX) |
| Live telemetry | `GET /live?since=<cursor>` (incremental), `GET /stream` (SSE: `hello`, `metrics`, `event`, `flows`, `heartbeat`, `end`), `GET /topology/live` |
| Signals | `GET /snmp`, `GET /traps`, `GET /syslog`, `GET /flows`, `GET /traffic` |
| Analytics | `GET /baselines`, `GET /health`, `GET /forecast`, `GET /congestion`, `GET /discovery`, `GET /dependencies`, `GET /drift`, `GET /drift/{device_id}/diff`, `GET /journey`, `GET /reliability?format=json\|markdown\|csv` |

What is real and what is simulated:

- Real: the decoders and normalisers (SNMP counter rates with 32/64-bit wrap and restart detection, trap OIDs,
  RFC 3164/5424 and Cisco syslog with template mining, binary NetFlow v5 and IPFIX, OpenConfig JSON), the bounded
  telemetry hub with SSE fan-out, the authenticated ingest API, and every analytic.
- Simulated: the data behind the scenarios. 14 days of 5-minute interface history, flow records, golden and running
  configurations and LLDP neighbour tables are generated deterministically from the topology and each scenario file
  (`app/observability/simulation.py`); a live simulator streams wall-clock values for scenarios someone is watching.
- Not bundled: live SNMP, gNMI, LLDP or configuration-collection transports. The interfaces exist (`SnmpTransport`,
  the ingest endpoints); connecting to devices is a deployment decision.
- Optional UDP receivers for syslog and NetFlow/IPFIX are off unless `TELEMETRY_SYSLOG_UDP_PORT` or
  `TELEMETRY_FLOW_UDP_PORT` is set; they bind to loopback unless `TELEMETRY_UDP_ALLOW_REMOTE=true`, are rate limited,
  and accept only senders that map to a device in the inventory.

Every buffer is bounded (series, points per series, events, flows, subscriber queues with drop-oldest). The agent gets
five compact tools over these analytics: `get_network_health`, `get_config_drift`, `analyze_traffic_flows`,
`trace_packet` and `forecast_capacity`.

## Diagnostic intelligence (Phase 2)

`app/reasoning` adds a deterministic reasoning layer over the evidence the read-only tools collect. No step calls a model.

- Specialist agents (transport/WAN, routing, security, DNS/DHCP) plan read-only checks. A coordinator runs them under
  the shared 10-call budget through `ToolExecutor`: `POST /api/v1/diagnosis/multi-agent`, or "run a multi-agent
  investigation" in a conversation.
- For any evidence set, the reasoning engine produces:
  - Bayesian fault probabilities with calibrated evidence weights.
  - Contradictions, a causal root-cause graph and temporal clusters.
  - Cross-layer and topology-based localisation.
  - Uncertainty, self-evaluation (calibrated confidence), a plain-language explanation and the next most useful checks.
  - Related incidents, drawn only from incidents the user may see.

  Full diagnoses store it on the investigation: `GET /conversations/{id}/investigations/{inv}/reasoning`.
- The conversation layer answers briefly by default and keeps the full detail in `details` ("tell me more").
  - It drafts customer emails and incident updates from verified facts only. They are never sent, with
    [placeholders] for unknowns and no invented causes or ETAs.
  - It gives numbered read-only troubleshooting steps with expected outputs, interprets pasted command output and
    handles failed steps.
  - It offers checks and runs them only after approval.
  - Every message carries `generated_by`: who wrote the reply and whether the result came from the AI agent,
    rules, or a rule-based fallback.
- Conversations persist to `CONVERSATION_STORE_DIR` (default `var/conversations`, per-owner files with mode 0600). An
  empty value keeps them in memory only.

## Protocol and security intelligence (Phase 3)

`app/protocols` adds 17 read-only engines over synthetic protocol and security telemetry:
- Routing: BGP route anomalies, the OSPF link-state database, IPv6 routing and multicast.
- Switching: STP loops and topology changes, ARP spoofing and conflicts, VLAN and trunk mismatches, and Wi-Fi
  interference.
- Transport and edge: NAT, IPsec, TCP retransmissions, MTU and fragmentation, and QoS.
- Security: certificates and TLS, suspicious traffic, lateral movement, and threat correlation.

Each finding is labelled confirmed fault, suspicious indicator, possible explanation or insufficient evidence. It carries:
- a calibrated confidence;
- the records it rests on;
- vendor-aware read-only commands, with healthy and faulty output.

Security findings are never stated as confirmed, and nothing attributes activity to anyone.

- **Data.** 20 protocol scenarios (normal, failure, edge-case and adversarial) live in `app/protocols/data/scenarios`,
  outside the core set, so `list_scenario_ids()` and the core benchmarks are unchanged.
  - Protocol telemetry for every scenario is generated deterministically from the topology and the scenario dataset on
    first use (`app.protocols.scenarios`).
  - Regenerate the scenario files with `.venv/bin/python -m app.protocols.scenarios`.
- **Correlation.** Each finding is linked to:
  - configuration changes and core fault records;
  - other protocol findings, through the Phase 2 causal graph;
  - Phase 1 packet journeys and traffic shifts;
  - incidents the caller may see.

  Symptoms such as retransmissions are never promoted to root causes.
- **API.** `GET /api/v1/protocols/engines` and `POST /api/v1/protocols/analyze` (run_diagnostics; incident visibility is
  enforced). The `analyze_protocol` tool is in the agent registry.
- **Specialists.** They run protocol checks only for clearly protocol-specific symptoms, in at most three of the ten
  budget slots. A switching and wireless specialist was added.
- **Conversation.** Protocol checks are offered first and run only after approval. Requests to actively scan a network
  are declined, with an offer to review the collected records instead.
- **Interface.** The *Protocols & security* page runs the selected engines on a button press.

## Incident scenarios SCN-01 to SCN-10

Ten further synthetic incidents live with the Phase 3 scenarios in `app/protocols/data/scenarios`, so the loader,
incidents, diagnosis, conversations, observability, protocol engines and UI selectors all see them. Each one combines
several capabilities and includes decoys and unaffected sites for comparison:

- WAN flap storm (BGP, OSPF, IPsec, TCP, multicast)
- unexpected BGP origin
- rogue spanning-tree root
- deleted voice VLAN, plus an unrelated IP conflict
- no-NAT rule shadowing PAT (with a DNS decoy)
- two hub VPN faults
- metro congestion from a patch push (QoS, MTU, allowlisted traffic)
- rogue IPv6 router advertisements
- IGMP querier loss flooding Wi-Fi
- an untrusted TLS inspection CA alongside two security indicators

Where things live:
- **Definitions:** `app/protocols/incidents.py`. Regenerate the files with `.venv/bin/python -m app.protocols.scenarios`.
- **Expected outcomes:** `app/protocols/cards.py`, which holds root cause, decoys, expected findings and confidence bands,
  evidence references, expected configuration and read-only commands. JSON copies are written by
  `.venv/bin/python -m app.protocols.cards`.
- **Separation from diagnostics:** no diagnostic module imports the cards, and a test enforces it.
- **Scoring:** the benchmark scores every layer against the cards and prints accuracy as measured. Accuracy does not gate
  the run; grounding and safety do.

## Tests

```bash
.venv/bin/python -m pytest -q
RUN_LIVE_AGENT_SPECS=1 .venv/bin/python -m pytest -q verification/agent/live_spec.py
```

The second command calls the configured model and runs only when explicitly requested.
