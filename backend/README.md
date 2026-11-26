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

Issue a local API token (shown once; only its hash is stored):

```bash
.venv/bin/python -m app.security.tokens issue --subject noc.operator --kind human --role operator --expires-hours 24
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

## Tests

```bash
.venv/bin/python -m pytest -q
RUN_LIVE_AGENT_SPECS=1 .venv/bin/python -m pytest -q verification/agent/live_spec.py
```

The second command calls the configured model and runs only when explicitly requested.
