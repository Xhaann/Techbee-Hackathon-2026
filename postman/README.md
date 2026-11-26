# Postman: Network Incident Diagnosis Agent API

Verified on 2026-11-26 against a live local server. All 64 requests passed in one Collection Runner-style replay.

## Setup

1. Start the backend:

   ```bash
   cd backend
   AUTH_TOKENS_FILE=var/auth/tokens.json .venv/bin/uvicorn app.main:app --port 8000
   ```

2. Issue one token per role. Each command prints the token once; copy it.

   ```bash
   cd backend
   export AUTH_TOKENS_FILE=var/auth/tokens.json
   .venv/bin/python -m app.security.tokens issue --subject noc.operator --kind human --role operator --expires-hours 24
   .venv/bin/python -m app.security.tokens issue --subject noc.manager --kind human --role incident_manager --expires-hours 24
   .venv/bin/python -m app.security.tokens issue --subject noc.viewer --kind human --role viewer --expires-hours 24
   ```

3. Import `NetworkIncidentDiagnosis.postman_collection.json` and `NetworkIncidentDiagnosis.local.postman_environment.json`.
4. Paste the tokens into `operatorToken`, `managerToken` and `viewerToken` in the environment.
5. Run folder **3. Incident workflow** in order. It chains `incidentId`, `incidentVersion`, `diagnosisId` and `escalationId` between requests.

## Notes

- **Rate limit.** The default is 120 requests per minute per client IP, and `/health` counts too. A full collection run is 64 requests, so running it twice within a minute returns `429 RATE_LIMITED`. To avoid this, wait for the `Retry-After` period, or start the server with `RATE_LIMIT_REQUESTS=1000` for testing.
- **Modes.** `mode: "rule_based"` works without a model. `mode: "agent"` is the default and runs the Microsoft Agent Framework agent. It needs `AI_PROVIDER=openai`, `AI_MODEL` and `AI_API_KEY` in `backend/.env`; without them it returns `503 AGENT_NOT_CONFIGURED`.
- **Scenarios.** `scenario_id` selects the synthetic telemetry dataset: `WAN-FAILURE`, `PACKET-LOSS`, `OSPF-ADJACENCY-FAILURE`, `FIREWALL-BLOCKING`, `DHCP-ALLOCATION-FAILURE`, `DNS-RESOLUTION-FAILURE`, `VLAN-AUTHENTICATION-FAILURE`, `SHARED-DEVICE-FAILURE` or `BASELINE`. When `incident_id` is given, the incident's `dataset_scenario_id` is used instead.
- **Site names.** Sites are resolved from the description using IDs, names and cities: `SIN`/Singapore, `NYC`/New York, `BLR`/Bengaluru, `CORE`/London, `DC1`/Slough. Aliases such as "Bangalore" are not recognised. Pass `site_ids` explicitly to be certain.
- **Attaching a diagnosis.** To attach a diagnosis, the incident must be `investigating`, and `expected_version` must match the incident's current version; otherwise the request returns `409`.
- **Closing an incident.** An incident can only be closed after any escalations are closed or cancelled, and after a manager has verified the resolution while the incident is `monitoring`.
