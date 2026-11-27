"""SCN-01 to SCN-10: data integrity, integration with every layer, and safety.

These tests gate what must hold for any dataset: valid data, deterministic generation, references that resolve, every
diagnostic tool and layer running cleanly, ground truth kept out of the diagnostic code, and the safety rules (no
confirmed security finding, grounded reports, read-only commands). How accurately each layer diagnoses the incidents is
measured, not gated: verification/benchmark/run.py prints it per scenario, misses included.
"""
import re
from pathlib import Path

import pytest

from app.diagnostics.common import ToolStatus
from app.engine.engine import DiagnosisEngine
from app.engine.registry import REGISTRY
from app.engine.safety import is_read_only_command
from app.network.repository import all_scenario_ids, list_protocol_scenario_ids, load_scenario, load_topology
from app.observability.simulation import golden_config, running_config
from app.protocols.analysis import analyze
from app.protocols.cards import CARD_DIR, CARDS, CARD_BY_ID, write_cards
from app.protocols.incidents import INCIDENT_SPECS
from app.protocols.repository import load_telemetry, record_index
from app.protocols.scenarios import PROTOCOL_SCENARIO_DIR, build_dataset, to_json
from app.security.provenance import provenance_issues, record_index as core_index
from verification.api.helpers import ApiHarness, incident_payload
from verification.scenarios.evaluate import SCENARIOS, request_for

APP = Path(__file__).resolve().parents[2] / "app"
REQUIRED = {"wan", "bgp", "ospf", "stp", "vlan", "arp", "nat", "firewall", "ipsec", "tcp", "mtu", "qos", "ipv6", "dns", "dhcp", "wireless",
            "multicast", "tls", "traffic", "lateral", "threats"}


# ---------------------------------------------------------------- the dataset itself

def test_exactly_ten_new_scenarios_with_unique_ids() -> None:
    assert [s.scenario_id for s in INCIDENT_SPECS] == SCENARIOS and len(SCENARIOS) == 10
    assert sorted(SCENARIOS) == sorted(s for s in list_protocol_scenario_ids() if s.startswith("SCN-"))
    incident_ids = [load_scenario(s).incident.incident_id for s in SCENARIOS]
    assert len(set(incident_ids)) == 10 and len({s.day for s in INCIDENT_SPECS}) == 10
    existing = [s for s in all_scenario_ids() if not s.startswith("SCN-")]
    assert len(existing) == 36, "the 16 core and 20 Phase 3 scenarios are still there"


@pytest.mark.parametrize("spec", INCIDENT_SPECS, ids=lambda s: s.scenario_id)
def test_generated_deterministically(spec) -> None:
    assert (PROTOCOL_SCENARIO_DIR / f"{spec.scenario_id}.json").read_text(encoding="utf-8") == to_json(build_dataset(spec))


def test_card_files_match_the_cards(tmp_path) -> None:
    write_cards(tmp_path)
    for card in CARDS:
        assert (tmp_path / f"{card.scenario_id}.json").read_text() == (CARD_DIR / f"{card.scenario_id}.json").read_text()


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_incident_contents(scenario: str) -> None:
    dataset, card = load_scenario(scenario), CARD_BY_ID[scenario]
    info, incident, truth = dataset.scenario, dataset.incident, dataset.ground_truth
    assert incident.incident_id == card.incident_id and truth.root_cause and truth.root_cause_device_ids and truth.affected_path_ids
    assert set(incident.affected_site_ids) == set(card.sites) and len(incident.symptoms) >= 2
    assert card.decoys and card.secondary_effects and len(card.capabilities) >= 3 and len(card.commands) >= 3 and card.timeline
    assert all(info.window_start <= t <= info.window_end for t in dataset.timestamps())
    devices = {d.device_id for d in load_topology().devices}
    assert set(card.affected_devices) <= devices and set(truth.root_cause_device_ids) <= devices
    assert {p.path_id for p in load_topology().paths} >= set(card.affected_paths)
    assert any(e.event_id.startswith(f"EVT-S{scenario[4:6]}") for e in dataset.events), "scenario-specific events in the timeline"


@pytest.mark.parametrize("card", CARDS, ids=lambda c: c.scenario_id)
def test_card_evidence_and_timeline_references_exist(card) -> None:
    index = record_index(load_telemetry(card.scenario_id)) | core_index(load_scenario(card.scenario_id), derived=True)
    references = card.evidence + [s.evidence for s in card.timeline] + [e for d in card.decoys for e in d.evidence]
    for reference in references:
        collection, record_id = reference.split(":", 1)
        assert record_id in index.get(collection, set()), reference


@pytest.mark.parametrize("card", CARDS, ids=lambda c: c.scenario_id)
def test_card_commands_are_read_only_and_config_expectations_hold(card) -> None:
    assert all(is_read_only_command(c.command) for c in card.commands)
    for expectation in card.configuration:
        golden, running = golden_config(expectation.device_id), running_config(card.scenario_id, expectation.device_id)
        assert all(line in golden for line in expectation.golden_contains)
        assert all(line in running for line in expectation.running_contains)
        assert not any(line in running for line in expectation.running_lacks)


def test_capability_coverage_and_difficulty_mix() -> None:
    covered = {c for spec in INCIDENT_SPECS for c in spec.features}
    assert REQUIRED <= covered, REQUIRED - covered
    difficulty = {d for card in CARDS for d in card.difficulty}
    assert {"straightforward", "multi-layer", "multiple-symptoms", "shared-device", "multi-site", "misleading-evidence",
            "security-uncertainty", "cascading"} <= difficulty
    assert all(len(spec.features) >= 3 for spec in INCIDENT_SPECS)
    assert sum(1 for card in CARDS if card.unaffected_sites) >= 6, "healthy comparison sites"


def test_ground_truth_is_kept_out_of_the_diagnostic_code() -> None:
    importers = [path for path in APP.rglob("*.py")
                 if path.name != "cards.py" and re.search(r"protocols\.cards|protocols import cards|data/cards", path.read_text())]
    assert importers == [], importers
    # Only the data layer (models, loader, generators) may touch a dataset's ground_truth block; no diagnostic module does.
    data_layer = {"network/models.py", "network/repository.py", "network/generator.py", "network/advanced_scenarios.py",
                  "protocols/scenarios.py", "protocols/incidents.py", "protocols/scenario_kit.py"}
    readers = {str(path.relative_to(APP)) for path in APP.rglob("*.py") if "ground_truth" in path.read_text()}
    assert readers <= data_layer, readers - data_layer


# ---------------------------------------------------------------- every layer runs cleanly on every scenario

def tool_calls(scenario: str) -> list[tuple[str, dict]]:
    card = CARD_BY_ID[scenario]
    site = card.sites[0]
    router, switch = f"{site}-RTR-01", f"{site}-SW-01"
    calls = [("get_topology", {"site_id": site}), ("get_device_logs", {"device_id": card.affected_devices[0]}),
             ("get_interface_stats", {"device_id": router}), ("get_routing_state", {"device_id": router}),
             ("get_firewall_logs", {"destination": "10.100.100.0/24"}), ("get_dhcp_dns_status", {"site_id": site}),
             ("check_network_reachability", {"source": switch, "destination": "10.100.100.40"}),
             ("analyze_packet_loss", {"device_id": router, "interface": "Gi0/0/0"}),
             ("analyze_interface_errors", {"device_id": router, "interface": "Gi0/0/0"}),
             ("analyze_routing_adjacency", {"device_id": router}), ("check_device_availability", {"device_id": card.affected_devices[0]}),
             ("analyze_network_dependencies", {"site_id": site}), ("analyze_path_health", {"source": switch, "destination": "10.100.100.40"}),
             ("get_event_timeline", {"site_id": site}), ("get_change_history", {}), ("get_network_health", {"site_id": site}),
             ("get_config_drift", {"device_id": card.affected_devices[0]}), ("analyze_traffic_flows", {"site_id": site}),
             ("trace_packet", {"source": switch, "destination": "10.100.100.40", "protocol": "tcp", "port": 443}),
             ("forecast_capacity", {"site_id": site})]
    calls += [("analyze_protocol", {"protocol": engine}) for engine in ("bgp", "ospf", "stp", "arp", "vlan", "nat", "ipsec", "tcp", "mtu", "qos",
                                                                        "ipv6", "wireless", "multicast", "tls", "threats", "traffic", "lateral", "all")]
    return calls


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_every_diagnostic_tool_runs(scenario: str) -> None:
    calls = tool_calls(scenario)
    assert {name for name, _ in calls} == set(REGISTRY)
    for name, arguments in calls:
        result = REGISTRY[name].invoke(scenario, REGISTRY[name].arguments(**arguments))
        assert result.status == ToolStatus.SUCCESS, (name, result.error)


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_phase_a_diagnosis_is_grounded(scenario: str) -> None:
    diagnosis = DiagnosisEngine().diagnose(request_for(CARD_BY_ID[scenario]))
    assert provenance_issues(diagnosis) == [] and diagnosis.validation_issues == []


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_protocol_report_is_grounded_and_safe(scenario: str) -> None:
    report = analyze(scenario)
    assert report.validation.grounded, report.validation.issues
    security = ("SUSPICIOUS_", "LATERAL_", "THREAT_", "ARP_GATEWAY", "TLS_UNEXPECTED", "IPV6_ROGUE", "WIFI_ROGUE", "BGP_ORIGIN_HIJACK")
    for finding in report.findings:
        if finding.code.startswith(security):
            assert finding.status in ("suspicious_indicator", "insufficient_evidence") and (finding.confidence or 0) <= 0.85
        assert all(is_read_only_command(c.command) for c in finding.commands)
    text = " ".join([report.headline] + [f.summary for f in report.findings])
    assert not re.search(r"\b(?:threat actor|APT\s?\d*|nation[- ]state|attributed to|confirmed (?:attack|breach))\b", text, re.I)


# ---------------------------------------------------------------- through the API, the incident flow and the conversation

@pytest.fixture
def api(tmp_path) -> ApiHarness:
    return ApiHarness(tmp_path)


def test_scenarios_are_offered_by_the_api(api) -> None:
    catalog = api.get("/protocols/engines", as_="viewer").json()
    offered = {s["scenario_id"]: s for s in catalog["scenarios"]}
    assert set(SCENARIOS) <= set(offered) and all(offered[s]["incident_title"] for s in SCENARIOS)


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_incident_diagnosis_and_protocol_analysis_through_the_api(api, scenario: str) -> None:
    created = api.post("/incidents", incident_payload(scenario), as_="operator")
    assert created.status_code == 201 and created.json()["incident"]["dataset_scenario_id"] == scenario
    incident_id = created.json()["incident"]["incident_id"]
    diagnosis = api.post("/diagnosis", {"scenario_id": scenario, "description": load_scenario(scenario).incident.description,
                                        "incident_id": incident_id, "site_ids": CARD_BY_ID[scenario].sites}, as_="operator")
    assert diagnosis.status_code == 200, diagnosis.text
    report = api.post("/protocols/analyze", {"incident_id": incident_id}, as_="operator").json()
    assert report["scenario_id"] == scenario and report["validation"]["grounded"] and len(report["engines"]) == 17
    assert api.get(f"/observability/health?scenario_id={scenario}", as_="operator").status_code == 200


@pytest.mark.parametrize("scenario", ["SCN-04-NYC-VOICE-VLAN-DELETED", "SCN-10-INSPECTION-CA-AND-SECURITY"])
def test_conversation_runs_protocol_checks_on_approval(api, scenario: str) -> None:
    created = api.post("/incidents", incident_payload(scenario), as_="operator").json()["incident"]
    cid = api.post("/conversations", {"mode": "rule_based", "incident_id": created["incident_id"]}, as_="operator").json()["conversation_id"]
    offer = api.post(f"/conversations/{cid}/messages", {"content": "run all protocol checks"}, as_="operator").json()
    assert offer["intent"]["name"] == "protocol_check" and not offer["execution"]["tools"]
    done = api.post(f"/conversations/{cid}/messages", {"content": "go ahead"}, as_="operator").json()
    assert any(s["tool"] == "analyze_protocol" and s["status"] == "executed" for s in done["execution"]["tools"])
    assert any(a["kind"] == "protocol" for a in done["attachments"])
