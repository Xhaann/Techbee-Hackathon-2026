"""Phase 2 diagnostic intelligence (features 1-17), checked against every scenario's ground truth. Deterministic, offline."""
import math
from datetime import timedelta
from functools import lru_cache

import pytest

from app.engine.engine import DiagnosisEngine
from app.engine.safety import is_read_only_command
from app.engine.schema import EvidenceItem, EvidenceType, FaultDomain
from app.network.repository import load_scenario
from app.reasoning.causal import build_graph, localise, precedence
from app.reasoning.commands import commands_for
from app.reasoning.inference import calibrate, contradictions, posterior, uncertainty
from app.reasoning.report import analyze, correlate_incidents
from app.reasoning.specialists import AGENTS, Scope, checks_from_records, coordinate, investigate, priority
from verification.benchmark.cases import CASES
from verification.engine.helpers import incident_request

SCENARIOS = sorted(CASES)


def scope_of(scenario_id: str) -> Scope:
    incident = load_scenario(scenario_id).incident
    if incident is None:
        return Scope(scenario_id, ("NYC",))
    return Scope(scenario_id, tuple(incident.affected_site_ids), (), (), (), incident.description + " " + " ".join(incident.symptoms))


@lru_cache(maxsize=None)
def engine_run(scenario_id: str):
    diagnosis, records = DiagnosisEngine().diagnose_with_records(incident_request(scenario_id))
    conclusion = {"fault_domain": diagnosis.fault.fault_domain.value, "device_ids": diagnosis.fault.device_ids,
                  "supporting_evidence_ids": diagnosis.fault.supporting_evidence_ids, "root_cause": diagnosis.fault.root_cause,
                  "confidence": diagnosis.confidence.level.value}
    report = analyze(diagnosis.evidence, scope_of(scenario_id), load_scenario(scenario_id).scenario.onset_at,
                     checks_from_records(records), conclusion)
    return diagnosis, records, report


@lru_cache(maxsize=None)
def team_run(scenario_id: str):
    run = investigate(scope_of(scenario_id))
    report = analyze(run.evidence, scope_of(scenario_id), load_scenario(scenario_id).scenario.onset_at, run.executed)
    return run, report


# ---- 1-4: multi-agent architecture and the three named specialists

def test_coordinator_runs_every_specialist_under_one_budget() -> None:
    plan = coordinate(scope_of("WAN-FAILURE"))
    assert len(plan) == 10 and len({c.key for c in plan}) == 10
    assert {c.agent for c in plan} == {"transport", "routing", "security", "dns_dhcp"}
    assert all(c.tool in {"analyze_path_health", "analyze_routing_adjacency", "get_firewall_logs", "get_dhcp_dns_status",
                          "get_event_timeline", "check_network_reachability", "get_device_logs", "get_change_history",
                          "check_device_availability", "get_routing_state", "trace_packet", "analyze_packet_loss"} for c in plan)


@pytest.mark.parametrize(("text", "first"), [("users cannot resolve names", "dns_dhcp"), ("802.1X authentication failed", "security"),
                                             ("laptops get a self-assigned 169.254 address", "dns_dhcp"), ("everything is down", "transport")])
def test_coordinator_puts_the_relevant_specialist_first(text: str, first: str) -> None:
    assert priority(Scope("BASELINE", ("SIN",), text=text))[0] == first


@pytest.mark.parametrize("scenario_id", SCENARIOS)
def test_multi_agent_investigation_finds_the_ground_truth_domain(scenario_id: str) -> None:
    run, report = team_run(scenario_id)
    assert len(run.executed) <= 10 and run.records
    assert report.fault_supported and report.leading in CASES[scenario_id].domains, (report.leading, report.hypotheses[:2])
    implicated = [s for s in report.specialists if s.verdict == "implicated"]
    assert len(implicated) == 1 and report.leading.value in implicated[0].domains


@pytest.mark.parametrize(("scenario_id", "agent"), [("OSPF-ADJACENCY-FAILURE", "routing"), ("ADV-BLR-OSPF-AUTH-MISMATCH", "routing"),
                                                    ("FIREWALL-BLOCKING", "security"), ("VLAN-AUTHENTICATION-FAILURE", "security"),
                                                    ("DNS-RESOLUTION-FAILURE", "dns_dhcp"), ("ADV-NYC-VOICE-DHCP-RELAY", "dns_dhcp")])
def test_each_specialist_implicates_its_own_faults_and_clears_others(scenario_id: str, agent: str) -> None:
    _, _, report = engine_run(scenario_id)
    verdicts = {s.agent: s for s in report.specialists}
    assert verdicts[agent].verdict == "implicated" and verdicts[agent].evidence_ids
    assert all(v.verdict in ("cleared", "inconclusive", "possible") for name, v in verdicts.items() if name != agent)
    assert all(is_read_only_command(c["command"]) for c in verdicts[agent].recommended_commands)


def test_baseline_has_no_fault_and_every_specialist_clears() -> None:
    _, report = team_run("BASELINE")
    assert not report.fault_supported and report.leading is None and report.self_evaluation.verdict == "no_fault"
    assert {s.verdict for s in report.specialists} <= {"cleared", "inconclusive"}


# ---- 5, 17: cross-layer and graph-based reasoning

def test_cross_layer_places_the_conclusion_on_the_lowest_failing_layer() -> None:
    _, _, report = engine_run("WAN-FAILURE")
    assert report.cross_layer["lowest_failing_layer"] == "physical" and report.cross_layer["conclusion_layer"] == "physical"
    _, _, routing = engine_run("OSPF-ADJACENCY-FAILURE")
    assert routing.cross_layer["conclusion_layer"] == "network"


def test_graph_localisation_finds_the_shared_upstream_device() -> None:
    shared = localise(["NYC", "SIN"], ["BLR"])
    assert "CORE-RTR-01" in shared["common_devices"] and shared["shared"] and "CORE-RTR-02" not in shared["common_devices"]
    assert "CORE-SW-01" in shared["excluded_by_unaffected"]


# ---- 6, 12: causal inference and the root-cause dependency graph

@pytest.mark.parametrize(("scenario_id", "root", "effect"), [
    ("OSPF-ADJACENCY-FAILURE", "CONFIG_CHANGE", "NO_ROUTE_TO_DESTINATION"), ("FIREWALL-BLOCKING", "RULE_MODIFIED_IN_RANGE", "TRAFFIC_DENIED"),
    ("VLAN-AUTHENTICATION-FAILURE", "RADIUS_INVALID_AUTHENTICATOR", "DHCP_TRANSACTIONS_STOPPED"),
    ("ADV-NYC-VOICE-DHCP-RELAY", "CONFIG_CHANGED", "DHCP_TRANSACTIONS_STOPPED"), ("SHARED-DEVICE-FAILURE", "TELEMETRY_GAP", "NO_ROUTE_TO_DESTINATION"),
])
def test_causal_chain_runs_from_root_cause_to_symptom(scenario_id: str, root: str, effect: str) -> None:
    _, _, report = engine_run(scenario_id)
    chain = [c["code"] for c in report.causal.chain]
    assert chain[0] == root and effect in chain and report.causal.coverage >= 0.6


def test_causal_edges_respect_time_and_topology() -> None:
    diagnosis, _, _ = engine_run("WAN-FAILURE")
    graph = build_graph(diagnosis.evidence, load_scenario("WAN-FAILURE").scenario.onset_at)
    by_id = {i.evidence_id: i for i in diagnosis.evidence}
    for edge in graph.edges:
        cause, effect = by_id[edge.cause], by_id[edge.effect]
        if cause.timestamp and effect.timestamp and effect.code not in ("TELEMETRY_GAP", "DHCP_TRANSACTIONS_STOPPED"):
            assert effect.timestamp >= cause.timestamp - timedelta(minutes=2), edge
    # A cause in another part of the network is never linked to an effect that does not depend on it.
    item = lambda eid, code, device: EvidenceItem(evidence_id=eid, call_id="C1", tool="t", evidence_type=EvidenceType.OBSERVED_FINDING,
                                                  code=code, device_id=device, summary="s")
    isolated = build_graph([item("E1", "LINK_DOWN", "BLR-RTR-01"), item("E2", "BGP_NEIGHBOR_DOWN", "NYC-RTR-01")], None)
    assert isolated.edges == []


# ---- 7, 8, 9, 14: multi-hypothesis, Bayesian probabilities, calibration, uncertainty

@pytest.mark.parametrize("scenario_id", SCENARIOS)
def test_bayesian_posterior_ranks_the_true_domain_first(scenario_id: str) -> None:
    _, _, report = engine_run(scenario_id)
    total = 0.0
    assert report.hypotheses[0].domain in CASES[scenario_id].domains and report.hypotheses[0].status == "leading"
    for h in report.hypotheses:
        total += h.probability
        assert 0.0 <= h.probability <= 1.0
    assert total <= 1.0001 and len(report.hypotheses) >= 3


def test_posterior_is_a_proper_distribution_and_calibration_weights_are_explained() -> None:
    diagnosis, _, _ = engine_run("WAN-FAILURE")
    calibrated = calibrate(diagnosis.evidence, load_scenario("WAN-FAILURE").scenario.onset_at)
    result = posterior(calibrated)
    assert math.isclose(sum(result.probabilities.values()), 1.0, abs_tol=1e-3)
    assert all(c.reasons for c in calibrated) and all(0 <= c.weight <= 1.2 for c in calibrated)
    observed = next(c for c in calibrated if c.code == "LINK_DOWN_AT_FAILURE_POINT")
    assert observed.weight >= 0.85


def test_injected_evidence_carries_no_weight_and_repeats_are_discounted() -> None:
    item = lambda eid, code: EvidenceItem(evidence_id=eid, call_id="C1", tool="t", evidence_type=EvidenceType.OBSERVED_FINDING,
                                          code=code, summary="s")
    flagged = calibrate([item("E1", "TRAFFIC_DENIED")], None, flagged={"E1"})
    assert flagged[0].weight == 0 and posterior(flagged).evidence_used == 0
    once = posterior(calibrate([item("E1", "DNS_SERVFAIL")], None)).probabilities[FaultDomain.DNS]
    ten = posterior(calibrate([item(f"E{i}", "DNS_SERVFAIL") for i in range(10)], None)).probabilities[FaultDomain.DNS]
    assert ten > once and ten < 1.0


def test_calibration_brier_score_across_all_scenarios() -> None:
    """Brier score of the probability given to the true answer; 0 is perfect, 0.25 is a coin flip."""
    scores = []
    for scenario_id in SCENARIOS:
        _, _, report = engine_run(scenario_id)
        truth = sum(h.probability for h in report.hypotheses if h.domain in CASES[scenario_id].domains)
        scores.append((1 - truth) ** 2)
    assert sum(scores) / len(scores) < 0.05, scores


def test_uncertainty_is_high_without_evidence_and_low_with_clear_evidence() -> None:
    assert uncertainty(posterior([])).level == "high"
    _, _, report = engine_run("DNS-RESOLUTION-FAILURE")
    assert report.uncertainty["level"] == "low" and report.uncertainty["margin"] > 0.6


# ---- 10: contradictions

def test_contradictions_are_detected() -> None:
    item = lambda eid, code, device=None: EvidenceItem(evidence_id=eid, call_id="C1", tool="t", evidence_type=EvidenceType.OBSERVED_FINDING,
                                                       code=code, device_id=device, summary="s")
    refuted = contradictions([item("E1", "PATH_REACHABLE"), item("E2", "PATH_REACHABLE")], FaultDomain.WAN_ISP, [], ["SIN"], ["SIN"])
    assert refuted[0].kind == "refutes_conclusion" and refuted[0].severity == "strong"
    conflict = contradictions([item("E1", "LINK_DOWN", "SIN-RTR-01"), item("E2", "PATH_REACHABLE", "SIN-RTR-01")], None, [], [], [])
    assert conflict[0].kind == "conflicting_telemetry"
    recovered = contradictions([item("E1", "LINK_FLAP_RECOVERED"), item("E2", "PATH_REACHABLE")], FaultDomain.WAN_ISP, [], [], [])
    assert recovered == []


@pytest.mark.parametrize("scenario_id", SCENARIOS)
def test_correct_diagnoses_have_no_contradictions_and_pass_self_evaluation(scenario_id: str) -> None:
    _, _, report = engine_run(scenario_id)
    assert not [c for c in report.contradictions if c.severity == "strong"]
    assert report.self_evaluation.verdict == "sound", [c for c in report.self_evaluation.checks if not c.passed]


# ---- 11: temporal correlation

def test_temporal_precedence_and_incident_correlation() -> None:
    diagnosis, _, report = engine_run("OSPF-ADJACENCY-FAILURE")
    first = precedence(diagnosis.evidence, load_scenario("OSPF-ADJACENCY-FAILURE").scenario.onset_at)[0]
    assert first["code"] in ("CONFIG_CHANGE", "MTU_CHANGE") and first["seconds_before_onset"] <= 120
    assert report.causal.clusters and report.causal.clusters[0]["evidence_ids"]
    from datetime import datetime, timezone
    now = datetime(2026, 3, 10, 9, 0, tzinfo=timezone.utc)
    current = {"incident_id": "INC-1", "site_ids": ["NYC"], "created_at": now, "devices": []}
    others = [{"incident_id": "INC-2", "title": "Singapore down", "site_ids": ["SIN"], "created_at": now + timedelta(minutes=4), "devices": []},
              {"incident_id": "INC-3", "title": "Old", "site_ids": ["NYC"], "created_at": now - timedelta(days=2), "devices": []}]
    related = correlate_incidents(current, others)
    assert [r.incident_id for r in related] == ["INC-2"] and "CORE-RTR-01" in related[0].relation


# ---- 13, 15, 16: explanation, self-evaluation, planning

def test_explanation_names_the_cause_the_chain_and_the_alternatives() -> None:
    _, _, report = engine_run("FIREWALL-BLOCKING")
    assert report.explanation.summary.startswith("Most likely firewall policy")
    assert any("rule modified" in line for line in report.explanation.why) and report.explanation.alternatives


def test_self_evaluation_catches_a_wrong_conclusion() -> None:
    diagnosis, records, _ = engine_run("WAN-FAILURE")
    wrong = {"fault_domain": "dns", "device_ids": [], "supporting_evidence_ids": ["E1", "E99"], "root_cause": "DNS outage", "confidence": "high"}
    report = analyze(diagnosis.evidence, scope_of("WAN-FAILURE"), load_scenario("WAN-FAILURE").scenario.onset_at,
                     checks_from_records(records), wrong)
    failed = {c.name for c in report.self_evaluation.checks if not c.passed}
    assert {"grounded", "agrees_with_probabilities"} <= failed and report.self_evaluation.verdict == "weak"
    assert report.self_evaluation.calibrated_confidence == "low"


def test_planning_proposes_unrun_checks_that_separate_hypotheses() -> None:
    run, report = team_run("PACKET-LOSS")
    executed = {(c.tool, str(sorted(c.arguments.items()))) for c in run.executed}
    assert report.plan, "a moderate-uncertainty case should get a plan"
    assert all(step.value > 0 and step.purpose for step in report.plan)
    assert not {(s.tool, str(sorted(s.arguments.items()))) for s in report.plan} & executed
    assert all(step.tool in {c.tool for agent in AGENTS.values() for c in agent.plan(scope_of("PACKET-LOSS"))} for step in report.plan)


def test_commands_are_read_only_and_platform_specific() -> None:
    commands = commands_for(site_id="BLR", services=["application", "dns", "dhcp", "authentication"])
    assert commands and all(is_read_only_command(c.command) for c in commands)
    assert {c.platform for c in commands} == {"Cisco IOS XE", "PAN-OS", "Linux"}
    assert "show ip ospf neighbor" in [c.command for c in commands] and "show ip bgp summary" not in [c.command for c in commands]
    assert "show ip bgp summary" in [c.command for c in commands_for(site_id="SIN")]


def test_compact_reasoning_stays_small() -> None:
    import json
    for scenario_id in SCENARIOS:
        assert len(json.dumps(engine_run(scenario_id)[2].compact())) < 1500
