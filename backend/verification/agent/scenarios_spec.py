from app.agent import build_report
from app.engine.safety import is_read_only_command
from app.engine.schema import Confidence
from app.security.provenance import provenance_issues
from verification.agent.helpers import answer, call, cite, scripted_agent, status
from verification.engine.helpers import draft

LOW_OR_BELOW = {Confidence.LOW, Confidence.INSUFFICIENT_EVIDENCE}


def test_scenario_a_singapore_wan_failure_is_diagnosed_by_the_agent() -> None:
    agent, model = scripted_agent([
        call("search_knowledge", query="wan circuit down"),
        call("check_network_reachability", source="SIN-SW-01", destination="DC1-SRV-APP-01"),
        call("analyze_routing_adjacency", device_id="SIN-RTR-01"),
        call("get_device_logs", device_id="SIN-RTR-01", min_severity="warning"),
        answer(cite("LINK_DOWN_AT_FAILURE_POINT", "NO_ROUTE_TO_DESTINATION", "ADJACENCY_FAILED")),
    ])
    run = agent.run("WAN-FAILURE", "Users at the Singapore branch cannot access internal applications since 09:00.")
    report = build_report(run)
    assert report.method.value == "model" and report.status == "completed" and report.discrepancies == []
    assert report.affected_site == ["SIN"] and report.affected_service == ["application"]
    assert report.incident_understanding.timeframe == "since 09:00"
    assert report.fault_domain.value == "wan_isp" and report.confidence.level == Confidence.HIGH
    assert report.root_cause_hypothesis.origin == "ai_agent" and report.root_cause_hypothesis.verified_against_rules
    assert [c.tool for c in report.tool_calls] == ["check_network_reachability", "analyze_routing_adjacency", "get_device_logs"]
    assert run.budget.order[0] == "search_knowledge" and report.knowledge_guidance
    assert report.affected_path.reachability == "unreachable" and report.correlated_timeline
    assert report.verified_facts and provenance_issues(run.diagnosis) == []
    cited = set(run.diagnosis.fault.supporting_evidence_ids)
    assert cited <= {fact.evidence_id for fact in report.verified_facts}
    assert all(is_read_only_command(check.command) for check in report.recommended_next_checks)
    assert len(model.requests) == 5


def test_scenario_b_conflicting_report_is_not_turned_into_a_bengaluru_fault() -> None:
    agent, _ = scripted_agent([
        call("check_network_reachability", source="BLR-SW-01", destination="DC1-SRV-APP-01"),
        call("check_device_availability", device_id="BLR-RTR-01"),
        answer(draft(fault_domain="unknown", root_cause="No fault is visible at Bengaluru in the collected evidence",
                     root_cause_device_ids=[], root_cause_link_ids=[], reasoning="Bengaluru paths are reachable",
                     confidence="insufficient_evidence", confidence_explanation="Report not reproduced in telemetry",
                     next_checks=[{"device_id": "BLR-SW-01", "command": "ping {peer_ip} repeat 100", "purpose": "Re-test the path",
                                   "expected_observation": "Replies", "reason": "Confirm the report"}],
                     escalation={"team": "Network Operations - L2 triage", "priority": "p3", "reason": "Unconfirmed report"})),
    ])
    report = build_report(agent.run("WAN-FAILURE", "Users at the Bengaluru branch cannot access internal applications."))
    assert report.affected_site == ["BLR"] and report.fault_domain.value == "unknown"
    assert report.discrepancies and "BLR" in report.discrepancies[0] and "PATH_REACHABLE" in report.discrepancies[0]
    assert report.confidence.level in LOW_OR_BELOW and report.recommended_next_checks
    assert all(is_read_only_command(check.command) for check in report.recommended_next_checks)
    assert any("Confirm the affected site" in item for item in report.missing_evidence)
    assert report.required_human_confirmations[0].startswith("Resolve the conflict")


def test_scenario_b_overconfident_agent_is_capped() -> None:
    agent, _ = scripted_agent([
        call("check_network_reachability", source="BLR-SW-01", destination="DC1-SRV-APP-01"),
        answer(cite("PATH_REACHABLE", root_cause="Bengaluru WAN circuit is down", root_cause_device_ids=["BLR-RTR-01"],
                    root_cause_link_ids=["LNK-WAN-BLR"])),
    ])
    report = build_report(agent.run("WAN-FAILURE", "Users at the Bengaluru branch cannot access internal applications."))
    assert report.root_cause_hypothesis.evidence_support == "unsupported"
    assert report.confidence.level == Confidence.INSUFFICIENT_EVIDENCE and report.confidence.capped_from is not None
    assert any("BLR" in note and "PATH_REACHABLE" in note for note in report.discrepancies)
    assert any("BLR-RTR-01" in note for note in report.discrepancies)


def test_scenario_c_shared_device_with_missing_telemetry() -> None:
    agent, _ = scripted_agent([
        call("check_network_reachability", source="NYC-SW-01", destination="DC1-SRV-APP-01"),
        call("check_network_reachability", source="SIN-SW-01", destination="DC1-SRV-APP-01"),
        call("check_device_availability", device_id="CORE-RTR-01"),
        answer(cite("PEER_LINKS_DOWN", "TELEMETRY_GAP", fault_domain="shared_infrastructure",
                    root_cause="CORE-RTR-01 appears to have failed, isolating NYC and SIN", root_cause_device_ids=["CORE-RTR-01"],
                    root_cause_link_ids=[], reasoning="All peers report links to CORE-RTR-01 down and its telemetry stopped",
                    escalation={"team": "Core Network Operations", "priority": "p1", "reason": "Shared core router failure"})),
    ])
    run = agent.run("SHARED-DEVICE-FAILURE", "New York and Singapore offices are both offline.")
    report = build_report(run)
    assert report.affected_site == ["NYC", "SIN"] and report.fault_domain.value == "shared_infrastructure"
    assert report.discrepancies == [] and "CORE-RTR-01" in report.root_cause_hypothesis.device_ids
    gaps = [item for item in report.missing_evidence if item.startswith("CORE-RTR-01") and "not proof of failure" in item]
    assert gaps and any(fact.statement.startswith("No interface statistics from CORE-RTR-01") for fact in report.verified_facts)


def test_rule_based_fallback_completes_within_the_shared_budget() -> None:
    agent, _ = scripted_agent([call("search_knowledge", query="core router failure"), status(500)])
    run = agent.run("SHARED-DEVICE-FAILURE", "New York and Singapore offices are both offline.")
    report = build_report(run)
    assert report.method.value == "rule_based_fallback" and report.fault_domain.value == "shared_infrastructure"
    assert run.budget.attempts <= 10 and any("rejected; rule-based" in item for item in run.diagnosis.limitations)
    assert any("not proof of failure" in item for item in report.missing_evidence)
