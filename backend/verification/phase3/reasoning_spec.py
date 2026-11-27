"""Cross-layer correlation and confidence calibration.

Correlation: protocol findings are tied to the configuration change that introduced them, to core fault records, to each
other (causal edges built by the Phase 2 graph builder), to packet journeys and traffic shifts (Phase 1) and to visible
incident history. Calibration: confirmed >= 0.7, suspicious <= 0.85, possible <= 0.65, insufficient has no confidence,
and the confidence of findings across every scenario is well calibrated (Brier score)."""
from datetime import timedelta

import pytest

from app.network.repository import load_scenario
from app.protocols.analysis import analyze
from app.protocols.engines.base import Draft
from app.protocols.registry import calibrate
from verification.phase3.cases import CASES, correct


@pytest.fixture(scope="module")
def reports():
    return {s: analyze(s) for s in CASES}  # the Phase 3 cases; SCN-01 to SCN-10 are scored in verification/scenarios


def finding(report, code):
    return next(f for f in report.findings if f.code == code)


@pytest.mark.parametrize("scenario", [s for s, c in CASES.items() if c.root])
def test_root_cause_is_named(reports, scenario: str) -> None:
    report = reports[scenario]
    assert report.root_causes, report.headline
    lead = next(f for f in report.findings if f.finding_id == report.root_causes[0])
    assert lead.code == CASES[scenario].root and "Likely cause" in report.headline


@pytest.mark.parametrize("scenario", ["PACKET-LOSS", "ADV-METRO-FIBRE-DEGRADATION", "FIREWALL-BLOCKING", "SHARED-DEVICE-FAILURE", "WAN-FAILURE"])
def test_symptoms_explained_by_core_faults_are_not_called_causes(reports, scenario: str) -> None:
    report = reports[scenario]
    assert "an effect, not the cause" in report.headline
    assert not any(f.code.startswith("TCP_") for f in report.findings if f.finding_id in report.root_causes)


def test_config_change_is_correlated_with_the_misconfiguration(reports) -> None:
    leak = finding(reports["P3-BGP-ROUTE-LEAK"], "BGP_ROUTE_LEAK")
    changes = [c for c in leak.correlations if c.kind == "config_change"]
    assert any("redistribute static" in c.detail and "labadmin" in c.detail for c in changes)
    assert all(c.evidence and c.evidence[0].collection == "events" for c in changes)
    for scenario, code, text in [("P3-OSPF-DUPLICATE-RID", "OSPF_DUPLICATE_ROUTER_ID", "router-id 10.255.0.2"),
                                 ("P3-VLAN-TRUNK-PRUNE-BLR", "VLAN_PRUNED", "allowed vlan 10,99"),
                                 ("P3-NAT-EXHAUSTION", "NAT_POOL_EXHAUSTED", "4 addresses -> 1 address"),
                                 ("P3-IPSEC-DH-MISMATCH", "IPSEC_PROPOSAL_MISMATCH", "group20 -> group21"),
                                 ("P3-MCAST-RP-MISMATCH", "MCAST_RP_MISMATCH", "rp-address 10.255.0.2")]:
        assert any(text in c.detail for c in finding(reports[scenario], code).correlations if c.kind == "config_change"), scenario


def test_cross_protocol_causal_chains(reports) -> None:
    leak = reports["P3-BGP-ROUTE-LEAK"]
    assert "BGP-1" in finding(leak, "MCAST_RPF_FAILURE").explained_by, "a unicast leak breaks the multicast RPF check"
    mtu = reports["P3-MTU-BLACKHOLE-SIN"]
    clamp = finding(mtu, "MTU_OVERHEAD_NO_MSS_CLAMP").finding_id
    assert clamp in finding(mtu, "MTU_BLACK_HOLE").explained_by
    assert set(finding(mtu, "TCP_RETRANSMISSION_HIGH").explained_by) & {clamp, finding(mtu, "MTU_BLACK_HOLE").finding_id}
    ipv6 = reports["P3-IPV6-OSPFV3-BLR"]
    assert ipv6.causal_chain[0] == finding(ipv6, "IPV6_OSPFV3_ADJACENCY_DOWN").finding_id and len(ipv6.causal_chain) >= 3
    dup = reports["P3-OSPF-DUPLICATE-RID"]
    assert finding(dup, "OSPF_DUPLICATE_ROUTER_ID").finding_id in finding(dup, "OSPF_LSA_CHURN").explained_by


def test_core_link_loss_explains_protocol_effects(reports) -> None:
    wan = reports["WAN-FAILURE"]
    for code in ("IPSEC_PEER_UNREACHABLE", "MCAST_PIM_NEIGHBOR_DOWN", "TCP_HANDSHAKE_FAILURES"):
        assert finding(wan, code).explained_by, code
    tunnel = finding(wan, "IPSEC_PEER_UNREACHABLE")
    assert "not a VPN configuration problem" in tunnel.summary


def test_mtu_mismatch_explains_the_stale_lsdb(reports) -> None:
    ospf = reports["OSPF-ADJACENCY-FAILURE"]
    assert finding(ospf, "MTU_MISMATCH").finding_id in finding(ospf, "OSPF_LSDB_STALE").explained_by


def test_packet_journey_and_traffic_from_phase_1(reports) -> None:
    leak = finding(reports["P3-BGP-ROUTE-LEAK"], "BGP_ROUTE_LEAK")
    journey = next(c for c in leak.correlations if c.kind == "packet_journey")
    assert "NYC-RTR-01" in journey.detail and journey.evidence
    shared = next(c for c in leak.correlations if c.kind == "topology")
    assert "CORE-SW-01" in shared.detail


def test_timing_relative_to_onset(reports) -> None:
    clamp = finding(reports["P3-MTU-BLACKHOLE-SIN"], "MTU_OVERHEAD_NO_MSS_CLAMP")
    assert any(c.kind == "timing" and "9 min before the reported onset" in c.detail for c in clamp.correlations)


def test_related_incidents_come_only_from_what_is_passed_in() -> None:
    onset = load_scenario("P3-STP-LOOP-NYC").scenario.onset_at
    current = {"incident_id": "INC-1", "site_ids": ["NYC"], "created_at": onset, "devices": []}
    others = [{"incident_id": "INC-2", "title": "NYC phones dropping", "site_ids": ["NYC"], "created_at": onset + timedelta(minutes=20), "devices": []},
              {"incident_id": "INC-3", "title": "Old SIN issue", "site_ids": ["SIN"], "created_at": onset - timedelta(days=3), "devices": []}]
    report = analyze("P3-STP-LOOP-NYC", ["stp"], symptoms="", current_incident=current, other_incidents=others)
    assert [r.incident_id for r in report.related_incidents] == ["INC-2"]
    assert analyze("P3-STP-LOOP-NYC", ["stp"]).related_incidents == []


def test_follow_up_checks_are_suggested_not_run() -> None:
    report = analyze("P3-MTU-BLACKHOLE-SIN", ["tcp"], symptoms="large downloads stall")
    assert {c.engine for c in report.next_checks} >= {"mtu"} and [e.engine for e in report.engines] == ["tcp"]


def test_phase_2_fault_model_ranks_protocol_evidence(reports) -> None:
    assert reports["P3-STP-LOOP-NYC"].hypotheses[0].domain == "switching"
    assert reports["P3-VLAN-TRUNK-PRUNE-BLR"].hypotheses[0].domain == "switching"
    assert reports["P3-NAT-EXHAUSTION"].hypotheses[0].domain == "firewall"
    assert reports["P3-OSPF-DUPLICATE-RID"].hypotheses[0].domain == "routing"


# ---------------------------------------------------------------- calibration

def draft(status: str, strength: str, **extra) -> Draft:
    return Draft("X", status, "anomaly", "major", "t", "s", strength, [], "b", **extra)


def test_calibration_rules() -> None:
    assert calibrate(draft("confirmed_fault", "two_sided"), False, False) == (0.92, "confirmed_fault")
    assert calibrate(draft("confirmed_fault", "measured", corroboration=5), False, False)[0] == 0.91
    assert calibrate(draft("confirmed_fault", "behavioural"), False, False) == (0.62, "possible_explanation"), "weak basis cannot confirm"
    assert calibrate(draft("confirmed_fault", "measured"), True, True)[1] == "possible_explanation", "stale and partial data downgrade"
    assert calibrate(draft("suspicious_indicator", "two_sided", corroboration=3), False, False)[0] == 0.85, "intent is never certain"
    assert calibrate(draft("possible_explanation", "direct"), False, False)[0] == 0.65
    assert calibrate(draft("insufficient_evidence", "none"), False, False) == (None, "insufficient_evidence")
    assert calibrate(draft("confirmed_fault", "direct", contradictions=1), False, False) == (0.68, "possible_explanation")


def test_status_bands_hold_everywhere(reports) -> None:
    for report in reports.values():
        for f in report.findings:
            if f.status == "insufficient_evidence":
                assert f.confidence is None
            elif f.status == "confirmed_fault":
                assert f.confidence >= 0.7
            elif f.status == "suspicious_indicator":
                assert f.confidence <= 0.85
            else:
                assert f.confidence <= 0.65


def test_confidence_is_well_calibrated(reports) -> None:
    pairs = [(f.confidence, 1.0 if correct(s, f.code) else 0.0) for s, r in reports.items() for f in r.findings if f.confidence is not None]
    brier = sum((c - o) ** 2 for c, o in pairs) / len(pairs)
    assert len(pairs) > 60 and brier < 0.08, brier


def test_threat_likelihood_grows_with_independent_indicators(reports) -> None:
    lateral = finding(reports["P3-SEC-LATERAL-MOVEMENT-NYC"], "THREAT_CORRELATED_ACTIVITY")
    tunnel = finding(reports["P3-SEC-DNS-TUNNEL-BLR"], "THREAT_CORRELATED_ACTIVITY")
    mitm = finding(reports["P3-SEC-ARP-MITM-SIN"], "THREAT_CORRELATED_ACTIVITY")
    assert lateral.facts["probability"] > mitm.facts["probability"] > tunnel.facts["probability"]
    assert lateral.facts["stages"] == ["recon", "credential_access", "lateral_movement", "command_and_control", "exfiltration"]
    assert all(t.facts["probability"] <= 0.9 for t in (lateral, tunnel, mitm))
