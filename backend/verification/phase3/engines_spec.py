"""Features 1-17, one by one: each engine detects its fault in its own scenario with the right status, stays silent on the
healthy baseline and the busy-but-healthy hour, and reports missing data as insufficient evidence instead of guessing."""
import pytest

from app.network.repository import load_scenario, load_topology
from app.protocols.registry import BY_NAME, ENGINES, run_engines
from app.protocols.repository import load_telemetry
from verification.phase3.cases import CASES, FEATURE_SCENARIO, correct

NAMES = [e.name for e in ENGINES]


def run(scenario_id: str, names: list[str], site: str | None = None, device: str | None = None):
    return run_engines(load_topology(), load_scenario(scenario_id), load_telemetry(scenario_id), names, site, device)


def test_seventeen_engines_numbered_one_to_seventeen() -> None:
    assert sorted(e.feature for e in ENGINES) == list(range(1, 18)) and len(BY_NAME) == 17


@pytest.mark.parametrize("engine", NAMES)
def test_engine_detects_its_fault(engine: str) -> None:
    scenario, code = FEATURE_SCENARIO[engine]
    results, findings = run(scenario, [engine])
    hit = [f for f in findings if f.code == code]
    assert hit, f"{engine} missed {code} in {scenario}: {[f.code for f in findings]}"
    assert hit[0].status == CASES[scenario].expect[code]
    assert hit[0].evidence and hit[0].confidence is not None
    assert results[0].status in ("fault", "suspicious", "possible")


@pytest.mark.parametrize("engine", NAMES)
@pytest.mark.parametrize("scenario", ["BASELINE", "P3-HEALTHY-BUSY", "P3-ADV-DECOYS"])
def test_engine_is_silent_on_healthy_and_decoy_data(engine: str, scenario: str) -> None:
    results, findings = run(scenario, [engine])
    assert findings == [] and results[0].status == "healthy", [f.title for f in findings]


@pytest.mark.parametrize("scenario", sorted(CASES))
def test_every_scenario_matches_its_expected_findings(scenario: str) -> None:
    case = CASES[scenario]
    _, findings = run(scenario, NAMES)
    found = {f.code: f.status for f in findings}
    for code, status in case.expect.items():
        assert found.get(code) == status, f"{scenario}: {code} expected {status}, got {found.get(code)}"
    unexpected = [f.code for f in findings if not correct(scenario, f.code)]
    assert not unexpected, f"{scenario}: unexpected findings {unexpected}"


def test_missing_sections_are_insufficient_evidence_not_healthy() -> None:
    results, findings = run("P3-EDGE-PARTIAL-TELEMETRY", ["wireless", "multicast"])
    assert [r.status for r in results] == ["insufficient", "insufficient"]
    assert all(f.status == "insufficient_evidence" and f.confidence is None for f in findings)


def test_stale_data_is_not_used_to_rule_anything_out() -> None:
    results, findings = run("P3-EDGE-PARTIAL-TELEMETRY", ["stp"])
    assert results[0].status == "insufficient" and findings[0].code == "STP_DATA_STALE"


def test_conflicting_session_states_are_flagged_not_resolved() -> None:
    _, findings = run("P3-EDGE-PARTIAL-TELEMETRY", ["bgp"])
    conflict = next(f for f in findings if f.code == "BGP_SESSION_STATE_CONFLICT")
    assert conflict.status == "possible_explanation" and conflict.kind == "conflicting_state" and conflict.confidence <= 0.65


def test_all_size_mtu_failures_are_reachability_not_mtu() -> None:
    results, findings = run("WAN-FAILURE", ["mtu"])
    assert not [f for f in findings if f.code.startswith("MTU_")]
    assert any("reachability problem, not an MTU problem" in n for n in results[0].notes)


def test_zero_window_points_at_the_server_not_the_network() -> None:
    _, findings = run("P3-TCP-ZERO-WINDOW-ERP", ["tcp"])
    assert [f.code for f in findings] == ["TCP_ZERO_WINDOW"] and findings[0].device_id == "DC1-SRV-APP-01"
    assert "not the network" in findings[0].basis


def test_loop_mac_flaps_are_not_reported_as_arp_spoofing() -> None:
    _, findings = run("P3-STP-LOOP-NYC", ["arp"])
    assert findings == []


def test_virtual_gateway_mac_is_not_spoofing() -> None:
    results, findings = run("P3-ADV-DECOYS", ["arp"])
    assert findings == [] and any("first-hop redundancy" in n for n in results[0].notes)


def test_static_conflict_is_a_fault_not_an_attack() -> None:
    _, findings = run("P3-ARP-IP-CONFLICT-SIN", ["arp"])
    assert [(f.code, f.status, f.kind) for f in findings] == [("ARP_IP_CONFLICT", "confirmed_fault", "misconfiguration")]


def test_scavenger_drops_are_by_design() -> None:
    results, findings = run("P3-HEALTHY-BUSY", ["qos"])
    assert findings == [] and any("by design" in n or "expected, not a fault" in n for n in results[0].notes)


def test_busy_wifi_with_clean_rf_is_healthy() -> None:
    results, findings = run("P3-HEALTHY-BUSY", ["wireless"])
    assert findings == [] and any("Busy but healthy" in n for n in results[0].notes)


def test_internal_route_leak_vs_external_hijack() -> None:
    _, findings = run("P3-BGP-ROUTE-LEAK", ["bgp"])
    leak = next(f for f in findings if f.code == "BGP_ROUTE_LEAK")
    assert leak.kind == "misconfiguration" and leak.facts["origin_asn"] == 65010 and leak.facts["registered_origin"] == 65000
    assert "DC1-SRV-APP-01" in leak.facts["covers"] and set(leak.affected_sites) == {"BLR", "NYC", "SIN"}


def test_remarking_is_located_to_the_hop_that_does_it() -> None:
    _, findings = run("P3-QOS-REMARK-NYC", ["qos"])
    remark = next(f for f in findings if f.code == "QOS_REMARKING")
    assert remark.device_id == "NYC-RTR-01" and remark.facts["last_correct"] == "NYC-SW-01:Gi1/0/24"


def test_ipsec_mismatch_names_the_field() -> None:
    _, findings = run("P3-IPSEC-DH-MISMATCH", ["ipsec"])
    assert findings[0].facts["fields"] == ["dh_group"] and findings[0].facts["hub"] == {"dh_group": 21}
    assert sorted(findings[0].facts["branches"]) == ["BLR-RTR-01", "NYC-RTR-01", "SIN-RTR-01"]


def test_mtu_black_hole_finds_the_effective_mtu() -> None:
    _, findings = run("P3-MTU-BLACKHOLE-SIN", ["mtu"])
    hole = next(f for f in findings if f.code == "MTU_BLACK_HOLE")
    assert hole.facts["effective_mtu"] == 1427 and hole.facts["icmp_filtered_on"] == ["DC1-FW-01"]


def test_tcp_size_dependent_loss_is_recognised() -> None:
    _, findings = run("P3-MTU-BLACKHOLE-SIN", ["tcp"])
    assert all(f.facts["size_dependent"] for f in findings if f.code == "TCP_RETRANSMISSION_HIGH")
    _, packet_loss = run("PACKET-LOSS", ["tcp"])
    assert not any(f.facts["size_dependent"] for f in packet_loss if f.code == "TCP_RETRANSMISSION_HIGH")


def test_multicast_rpf_check_uses_the_unicast_table() -> None:
    _, findings = run("P3-BGP-ROUTE-LEAK", ["multicast"])
    rpf = next(f for f in findings if f.code == "MCAST_RPF_FAILURE")
    assert "CORE-RTR-01" in rpf.facts["routers"] and rpf.facts["source"] == "10.100.100.40"


def test_site_and_device_scope_filter_findings() -> None:
    _, nyc = run("P3-SEC-LATERAL-MOVEMENT-NYC", ["traffic", "lateral"], site="NYC")
    _, sin = run("P3-SEC-LATERAL-MOVEMENT-NYC", ["traffic", "lateral"], site="SIN")
    assert nyc and not [f for f in sin if f.status != "insufficient_evidence"]
    _, device = run("P3-OSPF-DUPLICATE-RID", ["ospf"], device="BLR-RTR-01")
    assert any(f.code == "OSPF_DUPLICATE_ROUTER_ID" for f in device)


def test_an_engine_error_does_not_take_the_others_down(monkeypatch) -> None:
    from app.protocols import registry
    broken = registry.BY_NAME["bgp"].__class__(**{**registry.BY_NAME["bgp"].__dict__, "analyze": lambda ctx: 1 / 0})
    monkeypatch.setitem(registry.BY_NAME, "bgp", broken)
    results, findings = run("P3-STP-LOOP-NYC", ["bgp", "stp"])
    assert results[0].status == "error" and results[1].status == "fault" and any(f.code == "STP_LOOP" for f in findings)
