"""Regression tests for five diagnostic defects first exposed by the SCN-01..SCN-10 incident set.

Each defect is reproduced here on inputs built from the healthy BASELINE dataset (the defect's pattern injected into it),
or on the functions directly, so these tests do not just replay the scenarios that exposed them:
1. a hub's IKE failure about one peer attributed to every tunnel on the hub, and a one-way tunnel hidden behind it;
2. a minor "possible" finding ranked as the root over a measured fault, and link saturation treated only as a symptom;
3. "no protocol cause found" when a suspicious finding explains the symptom (protocol headline and reasoning summary);
4. one finding per repeated observation (rogue router advertisements, counter intervals) and one threat cluster each;
5. specialists that miss vague wording ("half the users", "short freezes", "new desk set up") or chase benign mentions.
"""
from datetime import timedelta

import pytest

from app.diagnostics import EvidenceRef
from app.engine.schema import EvidenceItem, EvidenceType
from app.network.models import NetworkEvent
from app.network.repository import load_scenario, load_topology
from app.protocols import analysis
from app.protocols.engines.base import Draft, ref
from app.protocols.engines.ipsec import tunnel_events
from app.protocols.models import ProtocolTelemetry
from app.protocols.registry import merge_duplicates, run_engines
from app.protocols.repository import load_telemetry
from app.reasoning.report import analyze as reason
from app.reasoning.specialists import Scope, coordinate, protocol_engines

BASE = "BASELINE"
ONSET = load_scenario(BASE).scenario.onset_at


def at(minutes: float):
    return ONSET + timedelta(minutes=minutes)


def telemetry_data() -> dict:
    return load_telemetry(BASE).model_dump(mode="json")


def run(names: list[str], dataset=None, data: dict | None = None, site: str | None = None):
    telemetry = ProtocolTelemetry.model_validate(data) if data is not None else load_telemetry(BASE)
    return run_engines(load_topology(), dataset or load_scenario(BASE), telemetry, names, site)


def analyse(monkeypatch, dataset=None, data: dict | None = None, **kwargs):
    """The full protocol report on BASELINE with the given changes injected."""
    telemetry = ProtocolTelemetry.model_validate(data) if data is not None else load_telemetry(BASE)
    monkeypatch.setattr(analysis, "load_scenario", lambda _: dataset or load_scenario(BASE))
    monkeypatch.setattr(analysis, "load_telemetry", lambda _: telemetry)
    return analysis.analyze(BASE, **kwargs)


def core_event(event_id: str, minutes: float, device: str, kind: str, message: str) -> NetworkEvent:
    return NetworkEvent(event_id=event_id, timestamp=at(minutes), device_id=device, severity="notice", event_type=kind, message=message)


def ike_failure(data: dict, device: str, peer: str | None, minutes: float, event_id: str = "PE-T-01") -> None:
    data["events"].append({"event_id": event_id, "timestamp": at(minutes).isoformat(), "protocol": "ipsec", "kind": "IKE_AUTH_FAILED",
                           "device_id": device, "detail": "IKEv2 authentication failed: pre-shared key mismatch", "peer": peer, "count": 12})


def set_tunnel(data: dict, tunnel_id: str, **values) -> None:
    next(t for t in data["ipsec"]["tunnels"] if t["tunnel_id"] == tunnel_id).update(values)


# ------------------------------------------------------------------ 1. IPsec evidence scoped to one tunnel

def test_hub_auth_failure_about_one_peer_is_one_finding_for_that_tunnel() -> None:
    data = telemetry_data()
    ike_failure(data, "CORE-FW-01", "SIN-RTR-01", 1)
    set_tunnel(data, "TUN-SIN-BACKUP", phase1="down", phase2_sas=0)
    set_tunnel(data, "TUN-SIN-BACKUP-HUB", phase1="negotiating", phase2_sas=0)
    _, findings = run(["ipsec"], data=data)
    auth = [f for f in findings if f.code == "IPSEC_AUTH_FAILURE"]
    assert len(auth) == 1 and auth[0].affected_sites == ["SIN"] and "SIN-RTR-01" in auth[0].title
    assert any(e.record_id == "PE-T-01" for e in auth[0].evidence)


def test_log_lines_outside_the_window_or_without_a_clear_tunnel_are_not_attributed() -> None:
    data = telemetry_data()
    ike_failure(data, "CORE-FW-01", "NYC-RTR-01", -24 * 60, "PE-T-OLD")  # yesterday
    ike_failure(data, "CORE-FW-01", None, 1, "PE-T-HUB")                 # the hub terminates three tunnels: ambiguous
    _, findings = run(["ipsec"], data=data)
    assert not [f for f in findings if f.code == "IPSEC_AUTH_FAILURE"]
    events = ProtocolTelemetry.model_validate(data).events
    hubs = {"CORE-FW-01"}
    window = (load_scenario(BASE).scenario.window_start - timedelta(hours=2), load_scenario(BASE).scenario.window_end)
    assert tunnel_events(events, "NYC-RTR-01", "CORE-FW-01", *window, hubs) == []
    ike_failure(data, "BLR-RTR-01", None, 1, "PE-T-BRANCH")               # a branch with one tunnel: unambiguous
    events = ProtocolTelemetry.model_validate(data).events
    assert [e.event_id for e in tunnel_events(events, "BLR-RTR-01", "CORE-FW-01", *window, hubs)] == ["PE-T-BRANCH"]


def test_one_way_tunnel_is_reported_beside_another_tunnels_auth_failure_and_names_the_removed_return_route() -> None:
    data = telemetry_data()
    ike_failure(data, "CORE-FW-01", "NYC-RTR-01", 1)
    set_tunnel(data, "TUN-NYC-BACKUP", phase1="down", phase2_sas=0)
    set_tunnel(data, "TUN-BLR-BACKUP", encaps=4000, decaps=0)
    set_tunnel(data, "TUN-BLR-BACKUP-HUB", encaps=0, decaps=4000)
    dataset = load_scenario(BASE)
    route = core_event("EVT-T-ROUTE", -3, "CORE-FW-01", "POLICY_CHANGE", "static route 10.30.0.0/16 via tunnel.30 deleted by fwadmin")
    other = core_event("EVT-T-OTHER", -2, "CORE-FW-01", "POLICY_CHANGE", "static route 10.20.0.0/16 via tunnel.20 deleted by fwadmin")
    _, findings = run(["ipsec"], dataset.model_copy(update={"events": dataset.events + [route, other]}), data)
    one_way = next(f for f in findings if f.code == "IPSEC_ONE_WAY")
    assert one_way.affected_sites == ["BLR"] and one_way.status == "possible_explanation" and one_way.confidence <= 0.65
    assert "no return route to 10.30.0.0/16" in one_way.title and one_way.facts["return_route_removed"] == ["EVT-T-ROUTE"]
    assert [f.affected_sites for f in findings if f.code == "IPSEC_AUTH_FAILURE"] == [["NYC"]]
    _, plain = run(["ipsec"], data=data)  # without the change log the finding stays generic instead of guessing
    assert next(f for f in plain if f.code == "IPSEC_ONE_WAY").title == "One-way traffic on TUN-BLR-BACKUP"


# ------------------------------------------------------------------ 2. Root cause versus symptom

def saturated(dataset, interface: str = "CORE-SW-01:Te1/0/4", level: float = 97.0, drops: int = 40_000, before: float | None = None):
    rows = []
    for row in dataset.interface_statistics:
        if row.interface_id == interface and row.timestamp >= ONSET:
            row = row.model_copy(update={"utilization_percent": level, "out_drops": drops})
        elif row.interface_id == interface and before is not None:
            row = row.model_copy(update={"utilization_percent": before})
        rows.append(row)
    return dataset.model_copy(update={"interface_statistics": rows})


def bulk_flows(data: dict, source: str = "10.100.100.50", count: int = 3) -> None:
    for index, client in enumerate(["10.10.10.100", "10.20.10.100", "10.30.10.100"][:count]):
        data["security"]["flows"].append({
            "flow_id": f"FL-T-{index}", "start": at(-0.5).isoformat(), "duration_seconds": 900.0, "src_ip": source, "dst_ip": client,
            "dst_port": 445, "protocol": "tcp", "bytes_out": 2_000_000_000, "bytes_in": 2_000_000, "packets": 1_500_000,
            "state": "established", "sensor_device_id": "DC1-FW-01"})


def fragmentation(data: dict) -> None:
    for counter in data["mtu"]["counters"]:
        if counter["device_id"] == "CORE-RTR-01" and counter["timestamp"] >= ONSET.isoformat().replace("+00:00", "Z"):
            counter.update(fragments_created=3500, reassembly_failures=110)


def test_saturation_with_a_dominant_source_is_the_root_and_minor_fragmentation_is_secondary(monkeypatch) -> None:
    data = telemetry_data()
    bulk_flows(data)
    fragmentation(data)
    report = analyse(monkeypatch, saturated(load_scenario(BASE)), data)
    by_id = {f.finding_id: f for f in report.findings}
    roots = [by_id[r].code for r in report.root_causes]
    assert roots[0] == "QOS_LINK_SATURATION" and "MTU_FRAGMENTATION" in roots[1:]
    lead = by_id[report.root_causes[0]]
    assert lead.status == "confirmed_fault" and lead.facts["driver"] == "10.100.100.50" and lead.facts["driver_name"] == "dc1-bkp-01"
    assert lead.facts["authorised_host"] and not lead.facts["maintenance_window"] and "not a security one" in lead.summary
    assert {e.collection for e in lead.evidence} >= {"interface_statistics", "security_flows"} and report.validation.grounded
    assert report.headline.startswith("Likely cause: Metro link LNK-CORE-DC1-METRO") and "Secondary: Reassembly failures" in report.headline


def test_a_possible_minor_finding_never_outranks_a_confirmed_fault(monkeypatch) -> None:
    data = telemetry_data()
    fragmentation(data)
    alone = analyse(monkeypatch, None, data)
    assert [f.code for f in alone.findings if f.finding_id in alone.root_causes] == ["MTU_FRAGMENTATION"]  # possible, so only "Possible"
    with_fault = analyse(monkeypatch, saturated(load_scenario(BASE)), data)
    assert {f.finding_id: f for f in with_fault.findings}[with_fault.root_causes[0]].status == "confirmed_fault"


@pytest.mark.parametrize("change", ["busy_before", "no_drops", "below_threshold"])
def test_saturation_needs_a_rise_to_saturation_with_queue_drops(change: str) -> None:
    dataset = {"busy_before": lambda d: saturated(d, before=88.0), "no_drops": lambda d: saturated(d, drops=0),
               "below_threshold": lambda d: saturated(d, level=85.0)}[change](load_scenario(BASE))
    _, findings = run(["qos"], dataset)
    assert not [f for f in findings if f.code == "QOS_LINK_SATURATION"]


def test_saturation_without_a_dominant_source_names_no_culprit() -> None:
    _, findings = run(["qos"], saturated(load_scenario(BASE)))
    finding = next(f for f in findings if f.code == "QOS_LINK_SATURATION")
    assert "driver" not in finding.facts and "bulk transfer" not in finding.title


# ------------------------------------------------------------------ 3. Suspicious findings in the conclusions

def rogue_ra(data: dict, site: str, mac: str, minutes: list[float]) -> None:
    for index, minute in enumerate(minutes):
        stamp = at(minute).strftime("%Y-%m-%dT%H:%M:%SZ")
        data["ipv6"]["adverts"].append({"ra_id": f"{site}|10|t{index}{mac[-2:]}@{stamp}", "timestamp": stamp,
                                        "site_id": site, "vlan_id": 10, "source_mac": mac, "source_link_local": "fe80::bad:1",
                                        "router_device_id": None, "prefix": "2001:db8:dead:1::/64", "router_lifetime": 1800})


def ipv6_broken(data: dict, site: str) -> None:
    for probe in data["ipv6"]["probes"]:
        if probe["site_id"] == site and probe["timestamp"] >= ONSET.isoformat().replace("+00:00", "Z"):
            probe["ipv6_ok"] = False


def test_suspicious_indicator_that_explains_the_symptom_is_named_but_not_confirmed(monkeypatch) -> None:
    data = telemetry_data()
    rogue_ra(data, "SIN", "02:00:aa:bb:cc:01", [-1])
    ipv6_broken(data, "SIN")
    report = analyse(monkeypatch, None, data)
    ra = next(f for f in report.findings if f.code == "IPV6_ROGUE_RA")
    assert ra.status == "suspicious_indicator" and report.suspected_causes == [ra.finding_id] and not report.root_causes
    assert "Suspected cause, not confirmed: Router advertisement from an unknown source at SIN" in report.headline
    assert "No protocol cause found" not in report.headline and "confirmed attack" not in report.headline.lower()


def test_a_suspicious_finding_elsewhere_is_not_offered_as_the_cause(monkeypatch) -> None:
    data = telemetry_data()
    rogue_ra(data, "NYC", "02:00:aa:bb:cc:02", [-1])
    ipv6_broken(data, "SIN")
    report = analyse(monkeypatch, None, data)
    assert report.suspected_causes == [] and "No protocol cause found" in report.headline


def test_reasoning_summary_names_a_suspicious_protocol_indicator_without_confirming_it() -> None:
    item = EvidenceItem(evidence_id="E1", call_id="C1", tool="analyze_protocol", evidence_type=EvidenceType.INFERRED_FINDING,
                        code="BGP_ORIGIN_HIJACK_SUSPECTED", device_id="CORE-RTR-01", timestamp=at(1),
                        summary="[Suspicious (not confirmed)] Unexpected origin AS64999 for 10.20.10.96/28: not one of our ASes.",
                        references=[EvidenceRef(collection="bgp_routes", record_id="x", timestamp=at(1))])
    report = reason([item], Scope(BASE, ("SIN",)), ONSET, [])
    assert not report.fault_supported
    assert report.explanation.summary.startswith("No fault domain is confirmed yet. Suspected, not confirmed: Unexpected origin AS64999")
    assert report.explanation.why[0].startswith("E1:")


# ------------------------------------------------------------------ 4. One finding per claim

def draft(title: str, minute: float, record: str) -> Draft:
    return Draft("IPV6_ROGUE_RA", "suspicious_indicator", "threat_indicator", "major", title, "An RA from an unknown source.", "direct",
                 [ref("router_adverts", record, at(minute))], "unknown source", site_id="SIN", timestamp=at(minute), affected_sites=["SIN"],
                 facts={"source_mac": "02:00:aa:bb:cc:01"})


def test_repeated_observations_merge_into_one_finding_with_all_evidence() -> None:
    drafts = merge_duplicates([draft("RA from an unknown source at SIN", m, f"r{m}") for m in (5, 1, 9)] + [draft("Other subject", 2, "x")])
    assert len(drafts) == 2
    merged = drafts[0]
    assert [e.record_id for e in merged.evidence] == ["r5", "r1", "r9"] and merged.timestamp == at(1)
    assert merged.facts["occurrences"] == 3 and "Seen 3 times between" in merged.summary


def test_repeated_rogue_adverts_give_one_finding_and_one_threat_cluster_but_distinct_sources_stay_apart() -> None:
    data = telemetry_data()
    rogue_ra(data, "SIN", "02:00:aa:bb:cc:01", [-1, 4, 9, 14])
    _, findings = run(["ipv6", "threats"], data=data)
    ra = [f for f in findings if f.code == "IPV6_ROGUE_RA"]
    assert len(ra) == 1 and len(ra[0].evidence) == 4 and ra[0].facts["occurrences"] == 4
    assert len([f for f in findings if f.code == "THREAT_CORRELATED_ACTIVITY"]) == 1
    rogue_ra(data, "SIN", "02:00:aa:bb:cc:09", [2])
    _, findings = run(["ipv6"], data=data)
    assert sorted(f.facts["source_mac"] for f in findings if f.code == "IPV6_ROGUE_RA") == ["02:00:aa:bb:cc:01", "02:00:aa:bb:cc:09"]


# ------------------------------------------------------------------ 5. Specialist selection from vague wording

@pytest.mark.parametrize("text,engines", [
    ("half the users can't reach ERP", ["bgp", "arp"]),
    ("only some desktops at the branch lose the file shares", ["bgp", "arp"]),
    ("users cannot reach ERP", []),
    ("short freezes every few minutes", ["stp"]),
    ("desktops freeze for a few seconds", ["stp"]),
    ("a new switch was plugged in at reception this morning", ["stp"]),
    ("the all-hands video freezes", ["multicast"]),
    ("Wi-Fi busy", []),
    ("Wi-Fi has been busy all morning", []),
    ("Wi-Fi not working", ["wireless"]),
    ("calls are choppy and robotic; data seems fine", ["qos"]),
])
def test_vague_and_benign_wording(text: str, engines: list[str]) -> None:
    assert protocol_engines(Scope("x", ("NYC",), text=text)) == engines


def test_engines_without_telemetry_are_not_planned() -> None:
    assert load_telemetry("P3-EDGE-PARTIAL-TELEMETRY").wireless is None
    assert protocol_engines(Scope("P3-EDGE-PARTIAL-TELEMETRY", ("SIN",), text="Wi-Fi keeps dropping")) == []
    assert protocol_engines(Scope(BASE, ("SIN",), text="Wi-Fi keeps dropping")) == ["wireless"]


def test_vague_partial_wording_spends_the_protocol_budget_on_routing_and_addressing() -> None:
    plan = coordinate(Scope(BASE, ("SIN",), text="Half of the Singapore desktops can't reach ERP; the rest are fine. Wi-Fi has been busy."))
    protocol = [(c.agent, c.arguments["protocol"]) for c in plan if c.tool == "analyze_protocol"]
    assert protocol == [("routing", "bgp"), ("security", "arp")] and len(plan) <= 10
