"""Deterministic analytics on the synthetic multi-site data: history, baselines, forecasts, health, drift, journeys, reliability."""
import math
from datetime import timedelta

import pytest

from app.network.models import LinkStatus
from app.network.repository import list_scenario_ids, load_scenario, load_topology
from app.observability.analytics import congestion, interface_baseline, interface_forecast, scenario_baselines
from app.observability.health import network_health
from app.observability.inventory import config_drift, dependency_graph, discovery
from app.observability.journey import trace
from app.observability.reliability import export_csv, export_markdown, reliability_report
from app.observability.signals import snmp_poll, syslog_view, trap_view
from app.observability.simulation import (
    DOWN,
    POINTS,
    UNKNOWN,
    golden_config,
    interface_history,
    lldp_neighbors,
    running_config,
    scenario_flows,
)
from app.observability.traffic import traffic_summary

FAILURES = [s for s in list_scenario_ids() if s != "BASELINE"]


def test_history_is_deterministic_and_ends_in_the_scenario_samples() -> None:
    first = interface_history("WAN-FAILURE", "SIN-RTR-01:Gi0/0/0")
    interface_history.cache_clear()
    again = interface_history("WAN-FAILURE", "SIN-RTR-01:Gi0/0/0")
    assert len(again) == POINTS and list(first.utilization) == list(again.utilization)
    samples = [s for s in load_scenario("WAN-FAILURE").interface_statistics if s.interface_id == "SIN-RTR-01:Gi0/0/0"]
    for sample in samples:
        index = again.index_of(sample.timestamp)
        expected = DOWN if sample.oper_status == LinkStatus.DOWN else 1
        assert again.status[index] == expected
        if sample.oper_status == LinkStatus.UP:
            assert again.utilization[index] == pytest.approx(sample.utilization_percent, abs=0.01)


def test_telemetry_gap_becomes_no_data_not_zero() -> None:
    history = interface_history("ADV-BLR-OSPF-AUTH-MISMATCH", "BLR-RTR-01:Gi0/0/0")
    assert history.status[len(history) - 1] == UNKNOWN and math.isnan(history.utilization[len(history) - 1])


def test_flows_respect_link_state_and_firewall_policy() -> None:
    onset = load_scenario("WAN-FAILURE").scenario.onset_at
    sin = [f for f in scenario_flows("WAN-FAILURE") if f.src_site == "SIN" and f.origin == "simulated_traffic"]
    assert sin and not [f for f in sin if f.start >= onset + timedelta(minutes=1)]
    blocked = [f for f in scenario_flows("FIREWALL-BLOCKING") if f.action == "dropped" and f.service == "application"]
    assert blocked and {f.src_site for f in blocked} == {"SIN"} and {f.exporter_id for f in blocked} == {"DC1-FW-01"}
    assert scenario_flows("BASELINE") == scenario_flows("BASELINE")


def test_baseline_scenario_has_no_baseline_anomalies() -> None:
    assert [a for b in scenario_baselines("BASELINE") for a in b["anomalies"]] == []


@pytest.mark.parametrize(("scenario", "interface", "kind"), [
    ("WAN-FAILURE", "SIN-RTR-01:Gi0/0/0", "down"), ("PACKET-LOSS", "NYC-RTR-01:Gi0/0/0", "above"),
    ("ADV-NYC-WAN-FLAP", "NYC-RTR-01:Gi0/0/0", "down"), ("ADV-METRO-FIBRE-DEGRADATION", "CORE-SW-01:Te1/0/4", "above"),
])
def test_faults_fall_outside_their_baseline(scenario: str, interface: str, kind: str) -> None:
    assert kind in {a["kind"] for a in interface_baseline(scenario, interface)["anomalies"]}


def test_nyc_wan_forecast_finds_the_growth_trend() -> None:
    forecast = interface_forecast("BASELINE", "NYC-RTR-01:Gi0/0/0")
    assert forecast["status"] == "ok" and 1.0 < forecast["trend_per_day"] < 1.7
    assert 0 < forecast["days_to"]["80"] < forecast["days_to"]["90"] < 30
    assert all(p["low"] <= p["peak"] <= p["high"] for p in forecast["forecast"])
    assert len(forecast["next_24h"]) == 24


def test_congestion_risk_levels() -> None:
    baseline = {row["link_id"]: row for row in congestion("BASELINE")}
    assert baseline["LNK-WAN-NYC"]["level"] in ("medium", "high") and baseline["LNK-WAN-NYC"]["recommendation"]
    assert baseline["LNK-CORE-RTR01-SW01"]["level"] == "low"
    assert {row["link_id"]: row["level"] for row in congestion("WAN-FAILURE")}["LNK-WAN-SIN"] == "unavailable"


def test_healthy_baseline_scores_100_everywhere() -> None:
    health = network_health("BASELINE")
    assert health["network"] == {"score": 100.0, "status": "healthy", "worst_site": health["network"]["worst_site"]}
    assert all(s["status"] == "healthy" for s in health["services"] + health["sites"])


@pytest.mark.parametrize("scenario", FAILURES)
def test_every_affected_site_is_unhealthy_and_unaffected_branches_are_not_critical(scenario: str) -> None:
    truth = load_scenario(scenario).ground_truth
    sites = {s["site_id"]: s for s in network_health(scenario)["sites"]}
    assert all(sites[site]["status"] != "healthy" for site in truth.affected_site_ids), truth.affected_site_ids
    branches = {"NYC", "SIN", "BLR"} - set(truth.affected_site_ids)
    assert all(sites[site]["status"] != "critical" for site in branches)


def test_health_deductions_carry_evidence() -> None:
    worst = network_health("WAN-FAILURE")["devices"][0]
    assert worst["device_id"] == "SIN-RTR-01" and worst["factors"][0]["factor"] == "availability"
    assert worst["factors"][0]["evidence"][0]["collection"] == "interface_statistics"


@pytest.mark.parametrize(("scenario", "device", "line", "event"), [
    ("ADV-NYC-VOICE-DHCP-RELAY", "NYC-RTR-01", "ip helper-address 10.100.100.20", "EVT-00024"),
    ("OSPF-ADJACENCY-FAILURE", "BLR-RTR-01", "mtu 1400", "EVT-00020"),
    ("ADV-BLR-OSPF-AUTH-MISMATCH", "CORE-RTR-02", "ip ospf message-digest-key 2 md5 <removed>", "EVT-00020"),
    ("FIREWALL-BLOCKING", "DC1-FW-01", "rule FWR-DC1-0125", "EVT-00020"),
])
def test_config_drift_is_found_and_attributed(scenario: str, device: str, line: str, event: str) -> None:
    items = [i for i in config_drift(scenario)["items"] if i["device_id"] == device and i["line"].startswith(line)]
    assert items and items[0]["attributed"] and items[0]["event_id"] == event and items[0]["severity"] in ("high", "critical")


def test_drift_baseline_is_compliant_and_unlogged_sessions_are_flagged() -> None:
    assert config_drift("BASELINE")["summary"]["items"] == 0
    nyc = next(d for d in config_drift("VLAN-AUTHENTICATION-FAILURE")["devices"] if d["device_id"] == "NYC-SW-01")
    assert nyc["status"] == "unverified" and "logged no commands" in nyc["notes"][0]
    assert config_drift("ADV-SIN-ERP-SUBNET-BLOCK")["items"][-1]["ticket"] in (None, "SEC-4471")
    assert any(i["ticket"] == "SEC-4471" for i in config_drift("ADV-SIN-ERP-SUBNET-BLOCK")["items"])


def test_running_config_replays_logged_changes_only() -> None:
    assert list(running_config("BASELINE", "NYC-RTR-01")) == golden_config("NYC-RTR-01")
    relay = list(running_config("ADV-NYC-VOICE-DHCP-RELAY", "NYC-RTR-01"))
    section = relay[relay.index("interface Gi0/0/1.20") + 1:]
    assert not any("helper-address" in l for l in section[:next(i for i, l in enumerate(section) if not l.startswith(" "))])


def test_discovery_reconciles_lldp_with_inventory() -> None:
    baseline = discovery("BASELINE")
    assert baseline["coverage_percent"] == 100.0 and [u["remote_system"] for u in baseline["unexpected"]] == ["lab-ap-07"]
    wan = discovery("WAN-FAILURE")
    assert [m["link_id"] for m in wan["missing"]] == ["LNK-WAN-SIN"] and "down" in wan["missing"][0]["reason"]
    assert wan["changes_since_baseline"] == [{"link_id": "LNK-WAN-SIN", "change": "adjacency_lost"}]
    assert len(lldp_neighbors("SHARED-DEVICE-FAILURE")) < len(lldp_neighbors("BASELINE"))


def test_dependency_graph_finds_single_points_of_failure() -> None:
    graph = dependency_graph("BASELINE")
    spof = {s["id"]: s for s in graph["single_points_of_failure"]}
    assert spof["CORE-SW-01"]["impact"] == 15 and "LNK-CORE-DC1-METRO" in spof
    assert "CORE-RTR-02" not in spof or "NYC application" not in spof["CORE-RTR-02"]["services_at_risk"]
    observed = [e for e in graph["edges"] if e["kind"] == "observed_traffic"]
    assert {(e["source"], e["target"]) for e in observed} >= {("SIN", "service:application"), ("NYC", "service:dns")}


@pytest.mark.parametrize(("scenario", "source", "destination", "protocol", "port", "verdict", "stop"), [
    ("BASELINE", "10.20.10.100", "DC1-SRV-APP-01", "tcp", 443, "delivered", "DC1-SRV-APP-01"),
    ("FIREWALL-BLOCKING", "10.20.10.100", "DC1-SRV-APP-01", "tcp", 443, "dropped_by_policy", "DC1-FW-01"),
    ("ADV-SIN-RADIUS-UDP-BLOCK", "SIN-SW-01", "DC1-SRV-AUTH-01", "udp", 1812, "dropped_by_policy", "DC1-FW-01"),
    ("WAN-FAILURE", "10.20.10.100", "DC1-SRV-APP-01", "tcp", 443, "no_route", "SIN-RTR-01"),
    ("BASELINE", "10.10.10.100", "203.0.113.10", "tcp", 443, "leaves_network", "CORE-FW-01"),
])
def test_packet_journeys(scenario, source, destination, protocol, port, verdict, stop) -> None:
    journey = trace(scenario, source, destination, protocol, port)
    assert journey["verdict"] == verdict
    assert next(h for h in journey["hops"] if h["index"] == journey["verdict_hop"])["device_id"] == stop
    assert journey["hops"][0]["cumulative_latency_ms"] <= journey["total_latency_ms"]


def test_journey_reports_the_mtu_mismatch_where_forwarding_stops() -> None:
    journey = trace("OSPF-ADJACENCY-FAILURE", "BLR-RTR-01", "CORE-RTR-02", "tcp", 22, 1500)
    assert journey["verdict"] == "no_route"
    assert "MTU mismatch on LNK-WAN-BLR" in journey["mtu_note"] and "1400" in journey["mtu_note"]
    assert trace("BASELINE", "BLR-RTR-01", "CORE-RTR-02", "tcp", 22)["mtu_note"] is None


def test_journey_rejects_bad_input() -> None:
    from app.diagnostics.common import ToolInputError
    for args in (("BASELINE", "SIN-SW-01", "DC1-SRV-APP-01", "sctp", 443), ("BASELINE", "SIN-SW-01", "DC1-SRV-APP-01", "tcp", 70000),
                 ("BASELINE", "NOPE-RTR-99", "DC1-SRV-APP-01", "tcp", 443)):
        with pytest.raises(ToolInputError):
            trace(*args)


def test_traffic_summary_explains_the_firewall_incident() -> None:
    summary = traffic_summary("FIREWALL-BLOCKING")
    drop = summary["dropped_by_policy"][0]
    assert drop["device_id"] == "DC1-FW-01" and drop["sources"] == ["SIN"] and drop["rules"][0]["name"] == "BLOCK-APAC-LEGACY-WEB"
    assert summary["traffic_shifts"] == [{"site_id": "SIN", "service": "application", "flows_per_minute_before": 4.2,
                                          "flows_per_minute_after": 0.0, "change": "dropped_off"}]
    assert sum(l["bytes"] for l in summary["sankey"]["links"]) == summary["totals"]["bytes"]


def test_reliability_report_and_exports() -> None:
    report = reliability_report("WAN-FAILURE")
    links = {r["link_id"]: r for r in report["links"]}
    assert links["LNK-WAN-SIN"]["sla_met"] is False and links["LNK-WAN-SIN"]["outage_list"][-1]["ongoing"] is True
    assert links["LNK-WAN-NYC"]["outages"] == 2 and links["LNK-WAN-NYC"]["mttr_minutes"] == 5.0
    assert reliability_report("BASELINE", "7d")["period"] == "7d"
    assert "| LNK-WAN-SIN |" in export_markdown(report) and export_csv(report).splitlines()[0].startswith("kind,id")


def test_signals_render_and_parse_the_scenario() -> None:
    assert trap_view("ADV-NYC-WAN-FLAP")["flaps"]
    assert syslog_view("ADV-NYC-WAN-FLAP")["formats"] == ["rfc3164+cisco"]
    poll = snmp_poll("WAN-FAILURE", "CORE-RTR-01")
    down = next(i for i in poll["interfaces"] if i["interface"] == "Gi0/0/3")
    assert down["oper_status"] == "down" and poll["polls"] == 4


def test_every_scenario_computes_without_error() -> None:
    for scenario in list_scenario_ids():
        assert network_health(scenario)["sites"] and congestion(scenario) and reliability_report(scenario)["links"]
        assert len(discovery(scenario)["matched"]) <= len(load_topology().links)


def test_provenance_resolves_derived_records_only_when_cited() -> None:
    from app.engine import diagnose
    from app.security import provenance
    from verification.engine.helpers import incident_request
    diagnosis = diagnose(incident_request("FIREWALL-BLOCKING"))
    assert provenance.provenance_issues(diagnosis) == []
    assert "flows" not in provenance.record_index(load_scenario("FIREWALL-BLOCKING"), derived=False)
    item = diagnosis.evidence[0]
    real_flow = scenario_flows("FIREWALL-BLOCKING")[0].flow_id
    for record_id, ok in ((real_flow, True), ("FLW-99999", False)):
        cited = item.model_copy(update={"references": item.references + [item.references[0].model_copy(update={"collection": "flows",
                                                                                                                  "record_id": record_id})]})
        forged = diagnosis.model_copy(update={"evidence": [cited] + diagnosis.evidence[1:]})
        assert (provenance.provenance_issues(forged) == []) is ok, record_id
