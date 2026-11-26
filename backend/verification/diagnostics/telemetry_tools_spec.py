from datetime import datetime, timedelta

import pytest

from app.diagnostics import (
    analyze_interface_errors,
    analyze_packet_loss,
    check_device_availability,
    get_device_logs,
    get_interface_stats,
)
from app.diagnostics import telemetry
from app.network.repository import load_scenario, load_topology
from verification.diagnostics.helpers import codes, failed, ok


def onset(scenario_id: str) -> datetime:
    return load_scenario(scenario_id).scenario.onset_at


def test_device_logs_are_chronological_and_preserve_records() -> None:
    result = ok(get_device_logs("SHARED-DEVICE-FAILURE", "CORE-RTR-02"))
    records = result.data["records"]
    assert len(records) >= 3
    assert [(r["timestamp"], r["event_id"]) for r in records] == sorted((r["timestamp"], r["event_id"]) for r in records)
    dataset = load_scenario("SHARED-DEVICE-FAILURE")
    originals = {event.event_id: event.model_dump(mode="json") for event in dataset.events}
    assert all(originals[record["event_id"]] == record for record in records)
    assert all(record["device_id"] == "CORE-RTR-02" for record in records)


def test_device_logs_severity_and_event_type_filters() -> None:
    severe = ok(get_device_logs("SHARED-DEVICE-FAILURE", "CORE-RTR-01", min_severity="critical")).data
    assert [r["event_type"] for r in severe["records"]] == ["POWER_SUPPLY_FAILURE", "SYSTEM_SHUTDOWN"]
    assert severe["severity_counts"] == {"emergency": 1, "critical": 1}
    typed = ok(get_device_logs("WAN-FAILURE", "SIN-RTR-01", event_types=["LINK_DOWN", "BGP_NEIGHBOR_DOWN"])).data
    assert sorted(r["event_type"] for r in typed["records"]) == ["BGP_NEIGHBOR_DOWN", "LINK_DOWN"]
    single = ok(get_device_logs("WAN-FAILURE", "SIN-RTR-01", event_types="CARRIER_LOSS")).data
    assert single["total_matched"] == 1


def test_device_logs_time_range_and_limit() -> None:
    start = onset("WAN-FAILURE")
    result = ok(get_device_logs("WAN-FAILURE", "SIN-RTR-01", start=start.isoformat(), end=start + timedelta(minutes=20)))
    assert all(r["timestamp"] >= start.strftime("%Y-%m-%dT%H:%M:%SZ") for r in result.data["records"])
    limited = ok(get_device_logs("WAN-FAILURE", "SIN-RTR-01", limit=1))
    assert limited.data["returned"] == 1 and limited.data["truncated"] is True and limited.warnings
    offset = ok(get_device_logs("WAN-FAILURE", "SIN-RTR-01", start="2026-03-03T14:30:00+05:30",
                                end="2026-03-03T15:00:00+05:30"))
    assert offset.data["time_range"] == {"start": "2026-03-03T09:00:00+00:00", "end": "2026-03-03T09:30:00+00:00"}


def test_device_logs_empty_result_is_success() -> None:
    result = ok(get_device_logs("BASELINE", "CORE-RTR-01", event_types=["LINK_DOWN"]))
    assert result.data["records"] == [] and result.data["total_matched"] == 0
    assert "No log records matched" in result.warnings[0]
    far = ok(get_device_logs("BASELINE", "CORE-RTR-01", start="2020-01-01T00:00:00Z", end="2020-01-01T01:00:00Z"))
    assert far.data["records"] == []


@pytest.mark.parametrize("kwargs, code", [
    ({"device_id": "GHOST-RTR-01"}, "NOT_FOUND"),
    ({"device_id": "core-rtr-01"}, "INVALID_ARGUMENT"),
    ({"device_id": "CORE-RTR-01", "start": "2026-03-02T09:00:00"}, "INVALID_ARGUMENT"),
    ({"device_id": "CORE-RTR-01", "start": "yesterday"}, "INVALID_ARGUMENT"),
    ({"device_id": "CORE-RTR-01", "start": "2026-03-02T09:10:00Z", "end": "2026-03-02T09:00:00Z"}, "INVALID_ARGUMENT"),
    ({"device_id": "CORE-RTR-01", "start": "2026-03-01T00:00:00Z", "end": "2026-03-03T00:00:00Z"}, "INVALID_ARGUMENT"),
    ({"device_id": "CORE-RTR-01", "min_severity": "severe"}, "INVALID_ARGUMENT"),
    ({"device_id": "CORE-RTR-01", "event_types": ["link down"]}, "INVALID_ARGUMENT"),
    ({"device_id": "CORE-RTR-01", "event_types": ["A"] * 21}, "INVALID_ARGUMENT"),
    ({"device_id": "CORE-RTR-01", "limit": 0}, "INVALID_ARGUMENT"),
    ({"device_id": "CORE-RTR-01", "limit": 10_000}, "INVALID_ARGUMENT"),
    ({"device_id": "CORE-RTR-01", "limit": True}, "INVALID_ARGUMENT"),
])
def test_device_logs_rejects_invalid_arguments(kwargs: dict, code: str) -> None:
    failed(get_device_logs("BASELINE", **kwargs), code)


def test_interface_stats_full_measurements_and_thresholds() -> None:
    result = ok(get_interface_stats("PACKET-LOSS", "NYC-RTR-01", "Gi0/0/0"))
    entry = result.data["interfaces"][0]
    assert entry["link"]["link_id"] == "LNK-WAN-NYC" and entry["link"]["peer_interface_id"] == "CORE-RTR-01:Gi0/0/2"
    fields = {"oper_status", "utilization_percent", "in_bps", "out_bps", "in_drops", "out_drops", "in_errors",
              "out_errors", "uptime_seconds", "latency_ms", "packet_loss_percent"}
    assert fields <= set(entry["latest"])
    assert entry["sample_count"] == 4 and entry["missing_sample_times"] == []
    assert result.data["thresholds"]["packet_loss_percent"] == 1.0
    assert {"HIGH_PACKET_LOSS", "HIGH_ERROR_COUNT", "HIGH_DROP_COUNT", "HIGH_LATENCY"} <= set(codes(result, "observed"))
    assert ok(get_interface_stats("BASELINE", "NYC-RTR-01", "Gi0/0/0")).findings == []


def test_interface_stats_never_invents_missing_measurements() -> None:
    result = ok(get_interface_stats("BASELINE", "NYC-SW-01", "Gi1/0/1"))
    assert all(sample["latency_ms"] is None and sample["packet_loss_percent"] is None
               for sample in result.data["interfaces"][0]["samples"])
    assert any("Latency is not measured" in item for item in result.missing_data)
    virtual = ok(get_interface_stats("BASELINE", "NYC-RTR-01", "Gi0/0/1.10"))
    assert virtual.data["interfaces"][0]["samples"] == [] and virtual.data["interfaces"][0]["latest"] is None
    assert any("virtual interface" in item for item in virtual.missing_data)


def test_interface_stats_missing_telemetry_is_not_failure() -> None:
    result = ok(get_interface_stats("SHARED-DEVICE-FAILURE", "CORE-RTR-01"))
    assert all(entry["sample_count"] == 2 and len(entry["missing_sample_times"]) == 2 for entry in result.data["interfaces"])
    assert "INTERFACE_DOWN" not in codes(result)
    gaps = [item for item in result.missing_data if item.startswith("No statistics")]
    assert len(gaps) == 4 and all("not evidence of failure" in item for item in gaps)


def test_interface_stats_down_interface() -> None:
    result = ok(get_interface_stats("WAN-FAILURE", "SIN-RTR-01"))
    assert len(result.data["interfaces"]) == 5
    down = [f for f in result.findings if f.code == "INTERFACE_DOWN"]
    assert len(down) == 1 and len(down[0].evidence) == 2


@pytest.mark.parametrize("interface, code", [("Gi9/9/9", "NOT_FOUND"), ("SIN-RTR-01:Gi0/0/0", "INVALID_ARGUMENT"),
                                             ("Gi0/0/0;rm -rf", "INVALID_ARGUMENT"), (5, "INVALID_ARGUMENT")])
def test_interface_stats_rejects_bad_interfaces(interface: object, code: str) -> None:
    failed(get_interface_stats("BASELINE", "NYC-RTR-01", interface), code)


def test_packet_loss_sustained_degradation() -> None:
    result = ok(analyze_packet_loss("PACKET-LOSS", "NYC-RTR-01", "Gi0/0/0"))
    data = result.data
    assert data["pattern"] == "sustained" and data["lossy_sample_count"] == 2 and data["outage_sample_count"] == 0
    assert data["peak_loss_percent"] > 9
    assert all(m["in_errors"] > 1000 for m in data["measurements"] if m["packet_loss_percent"] >= 1)
    assert len(data["peer"]["measurements"]) == 4
    assert codes(result, "observed") == ["PACKET_LOSS_MEASURED"]
    assert codes(result, "inferred") == ["PHYSICAL_LAYER_DEGRADATION_SUSPECTED"]


def test_packet_loss_from_outage_is_distinguished() -> None:
    result = ok(analyze_packet_loss("WAN-FAILURE", "SIN-RTR-01", "Gi0/0/0"))
    assert result.data["outage_sample_count"] == 2
    assert "LOSS_DURING_INTERFACE_DOWN" in codes(result, "inferred")
    assert "PHYSICAL_LAYER_DEGRADATION_SUSPECTED" not in codes(result)


def test_packet_loss_not_measured_and_none() -> None:
    lan = ok(analyze_packet_loss("PACKET-LOSS", "NYC-SW-01", "Gi1/0/24"))
    assert lan.data["pattern"] == "not_measured" and lan.missing_data and lan.findings == []
    baseline = ok(analyze_packet_loss("BASELINE", "NYC-RTR-01", "Gi0/0/0"))
    assert baseline.data["pattern"] == "none" and baseline.findings == []
    failed(analyze_packet_loss("PACKET-LOSS", "NYC-RTR-01"), "INVALID_ARGUMENT")


def test_interface_errors_pattern_and_events() -> None:
    result = ok(analyze_interface_errors("PACKET-LOSS", "CORE-RTR-01", "Gi0/0/2"))
    data = result.data
    assert data["error_pattern"] == "sustained" and data["drop_pattern"] == "sustained"
    assert data["crc_errors"] is None
    assert [event["event_type"] for event in data["related_events"]] == ["INTERFACE_ERRORS"]
    assert "CRC" in data["related_events"][0]["message"]
    assert {"HIGH_ERROR_COUNT", "HIGH_DROP_COUNT", "ERROR_COUNT_INCREASE", "INTERFACE_EVENTS_LOGGED"} <= set(codes(result))
    assert any("CRC counters are not part" in item for item in result.missing_data)
    assert all(m["errors_per_second"] >= 0 for m in data["measurements"])


def test_interface_errors_healthy_baseline() -> None:
    result = ok(analyze_interface_errors("BASELINE", "CORE-RTR-01", "Gi0/0/2"))
    assert result.data["error_pattern"] == "none" and result.findings == []


def test_device_availability_confirmed_by_peers() -> None:
    result = ok(check_device_availability("SHARED-DEVICE-FAILURE", "CORE-RTR-01"))
    data = result.data
    assert data["status"] == "unreachable"
    assert len(data["telemetry"]["missing_collection_times"]) == 2
    assert data["telemetry"]["routing_table_collected"] is False
    assert {link["peer_reported_status"] for link in data["peer_links"]} == {"down"}
    assert {"TELEMETRY_GAP", "PEER_LINKS_DOWN", "PEER_ADJACENCIES_LOST"} <= set(codes(result, "observed"))
    assert codes(result, "inferred") == ["DEVICE_FAILURE_LIKELY"]


def test_device_availability_healthy_and_faulty() -> None:
    healthy = ok(check_device_availability("BASELINE", "CORE-RTR-01"))
    assert healthy.data["status"] == "available" and healthy.findings == []
    faulty = ok(check_device_availability("WAN-FAILURE", "SIN-RTR-01"))
    assert faulty.data["status"] == "available_with_faults"
    assert "INTERFACES_DOWN" in codes(faulty)
    assert "DEVICE_FAILURE_LIKELY" not in codes(faulty)
    server = ok(check_device_availability("DNS-RESOLUTION-FAILURE", "DC1-SRV-DNS-01"))
    assert server.data["status"] == "available_with_faults" and "FAULT_EVENTS_LOGGED" in codes(server)
    assert server.data["telemetry"]["routing_table_collected"] is None


def test_device_availability_rejects_unknown_device() -> None:
    failed(check_device_availability("BASELINE", "CORE-RTR-09"), "NOT_FOUND")


def test_device_availability_without_peer_corroboration(monkeypatch: pytest.MonkeyPatch) -> None:
    dataset = load_scenario("BASELINE")
    trimmed = dataset.model_copy(update={"interface_statistics": [
        s for s in dataset.interface_statistics
        if not (s.device_id == "DC1-SRV-APP-01" and s.timestamp > dataset.scenario.onset_at)
    ]})
    monkeypatch.setattr(telemetry, "load_dataset", lambda scenario_id: (load_topology(), trimmed))
    result = ok(check_device_availability("BASELINE", "DC1-SRV-APP-01"))
    assert result.data["status"] == "telemetry_missing"
    assert "TELEMETRY_GAP" in codes(result) and "DEVICE_FAILURE_LIKELY" not in codes(result)
    assert any("not proof of failure" in warning for warning in result.warnings)
