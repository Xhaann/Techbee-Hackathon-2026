import json

from app.advanced.anomalies import detect_anomalies, interface_anomalies
from app.engine.executor import ToolExecutor
from verification.advanced_diagnosis.helpers import analysis


def sample(**values: object) -> dict:
    base = {"interface_id": "X-RTR-01:Gi0", "timestamp": "2026-03-02T09:00:00Z", "oper_status": "up", "in_errors": 0, "out_errors": 0,
            "packet_loss_percent": 0.0, "utilization_percent": 10.0}
    return base | values


def test_threshold_violations_with_baselines() -> None:
    found = {(a.category, a.asset_id) for a in analysis("PACKET-LOSS").anomalies.anomalies}
    assert ("packet_loss", "NYC-RTR-01:Gi0/0/0") in found and ("interface_errors", "NYC-RTR-01:Gi0/0/0") in found
    loss = next(a for a in analysis("PACKET-LOSS").anomalies.anomalies if a.category == "packet_loss")
    assert "first measured sample" in loss.baseline and loss.observed.endswith("% loss") and loss.timestamp is not None


def test_normal_baseline_has_no_anomalies() -> None:
    executor = ToolExecutor("BASELINE")
    for device in ("NYC-RTR-01", "CORE-RTR-01", "DC1-SW-01"):
        executor.execute("get_interface_stats", {"device_id": device})
    report = detect_anomalies(executor.records)
    assert report.anomalies == [] and report.assets_examined > 10


def test_missing_baseline_is_reported() -> None:
    report = detect_anomalies([])
    assert report.anomalies == [] and report.assets_examined == 0
    single = interface_anomalies("X", [sample(in_errors=5000)])
    assert single == []


def test_boundary_values() -> None:
    first = sample()
    assert interface_anomalies("X", [first, sample(packet_loss_percent=1.0, timestamp="2026-03-02T09:10:00Z")])[0].category == "packet_loss"
    assert interface_anomalies("X", [first, sample(packet_loss_percent=0.99, timestamp="2026-03-02T09:10:00Z")]) == []
    assert interface_anomalies("X", [first, sample(in_errors=100, timestamp="2026-03-02T09:10:00Z")]) == []
    assert interface_anomalies("X", [first, sample(in_errors=101, timestamp="2026-03-02T09:10:00Z")])[0].category == "interface_errors"
    noisy = sample(in_errors=60)
    assert interface_anomalies("X", [noisy, sample(in_errors=150, timestamp="2026-03-02T09:10:00Z")]) == []
    assert interface_anomalies("X", [first, sample(utilization_percent=80.0, timestamp="2026-03-02T09:10:00Z")])[0].category == "utilization"


def test_service_and_routing_anomalies() -> None:
    assert ("dhcp", "DHCP-BLR-USERS") in {(a.category, a.asset_id) for a in analysis("DHCP-ALLOCATION-FAILURE").anomalies.anomalies}
    assert any(a.category == "routing_adjacency" for a in analysis("OSPF-ADJACENCY-FAILURE").anomalies.anomalies)
    assert any(a.category == "availability" and a.asset_id == "CORE-RTR-01" for a in analysis("SHARED-DEVICE-FAILURE").anomalies.anomalies)
    assert analysis("FIREWALL-BLOCKING").anomalies.anomalies == []


def test_deterministic_and_no_ml_claims() -> None:
    first = json.dumps(analysis("PACKET-LOSS").anomalies.model_dump(mode="json"), sort_keys=True)
    assert first == json.dumps(analysis.__wrapped__("PACKET-LOSS").anomalies.model_dump(mode="json"), sort_keys=True)
    assert analysis("PACKET-LOSS").anomalies.method == "thresholds_and_first_sample_baseline"
    assert "predict" not in first.lower() and "machine learning" not in first.lower()
