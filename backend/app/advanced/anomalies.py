from app.advanced.schema import Anomaly, AnomalyReport
from app.diagnostics.telemetry import THRESHOLDS
from app.engine.executor import ToolCallRecord

BASELINE_RATIO = 3.0
DNS_FAILURE_RATIO = 0.2
DHCP_PRESSURE_PERCENT = 90.0


def series_by_interface(records: list[ToolCallRecord]) -> dict[str, list[dict]]:
    series: dict[str, dict[str, dict]] = {}
    for record in records:
        if record.succeeded and record.tool == "get_interface_stats":
            for entry in record.result.data["interfaces"]:
                for sample in entry["samples"]:
                    series.setdefault(sample["interface_id"], {})[sample["timestamp"]] = sample
    return {interface: [samples[key] for key in sorted(samples)] for interface, samples in sorted(series.items())}


def error_count(sample: dict) -> int:
    return sample["in_errors"] + sample["out_errors"]


def reference(sample: dict) -> str:
    return f"interface_statistics:{sample['interface_id']}@{sample['timestamp']}"


def interface_anomalies(interface: str, samples: list[dict]) -> list[Anomaly]:
    first, found = samples[0], []
    peak = max(samples, key=error_count)
    if error_count(peak) > THRESHOLDS["errors_per_interval"] and error_count(peak) >= BASELINE_RATIO * max(error_count(first), 1):
        found.append(Anomaly(category="interface_errors", asset_id=interface, observed=f"{error_count(peak)} errors per interval",
                             baseline=f"{error_count(first)} errors in the first sample", timestamp=peak["timestamp"],
                             rule=f"above {THRESHOLDS['errors_per_interval']} and at least {BASELINE_RATIO:g}x the first sample",
                             evidence_reference=reference(peak)))
    measured = [s for s in samples if s["packet_loss_percent"] is not None and s["oper_status"] == "up"]
    if measured:
        lossy = max(measured, key=lambda s: s["packet_loss_percent"])
        base = measured[0]["packet_loss_percent"]
        if lossy["packet_loss_percent"] >= THRESHOLDS["packet_loss_percent"] > base:
            found.append(Anomaly(category="packet_loss", asset_id=interface, observed=f"{lossy['packet_loss_percent']}% loss",
                                 baseline=f"{base}% in the first measured sample", timestamp=lossy["timestamp"],
                                 rule=f"at least {THRESHOLDS['packet_loss_percent']}% while the first sample was below it",
                                 evidence_reference=reference(lossy)))
    busy = max(samples, key=lambda s: s["utilization_percent"])
    if busy["utilization_percent"] >= THRESHOLDS["utilization_percent"] > first["utilization_percent"]:
        found.append(Anomaly(category="utilization", asset_id=interface, observed=f"{busy['utilization_percent']}% utilization",
                             baseline=f"{first['utilization_percent']}% in the first sample", timestamp=busy["timestamp"],
                             rule=f"at least {THRESHOLDS['utilization_percent']}% while the first sample was below it",
                             evidence_reference=reference(busy)))
    down = next((s for s in samples if s["oper_status"] == "down"), None)
    if down is not None and first["oper_status"] == "up":
        found.append(Anomaly(category="availability", asset_id=interface, observed="operational status down",
                             baseline="up in the first sample", timestamp=down["timestamp"], rule="status changed from up to down",
                             evidence_reference=reference(down)))
    return found


def detect_anomalies(records: list[ToolCallRecord]) -> AnomalyReport:
    anomalies, insufficient, examined = [], [], 0
    for interface, samples in series_by_interface(records).items():
        examined += 1
        if len(samples) < 2:
            insufficient.append(f"{interface}: fewer than two samples, no baseline comparison possible")
            continue
        anomalies += interface_anomalies(interface, samples)
    for record in records:
        if not record.succeeded:
            continue
        data = record.result.data
        if record.tool == "check_device_availability":
            examined += 1
            if data["status"] in ("unreachable", "telemetry_missing"):
                anomalies.append(Anomaly(category="availability", asset_id=data["device_id"], observed=f"availability {data['status']}",
                                         baseline=f"telemetry expected at {len(data['telemetry']['collection_times'])} collection times",
                                         timestamp=None, rule="telemetry stopped before the last collection time",
                                         evidence_reference=f"{record.call_id}:check_device_availability"))
        elif record.tool == "analyze_routing_adjacency":
            for adjacency in data["adjacencies"]:
                examined += 1
                if adjacency["status"] in ("failed", "stalled", "recently_changed"):
                    anomalies.append(Anomaly(category="routing_adjacency", asset_id=f"{data['device_id']}<->{adjacency['peer_device_id']}",
                                             observed=f"{adjacency['protocol']} adjacency {adjacency['status']}",
                                             baseline="established adjacency expected", timestamp=None,
                                             rule="adjacency not established or changed within the dataset window",
                                             evidence_reference=f"{record.call_id}:{adjacency['link_id']}"))
        elif record.tool == "get_dhcp_dns_status":
            dns = data["dns"]
            examined += 1
            failures = sum(count for result, count in dns["result_counts"].items() if result in ("servfail", "timeout", "refused"))
            if dns["query_count"] and failures / dns["query_count"] > DNS_FAILURE_RATIO:
                anomalies.append(Anomaly(category="dns", asset_id=data["site_id"],
                                         observed=f"{failures} of {dns['query_count']} queries failed",
                                         baseline=f"failure ratio at most {DNS_FAILURE_RATIO:.0%}", timestamp=None,
                                         rule="failed query ratio above the threshold", evidence_reference=f"{record.call_id}:dns"))
            for pool in data["dhcp"]["pools"]:
                examined += 1
                if pool["utilization_percent"] >= DHCP_PRESSURE_PERCENT:
                    anomalies.append(Anomaly(category="dhcp", asset_id=pool["pool"]["pool_id"],
                                             observed=f"{pool['utilization_percent']}% of {pool['size']} addresses in use",
                                             baseline=f"utilization below {DHCP_PRESSURE_PERCENT:g}%", timestamp=None,
                                             rule="pool utilization at or above the pressure threshold",
                                             evidence_reference=f"{record.call_id}:{pool['pool']['pool_id']}"))
    anomalies.sort(key=lambda a: (a.category, a.asset_id, a.timestamp.isoformat() if a.timestamp else ""))
    return AnomalyReport(anomalies=anomalies, assets_examined=examined, insufficient_baseline=insufficient)
