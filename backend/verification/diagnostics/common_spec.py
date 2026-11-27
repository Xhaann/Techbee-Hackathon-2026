import json
from datetime import datetime, timezone

import pytest

from app import diagnostics
from app.diagnostics import FindingKind, ToolStatus
from app.network.repository import list_scenario_ids
from verification.diagnostics.helpers import failed, ok

SCENARIO_TOOLS = {
    "get_device_logs": lambda s: diagnostics.get_device_logs(s, "CORE-RTR-01"),
    "get_interface_stats": lambda s: diagnostics.get_interface_stats(s, "NYC-RTR-01"),
    "get_routing_state": lambda s: diagnostics.get_routing_state(s, "CORE-RTR-02"),
    "get_firewall_logs": lambda s: diagnostics.get_firewall_logs(s, source="10.0.0.0/8"),
    "get_dhcp_dns_status": lambda s: diagnostics.get_dhcp_dns_status(s, "BLR"),
    "check_network_reachability": lambda s: diagnostics.check_network_reachability(s, "NYC-SW-01", "DC1-SRV-APP-01"),
    "analyze_packet_loss": lambda s: diagnostics.analyze_packet_loss(s, "NYC-RTR-01", "Gi0/0/0"),
    "analyze_interface_errors": lambda s: diagnostics.analyze_interface_errors(s, "CORE-RTR-01", "Gi0/0/2"),
    "analyze_routing_adjacency": lambda s: diagnostics.analyze_routing_adjacency(s, "CORE-RTR-01"),
    "check_device_availability": lambda s: diagnostics.check_device_availability(s, "CORE-RTR-01"),
    "analyze_path_health": lambda s: diagnostics.analyze_path_health(s, "NYC-SW-01", "DC1-SRV-APP-01"),
    "get_event_timeline": lambda s: diagnostics.get_event_timeline(s, device_id="NYC-RTR-01"),
    "get_change_history": lambda s: diagnostics.get_change_history(s, device_id="NYC-RTR-01"),
}
STATIC_TOOLS = {
    "get_topology": lambda: diagnostics.get_topology("NYC"),
    "analyze_network_dependencies": lambda: diagnostics.analyze_network_dependencies(device_id="CORE-RTR-01"),
}
SCENARIOS = list_scenario_ids()


def test_all_fifteen_tools_are_exported() -> None:
    assert len(SCENARIO_TOOLS) + len(STATIC_TOOLS) == 15
    assert set(SCENARIO_TOOLS) | set(STATIC_TOOLS) <= set(diagnostics.__all__)


@pytest.mark.parametrize("scenario_id", SCENARIOS)
@pytest.mark.parametrize("tool", sorted(SCENARIO_TOOLS))
def test_every_tool_succeeds_serialises_and_is_deterministic(tool: str, scenario_id: str) -> None:
    first, second = SCENARIO_TOOLS[tool](scenario_id), SCENARIO_TOOLS[tool](scenario_id)
    ok(first)
    assert first.tool == tool
    assert first.scenario_id == scenario_id
    encoded = json.dumps(first.model_dump(mode="json"), sort_keys=True)
    assert encoded == json.dumps(second.model_dump(mode="json"), sort_keys=True)
    assert json.loads(encoded)["status"] == "success"
    assert "OPENAI" not in encoded and "sk-" not in encoded


@pytest.mark.parametrize("tool", sorted(STATIC_TOOLS))
def test_static_tools_succeed_and_serialise(tool: str) -> None:
    result = ok(STATIC_TOOLS[tool]())
    assert result.scenario_id is None
    assert json.dumps(result.model_dump(mode="json"))


@pytest.mark.parametrize("scenario_id", ["UNKNOWN", "BASELINE2"])
def test_unknown_scenario_is_not_found(scenario_id: str) -> None:
    result = failed(diagnostics.get_device_logs(scenario_id, "CORE-RTR-01"), "NOT_FOUND")
    assert "BASELINE" in result.error.message


@pytest.mark.parametrize("scenario_id", ["../topology", "..\\topology", "/etc/passwd", "baseline", "", 42, None, "A" * 500])
def test_malformed_scenario_identifiers_are_rejected(scenario_id: object) -> None:
    result = failed(diagnostics.get_routing_state(scenario_id, "CORE-RTR-01"), "INVALID_ARGUMENT")
    assert len(json.dumps(result.model_dump(mode="json"))) < 2000


def test_missing_and_unexpected_arguments_are_reported() -> None:
    failed(diagnostics.get_device_logs("BASELINE"), "INVALID_ARGUMENT")
    failed(diagnostics.get_topology("NYC", extra=True), "INVALID_ARGUMENT")


def test_parameters_are_recorded_safely() -> None:
    result = diagnostics.get_device_logs("BASELINE", "CORE-RTR-01", start=datetime(2026, 3, 2, 8, 45, tzinfo=timezone.utc),
                                         event_types={"NTP_SYNC"}, limit=object())
    failed(result, "INVALID_ARGUMENT")
    assert result.parameters["start"] == "2026-03-02T08:45:00+00:00"
    assert result.parameters["event_types"] == ["NTP_SYNC"]
    assert result.parameters["limit"] == "<object>"


def test_findings_distinguish_observed_and_inferred() -> None:
    result = ok(diagnostics.check_device_availability("SHARED-DEVICE-FAILURE", "CORE-RTR-01"))
    kinds = {finding.code: finding.kind for finding in result.findings}
    assert kinds["TELEMETRY_GAP"] == FindingKind.OBSERVED
    assert kinds["DEVICE_FAILURE_LIKELY"] == FindingKind.INFERRED
    assert all(finding.evidence for finding in result.findings)


def test_error_results_never_contain_data() -> None:
    result = diagnostics.get_interface_stats("BASELINE", "GHOST-RTR-01")
    assert result.status == ToolStatus.ERROR and result.data is None and result.findings == []
