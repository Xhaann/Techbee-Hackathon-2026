import json

import pytest

from app.diagnostics import ToolResult
from app.engine.evidence import build_catalog, model_view
from app.engine.executor import MAX_RESULT_CHARS, MAX_TOOL_REQUESTS, ToolExecutor
from app.engine.registry import REGISTRY, TOOLS, ToolSpec, tool_schemas

EXPECTED_TOOLS = {
    "get_topology", "get_device_logs", "get_interface_stats", "get_routing_state", "get_firewall_logs",
    "get_dhcp_dns_status", "check_network_reachability", "analyze_packet_loss", "analyze_interface_errors",
    "analyze_routing_adjacency", "check_device_availability", "analyze_network_dependencies",
}


def test_all_twelve_tools_registered_with_explicit_schemas() -> None:
    assert set(REGISTRY) == EXPECTED_TOOLS and len(TOOLS) == 12
    for schema in tool_schemas():
        function = schema["function"]
        parameters = function["parameters"]
        assert schema["type"] == "function" and function["description"]
        assert parameters["type"] == "object" and parameters["additionalProperties"] is False
        assert "scenario_id" not in parameters["properties"]
        json.dumps(schema)


def test_valid_invocation_records_result() -> None:
    executor = ToolExecutor("WAN-FAILURE")
    record = executor.execute("get_routing_state", {"device_id": "SIN-RTR-01"})
    assert record.status == "executed" and record.succeeded and record.call_id == "C1"
    assert record.result.scenario_id == "WAN-FAILURE" and record.arguments == {"device_id": "SIN-RTR-01"}
    assert executor.remaining == 9


def test_json_string_arguments_are_accepted() -> None:
    record = ToolExecutor("BASELINE").execute("get_topology", '{"site_id": "NYC"}')
    assert record.succeeded and record.result.scenario_id is None


@pytest.mark.parametrize("name, arguments, code", [
    ("run_shell", {"command": "rm -rf /"}, "UNKNOWN_TOOL"),
    ("__import__", {}, "UNKNOWN_TOOL"),
    (None, {}, "UNKNOWN_TOOL"),
    ("get_routing_state", {"device_id": "SIN-RTR-01", "scenario_id": "BASELINE"}, "INVALID_ARGUMENTS"),
    ("get_routing_state", {}, "INVALID_ARGUMENTS"),
    ("get_device_logs", {"device_id": "SIN-RTR-01", "limit": 1000}, "INVALID_ARGUMENTS"),
    ("get_device_logs", {"device_id": "SIN-RTR-01", "min_severity": "loud"}, "INVALID_ARGUMENTS"),
    ("get_topology", "{not json", "INVALID_ARGUMENTS"),
    ("get_topology", "[1, 2]", "INVALID_ARGUMENTS"),
    ("get_topology", "x" * 5000, "INVALID_ARGUMENTS"),
])
def test_rejected_requests_are_not_executed(name: object, arguments: object, code: str) -> None:
    executor = ToolExecutor("BASELINE")
    record = executor.execute(name, arguments)
    assert record.status == "rejected" and record.error_code == code and record.result is None
    assert executor.remaining == 10


def test_tool_level_errors_are_preserved() -> None:
    record = ToolExecutor("BASELINE").execute("get_routing_state", {"device_id": "GHOST-RTR-01"})
    assert record.status == "executed" and not record.succeeded
    assert record.error_code == "NOT_FOUND" and record.result.data is None


def test_tool_exceptions_and_malformed_results(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*args: object, **kwargs: object) -> ToolResult:
        raise RuntimeError("internal secret detail")

    def malformed(*args: object, **kwargs: object) -> dict:
        return {"status": "success"}

    registry = dict(REGISTRY)
    registry["get_topology"] = ToolSpec("get_topology", "x", REGISTRY["get_topology"].arguments, explode, False)
    registry["check_device_availability"] = ToolSpec("check_device_availability", "x",
                                                     REGISTRY["check_device_availability"].arguments, malformed, True)
    executor = ToolExecutor("BASELINE", registry=registry)
    crashed = executor.execute("get_topology", {"site_id": "NYC"})
    assert crashed.status == "failed" and crashed.error_code == "TOOL_EXECUTION_ERROR"
    assert "secret" not in crashed.error
    invalid = executor.execute("check_device_availability", {"device_id": "CORE-RTR-01"})
    assert invalid.status == "failed" and invalid.error_code == "TOOL_RESULT_INVALID"
    assert executor.remaining == 8


def test_duplicate_calls_are_prevented() -> None:
    executor = ToolExecutor("BASELINE")
    first = executor.execute("get_routing_state", {"device_id": "CORE-SW-01"})
    second = executor.execute("get_routing_state", '{"device_id": "CORE-SW-01"}')
    assert second.status == "duplicate" and second.duplicate_of == first.call_id and second.result is None
    third = executor.execute("get_routing_state", {"device_id": "CORE-SW-01", "prefix": None})
    assert third.status == "duplicate"
    assert executor.remaining == 9


def test_tool_call_budget_is_enforced() -> None:
    executor = ToolExecutor("BASELINE")
    devices = ["CORE-RTR-01", "CORE-RTR-02", "CORE-SW-01", "CORE-FW-01", "DC1-FW-01", "DC1-SW-01", "NYC-RTR-01",
               "NYC-SW-01", "SIN-RTR-01", "SIN-SW-01", "BLR-RTR-01"]
    records = [executor.execute("check_device_availability", {"device_id": device}) for device in devices]
    assert [r.status for r in records[:10]] == ["executed"] * 10
    assert records[10].status == "rejected" and records[10].error_code == "BUDGET_EXHAUSTED"
    assert executor.remaining == 0 and len(executor.executed) == 10


def test_request_limit_stops_loops() -> None:
    executor = ToolExecutor("BASELINE")
    for _ in range(MAX_TOOL_REQUESTS):
        executor.execute("unknown_tool", {})
    assert executor.execute("get_topology", {"site_id": "NYC"}).error_code == "REQUEST_LIMIT"


def test_model_view_is_bounded_and_carries_evidence_ids() -> None:
    executor = ToolExecutor("SHARED-DEVICE-FAILURE")
    record = executor.execute("get_interface_stats", {"device_id": "CORE-SW-01"})
    catalog = build_catalog(executor.records)
    view = model_view(record, catalog)
    assert len(view) <= MAX_RESULT_CHARS
    parsed = json.loads(view)
    assert parsed["call_id"] == record.call_id and "untrusted_data_notice" in parsed
    assert {item["evidence_id"] for item in parsed["evidence"]} == {i.evidence_id for i in catalog if i.call_id == record.call_id}
    rejected = executor.execute("nope", {})
    assert json.loads(model_view(rejected, catalog))["error"]["code"] == "UNKNOWN_TOOL"
