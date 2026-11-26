import json
import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.diagnostics import get_device_logs
from app.engine.providers import ProviderError, ProviderErrorKind, build_provider
from app.incidents import IncidentConflictError, IncidentIntegrityError, IncidentService, JsonIncidentRepository, LifecycleStatus
from app.incidents.models import IncidentFilter
from app.knowledge import KnowledgeIntegrityError, KnowledgeQuery, KnowledgeRepository
from app.network.repository import DATA_DIR, SCENARIOS_DIR, DatasetIntegrityError, load_scenario, load_topology
from app.security.limits import resource_limits
from verification.engine.helpers import FakeTransport, ai_settings, completion
from verification.incidents.helpers import HUMAN, SteppingClock, create

EXPECTED_LIMITS = {
    "request_body_bytes": 1_048_576, "rate_limit_requests": 120, "rate_limit_window_seconds": 60.0, "concurrent_requests": 32,
    "network_dataset_bytes": 5_000_000, "incident_file_bytes": 5_000_000, "knowledge_dataset_bytes": 2_000_000,
    "ai_timeout_seconds": 30.0, "ai_max_output_tokens": 2000, "ai_response_bytes": 1_000_000, "ai_content_chars": 60_000,
    "ai_model_turns": 12, "ai_reference_documents": 3, "tool_calls_per_diagnosis": 10, "tool_requests_per_diagnosis": 20,
    "tool_argument_chars": 4000, "tool_result_chars_for_model": 12_000, "diagnostic_records_per_query": 500,
    "diagnostic_evidence_per_finding": 50, "diagnostic_time_range_seconds": 86_400, "knowledge_results_per_query": 10,
    "incident_history_results": 500,
}


def test_resource_limit_inventory_is_unchanged() -> None:
    assert resource_limits(Settings(_env_file=None)) == EXPECTED_LIMITS


def copy_network_data(tmp_path: Path) -> Path:
    target = tmp_path / "data"
    shutil.copytree(DATA_DIR, target)
    return target


def test_oversized_network_dataset_is_rejected(tmp_path: Path) -> None:
    data = copy_network_data(tmp_path)
    path = data / SCENARIOS_DIR / "BASELINE.json"
    path.write_text(path.read_text(encoding="utf-8") + " " * 5_000_001, encoding="utf-8")
    with pytest.raises(DatasetIntegrityError, match="size limit"):
        load_scenario("BASELINE", data)
    (data / "topology.json").write_text(" " * 5_000_001, encoding="utf-8")
    with pytest.raises(DatasetIntegrityError):
        load_topology(data)


def test_symlinked_network_dataset_is_rejected(tmp_path: Path) -> None:
    data = copy_network_data(tmp_path)
    outside = tmp_path / "outside.json"
    shutil.copy(data / SCENARIOS_DIR / "BASELINE.json", outside)
    (data / SCENARIOS_DIR / "BASELINE.json").unlink()
    (data / SCENARIOS_DIR / "BASELINE.json").symlink_to(outside)
    with pytest.raises(DatasetIntegrityError):
        load_scenario("BASELINE", data)


def test_oversized_incident_file_is_quarantined(tmp_path: Path) -> None:
    store = tmp_path / "store"
    service = IncidentService(JsonIncidentRepository(store), SteppingClock())
    incident = create(service)
    path = store / f"{incident.incident_id}.json"
    path.write_text(path.read_text(encoding="utf-8") + " " * 5_000_001, encoding="utf-8")
    repository = JsonIncidentRepository(store)
    assert repository.problems == {incident.incident_id: "unsafe_or_oversized_file"}
    with pytest.raises(IncidentIntegrityError):
        repository.get(incident.incident_id)


def test_oversized_knowledge_dataset_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "knowledge.json"
    path.write_text(" " * 2_000_001, encoding="utf-8")
    with pytest.raises(KnowledgeIntegrityError, match="size limit"):
        KnowledgeRepository(path)


def test_excessive_query_results_are_rejected() -> None:
    with pytest.raises(ValidationError):
        IncidentFilter(limit=501)
    with pytest.raises(ValidationError):
        KnowledgeQuery(text="dns", limit=11)
    assert get_device_logs("BASELINE", "CORE-RTR-01", limit=501).error.code == "INVALID_ARGUMENT"
    assert get_device_logs("BASELINE", "CORE-RTR-01", start="2026-03-01T00:00:00Z", end="2026-03-02T00:00:01Z").error.code == "INVALID_ARGUMENT"


def test_excessive_ai_output_is_rejected() -> None:
    for body in (completion("x" * 60_001), b"x" * 1_000_001):
        with pytest.raises(ProviderError) as error:
            build_provider(ai_settings(), FakeTransport(body=body)).complete([{"role": "user", "content": "x"}], None)
        assert error.value.kind == ProviderErrorKind.TRUNCATED
    payload = build_provider(ai_settings(), FakeTransport(body=completion("ok")))
    payload.complete([{"role": "user", "content": "x"}], None)
    assert payload.transport.requests[0]["payload"]["max_completion_tokens"] == 2000


def test_concurrent_update_conflicts(tmp_path: Path) -> None:
    store = tmp_path / "store"
    first = IncidentService(JsonIncidentRepository(store), SteppingClock())
    second = IncidentService(JsonIncidentRepository(store), SteppingClock())
    incident = create(first)
    stale = second.get_incident(incident.incident_id)
    first.change_status(incident.incident_id, HUMAN, LifecycleStatus.ACKNOWLEDGED)
    with pytest.raises(IncidentConflictError):
        second.commit(stale, {"title": "Stale overwrite attempt"}, [])
    assert json.loads((store / f"{incident.incident_id}.json").read_text(encoding="utf-8"))["status"] == "acknowledged"
