import json
from pathlib import Path

import pytest

from app.core.config import Settings
from app.incidents import (
    IncidentConflictError,
    IncidentIntegrityError,
    IncidentNotFoundError,
    IncidentService,
    IncidentValidationError,
    JsonIncidentRepository,
    LifecycleStatus,
    build_incident_service,
)
from app.incidents.repository import DEFAULT_STORE_DIR
from verification.incidents.helpers import HUMAN, SteppingClock, create, diagnosed


def test_persistence_across_restarts(store: Path, clock: SteppingClock) -> None:
    first = IncidentService(JsonIncidentRepository(store), clock)
    incident = diagnosed(first)
    restarted = IncidentService(JsonIncidentRepository(store), clock)
    reloaded = restarted.get_incident(incident.incident_id)
    assert reloaded == incident
    assert reloaded.active_diagnosis.diagnosis == incident.active_diagnosis.diagnosis
    assert [s.incident_id for s in restarted.list_incidents()] == [incident.incident_id]
    assert create(restarted, "PACKET-LOSS").incident_id == "INC-20260303-0002"


def test_files_are_written_atomically(service: IncidentService, store: Path) -> None:
    incident = create(service)
    assert sorted(path.name for path in store.iterdir()) == [f"{incident.incident_id}.json"]
    assert json.loads((store / f"{incident.incident_id}.json").read_text(encoding="utf-8"))["version"] == 1
    assert b"\r\n" not in (store / f"{incident.incident_id}.json").read_bytes()


def test_failed_write_leaves_previous_version(service: IncidentService, store: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    incident = create(service)
    original = (store / f"{incident.incident_id}.json").read_bytes()

    def fail(*args: object, **kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("app.incidents.repository.os.replace", fail)
    with pytest.raises(OSError):
        service.change_status(incident.incident_id, HUMAN, LifecycleStatus.ACKNOWLEDGED)
    assert (store / f"{incident.incident_id}.json").read_bytes() == original
    assert sorted(path.name for path in store.iterdir()) == [f"{incident.incident_id}.json"]


def test_corrupted_records_are_quarantined_not_overwritten(store: Path, clock: SteppingClock) -> None:
    service = IncidentService(JsonIncidentRepository(store), clock)
    good = create(service)
    corrupt = store / "INC-20260303-0002.json"
    corrupt.write_text("{\"incident_id\": \"INC-20260303-0002\", truncated", encoding="utf-8")
    mismatched = store / "INC-20260303-0003.json"
    mismatched.write_text((store / f"{good.incident_id}.json").read_text(encoding="utf-8"), encoding="utf-8")
    repository = JsonIncidentRepository(store)
    assert set(repository.problems) == {"INC-20260303-0002", "INC-20260303-0003"}
    restarted = IncidentService(repository, clock)
    with pytest.raises(IncidentIntegrityError):
        restarted.get_incident("INC-20260303-0002")
    assert [s.incident_id for s in restarted.list_incidents()] == [good.incident_id]
    new = create(restarted, "PACKET-LOSS")
    assert new.incident_id == "INC-20260303-0004"
    assert corrupt.read_text(encoding="utf-8").endswith("truncated")


def test_duplicate_identifiers_are_rejected(service: IncidentService) -> None:
    incident = create(service)
    with pytest.raises(IncidentConflictError):
        service.repository.add(incident)


def test_conflicting_updates_are_detected(store: Path, clock: SteppingClock) -> None:
    first = IncidentService(JsonIncidentRepository(store), clock)
    second = IncidentService(JsonIncidentRepository(store), clock)
    incident = create(first)
    stale = second.get_incident(incident.incident_id)
    first.change_status(incident.incident_id, HUMAN, LifecycleStatus.ACKNOWLEDGED)
    with pytest.raises(IncidentConflictError):
        second.commit(stale, {"title": "Stale writer title"}, [])
    assert second.get_incident(incident.incident_id).title == incident.title
    with pytest.raises(IncidentConflictError):
        first.repository.save(stale.model_copy(update={"version": 5}))


def test_missing_records_and_directories(tmp_path: Path, clock: SteppingClock) -> None:
    nested = tmp_path / "does" / "not" / "exist"
    service = IncidentService(JsonIncidentRepository(nested), clock)
    assert nested.is_dir() and service.list_incidents() == []
    with pytest.raises(IncidentNotFoundError):
        service.get_incident("INC-20260303-0099")


def test_store_location_is_configurable_and_relative_to_package(tmp_path: Path) -> None:
    assert DEFAULT_STORE_DIR == Path(__file__).resolve().parents[2] / "var" / "incidents"
    service = build_incident_service(Settings(_env_file=None, incident_store_dir=str(tmp_path / "custom")))
    assert service.repository.directory == (tmp_path / "custom").resolve()


@pytest.mark.parametrize("incident_id", ["../secrets", "INC-20260303-0001/../../x", "..\\..\\x", "INC-1", "", 42,
                                         "/etc/passwd", "INC-20260303-0001.json"])
def test_path_traversal_is_rejected(service: IncidentService, incident_id: object) -> None:
    with pytest.raises(IncidentValidationError):
        service.get_incident(incident_id)
