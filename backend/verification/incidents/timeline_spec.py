from datetime import datetime, timedelta, timezone

import pytest

from app.incidents import IncidentIntegrityError, IncidentService, IncidentValidationError, JsonIncidentRepository
from app.incidents.service import AssetUpdate
from app.incidents.models import AssetType, ImpactBasis, LifecycleStatus
from verification.incidents.helpers import AI, HUMAN, SteppingClock, create, resolved


def test_timeline_is_chronological_unique_and_utc(service: IncidentService) -> None:
    incident = resolved(service)
    timeline = service.timeline(incident.incident_id)
    assert [e.sequence for e in timeline] == list(range(1, len(timeline) + 1))
    assert [e.timestamp for e in timeline] == sorted(e.timestamp for e in timeline)
    assert len({e.event_id for e in timeline}) == len(timeline)
    assert all(e.timestamp.utcoffset() == timedelta(0) for e in timeline)
    assert all(e.event_id.startswith(incident.incident_id) for e in timeline)
    status_events = [(e.from_status, e.to_status) for e in timeline if e.to_status]
    assert status_events[0] == (None, LifecycleStatus.NEW) and status_events[-1][1] == LifecycleStatus.RESOLVED


def test_history_is_append_only(service: IncidentService) -> None:
    incident = create(service)
    before = [e.model_dump(mode="json") for e in incident.timeline]
    later = service.change_status(incident.incident_id, HUMAN, LifecycleStatus.ACKNOWLEDGED)
    assert [e.model_dump(mode="json") for e in later.timeline[:len(before)]] == before


def test_rewriting_history_is_rejected(service: IncidentService) -> None:
    incident = service.change_status(create(service).incident_id, HUMAN, LifecycleStatus.ACKNOWLEDGED)
    edited = incident.timeline[1].model_copy(update={"description": "Rewritten"})
    tampered = incident.model_copy(update={"timeline": [incident.timeline[0], edited], "version": incident.version + 1})
    with pytest.raises(IncidentIntegrityError):
        service.repository.save(tampered)
    removed = incident.model_copy(update={"timeline": incident.timeline[:1], "version": incident.version + 1})
    with pytest.raises(IncidentIntegrityError):
        service.repository.save(removed)
    assert service.get_incident(incident.incident_id).timeline[1].description == incident.timeline[1].description


def test_clock_skew_does_not_reorder_events(store, clock: SteppingClock) -> None:
    service = IncidentService(JsonIncidentRepository(store), clock)
    incident = create(service)
    clock.current = datetime(2026, 3, 1, tzinfo=timezone.utc)
    later = service.change_status(incident.incident_id, HUMAN, LifecycleStatus.ACKNOWLEDGED)
    assert later.timeline[1].timestamp >= later.timeline[0].timestamp


def test_asset_updates_are_recorded_without_duplicates(service: IncidentService) -> None:
    incident = create(service)
    first = service.update_affected_assets(incident.incident_id, AI, [AssetUpdate(asset_type=AssetType.DEVICE, asset_id="SIN-RTR-01",
                                                                                  basis=ImpactBasis.INFERRED)])
    confirmed = service.update_affected_assets(incident.incident_id, HUMAN, [
        AssetUpdate(asset_type=AssetType.DEVICE, asset_id="SIN-RTR-01", basis=ImpactBasis.CONFIRMED)])
    device = next(a for a in confirmed.affected_assets if a.asset_id == "SIN-RTR-01")
    assert device.basis == ImpactBasis.CONFIRMED and device.sources == ["ai:assistant", "human:noc.engineer"]
    assert len(confirmed.affected_assets) == len(first.affected_assets)
    assert "upgraded to confirmed" in confirmed.timeline[-1].description
    with pytest.raises(IncidentValidationError, match="do not change"):
        service.update_affected_assets(incident.incident_id, HUMAN, [
            AssetUpdate(asset_type=AssetType.DEVICE, asset_id="SIN-RTR-01", basis=ImpactBasis.INFERRED)])
