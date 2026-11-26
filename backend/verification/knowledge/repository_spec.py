import re
from pathlib import Path

import pytest

from app.engine.schema import FaultDomain
from app.knowledge import KnowledgeIntegrityError, KnowledgeNotFoundError, KnowledgeRepository, RecordType
from app.knowledge.dataset import build_knowledge_base, to_json, write_knowledge
from app.knowledge.models import KnowledgeCategory
from app.knowledge.repository import DATA_FILE
from app.network.models import DeviceType, PathService
from app.network.repository import list_scenario_ids, load_scenario
from verification.knowledge.helpers import edited_repository, knowledge_payload, write_payload

BACKEND = Path(__file__).resolve().parents[2]


def test_committed_dataset_matches_builder(tmp_path: Path) -> None:
    assert DATA_FILE == BACKEND / "app" / "knowledge" / "data" / "knowledge.json"
    assert DATA_FILE.read_bytes() == to_json(build_knowledge_base()).encode("utf-8")
    write_knowledge(tmp_path / "copy.json")
    assert (tmp_path / "copy.json").read_bytes() == DATA_FILE.read_bytes()
    assert b"\r\n" not in DATA_FILE.read_bytes()


def test_indicator_codes_are_emitted_by_tools_or_datasets() -> None:
    sources = " ".join(path.read_text() for path in (BACKEND / "app" / "diagnostics").glob("*.py"))
    known = set(re.findall(r'"([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)"', sources))
    known |= {f"ADJACENCY_{status}" for status in ("FAILED", "STALLED", "RECENTLY_CHANGED")}
    known |= {f"PATH_{status}" for status in ("REACHABLE", "UNREACHABLE", "INDETERMINATE")}
    known |= {f"DEVICE_{status}" for status in ("AVAILABLE", "AVAILABLE_WITH_FAULTS", "TELEMETRY_MISSING", "UNREACHABLE")}
    known |= {"NO_PACKET_LOSS_MEASURED"}
    known |= {event.event_type for scenario in list_scenario_ids() for event in load_scenario(scenario).events}
    knowledge = build_knowledge_base()
    used = {code for record in knowledge.records for code in getattr(record, "indicator_codes", [])}
    used |= {code for record in knowledge.records for item in getattr(record, "required_evidence", []) for code in item.codes}
    assert used and used <= known, sorted(used - known)


def test_loading_and_retrieval_by_id() -> None:
    repository = KnowledgeRepository()
    record = repository.get("PB-WAN-FAILURE")
    assert record.record_type == RecordType.PLAYBOOK and record.version == "1.0.0"
    assert [s.source_id for s in repository.sources_for(record)] == ["SRC-SYNTHETIC-PLAYBOOKS"]
    assert len(repository.records) == 23


@pytest.mark.parametrize("record_id", ["PB-MISSING", "../knowledge", "PB-WAN-FAILURE/../x", "", 7, None, "pb-wan-failure"])
def test_missing_or_invalid_identifiers(record_id: object) -> None:
    with pytest.raises(KnowledgeNotFoundError):
        KnowledgeRepository().get(record_id)


def test_filters() -> None:
    repository = KnowledgeRepository()
    ids = lambda **kw: [r.record_id for r in repository.list(**kw)]
    assert ids(record_type=RecordType.RUNBOOK, site_id="SIN") == ["RB-SIN-BRANCH"]
    assert "PB-DNS-RESOLUTION-FAILURE" in ids(fault_domain=FaultDomain.DNS)
    assert all(r.record_type != RecordType.RUNBOOK for r in repository.list(category=KnowledgeCategory.SECURITY))
    assert ids(category=KnowledgeCategory.SECURITY) == ["PB-FIREWALL-BLOCKING"]
    assert "PB-FIREWALL-BLOCKING" not in ids(device_type=DeviceType.SERVER)
    assert "PB-DHCP-ALLOCATION-FAILURE" in ids(service=PathService.DHCP)
    assert "PB-DHCP-ALLOCATION-FAILURE" not in ids(service=PathService.DNS)


def test_inactive_records_are_excluded(tmp_path: Path) -> None:
    def deactivate(payload: dict) -> None:
        payload["playbooks"][0]["active"] = False
    repository = edited_repository(tmp_path, deactivate)
    assert "PB-WAN-FAILURE" not in [r.record_id for r in repository.list()]
    assert "PB-WAN-FAILURE" in [r.record_id for r in repository.list(active_only=False)]


@pytest.mark.parametrize("content", ["{not json", "[]", "{}", '{"schema_version": "1.0.0"}'])
def test_corrupt_data_is_rejected(tmp_path: Path, content: str) -> None:
    with pytest.raises(KnowledgeIntegrityError):
        KnowledgeRepository(write_payload(tmp_path, content))


def test_invalid_paths_are_rejected(tmp_path: Path) -> None:
    for path in (tmp_path / "missing.json", tmp_path, write_payload(tmp_path, "{}", "knowledge.txt")):
        with pytest.raises(KnowledgeIntegrityError):
            KnowledgeRepository(path)


def test_integrity_validation(tmp_path: Path) -> None:
    def duplicate(payload: dict) -> None:
        payload["documents"].append(dict(payload["documents"][0]))

    def unknown_site(payload: dict) -> None:
        payload["runbooks"][0]["applicability"]["site_ids"] = ["MARS"]

    def unsupported_schema(payload: dict) -> None:
        payload["schema_version"] = "2.0.0"

    def unsafe_command(payload: dict) -> None:
        payload["playbooks"][0]["steps"][1]["commands"][0]["text"] = "configure terminal"

    for edit in (duplicate, unknown_site, unsupported_schema, unsafe_command):
        with pytest.raises(KnowledgeIntegrityError):
            edited_repository(tmp_path, edit)


def test_oversized_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(KnowledgeIntegrityError):
        KnowledgeRepository(write_payload(tmp_path, " " * 2_000_001))
    assert knowledge_payload()["schema_version"] == "1.0.0"
