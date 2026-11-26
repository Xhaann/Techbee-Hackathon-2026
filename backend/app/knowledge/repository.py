import re
from functools import lru_cache
from pathlib import Path

from pydantic import ValidationError

from app.engine.schema import FaultDomain
from app.knowledge.models import AnyRecord, KnowledgeBase, KnowledgeCategory, RecordType, SourceReference
from app.network.models import DeviceType, PathService
from app.network.repository import load_topology

DATA_FILE = Path(__file__).resolve().parent / "data" / "knowledge.json"
SUPPORTED_SCHEMA_MAJOR = "1"
RECORD_ID = re.compile(r"^(PB|RB|KD|DP)-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
MAX_FILE_BYTES = 2_000_000


class KnowledgeIntegrityError(ValueError):
    pass


class KnowledgeNotFoundError(LookupError):
    pass


def applies(values: list, wanted: object) -> bool:
    return wanted is None or not values or wanted in values


class KnowledgeRepository:
    def __init__(self, path: Path = DATA_FILE) -> None:
        self.path = Path(path).resolve()
        if self.path.suffix != ".json" or not self.path.is_file():
            raise KnowledgeIntegrityError("Knowledge data file is missing or is not a JSON file")
        if self.path.stat().st_size > MAX_FILE_BYTES:
            raise KnowledgeIntegrityError("Knowledge data file exceeds the size limit")
        try:
            knowledge = KnowledgeBase.model_validate_json(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, ValidationError) as exc:
            raise KnowledgeIntegrityError(f"Knowledge data failed validation: {type(exc).__name__}") from None
        if knowledge.schema_version.split(".")[0] != SUPPORTED_SCHEMA_MAJOR:
            raise KnowledgeIntegrityError(f"Unsupported knowledge schema version {knowledge.schema_version}")
        sites = {site.site_id for site in load_topology().sites}
        unknown = sorted({site for record in knowledge.records for site in record.applicability.site_ids} - sites)
        if unknown:
            raise KnowledgeIntegrityError(f"Knowledge records reference unknown sites: {', '.join(unknown)}")
        self.knowledge = knowledge
        self.records: dict[str, AnyRecord] = {record.record_id: record for record in knowledge.records}
        self.sources: dict[str, SourceReference] = {source.source_id: source for source in knowledge.sources}

    def get(self, record_id: str) -> AnyRecord:
        if not isinstance(record_id, str) or not RECORD_ID.match(record_id):
            raise KnowledgeNotFoundError("Invalid knowledge record identifier")
        record = self.records.get(record_id)
        if record is None:
            raise KnowledgeNotFoundError(f"Knowledge record {record_id} was not found")
        return record

    def sources_for(self, record: AnyRecord) -> list[SourceReference]:
        return [self.sources[source_id] for source_id in record.source_ids]

    def list(self, record_type: RecordType | None = None, active_only: bool = True, category: KnowledgeCategory | None = None,
             fault_domain: FaultDomain | None = None, site_id: str | None = None, device_type: DeviceType | None = None,
             service: PathService | None = None) -> list[AnyRecord]:
        selected = []
        for record in self.records.values():
            if active_only and not record.active:
                continue
            if record_type is not None and record.record_type != record_type:
                continue
            if category is not None and getattr(record, "category", None) != category:
                continue
            if fault_domain is not None and fault_domain not in record.fault_domains:
                continue
            scope = record.applicability
            if not (applies(scope.site_ids, site_id) and applies(scope.device_types, device_type) and applies(scope.services, service)):
                continue
            selected.append(record)
        return sorted(selected, key=lambda record: record.record_id)


@lru_cache
def default_repository() -> KnowledgeRepository:
    return KnowledgeRepository()
