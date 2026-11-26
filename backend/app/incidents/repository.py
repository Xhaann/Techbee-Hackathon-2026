import json
import os
import re
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from app.incidents.errors import (
    IncidentConflictError,
    IncidentIntegrityError,
    IncidentNotFoundError,
    IncidentValidationError,
)
from app.incidents.models import Incident, IncidentFilter, IncidentSummary

INCIDENT_FILE = re.compile(r"^(INC-\d{8}-\d{4})\.json$")
INCIDENT_ID = re.compile(r"^INC-\d{8}-\d{4}$")
DEFAULT_STORE_DIR = Path(__file__).resolve().parents[2] / "var" / "incidents"
MAX_DAILY_INCIDENTS = 9999
MAX_RECORD_BYTES = 5_000_000


class IncidentRepository(Protocol):
    def next_id(self, moment: datetime) -> str: ...

    def get(self, incident_id: str) -> Incident: ...

    def add(self, incident: Incident) -> None: ...

    def save(self, incident: Incident) -> None: ...

    def query(self, criteria: IncidentFilter) -> list[IncidentSummary]: ...


def matches(summary: IncidentSummary, criteria: IncidentFilter) -> bool:
    return (
        (criteria.site_id is None or criteria.site_id in summary.site_ids)
        and (criteria.device_id is None or criteria.device_id in summary.device_ids)
        and (criteria.severity is None or summary.severity == criteria.severity)
        and (criteria.status is None or summary.status == criteria.status)
        and (criteria.fault_domain is None or summary.fault_domain == criteria.fault_domain)
        and (criteria.start is None or summary.created_at >= criteria.start)
        and (criteria.end is None or summary.created_at < criteria.end)
    )


class JsonIncidentRepository:
    def __init__(self, directory: Path = DEFAULT_STORE_DIR) -> None:
        self.directory = Path(directory).resolve()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.index: dict[str, IncidentSummary] = {}
        self.problems: dict[str, str] = {}
        self.reload()

    def path_for(self, incident_id: str) -> Path:
        if not isinstance(incident_id, str) or not INCIDENT_ID.match(incident_id):
            raise IncidentValidationError("Invalid incident identifier")
        path = (self.directory / f"{incident_id}.json").resolve()
        if path.parent != self.directory:
            raise IncidentValidationError("Invalid incident identifier")
        return path

    def read(self, path: Path) -> Incident:
        incident = Incident.model_validate_json(path.read_text(encoding="utf-8"))
        if f"{incident.incident_id}.json" != path.name:
            raise ValueError("file name does not match the incident identifier")
        return incident

    def reload(self) -> None:
        with self.lock:
            self.index, self.problems = {}, {}
            for path in sorted(self.directory.iterdir()):
                match = INCIDENT_FILE.match(path.name)
                if not match:
                    continue
                if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_RECORD_BYTES:
                    self.problems[match.group(1)] = "unsafe_or_oversized_file"
                    continue
                try:
                    self.index[match.group(1)] = IncidentSummary.of(self.read(path))
                except (OSError, ValueError, ValidationError) as exc:
                    self.problems[match.group(1)] = type(exc).__name__

    def next_id(self, moment: datetime) -> str:
        with self.lock:
            prefix = f"INC-{moment:%Y%m%d}-"
            taken = [int(name[len(prefix):]) for name in list(self.index) + list(self.problems) if name.startswith(prefix)]
            number = max(taken, default=0) + 1
            if number > MAX_DAILY_INCIDENTS:
                raise IncidentConflictError("Daily incident identifier space exhausted")
            return f"{prefix}{number:04d}"

    def get(self, incident_id: str) -> Incident:
        path = self.path_for(incident_id)
        with self.lock:
            if incident_id in self.problems:
                raise IncidentIntegrityError(f"Incident {incident_id} is stored in a corrupted record")
            if not path.exists():
                raise IncidentNotFoundError(f"Incident {incident_id} was not found")
            try:
                return self.read(path)
            except (OSError, ValueError, ValidationError):
                self.problems[incident_id] = "unreadable"
                self.index.pop(incident_id, None)
                raise IncidentIntegrityError(f"Incident {incident_id} is stored in a corrupted record") from None

    def write(self, incident: Incident) -> None:
        path = self.path_for(incident.incident_id)
        payload = json.dumps(incident.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"
        handle, temporary = tempfile.mkstemp(prefix=f".{incident.incident_id}.", suffix=".tmp", dir=self.directory)
        try:
            with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        self.index[incident.incident_id] = IncidentSummary.of(incident)

    def add(self, incident: Incident) -> None:
        with self.lock:
            path = self.path_for(incident.incident_id)
            if path.exists() or incident.incident_id in self.problems or incident.incident_id in self.index:
                raise IncidentConflictError(f"Incident {incident.incident_id} already exists")
            if incident.version != 1:
                raise IncidentValidationError("New incidents must start at version 1")
            self.write(incident)

    def save(self, incident: Incident) -> None:
        with self.lock:
            stored = self.get(incident.incident_id)
            if incident.version != stored.version + 1:
                raise IncidentConflictError(
                    f"Incident {incident.incident_id} was modified concurrently (stored version {stored.version})"
                )
            previous = [event.model_dump(mode="json") for event in stored.timeline]
            current = [event.model_dump(mode="json") for event in incident.timeline[:len(stored.timeline)]]
            if current != previous:
                raise IncidentIntegrityError("Historical timeline events cannot be modified or removed")
            if incident.created_at != stored.created_at:
                raise IncidentIntegrityError("Incident creation time cannot be modified")
            self.write(incident)

    def query(self, criteria: IncidentFilter) -> list[IncidentSummary]:
        with self.lock:
            selected = [summary for summary in self.index.values() if matches(summary, criteria)]
        selected.sort(key=lambda summary: (summary.created_at, summary.incident_id), reverse=True)
        return selected[:criteria.limit]
