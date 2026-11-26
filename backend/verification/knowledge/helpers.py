import json
from pathlib import Path
from typing import Any, Callable

from app.knowledge import KnowledgeRepository
from app.knowledge.dataset import build_knowledge_base


def knowledge_payload() -> dict[str, Any]:
    return build_knowledge_base().model_dump(mode="json")


def write_payload(directory: Path, payload: dict[str, Any] | str, name: str = "knowledge.json") -> Path:
    path = directory / name
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
    return path


def edited_repository(directory: Path, edit: Callable[[dict[str, Any]], None]) -> KnowledgeRepository:
    payload = knowledge_payload()
    edit(payload)
    return KnowledgeRepository(write_payload(directory, payload))


def playbook(payload: dict[str, Any], record_id: str) -> dict[str, Any]:
    return next(item for item in payload["playbooks"] if item["record_id"] == record_id)
