import copy

import pytest
from pydantic import ValidationError

from app.knowledge.dataset import build_knowledge_base
from app.knowledge.models import CommandSpec, KnowledgeBase, Playbook, SourceReference, ToolReference
from verification.knowledge.helpers import knowledge_payload, playbook

BASE_PLAYBOOK = playbook(knowledge_payload(), "PB-WAN-FAILURE")


def variant(**changes: object) -> dict:
    record = copy.deepcopy(BASE_PLAYBOOK)
    record.update(changes)
    return record


def test_dataset_is_valid_and_complete() -> None:
    knowledge = build_knowledge_base()
    assert {p.record_id for p in knowledge.playbooks} >= {
        "PB-WAN-FAILURE", "PB-PACKET-LOSS", "PB-OSPF-ADJACENCY-FAILURE", "PB-FIREWALL-BLOCKING", "PB-DHCP-ALLOCATION-FAILURE",
        "PB-DNS-RESOLUTION-FAILURE", "PB-VLAN-AUTHENTICATION-FAILURE", "PB-SHARED-DEVICE-FAILURE", "PB-GENERAL-TRIAGE",
        "PB-TOPOLOGY-INVESTIGATION"}
    assert {r.record_id for r in knowledge.runbooks} == {"RB-NYC-BRANCH", "RB-SIN-BRANCH", "RB-BLR-BRANCH", "RB-CORE-NETWORK",
                                                         "RB-DC1-SERVICES"}
    assert {p.record_id for p in knowledge.procedures} == {"DP-INTERFACE-HEALTH", "DP-ROUTING-VERIFICATION", "DP-DNS-DHCP-SERVICES",
                                                          "DP-FIREWALL-POLICY", "DP-TOPOLOGY-DEPENDENCIES"}
    for item in knowledge.playbooks[:8]:
        assert item.symptoms and item.possible_causes and item.required_evidence and item.steps and item.decisions
        assert item.escalation and item.fault_domains and item.indicator_codes
        assert any(step.commands for step in item.steps) and any(step.tool for step in item.steps)
    assert all(command.illustrative for record in knowledge.records for step in getattr(record, "steps", []) + getattr(record, "procedures", [])
               for command in step.commands)


def test_records_are_immutable() -> None:
    record = build_knowledge_base().playbooks[0]
    with pytest.raises(ValidationError):
        record.title = "changed"


@pytest.mark.parametrize("changes", [
    {"record_id": "pb-wan"}, {"record_id": "XX-WAN"}, {"record_id": "PB-"}, {"version": "1.0"}, {"version": "v1.0.0"},
    {"symptoms": []}, {"required_evidence": []}, {"steps": []}, {"fault_domains": ["satellite"]},
    {"updated_at": "2026-01-01T00:00:00Z"}, {"created_at": "2026-02-01T00:00:00"}, {"unexpected": True},
    {"source_ids": []}, {"source_ids": ["external-blog"]}, {"tags": ["Has Spaces"]}, {"indicator_codes": ["lower_case"]},
])
def test_invalid_playbooks_are_rejected(changes: dict) -> None:
    with pytest.raises(ValidationError):
        Playbook.model_validate(variant(**changes))


@pytest.mark.parametrize("field", ["record_id", "title", "version", "description", "category", "layers", "symptoms",
                                   "possible_causes", "decisions", "escalation", "source_ids", "created_at"])
def test_missing_required_fields(field: str) -> None:
    record = variant()
    del record[field]
    with pytest.raises(ValidationError):
        Playbook.model_validate(record)


def test_unregistered_tools_are_rejected() -> None:
    with pytest.raises(ValidationError):
        ToolReference(tool="run_shell", purpose="Execute arbitrary commands")


def test_untrusted_sources_are_rejected() -> None:
    for kind in ("external_web", "vendor_forum", "customer"):
        with pytest.raises(ValidationError):
            SourceReference(source_id="SRC-EXTERNAL", title="Some external page", kind=kind, revision="1.0.0")
    with pytest.raises(ValidationError):
        SourceReference(source_id="SRC-X", title="Has uri", kind="synthetic_internal", revision="1.0.0", uri="https://example.com")


@pytest.mark.parametrize("text, platform", [
    ("show interfaces {interface}", "pan_os_typo"),
    ("show interfaces Gi0/0/0", "linux"),
    ("journalctl -u named", "cisco_ios_xe"),
])
def test_command_platform_format_is_validated(text: str, platform: str) -> None:
    with pytest.raises(ValidationError):
        CommandSpec(text=text, platform=platform, device_types=["router"], purpose="Interface state check")


def test_commands_must_be_marked_illustrative() -> None:
    with pytest.raises(ValidationError):
        CommandSpec(text="show logging", platform="cisco_ios_xe", device_types=["router"], purpose="Recent logs", illustrative=False)
    command = CommandSpec(text="show interfaces {interface}", platform="cisco_ios_xe", device_types=["router"], purpose="State")
    assert command.parameters == ["interface"] and command.illustrative is True


def test_knowledge_base_cross_references() -> None:
    payload = knowledge_payload()
    cases = []
    duplicate = copy.deepcopy(payload)
    duplicate["playbooks"].append(copy.deepcopy(duplicate["playbooks"][0]))
    cases.append(duplicate)
    dangling = copy.deepcopy(payload)
    dangling["playbooks"][0]["related_ids"] = ["PB-DOES-NOT-EXIST"]
    cases.append(dangling)
    unknown_source = copy.deepcopy(payload)
    unknown_source["runbooks"][0]["source_ids"] = ["SRC-UNKNOWN"]
    cases.append(unknown_source)
    wrong_prefix = copy.deepcopy(payload)
    wrong_prefix["runbooks"][0]["record_id"] = "PB-NOT-A-RUNBOOK"
    cases.append(wrong_prefix)
    self_reference = copy.deepcopy(payload)
    self_reference["playbooks"][0]["related_ids"] = [self_reference["playbooks"][0]["record_id"]]
    cases.append(self_reference)
    misordered = copy.deepcopy(payload)
    misordered["playbooks"][0]["steps"][0]["order"] = 7
    cases.append(misordered)
    site_free_runbook = copy.deepcopy(payload)
    site_free_runbook["runbooks"][0]["applicability"]["site_ids"] = []
    cases.append(site_free_runbook)
    for case in cases:
        with pytest.raises(ValidationError):
            KnowledgeBase.model_validate(case)
