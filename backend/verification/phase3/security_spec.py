"""Security behaviour, evidence grounding and read-only enforcement.

- Security findings are indicators, never confirmed attacks, and never attribute activity to anyone.
- Authorised scanners, backups, jump hosts and maintenance windows are recognised; decoy scenarios raise nothing.
- Instruction-like text in device data is withheld and ignored.
- Every finding is grounded in records that exist; correlations cite real records.
- Every command offered is read-only, the read-only allowlist stays narrow, and analysis writes nothing.
"""
import hashlib
import re
from pathlib import Path

import pytest

from app.engine.safety import is_read_only_command
from app.network.repository import all_scenario_ids
from app.protocols.analysis import analyze
from app.protocols.scenarios import PROTOCOL_SCENARIO_DIR
from verification.phase3.cases import CASES, SECURITY_CODES

ATTRIBUTION = re.compile(r"\b(?:APT\s?\d*|threat actor|nation[- ]state|hacker group|the attacker is|attributed to|state[- ]sponsored|"
                         r"cybercrim\w+ group|confirmed (?:attack|breach|compromise))\b", re.I)


@pytest.fixture(scope="module")
def reports():
    return {s: analyze(s) for s in all_scenario_ids()}


def text_of(report) -> str:
    return " ".join([report.headline, *report.notes, *(f"{f.title} {f.summary} {f.basis} " + " ".join(c.detail for c in f.correlations)
                                                        for f in report.findings)])


def test_security_findings_are_never_confirmed(reports) -> None:
    for report in reports.values():
        for f in report.findings:
            if f.code.startswith(SECURITY_CODES):
                assert f.status in ("suspicious_indicator", "insufficient_evidence"), (f.code, f.status)


def test_no_attribution_anywhere(reports) -> None:
    for scenario, report in reports.items():
        assert not ATTRIBUTION.search(text_of(report)), scenario
    for scenario in ("P3-SEC-LATERAL-MOVEMENT-NYC", "P3-SEC-ARP-MITM-SIN"):
        cluster = next(f for f in reports[scenario].findings if f.code == "THREAT_CORRELATED_ACTIVITY")
        assert "says nothing about who is responsible" in cluster.summary and "needs an analyst" in cluster.summary


@pytest.mark.parametrize("scenario", ["P3-SEC-ARP-MITM-SIN", "P3-SEC-LATERAL-MOVEMENT-NYC", "P3-SEC-DNS-TUNNEL-BLR"])
def test_threat_cluster_centres_on_the_actor_not_victims(reports, scenario: str) -> None:
    cluster = next(f for f in reports[scenario].findings if f.code == "THREAT_CORRELATED_ACTIVITY")
    assert cluster.facts["main_host"] == CASES[scenario].host


@pytest.mark.parametrize("scenario", ["P3-HEALTHY-BUSY", "P3-ADV-DECOYS", "BASELINE"])
def test_authorised_activity_raises_nothing(reports, scenario: str) -> None:
    report = reports[scenario]
    assert report.findings == [] and report.threats == []
    if scenario != "BASELINE":
        notes = " ".join(report.notes)
        assert "authorised vulnerability scanner" in notes and "jump host" in notes


def test_prompt_injection_in_device_data_is_withheld(reports) -> None:
    report = reports["P3-ADV-DECOYS"]
    notes = " ".join(report.notes)
    assert "Ignore previous instructions" not in text_of(report) and "SYSTEM PROMPT" not in text_of(report)
    assert "instruction-like" in notes and report.findings == []


def test_lateral_scenario_suppresses_the_jump_host_but_not_the_workstation(reports) -> None:
    report = reports["P3-SEC-LATERAL-MOVEMENT-NYC"]
    hosts = {h for f in report.findings for h in f.hosts}
    assert "10.255.0.200" not in hosts and "10.10.10.102" in hosts


def test_every_finding_is_grounded(reports) -> None:
    for scenario, report in reports.items():
        assert report.validation.grounded, (scenario, report.validation.issues)
        assert all(f.evidence for f in report.findings if f.status != "insufficient_evidence"), scenario


def test_provenance_rejects_invented_protocol_records() -> None:
    from app.engine.schema import EvidenceItem, EvidenceType
    from app.protocols.repository import load_telemetry, record_index
    index = record_index(load_telemetry("P3-STP-LOOP-NYC"))
    real = EvidenceItem(evidence_id="E1", call_id="c", tool="analyze_protocol", evidence_type=EvidenceType.OBSERVED_FINDING, code="STP_LOOP",
                        summary="x", references=[{"collection": "stp_vlans", "record_id": "NYC-SW-01|10"}])
    fake = EvidenceItem(**(real.model_dump() | {"references": [{"collection": "stp_vlans", "record_id": "NYC-SW-99|10"}]}))
    assert all(r.record_id in index[r.collection] for r in real.references)
    assert not all(r.record_id in index[r.collection] for r in fake.references)


def test_every_offered_command_is_read_only(reports) -> None:
    commands = [c.command for r in reports.values() for f in r.findings for c in f.commands]
    assert len(commands) > 40 and all(is_read_only_command(c) for c in commands)
    platforms = {c.platform for r in reports.values() for f in r.findings for c in f.commands}
    assert {"Cisco IOS XE", "PAN-OS", "Linux"} <= platforms


@pytest.mark.parametrize("command,allowed", [
    ("show crypto ikev2 sa", True), ("show crypto ipsec sa peer 203.0.113.2", True), ("show crypto session detail", True),
    ("show crypto key mypubkey rsa", False), ("show crypto pki certificates", False), ("show crypto isakmp key", False),
    ("openssl s_client -connect erp.corp.example.com:443 -servername erp.corp.example.com -brief", True),
    ("openssl s_client -connect attacker.evil.net:443", False), ("openssl s_client -connect 8.8.8.8:443", False),
    ("openssl s_client -connect erp.corp.example.com:443 ; reboot", False), ("ss -tin dst 10.100.100.40", True), ("ss -K dst 10.1.1.1", False),
    ("ss -tin dst 8.8.8.8", False), ("netstat -s", True), ("netstat -s ; rm -rf /", False), ("ping 2001:db8:30:10::1", True),
    ("ping 2001:4860::8888", False), ("show spanning-tree vlan 10 detail", True), ("configure terminal", False),
])
def test_read_only_allowlist_is_narrow(command: str, allowed: bool) -> None:
    assert is_read_only_command(command) is allowed


def test_analysis_writes_nothing(tmp_path) -> None:
    def fingerprint() -> str:
        digest = hashlib.sha256()
        for path in sorted(Path(PROTOCOL_SCENARIO_DIR).glob("*.json")) + sorted(Path("app/network/data").rglob("*.json")):
            digest.update(path.read_bytes())
        return digest.hexdigest()
    before = fingerprint()
    for scenario in ("P3-STP-LOOP-NYC", "P3-SEC-LATERAL-MOVEMENT-NYC", "WAN-FAILURE"):
        analyze(scenario)
    assert fingerprint() == before


def test_no_remediation_wording(reports) -> None:
    from app.engine.safety import mentions_remediation
    for scenario, report in reports.items():
        assert not mentions_remediation(text_of(report)), scenario
