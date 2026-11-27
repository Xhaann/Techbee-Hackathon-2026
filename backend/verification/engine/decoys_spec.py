"""Phase A (rule-based diagnosis) against decoys: coincidental failures, failures that ended before the fault, effects
that look like causes, and a single host's problem that looks like a service fault.

These defects were first exposed by SCN-04, SCN-05 and SCN-08. Every case here injects the pattern into the healthy BASELINE
dataset instead, so the rules are checked on data the scenarios never contained, and the true-positive side is checked too
(a real DNS fault, a real failure during the incident) so the fixes cannot pass by concluding less.
"""
from datetime import timedelta

import pytest

from app.diagnostics import common, get_dhcp_dns_status
from app.engine import planner
from app.engine.engine import DiagnosisEngine
from app.engine.schema import DiagnosisRequest, EvidenceItem, EvidenceType
from app.network.models import DhcpEvent, DnsQuery, NetworkEvent
from app.network.repository import load_scenario
from app.reasoning.evidence_model import likelihood
from app.reasoning.report import analyze as reason
from app.reasoning.specialists import Scope

BASE = "BASELINE"
ONSET = load_scenario(BASE).scenario.onset_at
CLIENTS = {"NYC": "10.10.10.100", "SIN": "10.20.10.100", "BLR": "10.30.10.100"}
DNS1, DNS2 = "10.100.100.10", "10.100.100.11"


def at(minutes: float):
    return ONSET + timedelta(minutes=minutes)


def query(n: int, minutes: float, site: str, server: str, domain: str, result: str) -> DnsQuery:
    return DnsQuery(query_id=f"DNS-T-{n:03d}", timestamp=at(minutes), client_ip=CLIENTS[site], server_ip=server, domain=domain,
                    record_type="A", result=result, answers=["10.100.100.40"] if result == "noerror" else [], response_time_ms=80.0)


def event(n: int, minutes: float, device: str, kind: str, message: str, interface: str | None = None) -> NetworkEvent:
    return NetworkEvent(event_id=f"EVT-T-{n:03d}", timestamp=at(minutes), device_id=device, severity="warning", event_type=kind,
                        message=message, interface_id=interface)


@pytest.fixture
def inject(monkeypatch):
    """Replaces BASELINE with a copy carrying extra DNS queries, events and DHCP events, for every tool and the planner."""
    original = load_scenario

    def apply(queries=(), events=(), dhcp=()):
        base = original(BASE)
        dataset = base.model_copy(update={
            "dns": base.dns.model_copy(update={"queries": base.dns.queries + list(queries)}),
            "events": base.events + list(events),
            "dhcp": base.dhcp.model_copy(update={"events": base.dhcp.events + list(dhcp)}),
        })
        fake = lambda scenario_id, *args, **kwargs: dataset if scenario_id == BASE else original(scenario_id, *args, **kwargs)  # noqa: E731
        monkeypatch.setattr(common, "load_scenario", fake)
        monkeypatch.setattr(planner, "load_scenario", fake)
        return dataset
    return apply


def diagnose(text: str, sites: list[str]):
    return DiagnosisEngine().diagnose(DiagnosisRequest(scenario_id=BASE, description=text, site_ids=sites))


def internet_down(start: int = 2) -> list[DnsQuery]:
    """Internet names SERVFAIL at every site while our own names keep resolving."""
    out = []
    for index, site in enumerate(CLIENTS):
        out.append(query(start + index * 10, 2 + index * 3, site, DNS1, "www.example.org", "servfail"))
        out.append(query(start + index * 10 + 1, 2.5 + index * 3, site, DNS1, "erp.corp.example.com", "noerror"))
    return out


INTERNET_REPORT = "No office can open external websites since about 09:00; internal ERP works; DNS errors for external names."


# ------------------------------------------------------------------ effects that look like causes (SCN-05 pattern)

def test_internet_names_failing_while_ours_resolve_is_not_a_dns_fault(inject) -> None:
    inject(internet_down())
    tool = get_dhcp_dns_status(BASE, "NYC")
    codes = [f.code for f in tool.findings]
    assert "DNS_UPSTREAM_RESOLUTION_FAILURE" in codes and "DNS_SERVER_RESOLUTION_FAULT_SUSPECTED" not in codes
    diagnosis = diagnose(INTERNET_REPORT, ["NYC", "SIN", "BLR"])
    assert diagnosis.fault.fault_domain.value != "dns"
    assert any("internet egress is failing" in line for line in diagnosis.limitations)  # says what it does not know


def test_a_change_on_the_internet_edge_is_the_likely_cause_but_only_at_medium_confidence(inject) -> None:
    change = event(1, -3, "CORE-FW-01", "POLICY_CHANGE", "NAT policy committed by 'fwadmin': rule NONAT-TEST added at position 10 (CHG-1)")
    inject(internet_down(), [change])
    diagnosis = diagnose(INTERNET_REPORT, ["NYC", "SIN", "BLR"])
    assert diagnosis.fault.fault_domain.value == "firewall" and "CORE-FW-01" in diagnosis.fault.root_cause
    assert diagnosis.confidence.level.value == "medium"  # tied by timing; the effect is not observed directly


def test_a_real_dns_fault_on_our_own_names_is_still_found(inject) -> None:
    failing = [query(100 + i, 2 + i * 2, site, DNS1, "files.corp.example.com", "servfail") for i, site in enumerate(["NYC", "NYC", "NYC"])]
    answered = [query(110 + i, 3 + i * 2, "NYC", DNS2, "files.corp.example.com", "noerror") for i in range(3)]
    inject(failing + answered)
    assert "DNS_SERVER_RESOLUTION_FAULT_SUSPECTED" in [f.code for f in get_dhcp_dns_status(BASE, "NYC").findings]
    assert diagnose("New York users cannot resolve names of internal servers", ["NYC"]).fault.fault_domain.value == "dns"


# ------------------------------------------------------------------ coincidence in time (SCN-08 pattern)

@pytest.mark.parametrize("minute,expect_dns", [(-25, False), (5, True)])
def test_a_failure_that_ended_before_the_fault_is_background(inject, minute: float, expect_dns: bool) -> None:
    failing = [query(200 + i, minute + i, "SIN", DNS2, "mail.corp.example.com", "servfail") for i in range(2)]
    answered = [query(210 + i, minute + i + 0.5, "SIN", DNS1, "mail.corp.example.com", "noerror") for i in range(2)]
    inject(failing + answered)
    diagnosis = diagnose("Singapore users report slow applications", ["SIN"])
    assert (diagnosis.fault.fault_domain.value == "dns") is expect_dns
    if not expect_dns:
        assert any("well before the fault began" in line for line in diagnosis.limitations)


# ------------------------------------------------------------------ a host's problem and the real layer-2 cause (SCN-04 pattern)

def conflict(n: int, minutes: float) -> DhcpEvent:
    return DhcpEvent(event_id=f"DHCP-T-{n:03d}", timestamp=at(minutes), server_device_id="DC1-SRV-DHCP-01", pool_id="DHCP-BLR-USERS",
                     event_type="ip_conflict", mac_address="02:00:0a:1e:00:07", ip_address="10.30.10.107",
                     message="Lease check: 10.30.10.107 answered ping from another host after it was leased")


def test_a_deleted_vlan_beats_an_unrelated_address_conflict(inject) -> None:
    inject(events=[event(10, -5, "BLR-SW-01", "CONFIG_COMMAND_LOGGED", "%PARSER-5-CFGLOG_LOGGEDCMD: User:netops logged command:no vlan 20"),
                   event(11, -4.7, "BLR-SW-01", "VLAN_INACTIVE", "%SW_VLAN-4-VLAN_NOT_FOUND: Access VLAN 20 on Gi1/0/3 does not exist; port inactive",
                         "BLR-SW-01:Gi1/0/3")],
           dhcp=[conflict(1, 4)])
    diagnosis = diagnose("Bengaluru desk phones have no network since this morning's switch clean-up", ["BLR"])
    assert diagnosis.fault.fault_domain.value == "switching" and "VLAN 20" in diagnosis.fault.root_cause
    assert all("cannot allocate" not in alternative.hypothesis for alternative in diagnosis.alternatives)


def test_an_address_conflict_alone_is_reported_as_a_conflict_not_a_failing_pool(inject) -> None:
    inject(dhcp=[conflict(2, 3)])
    diagnosis = diagnose("One Bengaluru desktop keeps losing its network connection", ["BLR"])
    assert diagnosis.fault.fault_domain.value == "dhcp" and diagnosis.fault.root_cause.startswith("Address conflict")
    assert "cannot allocate" not in diagnosis.fault.root_cause and diagnosis.confidence.level.value in ("low", "medium")


# ------------------------------------------------------------------ specialists (Phase 2 reasoning) on the same patterns

def item(eid: str, code: str, summary: str, kind=EvidenceType.OBSERVED_FINDING, tool: str = "get_dhcp_dns_status") -> EvidenceItem:
    return EvidenceItem(evidence_id=eid, call_id="C1", tool=tool, evidence_type=kind, code=code, device_id="DC1-SRV-DNS-01",
                        summary=summary, timestamp=at(3), references=[])


def test_internet_only_failures_weigh_little_for_dns() -> None:
    external = item("E1", "DNS_SERVFAIL", "3 queries returned servfail (domains: www.example.org); names outside our DNS zones only")
    internal = item("E2", "DNS_SERVFAIL", "3 queries returned servfail (domains: files.corp.example.com)")
    assert likelihood(external)["dns"] < 1 < likelihood(internal)["dns"]
    upstream = item("E3", "DNS_UPSTREAM_RESOLUTION_FAILURE", "Only names outside our zones fail", EvidenceType.INFERRED_FINDING)
    report = reason([external, upstream], Scope(BASE, ("NYC",)), ONSET, [])
    assert not (report.fault_supported and report.leading.value == "dns")


def test_reasoning_lists_an_unconfirmed_suspect_when_no_fault_is_supported() -> None:
    suspect = item("E1", "IPV6_ROGUE_RA", "[Suspicious (not confirmed)] Router advertisement from an unknown source at SIN: RA from a host",
                   EvidenceType.INFERRED_FINDING, "analyze_protocol")
    report = reason([suspect], Scope(BASE, ("SIN",)), ONSET, [])
    assert not report.fault_supported and report.suspected == ["Router advertisement from an unknown source at SIN"]
    assert report.compact()["suspected_not_confirmed"] == report.suspected
