"""Troubleshooting recommendations rest on the diagnosis, the evidence and the user's report, never on a default WAN checklist.

Before this fix every unknown-cause incident got the same WAN-edge steps (WAN interface, ping, BGP, route) whatever users
reported: DNS time-outs, a DHCP pool warning, VPN alarms, Wi-Fi, certificate errors. These cases pin the grounded behaviour.
"""
import tempfile
from pathlib import Path

import pytest

from app.conversation import assist
from app.engine.schema import EvidenceItem, EvidenceType, FaultDomain
from verification.api.helpers import ApiHarness

WAN_EDGE_COMMANDS = ("show interfaces Gi0/0/0", "ping 172.16.0.", "show ip bgp summary", "show ip ospf neighbor")


def item(evidence_id: str, code: str, device: str, summary: str, kind: EvidenceType = EvidenceType.OBSERVED_FINDING) -> EvidenceItem:
    return EvidenceItem(evidence_id=evidence_id, call_id=f"C{evidence_id[1:]}", tool="test", evidence_type=kind, code=code,
                        device_id=device, summary=summary)


def reachable(evidence_id: str, switch: str) -> EvidenceItem:
    return item(evidence_id, "PATH_REACHABLE", switch, f"Layer-3 path {switch} -> DC1-SRV-APP-01 is reachable; path {switch} > CORE",
                EvidenceType.OBSERVED_RESULT)


def commands(plan: assist.Plan) -> list[str]:
    return [f"{c.device_id} {c.command}" for c in plan.commands]


def domains(plan: assist.Plan) -> set[FaultDomain]:
    return {c.domain for c in plan.commands}


# ---------- the planning rules ----------

def test_unknown_cause_with_wan_symptoms_checks_that_sites_circuit() -> None:
    grounds = assist.Grounds(report=["Calls drop every few minutes", "Packet loss on the New York circuit"], sites=["NYC"])
    plan = assist.plan_checks(grounds, "NYC")
    assert "NYC-RTR-01 show interfaces Gi0/0/0" in commands(plan) and FaultDomain.WAN_ISP in domains(plan)
    assert plan.reasons == ["report"] and plan.status == "unknown"


def test_connectivity_alone_never_implies_the_wan() -> None:
    reachability = assist.plan_checks(assist.Grounds(report=["Users can't reach the ERP portal"], sites=["SIN"]), "SIN")
    assert FaultDomain.WAN_ISP not in domains(reachability) and FaultDomain.ROUTING in domains(reachability)
    several = assist.plan_checks(assist.Grounds(report=["Packet loss at every office"], sites=["NYC", "SIN", "BLR"]), "NYC")
    assert not several.commands, "loss at several offices at once is not one branch's circuit"
    one_host = assist.plan_checks(assist.Grounds(report=["One desktop drops off every few minutes"], sites=["NYC"]), "NYC")
    assert not one_host.commands, "one machine dropping out is not the site's circuit"
    vague = assist.plan_checks(assist.Grounds(report=["Everything is slow", "Short freezes"], sites=["BLR"]), "BLR")
    assert not vague.commands, "vague symptoms justify no device check"


def test_unknown_cause_with_dns_symptoms_checks_dns_only() -> None:
    plan = assist.plan_checks(assist.Grounds(report=["DNS errors for internal names", "ERP times out"], sites=["SIN"]), "SIN")
    assert domains(plan) == {FaultDomain.DNS}
    assert any("dig @10.100.100.10" in c for c in commands(plan)) and not any(w in c for c in commands(plan) for w in WAN_EDGE_COMMANDS)


def test_unknown_cause_with_routing_symptoms_checks_routing_not_the_circuit() -> None:
    grounds = assist.Grounds(report=["BGP routes to the data centre are missing at Singapore"], sites=["SIN"])
    plan = assist.plan_checks(grounds, "SIN")
    assert "SIN-RTR-01 show ip route 10.100.100.0" in commands(plan) and "SIN-RTR-01 show ip bgp summary" in commands(plan)
    assert FaultDomain.WAN_ISP not in domains(plan)
    # A working path from the site rules routing out there; nothing is left to check, so nothing is invented.
    ruled = assist.plan_checks(assist.Grounds(report=grounds.report, sites=["SIN"], evidence=[reachable("E1", "SIN-SW-01")]), "SIN")
    assert not ruled.commands and ruled.ruled_out == {"SIN": ["E1"]}


def test_conflicting_evidence_checks_both_sides() -> None:
    against = item("E5", "TRAFFIC_DENIED", "DC1-FW-01", "14 flows denied by rule FWR-DC1-0120 (DENY-DNS) on DC1-FW-01 between "
                                                        "2026-04-25T09:01:00+00:00 and 2026-04-25T09:09:00+00:00")
    grounds = assist.Grounds(status="conflicting", domain=FaultDomain.DNS, sites=["NYC"], evidence=[against], contradicting=[against])
    plan = assist.plan_checks(grounds, "NYC")
    assert {FaultDomain.DNS, FaultDomain.FIREWALL} <= domains(plan) and plan.commands[0].domain == FaultDomain.DNS
    assert "E5" in plan.evidence_ids and plan.status == "conflicting"


def test_insufficient_telemetry_checks_the_silent_device_or_asks_for_evidence() -> None:
    gap = item("E2", "TELEMETRY_GAP", "CORE-RTR-01", "No interface statistics from CORE-RTR-01 from 09:05 onwards",
               EvidenceType.INFERRED_FINDING)
    plan = assist.plan_checks(assist.Grounds(sites=["NYC"], evidence=[gap]), "NYC")
    assert plan.commands and {c.device_id for c in plan.commands} == {"CORE-RTR-01"} and [g.evidence_id for g in plan.telemetry_gaps] == ["E2"]
    nothing = assist.plan_checks(assist.Grounds(sites=["NYC"]), "NYC")
    assert nothing.commands == []


def test_a_single_denied_flow_justifies_nothing() -> None:
    one = item("E4", "TRAFFIC_DENIED", "DC1-FW-01", "1 flows denied by rule FWR-DC1-9999 (DENY-ALL) on DC1-FW-01 between "
                                                    "2026-04-30T08:49:00+00:00 and 2026-04-30T08:49:00+00:00")
    assert assist.plan_checks(assist.Grounds(sites=["NYC"], evidence=[one]), "NYC").commands == []


def test_confirmed_fault_puts_its_own_checks_first() -> None:
    plan = assist.plan_checks(assist.Grounds(status="confirmed", domain=FaultDomain.WAN_ISP, sites=["SIN"],
                                             report=["DNS errors too"]), "SIN")
    assert plan.commands[0].command.startswith("show interfaces") and plan.commands[0].device_id == "SIN-RTR-01"
    assert plan.commands[-1].domain == FaultDomain.DNS, "report-based checks come after the confirmed fault's checks"


# ---------- the same rules in the conversation ----------

@pytest.fixture(scope="module")
def demo():
    api = ApiHarness(Path(tempfile.mkdtemp()), demo_incidents=True)
    with api.client:
        yield api


def ask(api: ApiHarness, incident_id: str, *messages: str) -> list[dict]:
    cid = api.post("/conversations", {"incident_id": incident_id}, as_="manager").json()["conversation_id"]
    return [api.post(f"/conversations/{cid}/messages", {"content": m}, as_="manager").json() for m in messages]


def guide_steps(turn: dict) -> list[dict]:
    return next((a["data"]["steps"] for a in turn["attachments"] if a["kind"] == "troubleshooting_guide"), [])


def test_certificate_errors_get_no_invented_steps(demo) -> None:
    steps, nxt = ask(demo, "INC-20260430-0410", "Give me step-by-step troubleshooting", "What should I check next?")
    assert guide_steps(steps) == [] and steps["response"].startswith("I can't point to specific commands yet")
    assert steps["execution"]["tool_calls"] == 0 and steps["context"]["pending_action"]["kind"] == "protocol"
    assert "certificates" in nxt["response"] and nxt["execution"]["tool_calls"] == 0


def test_dns_time_outs_get_dns_steps_not_the_wan(demo) -> None:
    (turn,) = ask(demo, "INC-20260422-0402", "Give me step-by-step troubleshooting")
    commands_run = [s["command"] for s in guide_steps(turn)]
    assert commands_run and all(s["domain"] == "dns" for s in guide_steps(turn))
    assert turn["response"].startswith("Nothing points at a cause yet") and "routing checks for Singapore" in turn["response"]
    assert not any(w in c for c in commands_run for w in WAN_EDGE_COMMANDS)
    assert {r["evidence_id"] for r in turn["evidence_references"]} >= {"E2"}, "the evidence the steps rest on is cited"


def test_vpn_alarms_suggest_the_tunnel_check(demo) -> None:
    (nxt,) = ask(demo, "INC-20260426-0406", "What should I check next?")
    calls = nxt["context"]["pending_action"]["calls"]
    assert [c["arguments"]["protocol"] for c in calls] == ["ipsec"] and nxt["execution"]["tool_calls"] == 0


def test_likely_fault_is_labelled_and_its_steps_come_first(demo) -> None:
    (turn,) = ask(demo, "INC-20260421-0401", "Give me step-by-step troubleshooting")
    assert "likely WAN / ISP circuit fault, which isn't confirmed yet" in turn["response"]
    assert guide_steps(turn)[0]["command"] == "show interfaces Gi0/0/0" and guide_steps(turn)[0]["device_id"] == "NYC-RTR-01"


def test_confirmed_fault_gets_a_relevant_next_check(tmp_path: Path) -> None:
    api = ApiHarness(tmp_path)
    with api.client:
        incident = api.diagnosed()
        confirmed = api.post(f"/incidents/{incident['incident_id']}/classification",
                             {"expected_version": incident["version"], "fault_domain": "wan_isp", "reason": "Carrier confirmed"})
        assert confirmed.status_code == 200, confirmed.text
        guide, nxt = ask(api, incident["incident_id"], "Give me step-by-step troubleshooting", "What should I check next?")
        assert guide["response"].startswith("The cause is confirmed as WAN / ISP circuit")
        assert guide_steps(guide)[0]["device_id"] == "SIN-RTR-01" and guide_steps(guide)[0]["domain"] == "wan_isp"
        assert nxt["execution"]["tool_calls"] == 0 and ("SIN" in nxt["response"] or "Singapore" in nxt["response"])


def test_conflicting_evidence_is_said_out_loud(demo) -> None:
    service = demo.client.app.state.services.conversations
    against = item("E5", "TRAFFIC_DENIED", "DC1-FW-01", "14 flows denied by rule FWR-DC1-0120 (DENY-DNS) on DC1-FW-01 between "
                                                        "2026-04-25T09:01:00+00:00 and 2026-04-25T09:09:00+00:00")
    grounds = assist.Grounds(status="conflicting", domain=FaultDomain.DNS, sites=["NYC"], evidence=[against], contradicting=[against])
    lead = service.guide_lead(grounds, assist.plan_checks(grounds, "NYC"), 4)
    assert lead.startswith("The evidence conflicts. It points to DNS, but the data-centre firewall blocked 14 connections (E5)")
