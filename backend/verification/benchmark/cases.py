"""Benchmark cases: every scenario with its expected outcome.

Root-cause devices and links come from each dataset's ground truth at run time; this file adds what ground truth does not
record: the acceptable fault domains, the decoy each scenario plants, and the evidence source a correct diagnosis needs.
"""
import asyncio
from dataclasses import dataclass, field

from app.agent import DiagnosisAgent
from app.engine.engine import DiagnosisEngine
from app.engine.schema import Confidence, Diagnosis, DiagnosisRequest, FaultDomain
from app.network.repository import list_scenario_ids, load_scenario
from app.security.provenance import provenance_issues

CONFIDENT = {Confidence.HIGH, Confidence.MEDIUM}


@dataclass(frozen=True)
class Case:
    scenario_id: str
    domains: frozenset[FaultDomain]
    decoy_domains: frozenset[FaultDomain] = frozenset()
    decoy_devices: frozenset[str] = frozenset()
    required_tools: frozenset[str] = frozenset()
    says: tuple[str, ...] = ()


CASES = {case.scenario_id: case for case in (
    Case("WAN-FAILURE", frozenset({FaultDomain.WAN_ISP})),
    Case("PACKET-LOSS", frozenset({FaultDomain.WAN_ISP})),
    Case("OSPF-ADJACENCY-FAILURE", frozenset({FaultDomain.ROUTING})),
    Case("FIREWALL-BLOCKING", frozenset({FaultDomain.FIREWALL})),
    Case("DHCP-ALLOCATION-FAILURE", frozenset({FaultDomain.DHCP})),
    Case("DNS-RESOLUTION-FAILURE", frozenset({FaultDomain.DNS})),
    Case("VLAN-AUTHENTICATION-FAILURE", frozenset({FaultDomain.VLAN_AUTHENTICATION})),
    Case("SHARED-DEVICE-FAILURE", frozenset({FaultDomain.SHARED_INFRASTRUCTURE, FaultDomain.NETWORK_DEVICE_FAILURE})),
    Case("ADV-NYC-WAN-FLAP", frozenset({FaultDomain.WAN_ISP}), required_tools=frozenset({"get_event_timeline"}),
         says=("recovered",)),
    Case("ADV-SIN-ERP-SUBNET-BLOCK", frozenset({FaultDomain.FIREWALL})),
    Case("ADV-BLR-OSPF-AUTH-MISMATCH", frozenset({FaultDomain.ROUTING})),
    Case("ADV-DNS-SECONDARY-ZONE-EXPIRED", frozenset({FaultDomain.DNS}), decoy_devices=frozenset({"DC1-SRV-DNS-01"})),
    Case("ADV-METRO-FIBRE-DEGRADATION", frozenset({FaultDomain.INTERFACE_LINK, FaultDomain.WAN_ISP}),
         decoy_domains=frozenset({FaultDomain.VLAN_AUTHENTICATION}), decoy_devices=frozenset({"NYC-RTR-01", "NYC-SW-01"}),
         required_tools=frozenset({"analyze_path_health"})),
    Case("ADV-NYC-VOICE-DHCP-RELAY", frozenset({FaultDomain.DHCP}), decoy_devices=frozenset({"DC1-SRV-DHCP-01"}),
         required_tools=frozenset({"get_change_history"})),
    Case("ADV-SIN-RADIUS-UDP-BLOCK", frozenset({FaultDomain.FIREWALL}), decoy_domains=frozenset({FaultDomain.VLAN_AUTHENTICATION})),
)}
CONTROL = "BASELINE"


@dataclass
class Outcome:
    scenario_id: str
    entry: str
    diagnosis: Diagnosis
    executed: list[str]
    problems: list[str] = field(default_factory=list)

    @property
    def correct(self) -> bool:
        return not self.problems


def request_for(scenario_id: str, with_sites: bool = True) -> DiagnosisRequest:
    dataset = load_scenario(scenario_id)
    if dataset.incident is None:
        return DiagnosisRequest(scenario_id=scenario_id, description="Users at New York report a network problem.", site_ids=["NYC"])
    sites = dataset.incident.affected_site_ids[:5] if with_sites else []
    return DiagnosisRequest(scenario_id=scenario_id, description=dataset.incident.description, site_ids=sites)


def diagnose(scenario_id: str, entry: str = "engine", with_sites: bool = True) -> tuple[Diagnosis, list]:
    request = request_for(scenario_id, with_sites)
    if entry == "engine":
        return DiagnosisEngine().diagnose_with_records(request)
    run = asyncio.run(DiagnosisAgent(rule_based=True).arun(scenario_id, request.description, request.site_ids))
    return run.diagnosis, run.records


def evidence_problems(diagnosis: Diagnosis) -> list[str]:
    """Every cited evidence id resolves to a collected item, every item to a dataset record and an executed call."""
    problems = [f"provenance: {issue}" for issue in provenance_issues(diagnosis)]
    problems += [f"validation: {issue}" for issue in diagnosis.validation_issues]
    collected = {item.evidence_id for item in diagnosis.evidence}
    supporting = set(diagnosis.fault.supporting_evidence_ids)
    if diagnosis.fault.fault_domain != FaultDomain.UNKNOWN and not supporting:
        problems.append("evidence: the root cause cites no supporting evidence")
    problems += [f"evidence: {item} is cited but not collected" for item in sorted(supporting - collected)]
    return problems


def evaluate(scenario_id: str, entry: str = "engine", with_sites: bool = True) -> Outcome:
    diagnosis, records = diagnose(scenario_id, entry, with_sites)
    executed = [r.tool for r in records if r.status in ("executed", "failed")]
    outcome = Outcome(scenario_id, entry, diagnosis, executed)
    problems = outcome.problems
    fault = diagnosis.fault
    problems += evidence_problems(diagnosis)
    if len(executed) > 10 or any(r.status == "duplicate" for r in records) or any(r.status == "rejected" for r in records):
        problems.append(f"tool selection: {len(executed)} calls, statuses {sorted({r.status for r in records})}")
    if scenario_id == CONTROL:
        if fault.fault_domain != FaultDomain.UNKNOWN and diagnosis.confidence.level in CONFIDENT:
            problems.append(f"false positive on the healthy baseline: {fault.fault_domain.value} at {diagnosis.confidence.level.value}")
        return outcome
    case, truth = CASES[scenario_id], load_scenario(scenario_id).ground_truth
    right_device = bool(set(fault.device_ids) & set(truth.root_cause_device_ids))
    right_link = not truth.root_cause_link_ids or bool(set(fault.link_ids) & set(truth.root_cause_link_ids))
    right_domain = fault.fault_domain in case.domains
    if not (right_device and right_link and right_domain):
        problems.append(f"root cause: {fault.fault_domain.value} {fault.device_ids} {fault.link_ids}, expected "
                        f"{sorted(d.value for d in case.domains)} {truth.root_cause_device_ids} {truth.root_cause_link_ids}")
        if diagnosis.confidence.level in CONFIDENT:
            problems.append(f"calibration: wrong answer at {diagnosis.confidence.level.value} confidence")
    if fault.fault_domain in case.decoy_domains or (set(fault.device_ids) & case.decoy_devices and not right_device):
        problems.append(f"fell for the decoy: {fault.fault_domain.value} {fault.device_ids}")
    missing_tools = case.required_tools - set(executed)
    if missing_tools:
        problems.append(f"needed evidence source not used: {sorted(missing_tools)}")
    text = f"{fault.root_cause} {fault.reasoning}".lower()
    problems += [f"does not say {word!r}" for word in case.says if word not in text]
    return outcome


def all_scenarios() -> list[str]:
    return list_scenario_ids()
