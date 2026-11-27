from datetime import datetime

from app.advanced.schema import (
    AlignedEvidence,
    CrossLayerAnalysis,
    EvidenceRole,
    Layer,
    LayerCorrelation,
    LayerStatus,
    LayerSummary,
)
from app.engine.executor import ToolCallRecord
from app.engine.schema import Diagnosis, EvidenceItem, FaultDomain, TimelineRelevance

LAYER_CODES = {
    Layer.PHYSICAL_INTERFACE: {
        "INTERFACE_DOWN", "INTERFACES_DOWN", "HIGH_ERROR_COUNT", "HIGH_DROP_COUNT", "ERROR_COUNT_INCREASE", "HIGH_LATENCY",
        "HIGH_UTILIZATION", "PACKET_LOSS_MEASURED", "PHYSICAL_LAYER_DEGRADATION_SUSPECTED", "LOSS_DURING_INTERFACE_DOWN",
        "LINK_DOWN_AT_FAILURE_POINT", "LINK_DOWN_ON_PATH", "LINK_DOWN", "CARRIER_LOSS", "INTERFACE_ERRORS",
        "INTERFACE_EVENTS_LOGGED", "NO_PACKET_LOSS_MEASURED", "CONGESTION_SUSPECTED", "MTU_CHANGE", "MTU_CHANGED",
        "PATH_SEGMENT_DEGRADED", "PATH_SEGMENT_CONGESTED", "PATH_SEGMENT_DOWN", "LINK_FLAP_RECOVERED", "LINK_DOWN_ONGOING",
        "INTERMITTENT_FAULT_SUSPECTED",
    },
    Layer.SWITCHING_VLAN: {"DOT1X_AUTH_FAILURE", "PORT_UNAUTHORIZED", "RADIUS_SERVER_DEAD", "RADIUS_INVALID_AUTHENTICATOR"},
    Layer.ROUTING: {
        "NO_ROUTE_TO_DESTINATION", "ADJACENCY_FAILED", "ADJACENCY_STALLED", "ADJACENCY_RECENTLY_CHANGED",
        "ADJACENCY_LOSS_FOLLOWS_INTERFACE_DOWN", "CONTROL_PLANE_FAILURE_SUSPECTED", "NEIGHBOR_NOT_ESTABLISHED", "ROUTES_WITHDRAWN",
        "ROUTES_ADDED", "NEXT_HOP_CHANGED", "OSPF_ADJACENCY_DOWN", "OSPF_MTU_MISMATCH", "BGP_NEIGHBOR_DOWN", "PEER_ADJACENCIES_LOST",
        "ADJACENCY_FLAP_RECOVERED", "ROUTES_WITHDRAWN_AND_RESTORED", "ADJACENCY_DOWN_ONGOING",
    },
    Layer.WAN_CONNECTIVITY: {"PATH_REACHABLE", "PATH_UNREACHABLE", "PATH_INDETERMINATE", "WAN_PROBE_FAILURE", "SLA_THRESHOLD_EXCEEDED",
                             "PROBE_FLAP_RECOVERED", "PROBE_DOWN_ONGOING"},
    Layer.FIREWALL_SECURITY: {"TRAFFIC_DENIED", "RULE_MODIFIED_IN_RANGE", "POLICY_CHANGE", "POLICY_CHANGED", "FIREWALL_RULE_MODIFIED"},
    Layer.DHCP: {"DHCP_POOL_EXHAUSTED", "DHCP_POOL_HIGH_UTILIZATION", "DHCP_ALLOCATION_FAILURES", "DHCP_IP_CONFLICTS",
                 "DHCP_TRANSACTIONS_STOPPED", "DHCP_RELAY_TO_SERVER_REMOVED", "DHCP_RELAY_FAILURE_SUSPECTED", "DHCP_HELPER_REMOVED"},
    Layer.DNS: {"DNS_SERVFAIL", "DNS_TIMEOUTS", "DNS_REFUSED", "DNS_SERVER_RESOLUTION_FAULT_SUSPECTED", "DNS_UPSTREAM_RESOLUTION_FAILURE",
                "DNS_UNREACHABLE_FROM_SITE_SUSPECTED", "ZONE_LOAD_FAILURE", "ZONE_NOT_LOADED", "ZONE_RELOAD", "DNS_LOOKUP_FAILURE",
                "ZONE_RELOADED", "SERVICE_FLAP_RECOVERED", "SERVICE_DOWN_ONGOING"},
    Layer.SHARED_INFRASTRUCTURE: {
        "TELEMETRY_GAP", "PEER_LINKS_DOWN", "DEVICE_FAILURE_LIKELY", "DEVICE_UNREACHABLE", "DEVICE_TELEMETRY_MISSING",
        "DEVICE_AVAILABLE", "DEVICE_AVAILABLE_WITH_FAULTS", "POWER_SUPPLY_FAILURE", "SYSTEM_SHUTDOWN", "FAULT_EVENTS_LOGGED",
    },
}
CODE_LAYER = {code: layer for layer, codes in LAYER_CODES.items() for code in codes}
DOMAIN_LAYER = {
    FaultDomain.WAN_ISP: Layer.WAN_CONNECTIVITY, FaultDomain.ROUTING: Layer.ROUTING, FaultDomain.SWITCHING: Layer.SWITCHING_VLAN,
    FaultDomain.FIREWALL: Layer.FIREWALL_SECURITY, FaultDomain.VLAN_AUTHENTICATION: Layer.SWITCHING_VLAN, FaultDomain.DHCP: Layer.DHCP,
    FaultDomain.DNS: Layer.DNS, FaultDomain.NETWORK_DEVICE_FAILURE: Layer.SHARED_INFRASTRUCTURE,
    FaultDomain.INTERFACE_LINK: Layer.PHYSICAL_INTERFACE, FaultDomain.SHARED_INFRASTRUCTURE: Layer.SHARED_INFRASTRUCTURE,
}
SERVICE_SYMPTOMS = {"DNS_TIMEOUTS", "DNS_UNREACHABLE_FROM_SITE_SUSPECTED", "DHCP_TRANSACTIONS_STOPPED"}
HEALTHY_CODES = {"PATH_REACHABLE", "DEVICE_AVAILABLE", "DEVICE_AVAILABLE_WITH_FAULTS", "NO_PACKET_LOSS_MEASURED"}
DEVICE_DOMAINS = {FaultDomain.SHARED_INFRASTRUCTURE, FaultDomain.NETWORK_DEVICE_FAILURE}
CONCURRENT_SECONDS = 60
MAX_MISSING = 15


def layer_of(code: str) -> Layer:
    return CODE_LAYER.get(code, Layer.BACKGROUND)


def onset_of(diagnosis: Diagnosis) -> datetime | None:
    return next((entry.timestamp for entry in diagnosis.timeline if entry.relevance == TimelineRelevance.FAULT_ONSET), None)


def assign_roles(diagnosis: Diagnosis, catalog: list[EvidenceItem]) -> dict[str, EvidenceRole]:
    fault = diagnosis.fault
    supporting, contradicting = set(fault.supporting_evidence_ids), set(fault.contradictory_evidence_ids)
    background = {entry.evidence_id for entry in diagnosis.timeline if entry.relevance == TimelineRelevance.BACKGROUND}
    primary_layer = DOMAIN_LAYER.get(fault.fault_domain)
    roles = {}
    for item in catalog:
        layer = layer_of(item.code)
        if item.evidence_id in contradicting:
            role = EvidenceRole.CONTRADICTING
        elif item.evidence_id in supporting:
            if item.code in HEALTHY_CODES:
                role = EvidenceRole.CONTEXT
            elif fault.fault_domain in DEVICE_DOMAINS and item.device_id in fault.device_ids:
                role = (EvidenceRole.SHARED_DEPENDENCY_FAILURE if fault.fault_domain == FaultDomain.SHARED_INFRASTRUCTURE
                        else EvidenceRole.PRIMARY_FAULT)
            elif item.code in SERVICE_SYMPTOMS or (layer in (Layer.DHCP, Layer.DNS) and primary_layer not in (Layer.DHCP, Layer.DNS)):
                role = EvidenceRole.DOWNSTREAM_SERVICE_IMPACT
            elif item.device_id in fault.device_ids or layer == primary_layer:
                role = EvidenceRole.PRIMARY_FAULT
            else:
                role = EvidenceRole.SECONDARY_SYMPTOM
        elif item.evidence_id in background or layer == Layer.BACKGROUND:
            role = EvidenceRole.UNRELATED_BACKGROUND
        elif item.code in SERVICE_SYMPTOMS and fault.fault_domain != FaultDomain.UNKNOWN:
            role = EvidenceRole.DOWNSTREAM_SERVICE_IMPACT
        else:
            role = EvidenceRole.CONTEXT
        roles[item.evidence_id] = role
    return roles


def relation(seconds: int) -> str:
    if abs(seconds) <= CONCURRENT_SECONDS:
        return "concurrent"
    return "precedes" if seconds < 0 else "follows"


def cross_layer(diagnosis: Diagnosis, catalog: list[EvidenceItem], roles: dict[str, EvidenceRole],
                records: list[ToolCallRecord]) -> CrossLayerAnalysis:
    onset = onset_of(diagnosis)
    primary_layer = DOMAIN_LAYER.get(diagnosis.fault.fault_domain)
    ordered = sorted(catalog, key=lambda item: (item.timestamp is None, item.timestamp or datetime.min, int(item.evidence_id[1:])))
    aligned = [
        AlignedEvidence(evidence_id=item.evidence_id, layer=layer_of(item.code), role=roles[item.evidence_id],
                        device_id=item.device_id, code=item.code, timestamp=item.timestamp,
                        seconds_from_onset=int((item.timestamp - onset).total_seconds()) if onset and item.timestamp else None)
        for item in ordered
    ]
    fault_roles = {EvidenceRole.PRIMARY_FAULT, EvidenceRole.SHARED_DEPENDENCY_FAILURE, EvidenceRole.SECONDARY_SYMPTOM,
                   EvidenceRole.DOWNSTREAM_SERVICE_IMPACT}
    summaries = []
    for layer in Layer:
        if layer == Layer.BACKGROUND:
            continue
        members = [entry for entry in aligned if entry.layer == layer]
        stamps = [entry.timestamp for entry in members if entry.timestamp]
        faulty = [entry for entry in members if entry.role in fault_roles and entry.code not in HEALTHY_CODES]
        healthy = [entry for entry in members if entry.code in HEALTHY_CODES]
        status = (LayerStatus.FAULT_INDICATED if faulty else LayerStatus.HEALTHY_INDICATED if healthy else LayerStatus.NO_EVIDENCE)
        summaries.append(LayerSummary(layer=layer, status=status, evidence_ids=[entry.evidence_id for entry in members],
                                      devices=sorted({entry.device_id for entry in members if entry.device_id}),
                                      earliest=min(stamps, default=None), latest=max(stamps, default=None)))
    anchor = next((entry for entry in aligned if entry.timestamp and entry.role in
                   (EvidenceRole.PRIMARY_FAULT, EvidenceRole.SHARED_DEPENDENCY_FAILURE)), None)
    correlations = []
    if anchor is not None:
        for summary in summaries:
            if summary.layer == anchor.layer or summary.status != LayerStatus.FAULT_INDICATED:
                continue
            first = next((entry for entry in aligned if entry.layer == summary.layer and entry.timestamp
                          and entry.role in fault_roles), None)
            if first is not None:
                seconds = int((first.timestamp - anchor.timestamp).total_seconds())
                correlations.append(LayerCorrelation(from_layer=anchor.layer, to_layer=summary.layer, from_evidence_id=anchor.evidence_id,
                                                     to_evidence_id=first.evidence_id, seconds_apart=seconds, relation=relation(seconds)))
    by_id = {item.evidence_id: item for item in catalog}
    conflicts = [f"{evidence_id} ({by_id[evidence_id].code}) contradicts the suspected {diagnosis.fault.fault_domain.value} fault"
                 for evidence_id in diagnosis.fault.contradictory_evidence_ids if evidence_id in by_id]
    for alternative in diagnosis.alternatives:
        conflicts += [f"{evidence_id} ({by_id[evidence_id].code}) contradicts the alternative {alternative.fault_domain.value} hypothesis"
                      for evidence_id in alternative.contradictory_evidence_ids if evidence_id in by_id]
    missing = list(dict.fromkeys(note for record in records if record.succeeded for note in record.result.missing_data))
    return CrossLayerAnalysis(onset=onset, primary_layer=primary_layer, layers=summaries, correlations=correlations,
                              aligned_evidence=aligned, conflicts=list(dict.fromkeys(conflicts)), missing_telemetry=missing[:MAX_MISSING])
