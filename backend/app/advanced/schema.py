from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.engine.schema import Confidence, Diagnosis, DiagnosisRequest, FaultDomain, NextCheck
from app.incidents.models import AssetType
from app.incidents.similarity import SimilarIncident
from app.network.models import Identifier

CAUSATION_NOTICE = "Temporal proximity or similarity does not establish causation."


class AdvancedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Layer(str, Enum):
    PHYSICAL_INTERFACE = "physical_interface"
    SWITCHING_VLAN = "switching_vlan"
    ROUTING = "routing"
    WAN_CONNECTIVITY = "wan_connectivity"
    FIREWALL_SECURITY = "firewall_security"
    DHCP = "dhcp"
    DNS = "dns"
    SHARED_INFRASTRUCTURE = "shared_infrastructure"
    BACKGROUND = "background"


class LayerStatus(str, Enum):
    FAULT_INDICATED = "fault_indicated"
    HEALTHY_INDICATED = "healthy_indicated"
    NO_EVIDENCE = "no_evidence"


class EvidenceRole(str, Enum):
    PRIMARY_FAULT = "primary_fault"
    SHARED_DEPENDENCY_FAILURE = "shared_dependency_failure"
    SECONDARY_SYMPTOM = "secondary_symptom"
    DOWNSTREAM_SERVICE_IMPACT = "downstream_service_impact"
    CONTRADICTING = "contradicting"
    CONTEXT = "context"
    UNRELATED_BACKGROUND = "unrelated_background"


class CandidateStatus(str, Enum):
    SUSPECTED = "suspected"
    HUMAN_CONFIRMED = "human_confirmed"
    ALTERNATIVE = "alternative"
    CONTRADICTED = "contradicted"


class ImpactCategory(str, Enum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    REPORTED = "reported"
    POTENTIAL = "potential"


class CorrelationStrength(str, Enum):
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"


class AdvancedRequest(AdvancedModel):
    diagnosis: DiagnosisRequest
    incident_id: str | None = Field(default=None, pattern=r"^INC-\d{8}-\d{4}$")
    supplementary_tool_calls: int = Field(default=3, ge=0, le=5)


class LayerSummary(AdvancedModel):
    layer: Layer
    status: LayerStatus
    evidence_ids: list[str]
    devices: list[str]
    earliest: datetime | None
    latest: datetime | None


class LayerCorrelation(AdvancedModel):
    from_layer: Layer
    to_layer: Layer
    from_evidence_id: str
    to_evidence_id: str
    seconds_apart: int
    relation: Literal["precedes", "concurrent", "follows"]


class AlignedEvidence(AdvancedModel):
    evidence_id: str
    layer: Layer
    role: EvidenceRole
    device_id: str | None
    code: str
    timestamp: datetime | None
    seconds_from_onset: int | None


class CrossLayerAnalysis(AdvancedModel):
    onset: datetime | None
    primary_layer: Layer | None
    layers: list[LayerSummary]
    correlations: list[LayerCorrelation]
    aligned_evidence: list[AlignedEvidence]
    conflicts: list[str]
    missing_telemetry: list[str]


class RootCauseCandidate(AdvancedModel):
    rank: int
    status: CandidateStatus
    fault_domain: FaultDomain
    hypothesis: str
    device_ids: list[str]
    link_ids: list[str]
    supporting_evidence_ids: list[str]
    contradicting_evidence_ids: list[str]
    missing_evidence: list[str]
    dependent_symptom_ids: list[str]
    confidence: Confidence
    verification_checks: list[str]


class PathHop(AdvancedModel):
    device_id: str
    site_id: str
    role: Literal["source", "intermediate", "destination"]
    link_to_next: str | None
    interfaces: list[str]
    routing_protocol: str | None


class PathAnalysis(AdvancedModel):
    source: str
    destination: str
    status: Literal["reachable", "unreachable", "indeterminate", "not_evaluated"]
    complete: bool
    hops: list[PathHop]
    modelled_path_id: str | None
    modelled_path_devices: list[str]
    earliest_affected_point: str | None
    failed_links: list[str]
    degraded_links: list[str]
    shared_devices: list[str]
    topology_alternatives: list[list[str]]
    limitations: list[str]


class ImpactItem(AdvancedModel):
    asset_type: AssetType
    asset_id: str
    category: ImpactCategory
    basis: str
    evidence_ids: list[str]


class BlastRadius(AdvancedModel):
    items: list[ImpactItem]
    affected_sites: list[str]
    potentially_affected_sites: list[str]
    shared_dependencies: list[str]
    business_impact: Literal["not_assessed"] = "not_assessed"
    note: str


class ChangeRecord(AdvancedModel):
    change_id: str
    source: Literal["device_event_log", "firewall_rule_history"]
    change_type: str
    timestamp: datetime
    device_id: str
    description: str


class ChangeCorrelation(AdvancedModel):
    change: ChangeRecord
    seconds_from_onset: int
    on_affected_path: bool
    related_evidence_ids: list[str]
    strength: CorrelationStrength
    alternative_explanations: list[str]
    notice: str = CAUSATION_NOTICE


class ChangeAnalysis(AdvancedModel):
    available: bool
    window_minutes: int
    correlations: list[ChangeCorrelation]
    message: str


class HistoricalComparison(AdvancedModel):
    available: bool
    message: str
    similar: list[SimilarIncident]
    recurring_site_domains: list[str]
    resolution_notes: dict[str, str]
    notice: str = CAUSATION_NOTICE


class Anomaly(AdvancedModel):
    category: Literal["interface_errors", "packet_loss", "utilization", "availability", "routing_adjacency", "dns", "dhcp"]
    asset_id: str
    observed: str
    baseline: str
    rule: str
    timestamp: datetime | None
    evidence_reference: str


class AnomalyReport(AdvancedModel):
    anomalies: list[Anomaly]
    assets_examined: int
    insufficient_baseline: list[str]
    method: Literal["thresholds_and_first_sample_baseline"] = "thresholds_and_first_sample_baseline"


class GuidanceReference(AdvancedModel):
    record_id: str
    title: str
    match_type: str
    reasons: list[str]


class AdvancedDiagnosis(AdvancedModel):
    incident_id: Identifier | None
    base: Diagnosis
    primary_fault: RootCauseCandidate | None
    root_cause_candidates: list[RootCauseCandidate]
    cross_layer: CrossLayerAnalysis
    paths: list[PathAnalysis]
    blast_radius: BlastRadius
    changes: ChangeAnalysis
    history: HistoricalComparison
    anomalies: AnomalyReport
    playbooks: list[GuidanceReference]
    missing_evidence: list[str]
    next_checks: list[NextCheck]
    supplementary_tool_calls: list[str]
    narrative: list[str]
    validation_issues: list[str]
    human_verification_required: Literal[True] = True
