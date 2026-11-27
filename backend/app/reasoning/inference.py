"""Evidence calibration, Bayesian fault probabilities, uncertainty and contradiction detection."""
import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.engine.schema import EvidenceItem, EvidenceType, FaultDomain
from app.reasoning.evidence_model import DOMAINS, EQUIVALENT, GENERIC, LABEL, PRIORS, TYPE_WEIGHT, likelihood

ONSET_GRACE = timedelta(minutes=2)
CONFIDENCE_BANDS = ((0.85, "high"), (0.6, "medium"), (0.0, "low"))


@dataclass(frozen=True)
class CalibratedEvidence:
    evidence_id: str
    code: str
    device_id: str | None
    weight: float
    reasons: tuple[str, ...]
    domains: dict[FaultDomain, float]


def calibrate(evidence: list[EvidenceItem], onset: datetime | None, flagged: set[str] = frozenset()) -> list[CalibratedEvidence]:
    """A reliability weight per item: kind of evidence, corroboration by another tool, timing against the onset, and any
    security flag (text that tried to instruct the assistant counts for nothing)."""
    by_code_tools: dict[str, set[str]] = defaultdict(set)
    for item in evidence:
        by_code_tools[item.code].add(item.tool)
    context_codes = set(by_code_tools)
    calibrated = []
    for item in evidence:
        reasons = [f"{item.evidence_type.value.replace('_', ' ')} (x{TYPE_WEIGHT[item.evidence_type]:g})"]
        weight = TYPE_WEIGHT[item.evidence_type]
        if len(by_code_tools[item.code]) > 1:
            weight *= 1.15
            reasons.append("corroborated by another tool (x1.15)")
        if onset is not None and item.timestamp is not None and item.timestamp < onset - ONSET_GRACE:
            weight *= 0.5
            reasons.append("recorded before the reported onset (x0.5)")
        if item.evidence_id in flagged:
            weight = 0.0
            reasons.append("contains text that tried to instruct the assistant (ignored)")
        if item.code in UP and context_codes & (RECOVERY | DEGRADATION):
            weight = 0.0
            reasons.append("a reachable path is expected after the recorded recovery or with a degraded (not failed) link")
        calibrated.append(CalibratedEvidence(item.evidence_id, item.code, item.device_id, round(min(weight, 1.2), 3), tuple(reasons),
                                             likelihood(item)))
    return calibrated


@dataclass(frozen=True)
class Posterior:
    probabilities: dict[FaultDomain, float]
    contributions: dict[FaultDomain, list[tuple[str, float]]]
    evidence_used: int

    def ranked(self) -> list[tuple[FaultDomain, float]]:
        return sorted(self.probabilities.items(), key=lambda item: -item[1])

    @property
    def top(self) -> tuple[FaultDomain, float]:
        return self.ranked()[0]


def posterior(calibrated: list[CalibratedEvidence]) -> Posterior:
    """log P(d | e) = log P(d) + sum of weighted log-likelihood ratios, then normalised.

    Repeated findings of the same code add with diminishing weight (1, 1/2, 1/3, ...) so that ten copies of one
    symptom do not outvote two independent measurements."""
    scores = {d: math.log(PRIORS[d]) for d in DOMAINS}
    contributions: dict[FaultDomain, list[tuple[str, float]]] = defaultdict(list)
    seen: dict[tuple[str, FaultDomain], int] = defaultdict(int)
    used = 0
    for item in calibrated:
        if not item.domains or item.weight == 0:
            continue
        used += 1
        for domain, ratio in item.domains.items():
            seen[(item.code, domain)] += 1
            delta = item.weight * ratio / seen[(item.code, domain)]
            scores[domain] += delta
            contributions[domain].append((item.evidence_id, round(delta, 3)))
    peak = max(scores.values())
    exp = {d: math.exp(s - peak) for d, s in scores.items()}
    total = sum(exp.values())
    return Posterior({d: round(v / total, 4) for d, v in exp.items()}, dict(contributions), used)


def percent(probability: float) -> str:
    """A probability for people: never "100%" (the model is never certain), never "0%" for something still possible."""
    if probability >= 0.995:
        return "99%+"
    if 0 < probability < 0.005:
        return "<1%"
    return f"{probability:.0%}"


def same_answer(a: FaultDomain, b: FaultDomain) -> bool:
    return a == b or any(a in group and b in group for group in EQUIVALENT)


def confidence_label(probability: float) -> str:
    return next(label for floor, label in CONFIDENCE_BANDS if probability >= floor)


@dataclass(frozen=True)
class Uncertainty:
    entropy: float
    margin: float
    effective_hypotheses: float
    level: str
    statement: str


def uncertainty(result: Posterior) -> Uncertainty:
    """Normalised entropy of the posterior, the margin between the two leading domains and the effective number of
    hypotheses still in play (exp of the entropy)."""
    probs = [p for p in result.probabilities.values() if p > 0]
    entropy = -sum(p * math.log(p) for p in probs) / math.log(len(DOMAINS))
    ranked = result.ranked()
    margin = ranked[0][1] - ranked[1][1]
    effective = math.exp(-sum(p * math.log(p) for p in probs))
    if result.evidence_used == 0:
        level, statement = "high", "No collected evidence bears on any fault domain yet."
    elif margin >= 0.6 and entropy < 0.25:
        level = "low"
        statement = f"The evidence clearly favours {LABEL[ranked[0][0]]} over {LABEL[ranked[1][0]]}."
    elif margin >= 0.25:
        level = "moderate"
        statement = f"{LABEL[ranked[0][0]]} leads, but {LABEL[ranked[1][0]]} is still possible ({percent(ranked[1][1])})."
    else:
        level = "high"
        statement = f"{LABEL[ranked[0][0]]} and {LABEL[ranked[1][0]]} are close ({percent(ranked[0][1])} vs {percent(ranked[1][1])})."
    return Uncertainty(round(entropy, 3), round(margin, 3), round(effective, 2), level, statement)


@dataclass(frozen=True)
class Contradiction:
    kind: str
    domain: FaultDomain | None
    evidence_ids: tuple[str, ...]
    statement: str
    severity: str


REFUTES = {
    FaultDomain.FIREWALL: {"PATH_UNREACHABLE": "the path is broken at layer 3 before any firewall policy applies"},
    FaultDomain.DNS: {"PATH_UNREACHABLE": "the site cannot reach the DNS servers at all, so a DNS server fault cannot be told apart"},
    FaultDomain.ROUTING: {"PATH_REACHABLE": "the layer-3 path to the service is reachable",
                          "ADJACENCY_LOSS_FOLLOWS_INTERFACE_DOWN": "the routing session dropped only after its interface went down"},
    FaultDomain.WAN_ISP: {"PATH_REACHABLE": "the layer-3 path across the WAN is reachable"},
    FaultDomain.SHARED_INFRASTRUCTURE: {"PATH_REACHABLE": "the path through the shared devices is reachable"},
    FaultDomain.NETWORK_DEVICE_FAILURE: {"DEVICE_AVAILABLE_WITH_FAULTS": "the device still answers and reports telemetry"},
}
DOWN = {"LINK_DOWN", "CARRIER_LOSS", "PATH_LINK_DOWN", "PATH_SEGMENT_DOWN", "INTERFACES_DOWN"}
UP = {"PATH_REACHABLE"}
RECOVERY = {"LINK_FLAP_RECOVERED", "PROBE_FLAP_RECOVERED", "ROUTES_WITHDRAWN_AND_RESTORED", "ADJACENCY_FLAP_RECOVERED"}
DEGRADATION = {"PATH_SEGMENT_DEGRADED", "PHYSICAL_LAYER_DEGRADATION_SUSPECTED", "PACKET_LOSS_MEASURED", "HIGH_ERROR_COUNT"}


def contradictions(evidence: list[EvidenceItem], conclusion: FaultDomain | None, conclusion_devices: list[str],
                   reported_sites: list[str], affected_sites: list[str]) -> list[Contradiction]:
    found: list[Contradiction] = []
    codes = defaultdict(list)
    for item in evidence:
        codes[item.code].append(item)
    explained = set(codes) & (RECOVERY | DEGRADATION)
    if conclusion is not None:
        for code, reason in REFUTES.get(conclusion, {}).items():
            items = codes.get(code, []) if not (code in UP and explained) else []
            if items:
                found.append(Contradiction("refutes_conclusion", conclusion, tuple(i.evidence_id for i in items[:4]),
                                           f"Against {LABEL[conclusion]}: {reason}.", "strong" if len(items) > 1 else "moderate"))
    # The same device reported both down and healthy, with no recovery event to explain the change.
    downs = {i.device_id: i for code in DOWN for i in codes.get(code, []) if i.device_id}
    ups = {i.device_id: i for code in UP for i in codes.get(code, []) if i.device_id}
    recovered = {i.device_id for code in RECOVERY for i in codes.get(code, [])}
    for device in sorted(set(downs) & set(ups) - recovered):
        found.append(Contradiction("conflicting_telemetry", None, (downs[device].evidence_id, ups[device].evidence_id),
                                   f"{device} is reported down in {downs[device].evidence_id} but reachable in {ups[device].evidence_id}, "
                                   "with no recovery recorded between them.", "moderate"))
    # The report and the evidence disagree about where the problem is.
    extra = sorted(set(affected_sites) - set(reported_sites)) if reported_sites else []
    if extra and reported_sites:
        found.append(Contradiction("scope_mismatch", None, (), f"The evidence also implicates {', '.join(extra)}, which the report did "
                                   "not mention; the impact may be wider than reported.", "low"))
    if conclusion is not None and conclusion_devices:
        stray = [i for i in evidence if i.code in DOWN and i.device_id and i.device_id not in conclusion_devices
                 and i.timestamp is not None and conclusion not in (FaultDomain.SHARED_INFRASTRUCTURE,)]
        if stray and conclusion not in (FaultDomain.WAN_ISP, FaultDomain.INTERFACE_LINK):
            found.append(Contradiction("unexplained_outage", conclusion, tuple(i.evidence_id for i in stray[:3]),
                                       f"Link outages on {', '.join(sorted({i.device_id for i in stray}))} are not explained by a "
                                       f"{LABEL[conclusion]} fault.", "moderate"))
    return found


def generic(code: str) -> bool:
    return code in GENERIC


def observed(item: EvidenceItem) -> bool:
    return item.evidence_type in (EvidenceType.OBSERVED_FINDING, EvidenceType.OBSERVED_RESULT)
