"""The reasoning report: multi-hypothesis view, calibrated probabilities, contradictions, causal graph, specialist
reviews, investigation plan, self-evaluation and a plain-language explanation, all derived from one evidence set."""
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.engine.schema import EvidenceItem, FaultDomain
from app.reasoning.causal import build_graph, cross_layer, localise, precedence
from app.reasoning.evidence_model import LABEL
from app.reasoning.inference import (
    calibrate,
    confidence_label,
    contradictions,
    observed,
    percent,
    posterior,
    same_answer,
    uncertainty,
)
from app.reasoning.specialists import AGENTS, PlannedCheck, Scope, priority, review_all

LEVELS = ["low", "medium", "high"]
MIN_FAULT_WEIGHT = 1.5
SUSPICIOUS_PREFIX = "[Suspicious (not confirmed)]"  # how the protocol tool marks suspicious indicators (app/diagnostics/protocols.py)
RELATED_WINDOW = timedelta(hours=6)


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HypothesisView(Model):
    domain: FaultDomain
    label: str
    probability: float
    status: Literal["leading", "plausible", "unlikely", "rejected"]
    supporting_evidence_ids: list[str]
    contradicting_evidence_ids: list[str]
    owner: str
    test: str | None = None


class EvidenceWeight(Model):
    evidence_id: str
    code: str
    weight: float
    reasons: list[str]


class ContradictionView(Model):
    kind: str
    domain: FaultDomain | None
    evidence_ids: list[str]
    statement: str
    severity: str


class CausalView(Model):
    roots: list[dict[str, Any]]
    chain: list[dict[str, Any]]
    coverage: float
    unexplained: list[str]
    edges: list[dict[str, Any]]
    nodes: list[dict[str, Any]]
    clusters: list[dict[str, Any]]
    precedence: list[dict[str, Any]]
    localisation: dict[str, Any]


class SpecialistView(Model):
    agent: str
    title: str
    domains: list[str]
    verdict: Literal["implicated", "possible", "cleared", "inconclusive"]
    probability: float
    statement: str
    evidence_ids: list[str]
    checks_run: int
    recommended_commands: list[dict[str, Any]]
    missing: list[str]


class PlanStep(Model):
    agent: str
    tool: str
    arguments: dict[str, Any]
    reason: str
    tests: list[str]
    value: float
    purpose: str


class SelfCheck(Model):
    name: str
    passed: bool
    severity: Literal["hard", "soft"]
    detail: str


class SelfEvaluation(Model):
    verdict: Literal["sound", "review", "weak", "no_fault"]
    checks: list[SelfCheck]
    calibrated_confidence: Literal["low", "medium", "high"]
    adjustments: list[str]


class ExplanationView(Model):
    summary: str
    why: list[str]
    alternatives: list[str]
    uncertainty: str
    next_step: str | None


class RelatedIncident(Model):
    incident_id: str
    title: str
    relation: str
    score: float


class ReasoningReport(Model):
    generated_at: datetime
    method: Literal["deterministic_reasoning"] = "deterministic_reasoning"
    evidence_count: int
    fault_supported: bool
    leading: FaultDomain | None
    hypotheses: list[HypothesisView]
    uncertainty: dict[str, Any]
    contradictions: list[ContradictionView]
    causal: CausalView
    cross_layer: dict[str, Any]
    specialists: list[SpecialistView]
    plan: list[PlanStep]
    self_evaluation: SelfEvaluation
    explanation: ExplanationView
    related_incidents: list[RelatedIncident] = Field(default_factory=list)
    calibration: list[EvidenceWeight]
    # Suspicious indicators that could explain the symptoms but are not confirmed (only when no fault is supported).
    suspected: list[str] = Field(default_factory=list)

    def compact(self) -> dict[str, Any]:
        """A few hundred tokens for a model or a reply: no raw evidence, only the conclusions and their ids."""
        return {
            "fault_supported": self.fault_supported,
            "hypotheses": [{"domain": h.domain.value, "probability": h.probability, "status": h.status} for h in self.hypotheses[:3]],
            "uncertainty": self.uncertainty["level"], "contradictions": [c.statement for c in self.contradictions[:2]],
            "causal_chain": [f"{c['evidence_id']} {c['code']}" for c in self.causal.chain[:5]],
            "self_evaluation": self.self_evaluation.verdict, "calibrated_confidence": self.self_evaluation.calibrated_confidence,
            "next_check": self.plan[0].purpose if self.plan else None,
            "specialists": {s.agent: s.verdict for s in self.specialists},
            "suspected_not_confirmed": self.suspected[:2],
        }


def owner_of(domain: FaultDomain) -> str:
    return next((name for name, agent in AGENTS.items() if domain in agent.domains), "transport")


def plan_next(scope: Scope, probabilities: dict[FaultDomain, float], done: set[tuple], limit: int = 3) -> list[PlanStep]:
    """Automatic investigation planning: the checks not yet run whose outcome would move the probabilities most. A check
    that tests domains holding about half the probability mass separates the leading hypothesis from the rest best."""
    leading = max(probabilities, key=probabilities.get)
    steps: list[PlanStep] = []
    seen: set[tuple] = set()
    for name in priority(scope):
        for check in AGENTS[name].plan(scope):
            if check.key in done or check.key in seen:
                continue
            seen.add(check.key)
            mass = sum(probabilities.get(d, 0.0) for d in check.tests)
            value = 4 * mass * (1 - mass) + (0.25 if leading in check.tests else 0.0)
            others = [d for d in check.tests if d != leading]
            purpose = (f"Confirm {LABEL[leading]}: {check.reason}" if leading in check.tests and not others
                       else f"Separate {LABEL[leading]} from {LABEL[others[0]]}: {check.reason}" if leading in check.tests
                       else f"Rule out {LABEL[check.tests[0]]}: {check.reason}")
            steps.append(PlanStep(agent=check.agent, tool=check.tool, arguments=check.arguments, reason=check.reason,
                                  tests=[d.value for d in check.tests], value=round(value, 3), purpose=purpose))
    return sorted(steps, key=lambda s: -s.value)[:limit]


def correlate_incidents(current: dict[str, Any] | None, others: list[dict[str, Any]]) -> list[RelatedIncident]:
    """Temporal incident correlation over the incidents this user may see: overlapping sites or a shared upstream device,
    opened within six hours of each other."""
    if not current:
        return []
    related: list[RelatedIncident] = []
    created = current.get("created_at")
    for other in others:
        if other["incident_id"] == current["incident_id"] or other.get("created_at") is None or created is None:
            continue
        gap = abs(other["created_at"] - created)
        if gap > RELATED_WINDOW:
            continue
        shared_sites = sorted(set(current.get("site_ids", [])) & set(other.get("site_ids", [])))
        upstream = localise(sorted(set(current.get("site_ids", [])) | set(other.get("site_ids", []))), [])["common_devices"] \
            if set(current.get("site_ids", [])) != set(other.get("site_ids", [])) else []
        shared_devices = sorted(set(current.get("devices", [])) & set(other.get("devices", [])))
        if not (shared_sites or shared_devices or upstream):
            continue
        minutes = int(gap.total_seconds() // 60)
        reason = (f"same site{'s' if len(shared_sites) > 1 else ''} ({', '.join(shared_sites)})" if shared_sites
                  else f"same suspected device ({', '.join(shared_devices)})" if shared_devices
                  else f"both depend on {', '.join(upstream[:2])}")
        score = (0.5 if shared_sites else 0) + (0.4 if shared_devices else 0) + (0.3 if upstream else 0) + max(0.0, 0.3 - minutes / 1200)
        related.append(RelatedIncident(incident_id=other["incident_id"], title=other.get("title", "")[:120],
                                       relation=f"{reason}, opened {minutes} min apart", score=round(min(score, 1.0), 2)))
    return sorted(related, key=lambda r: -r.score)[:5]


def analyze(evidence: list[EvidenceItem], scope: Scope, onset: datetime | None, ran: list[PlannedCheck],
            conclusion: dict[str, Any] | None = None, flagged: set[str] = frozenset(),
            current_incident: dict[str, Any] | None = None, other_incidents: list[dict[str, Any]] | None = None) -> ReasoningReport:
    calibrated = calibrate(evidence, onset, flagged)
    result = posterior(calibrated)
    ranked = result.ranked()
    doubt = uncertainty(result)
    leading, lead_p = ranked[0]
    strength = {d: sum(delta for _, delta in result.contributions.get(d, []) if delta > 0) for d in FaultDomain}
    fault_supported = max(strength.values()) >= MIN_FAULT_WEIGHT and lead_p >= 0.35 and leading != FaultDomain.UNKNOWN
    concluded = FaultDomain(conclusion["fault_domain"]) if conclusion and conclusion.get("fault_domain") not in (None, "unknown") else None
    found = contradictions(evidence, concluded or (leading if fault_supported else None), (conclusion or {}).get("device_ids", []),
                           list(scope.site_ids), list(scope.site_ids))
    graph = build_graph(evidence, onset)
    by_id = {item.evidence_id: item for item in evidence}
    reviews = review_all(evidence, result, scope, ran, fault_supported)

    hypotheses: list[HypothesisView] = []
    for domain, probability in ranked[:5]:
        if domain == FaultDomain.UNKNOWN:
            continue
        support = [eid for eid, delta in sorted(result.contributions.get(domain, []), key=lambda x: -x[1]) if delta > 0][:5]
        against = [eid for eid, delta in result.contributions.get(domain, []) if delta < 0][:4]
        against += [eid for c in found if c.domain == domain for eid in c.evidence_ids if eid not in against]
        status = ("leading" if domain == leading and fault_supported else "plausible" if probability >= 0.15
                  else "rejected" if against and probability < 0.05 else "unlikely")
        owner = owner_of(domain)
        test = next((c.reason for c in AGENTS[owner].plan(scope) if domain in c.tests and c.key not in {r.key for r in ran}), None)
        hypotheses.append(HypothesisView(domain=domain, label=LABEL[domain], probability=probability, status=status,
                                         supporting_evidence_ids=support, contradicting_evidence_ids=against[:4], owner=owner, test=test))

    done = {check.key for check in ran}
    plan = plan_next(scope, result.probabilities, done) if fault_supported or result.evidence_used == 0 or doubt.level != "low" else []

    # Self-evaluation: does the conclusion stand up to its own evidence?
    checks: list[SelfCheck] = []
    supporting = [by_id[e] for e in (conclusion or {}).get("supporting_evidence_ids", []) if e in by_id]
    if conclusion is not None:
        missing = [e for e in conclusion.get("supporting_evidence_ids", []) if e not in by_id]
        checks.append(SelfCheck(name="grounded", passed=not missing, severity="hard",
                                detail="every cited evidence id resolves to collected evidence" if not missing
                                else f"cites evidence that was not collected: {', '.join(missing[:4])}"))
    target = concluded or leading
    lead_support = supporting or [by_id[e] for e in next((h.supporting_evidence_ids for h in hypotheses if h.domain == target), []) if e in by_id]
    sufficient = len(lead_support) >= 2 and any(observed(i) for i in lead_support)
    checks.append(SelfCheck(name="sufficient_evidence", passed=sufficient, severity="soft",
                            detail=f"{len(lead_support)} supporting items, {sum(observed(i) for i in lead_support)} directly observed"))
    if concluded is not None:
        agree = same_answer(concluded, leading)
        checks.append(SelfCheck(name="agrees_with_probabilities", passed=agree, severity="hard",
                                detail=f"the probabilities also favour {LABEL[leading]} ({percent(lead_p)})" if agree
                                else f"the probabilities favour {LABEL[leading]} ({percent(lead_p)}) over {LABEL[concluded]} "
                                     f"({percent(result.probabilities.get(concluded, 0))})"))
    strong = [c for c in found if c.severity == "strong" and c.domain in (target, None)]
    checks.append(SelfCheck(name="no_strong_contradiction", passed=not strong, severity="hard",
                            detail="no evidence strongly contradicts it" if not strong else strong[0].statement))
    checks.append(SelfCheck(name="explains_symptoms", passed=graph.coverage >= 0.6, severity="soft",
                            detail=f"the causal graph explains {graph.coverage:.0%} of the service symptoms"
                            + (f"; unexplained: {', '.join(graph.unexplained[:4])}" if graph.unexplained else "")))
    if graph.roots and onset is not None and graph.roots[0]["timestamp"]:
        first = datetime.fromisoformat(graph.roots[0]["timestamp"])
        on_time = first <= onset + timedelta(minutes=5)
        checks.append(SelfCheck(name="cause_precedes_symptoms", passed=on_time, severity="soft",
                                detail=f"the first root-cause evidence ({graph.roots[0]['evidence_id']}) is "
                                       f"{abs(int((first - onset).total_seconds()))} s {'before' if first <= onset else 'after'} the onset"))
    checks.append(SelfCheck(name="uncertainty_acceptable", passed=doubt.level != "high", severity="soft", detail=doubt.statement))
    if not fault_supported:
        verdict = "no_fault"
    elif any(not c.passed and c.severity == "hard" for c in checks):
        verdict = "weak"
    elif any(not c.passed for c in checks):
        verdict = "review"
    else:
        verdict = "sound"
    group_p = sum(p for d, p in result.probabilities.items() if same_answer(d, target)) if target else 0.0
    label = confidence_label(group_p)
    adjustments = []
    if conclusion and conclusion.get("confidence") in LEVELS and LEVELS.index(conclusion["confidence"]) < LEVELS.index(label):
        adjustments.append(f"kept at the diagnosis engine's {conclusion['confidence']} confidence")
        label = conclusion["confidence"]
    if verdict == "weak" and label != "low":
        adjustments.append(f"lowered from {label} because a hard self-check failed")
        label = "low"
    elif verdict in ("review", "no_fault") and label == "high":
        adjustments.append("lowered from high because a self-check needs review")
        label = "medium"

    # Explanation
    chain = [by_id[e] for e in graph.chain if e in by_id]
    why = []
    if chain:
        why.append(" → ".join(f"{i.evidence_id} {i.code.lower().replace('_', ' ')}" + (f" ({i.device_id})" if i.device_id else "")
                              for i in chain))
    for eid in next((h.supporting_evidence_ids for h in hypotheses if h.domain == target), [])[:3]:
        if eid in by_id:
            why.append(f"{eid}: {by_id[eid].summary}")
    alternatives = []
    for h in hypotheses:
        if h.domain == target or len(alternatives) >= 2:
            continue
        reason = (f"contradicted by {', '.join(h.contradicting_evidence_ids[:2])}" if h.contradicting_evidence_ids
                  else "much less evidence" if h.probability < 0.05 else "some evidence, but less than the leading explanation")
        alternatives.append(f"{h.label} ({percent(h.probability)}): {reason}")
    if fault_supported:
        statement = (conclusion or {}).get("root_cause") or (lead_support[0].summary if lead_support else LABEL[leading])
        summary = f"Most likely {LABEL[target]} ({percent(group_p)}): {statement}"
    suspected: list[str] = []
    if not fault_supported:
        summary = "No fault domain is supported by the evidence collected so far."
        # A suspicious indicator is not enough to support a fault domain, but it must not disappear from the conclusion
        # either: name it as an unconfirmed candidate (security correlation clusters are summaries of these, not new ones).
        suspects = [item for item in evidence if item.tool == "analyze_protocol" and item.summary.startswith(SUSPICIOUS_PREFIX)
                    and item.code != "THREAT_CORRELATED_ACTIVITY"]
        if suspects:
            suspected = list(dict.fromkeys(item.summary[len(SUSPICIOUS_PREFIX):].split(": ", 1)[0].strip() for item in suspects))
            summary = (f"No fault domain is confirmed yet. Suspected, not confirmed: {suspected[0]} ({suspects[0].evidence_id}). It could "
                       "explain the symptoms; verify it before treating it as the cause or as an attack.")
            why = [f"{item.evidence_id}: {item.summary}" for item in suspects[:2]] + why
    explanation = ExplanationView(summary=summary, why=why[:5], alternatives=alternatives, uncertainty=doubt.statement,
                                  next_step=plan[0].purpose if plan else None)
    edges = [{"cause": e.cause, "effect": e.effect, "mechanism": e.mechanism, "reason": e.reason, "lag_seconds": e.lag_seconds,
              "weight": e.weight} for e in sorted(graph.edges, key=lambda e: (-e.weight, e.cause))[:40]]
    causal = CausalView(roots=graph.roots[:5], chain=[{"evidence_id": i.evidence_id, "code": i.code, "device_id": i.device_id,
                                                         "summary": i.summary} for i in chain],
                        coverage=graph.coverage, unexplained=graph.unexplained[:10], edges=edges, nodes=graph.nodes[:60],
                        clusters=graph.clusters[:10], precedence=precedence(evidence, onset)[:6],
                        localisation=localise(list(scope.site_ids), list(scope.unaffected_site_ids)))
    weights = sorted(calibrated, key=lambda c: -c.weight)
    return ReasoningReport(
        generated_at=datetime.now(timezone.utc), evidence_count=len(evidence), fault_supported=fault_supported,
        leading=leading if fault_supported else None, hypotheses=hypotheses, suspected=suspected,
        uncertainty={"level": doubt.level, "entropy": doubt.entropy, "margin": doubt.margin,
                     "effective_hypotheses": doubt.effective_hypotheses, "statement": doubt.statement},
        contradictions=[ContradictionView(kind=c.kind, domain=c.domain, evidence_ids=list(c.evidence_ids), statement=c.statement,
                                          severity=c.severity) for c in found],
        causal=causal, cross_layer=cross_layer(evidence, target if fault_supported else None),
        specialists=[SpecialistView(**{**r.__dict__}) for r in reviews], plan=plan,
        self_evaluation=SelfEvaluation(verdict=verdict, checks=checks, calibrated_confidence=label, adjustments=adjustments),
        explanation=explanation, related_incidents=correlate_incidents(current_incident, other_incidents or []),
        calibration=[EvidenceWeight(evidence_id=c.evidence_id, code=c.code, weight=c.weight, reasons=list(c.reasons))
                     for c in weights[:12]],
    )
