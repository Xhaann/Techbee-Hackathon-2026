import re
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.engine.retrieval import RetrievedDocument
from app.engine.safety import injection_flags
from app.engine.schema import FaultDomain
from app.knowledge.models import AnyRecord, RecordType, SourceReference
from app.knowledge.repository import KnowledgeRepository, applies, default_repository
from app.network.models import DeviceType, EventType, Identifier, PathService

TOKEN = re.compile(r"[a-z0-9][a-z0-9.\-]{2,}")
STOPWORDS = {
    "the", "and", "for", "with", "from", "that", "this", "are", "was", "were", "has", "have", "not", "but", "all", "any",
    "can", "cannot", "users", "user", "report", "reports", "reported", "site", "sites", "office", "while", "when", "after",
    "into", "their", "they", "them", "one", "two", "only", "other", "same", "does", "show", "shows", "access",
    "work", "time", "unaffect", "normal", "still",
}
MIN_POINTS = 3
MAX_CODE_POINTS = 8
MAX_TERM_POINTS = 6
TYPE_ORDER = {RecordType.PLAYBOOK: 0, RecordType.RUNBOOK: 1, RecordType.PROCEDURE: 2, RecordType.DOCUMENT: 3}
GUIDANCE_NOTICE = "Guidance only: this knowledge does not establish a fault. Diagnostic evidence is authoritative."


class MatchType(str, Enum):
    EXACT = "exact"
    PARTIAL = "partial"


class KnowledgeQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str = Field(default="", max_length=4000)
    symptoms: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(default_factory=list, max_length=20)
    fault_domain: FaultDomain | None = None
    site_id: Identifier | None = None
    device_type: DeviceType | None = None
    service: PathService | None = None
    finding_codes: list[EventType] = Field(default_factory=list, max_length=60)
    record_types: list[RecordType] = Field(default_factory=list, max_length=4)
    limit: int = Field(default=5, ge=1, le=10)

    @model_validator(mode="after")
    def check_signal(self) -> "KnowledgeQuery":
        if not (self.text.strip() or self.symptoms or self.fault_domain or self.finding_codes or self.site_id):
            raise ValueError("a knowledge query requires text, symptoms, a fault domain, finding codes or a site")
        return self


class KnowledgeMatch(BaseModel):
    model_config = ConfigDict(frozen=True)

    record_id: str
    record_type: RecordType
    title: str
    version: str
    match_type: MatchType
    points: int
    reasons: list[str]
    matched_codes: list[str]
    matched_terms: list[str]
    sources: list[SourceReference]
    notice: str = GUIDANCE_NOTICE


class RetrievalResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    matches: list[KnowledgeMatch]
    no_match: bool
    message: str
    security_flags: list[str]


SUFFIXES = ("ingly", "edly", "ing", "ed", "ly", "es", "s")


def stem(word: str) -> str:
    for suffix in SUFFIXES:
        if suffix == "s" and word.endswith("ss"):
            continue
        if word.endswith(suffix) and len(word) - len(suffix) >= 4:
            return word[:-len(suffix)]
    return word


def terms(text: str) -> set[str]:
    return {stem(word.rstrip(".")) for word in TOKEN.findall(text.lower()) if word not in STOPWORDS}


def record_codes(record: AnyRecord) -> set[str]:
    codes = set(getattr(record, "indicator_codes", []))
    codes |= {code for requirement in getattr(record, "required_evidence", []) for code in requirement.codes}
    return codes


def render(record: AnyRecord) -> str:
    lines = [f"{record.title} ({record.record_id} v{record.version})", GUIDANCE_NOTICE]
    for label in ("description", "context", "content"):
        if getattr(record, label, None):
            lines.append(getattr(record, label))
    if getattr(record, "symptoms", None):
        lines.append("Symptoms: " + "; ".join(record.symptoms))
    for requirement in getattr(record, "required_evidence", []):
        lines.append(f"Evidence {requirement.requirement_id}: {requirement.description} via {requirement.tool.tool}")
    for step in getattr(record, "steps", []) + getattr(record, "procedures", []):
        commands = ", ".join(f"{c.text} [illustrative, read-only]" for c in step.commands)
        lines.append(f"Step {step.order}: {step.action}. Expect: {step.expected_observation}" + (f". Commands: {commands}" if commands else ""))
    for decision in getattr(record, "decisions", []):
        lines.append(f"If {decision.condition}: {decision.conclusion}")
    return "\n".join(lines)[:4000]


class KnowledgeRetriever:
    def __init__(self, repository: KnowledgeRepository | None = None) -> None:
        self.repository = repository or default_repository()

    def score(self, record: AnyRecord, query: KnowledgeQuery, query_terms: set[str]) -> KnowledgeMatch | None:
        scope = record.applicability
        if query.fault_domain and record.fault_domains and query.fault_domain not in record.fault_domains:
            return None
        if not (applies(scope.site_ids, query.site_id) and applies(scope.device_types, query.device_type)
                and applies(scope.services, query.service)):
            return None
        points, reasons = 0, []
        domain_match = bool(query.fault_domain and query.fault_domain in record.fault_domains)
        if domain_match:
            points += 5
            reasons.append(f"fault domain {query.fault_domain.value} matches")
        codes = sorted(record_codes(record) & set(query.finding_codes))
        if codes:
            points += min(2 * len(codes), MAX_CODE_POINTS)
            reasons.append(f"observed finding codes match expected indicators: {', '.join(codes)}")
        matched_terms = sorted(query_terms & terms(" ".join(record.texts())))
        if matched_terms:
            points += min(len(matched_terms), MAX_TERM_POINTS)
            reasons.append(f"symptom terms match: {', '.join(matched_terms[:10])}")
        site_specific = bool(query.site_id and query.site_id in scope.site_ids)
        if site_specific:
            points += 3
            reasons.append(f"applies specifically to site {query.site_id}")
        if query.device_type and query.device_type in scope.device_types:
            points += 1
            reasons.append(f"applies to {query.device_type.value} devices")
        if query.service and query.service in scope.services:
            points += 1
            reasons.append(f"applies to the {query.service.value} service")
        substantive = domain_match or codes or len(matched_terms) >= 2 or site_specific
        if points < MIN_POINTS or not substantive:
            return None
        exact = (domain_match and (codes or len(matched_terms) >= 2)) or (len(codes) >= 2 and len(matched_terms) >= 2)
        return KnowledgeMatch(
            record_id=record.record_id, record_type=record.record_type, title=record.title, version=record.version,
            match_type=MatchType.EXACT if exact else MatchType.PARTIAL, points=points, reasons=reasons,
            matched_codes=codes, matched_terms=matched_terms[:20], sources=self.repository.sources_for(record),
        )

    def search(self, query: KnowledgeQuery) -> RetrievalResult:
        query_terms = terms(" ".join([query.text, *query.symptoms]))
        candidates = [record for record in self.repository.list() if not query.record_types or record.record_type in query.record_types]
        matches = [match for record in candidates if (match := self.score(record, query, query_terms))]
        matches.sort(key=lambda m: (-m.points, m.match_type != MatchType.EXACT, TYPE_ORDER[m.record_type], m.record_id))
        matches = matches[:query.limit]
        flags = sorted({flag for m in matches for flag in injection_flags(f"knowledge record {m.record_id}",
                                                                           render(self.repository.get(m.record_id)))})
        message = (f"{len(matches)} knowledge records matched" if matches
                   else "No knowledge records are relevant to the query; no guidance is returned")
        return RetrievalResult(matches=matches, no_match=not matches, message=message, security_flags=flags)


class PlaybookRetriever:
    def __init__(self, retriever: KnowledgeRetriever | None = None) -> None:
        self.retriever = retriever or KnowledgeRetriever()

    def search(self, query: str, limit: int) -> list[RetrievedDocument]:
        if not isinstance(query, str) or not query.strip():
            return []
        result = self.retriever.search(KnowledgeQuery(text=query[:4000], limit=max(1, min(limit, 10))))
        documents = []
        for match in result.matches:
            record = self.retriever.repository.get(match.record_id)
            documents.append(RetrievedDocument(document_id=record.record_id, title=record.title[:200],
                                               source=", ".join(s.source_id for s in match.sources)[:200], content=render(record)))
        return documents
