import re
from datetime import timedelta
from enum import Enum

from pydantic import BaseModel, ConfigDict

from app.incidents.models import AssetType, Incident, VerificationStatus

STOPWORDS = {
    "about", "after", "again", "also", "because", "been", "being", "cannot", "could", "does", "from", "have", "into",
    "more", "most", "only", "other", "report", "reports", "reported", "since", "some", "than", "that", "their", "them",
    "then", "there", "they", "this", "users", "user", "were", "what", "when", "which", "while", "with", "work", "working",
}
WEIGHTS = {
    "fault_domain": 3.0, "sites": 2.0, "devices": 2.0, "links": 2.0, "path": 1.0, "services": 1.0, "keywords": 2.0,
    "evidence_types": 1.0, "time_window": 1.0,
}
MAX_POINTS = sum(WEIGHTS.values())
DEFAULT_WINDOW = timedelta(hours=4)
CAUTION = "Similarity reflects shared attributes only; it does not establish a common root cause."


class MatchStrength(str, Enum):
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"


class SimilarIncident(BaseModel):
    model_config = ConfigDict(frozen=True)

    incident_id: str
    strength: MatchStrength
    points: float
    max_points: float
    matching: dict[str, list[str]]
    differences: dict[str, list[str]]
    historical_resolution: str | None
    caution: str = CAUTION


def keywords(incident: Incident) -> set[str]:
    text = " ".join([incident.title, incident.description, *incident.symptoms]).lower()
    return {word for word in re.findall(r"[a-z0-9][a-z0-9.\-]{3,}", text) if word not in STOPWORDS}


def assets_of(incident: Incident, *types: AssetType) -> set[str]:
    return {asset.asset_id for asset in incident.affected_assets if asset.asset_type in types}


def features(incident: Incident) -> dict[str, set[str]]:
    return {
        "fault_domain": {incident.fault_domain.value} if incident.fault_domain else set(),
        "sites": set(incident.site_ids),
        "devices": assets_of(incident, AssetType.DEVICE, AssetType.SHARED_DEPENDENCY),
        "links": assets_of(incident, AssetType.LINK),
        "path": set(incident.affected_path) | assets_of(incident, AssetType.PATH),
        "services": assets_of(incident, AssetType.SERVICE),
        "keywords": keywords(incident),
        "evidence_types": {link.code for link in incident.evidence},
    }


def jaccard(left: set[str], right: set[str]) -> float:
    return len(left & right) / len(left | right) if left | right else 0.0


def compare(subject: Incident, other: Incident, window: timedelta = DEFAULT_WINDOW) -> SimilarIncident:
    left, right = features(subject), features(other)
    matching: dict[str, list[str]] = {}
    differences: dict[str, list[str]] = {}
    points = 0.0
    for name, weight in WEIGHTS.items():
        if name == "time_window":
            gap = abs(subject.created_at - other.created_at)
            if gap <= window:
                points += weight
                matching[name] = [f"created {int(gap.total_seconds() // 60)} minutes apart"]
            else:
                differences[name] = [f"created {gap.days} days {gap.seconds // 3600} hours apart"]
            continue
        shared, distinct = left[name] & right[name], left[name] ^ right[name]
        points += weight * jaccard(left[name], right[name])
        if shared:
            matching[name] = sorted(shared)[:20]
        if distinct:
            differences[name] = sorted(distinct)[:20]
    resolution = other.current_resolution
    history = resolution.summary if resolution and resolution.verification == VerificationStatus.VERIFIED else None
    ratio = points / MAX_POINTS
    strength = MatchStrength.STRONG if ratio >= 0.6 else MatchStrength.MODERATE if ratio >= 0.35 else MatchStrength.WEAK
    return SimilarIncident(incident_id=other.incident_id, strength=strength, points=round(points, 2), max_points=MAX_POINTS,
                           matching=matching, differences=differences, historical_resolution=history)


def duplicate_reason(subject: Incident, other: Incident, match: SimilarIncident) -> str | None:
    if "sites" not in match.matching or "time_window" not in match.matching:
        return None
    overlap = jaccard(keywords(subject), keywords(other))
    corroborating = sorted(key for key in ("devices", "links", "path", "services") if key in match.matching)
    if overlap >= 0.75 or (overlap >= 0.5 and corroborating):
        extra = f" and shared {', '.join(corroborating)}" if corroborating else ""
        return (f"Same site ({', '.join(match.matching['sites'])}) within the time window, "
                f"{overlap:.2f} symptom keyword overlap{extra}")
    return None
