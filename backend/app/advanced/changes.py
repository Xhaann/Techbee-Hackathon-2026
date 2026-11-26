from datetime import datetime, timedelta

from app.advanced.schema import ChangeAnalysis, ChangeCorrelation, ChangeRecord, CorrelationStrength, EvidenceRole
from app.engine.schema import Diagnosis, EvidenceItem
from app.network.repository import load_scenario

CHANGE_EVENT_TYPES = {"CONFIG_CHANGE", "MTU_CHANGE", "POLICY_CHANGE", "ZONE_RELOAD"}
LOOKBACK = timedelta(minutes=60)
LOOKAHEAD = timedelta(minutes=15)
STRONG_BEFORE = timedelta(minutes=15)
STRONG_AFTER = timedelta(seconds=60)
FAULT_ROLES = {EvidenceRole.PRIMARY_FAULT, EvidenceRole.SHARED_DEPENDENCY_FAILURE, EvidenceRole.SECONDARY_SYMPTOM}


class ChangeHistory:
    def __init__(self, scenario_id: str) -> None:
        dataset = load_scenario(scenario_id)
        events = [
            ChangeRecord(change_id=event.event_id, source="device_event_log", change_type=event.event_type, timestamp=event.timestamp,
                         device_id=event.device_id, description=event.message[:400])
            for event in dataset.events if event.event_type in CHANGE_EVENT_TYPES
        ]
        rules = [
            ChangeRecord(change_id=rule.rule_id, source="firewall_rule_history", change_type="FIREWALL_RULE_MODIFIED",
                         timestamp=rule.last_modified, device_id=rule.device_id,
                         description=f"Rule {rule.rule_id} ({rule.name}, {rule.action.value}) last modified")
            for rule in dataset.firewall.rules
        ]
        self.records = sorted(events + rules, key=lambda record: (record.timestamp, record.change_id))

    def between(self, start: datetime, end: datetime) -> list[ChangeRecord]:
        return [record for record in self.records if start <= record.timestamp <= end]


def correlate_changes(history: ChangeHistory | None, onset: datetime | None, diagnosis: Diagnosis, catalog: list[EvidenceItem],
                      roles: dict[str, EvidenceRole], path_devices: set[str]) -> ChangeAnalysis:
    window = int((LOOKBACK + LOOKAHEAD).total_seconds() // 60)
    if history is None:
        return ChangeAnalysis(available=False, window_minutes=window, correlations=[],
                              message="No change history source is available; change correlation was not performed")
    if onset is None:
        return ChangeAnalysis(available=True, window_minutes=window, correlations=[],
                              message="No fault onset was established, so changes could not be aligned with the incident")
    scope = path_devices | set(diagnosis.fault.device_ids)
    alternatives = [f"{a.fault_domain.value}: {a.hypothesis}" for a in diagnosis.alternatives][:3]
    alternatives.append("The change may be coincidental to an independent fault")
    correlations = []
    for change in history.between(onset - LOOKBACK, onset + LOOKAHEAD):
        delta = change.timestamp - onset
        on_path = change.device_id in scope
        related = sorted(
            {item.evidence_id for item in catalog
             if roles.get(item.evidence_id) in FAULT_ROLES
             and (item.device_id == change.device_id or any(ref.record_id == change.change_id for ref in item.references))},
            key=lambda value: int(value[1:]),
        )
        if on_path and related and -STRONG_BEFORE <= delta <= STRONG_AFTER:
            strength = CorrelationStrength.STRONG
        elif on_path:
            strength = CorrelationStrength.MODERATE
        else:
            strength = CorrelationStrength.WEAK
        correlations.append(ChangeCorrelation(change=change, seconds_from_onset=int(delta.total_seconds()), on_affected_path=on_path,
                                              related_evidence_ids=related, strength=strength, alternative_explanations=alternatives))
    order = {CorrelationStrength.STRONG: 0, CorrelationStrength.MODERATE: 1, CorrelationStrength.WEAK: 2}
    correlations.sort(key=lambda c: (order[c.strength], abs(c.seconds_from_onset), c.change.change_id))
    message = (f"{len(correlations)} change records within {window} minutes of the onset" if correlations
               else "No change records fall within the correlation window")
    return ChangeAnalysis(available=True, window_minutes=window, correlations=correlations, message=message)
