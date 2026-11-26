from datetime import timedelta

from app.advanced.changes import ChangeHistory, correlate_changes
from app.advanced.layers import assign_roles
from app.advanced.schema import CAUSATION_NOTICE, CorrelationStrength
from app.engine.evidence import build_catalog
from verification.advanced_diagnosis.helpers import analysis


def test_related_changes_are_strong_but_not_causal() -> None:
    result = analysis("OSPF-ADJACENCY-FAILURE")
    top = result.changes.correlations[0]
    assert top.change.device_id == "BLR-RTR-01" and top.change.change_type in ("CONFIG_CHANGE", "MTU_CHANGE")
    assert top.strength == CorrelationStrength.STRONG and top.on_affected_path and top.related_evidence_ids
    assert top.notice == CAUSATION_NOTICE and "coincidental" in top.alternative_explanations[-1]
    assert abs(top.seconds_from_onset) <= 60


def test_firewall_rule_history_is_correlated() -> None:
    sources = {(c.change.source, c.change.change_id) for c in analysis("FIREWALL-BLOCKING").changes.correlations}
    assert ("firewall_rule_history", "FWR-DC1-0125") in sources and any(s == "device_event_log" for s, _ in sources)


def test_unrelated_and_missing_changes() -> None:
    for scenario in ("WAN-FAILURE", "PACKET-LOSS", "SHARED-DEVICE-FAILURE"):
        changes = analysis(scenario).changes
        assert changes.available and changes.correlations == [] and "No change records" in changes.message
    base = analysis("WAN-FAILURE").base
    unavailable = correlate_changes(None, None, base, [], {}, set())
    assert not unavailable.available and "No change history" in unavailable.message
    no_onset = correlate_changes(ChangeHistory("WAN-FAILURE"), None, base, [], {}, set())
    assert no_onset.available and "No fault onset" in no_onset.message


def test_off_path_changes_are_weak() -> None:
    result = analysis("OSPF-ADJACENCY-FAILURE")
    history = ChangeHistory("VLAN-AUTHENTICATION-FAILURE")
    record = history.records[0]
    history.records = [record]
    roles = assign_roles(result.base, build_catalog([]))
    onset = record.timestamp + timedelta(minutes=5)
    weak = correlate_changes(history, onset, result.base, [], roles, {"BLR-RTR-01"})
    assert weak.correlations[0].strength == CorrelationStrength.WEAK and not weak.correlations[0].on_affected_path


def test_on_path_change_outside_strong_window_is_moderate() -> None:
    result = analysis("OSPF-ADJACENCY-FAILURE")
    history = ChangeHistory("OSPF-ADJACENCY-FAILURE")
    change = next(r for r in history.records if r.change_type == "MTU_CHANGE")
    history.records = [change]
    catalog = list(result.base.evidence)
    roles = assign_roles(result.base, catalog)
    near = correlate_changes(history, change.timestamp + timedelta(minutes=15), result.base, catalog, roles, {"BLR-RTR-01"})
    far = correlate_changes(history, change.timestamp + timedelta(minutes=16), result.base, catalog, roles, {"BLR-RTR-01"})
    assert near.correlations[0].strength == CorrelationStrength.STRONG
    assert far.correlations[0].strength == CorrelationStrength.MODERATE and far.correlations[0].on_affected_path


def test_window_boundaries() -> None:
    history = ChangeHistory("OSPF-ADJACENCY-FAILURE")
    change = next(r for r in history.records if r.change_type == "MTU_CHANGE")
    base = analysis("OSPF-ADJACENCY-FAILURE").base
    inside = correlate_changes(history, change.timestamp + timedelta(minutes=60), base, [], {}, set())
    assert change.change_id in {c.change.change_id for c in inside.correlations}
    outside = correlate_changes(history, change.timestamp + timedelta(minutes=60, seconds=1), base, [], {}, set())
    assert change.change_id not in {c.change.change_id for c in outside.correlations}
    after = correlate_changes(history, change.timestamp - timedelta(minutes=15), base, [], {}, set())
    assert change.change_id in {c.change.change_id for c in after.correlations}
    beyond = correlate_changes(history, change.timestamp - timedelta(minutes=15, seconds=1), base, [], {}, set())
    assert change.change_id not in {c.change.change_id for c in beyond.correlations}
