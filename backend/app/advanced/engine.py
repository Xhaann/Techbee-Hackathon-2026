import json

from app.advanced.anomalies import detect_anomalies
from app.advanced.causes import root_cause_candidates
from app.advanced.changes import ChangeHistory, correlate_changes
from app.advanced.history import compare_history
from app.advanced.impact import blast_radius, incident_asset_updates
from app.advanced.layers import assign_roles, cross_layer, onset_of
from app.advanced.paths import analyze_paths
from app.advanced.schema import AdvancedDiagnosis, AdvancedRequest, CandidateStatus, GuidanceReference
from app.engine import DiagnosisEngine
from app.engine.evidence import build_catalog
from app.engine.executor import MAX_TOOL_CALLS, ToolCallRecord, ToolExecutor
from app.engine.providers import ModelProvider
from app.engine.safety import is_read_only_command
from app.engine.schema import Diagnosis, NextCheck
from app.incidents.models import Actor, Incident, ImpactBasis
from app.incidents.service import AssetUpdate, IncidentService
from app.knowledge.service import KnowledgeService
from app.network.models import DeviceType
from app.network.repository import load_topology

MAX_NEXT_CHECKS = 12


class AdvancedDiagnosisEngine:
    def __init__(self, provider: ModelProvider | None = None, knowledge: KnowledgeService | None = None,
                 incidents: IncidentService | None = None) -> None:
        self.provider = provider
        self.knowledge = knowledge
        self.incidents = incidents
        self.topology = load_topology()
        self.devices = {device.device_id: device for device in self.topology.devices}

    def supplement(self, scenario_id: str, diagnosis: Diagnosis, records: list[ToolCallRecord], extra: int) -> list[ToolCallRecord]:
        executed = [record for record in records if record.status in ("executed", "failed")]
        executor = ToolExecutor(scenario_id, max_calls=min(MAX_TOOL_CALLS, len(executed) + extra))
        executor.records = list(records)
        executor.requests = len(records)
        executor.seen = {json.dumps([r.tool, r.arguments], sort_keys=True): r.call_id for r in executed}
        covered = {r.arguments.get("device_id") for r in executed if r.tool == "get_interface_stats"}
        path = diagnosis.affected_path.path if diagnosis.affected_path else []
        candidates = list(dict.fromkeys(diagnosis.fault.device_ids + [d for d in path if self.devices[d].device_type == DeviceType.ROUTER]))
        for device_id in candidates:
            if executor.remaining <= 0:
                break
            if device_id not in covered:
                executor.execute("get_interface_stats", {"device_id": device_id})
        return executor.records

    def next_checks(self, diagnosis: Diagnosis, assessment) -> list[NextCheck]:
        checks = list(diagnosis.next_checks)
        seen = {(check.device_id, check.command) for check in checks}
        for guidance in assessment.supplementary_checks if assessment else []:
            if guidance.device_id is None or (guidance.device_id, guidance.command) in seen:
                continue
            if not is_read_only_command(guidance.command):
                continue
            checks.append(NextCheck(device_id=guidance.device_id, command=guidance.command, purpose=guidance.purpose,
                                    expected_observation=f"See playbook {guidance.source_record_id} step {guidance.step_order}",
                                    reason=f"Illustrative read-only check from {guidance.source_record_id}"))
            seen.add((guidance.device_id, guidance.command))
        return checks[:MAX_NEXT_CHECKS]

    def analyze(self, request: AdvancedRequest) -> AdvancedDiagnosis:
        incident = self.incidents.get_incident(request.incident_id) if self.incidents and request.incident_id else None
        retriever = self.knowledge.diagnosis_retriever() if self.knowledge else None
        diagnosis, base_records = DiagnosisEngine(self.provider, retriever).diagnose_with_records(request.diagnosis)
        records = self.supplement(request.diagnosis.scenario_id, diagnosis, base_records, request.supplementary_tool_calls)
        supplementary = records[len(base_records):]
        catalog = build_catalog(records)
        roles = assign_roles(diagnosis, catalog)
        assessment = self.knowledge.assess_diagnosis(diagnosis) if self.knowledge else None
        layers = cross_layer(diagnosis, catalog, roles, records)
        degraded = {record.result.data["link"]["link_id"] for record in records
                    if record.succeeded and record.tool == "analyze_packet_loss" and record.result.data["link"]
                    and record.result.data["pattern"] in ("sustained", "intermittent", "isolated")
                    and not record.result.data["outage_sample_count"]}
        paths = analyze_paths(records, self.topology, diagnosis, degraded)
        confirmed = incident.classification.confirmed_fault_domain if incident else None
        candidates = root_cause_candidates(diagnosis, catalog, roles, assessment, confirmed)
        radius = blast_radius(diagnosis, catalog, roles, paths, self.topology, incident)
        path_devices = {hop.device_id for analysis in paths for hop in analysis.hops}
        changes = correlate_changes(ChangeHistory(request.diagnosis.scenario_id), onset_of(diagnosis), diagnosis, catalog, roles,
                                    path_devices)
        history = compare_history(self.incidents, request.incident_id if incident else None)
        anomalies = detect_anomalies(records)
        playbooks = [GuidanceReference(record_id=m.record_id, title=m.title, match_type=m.match_type.value, reasons=m.reasons)
                     for m in (assessment.matches if assessment else [])][:5]
        primary = candidates[0] if candidates and candidates[0].status in (CandidateStatus.SUSPECTED, CandidateStatus.HUMAN_CONFIRMED) else None
        result = AdvancedDiagnosis(
            incident_id=request.incident_id, base=diagnosis, primary_fault=primary, root_cause_candidates=candidates,
            cross_layer=layers, paths=paths, blast_radius=radius, changes=changes, history=history, anomalies=anomalies,
            playbooks=playbooks, missing_evidence=primary.missing_evidence if primary else
            ["No primary fault is supported by the collected evidence"],
            next_checks=self.next_checks(diagnosis, assessment), supplementary_tool_calls=[f"{r.call_id}:{r.tool}" for r in supplementary],
            narrative=[], validation_issues=[],
        )
        return result.model_copy(update={"narrative": self.narrative(result), "validation_issues": self.validate(result, catalog)})

    def narrative(self, result: AdvancedDiagnosis) -> list[str]:
        base, lines = result.base, []
        facts = [item.summary for item in base.evidence if item.evidence_id in base.fault.supporting_evidence_ids
                 and item.evidence_type.value != "inferred_finding"][:3]
        lines += [f"Observed: {fact}" for fact in facts]
        if result.primary_fault:
            fault = result.primary_fault
            state = "confirmed by a human" if fault.status == CandidateStatus.HUMAN_CONFIRMED else "suspected, not confirmed"
            lines.append(f"Primary fault ({state}, {fault.confidence.value.replace('_', ' ')} confidence): {fault.hypothesis}")
            lines.append(f"{len(fault.dependent_symptom_ids)} evidence items are dependent symptoms or downstream service impact")
        else:
            lines.append("No primary fault is supported by the collected evidence")
        for analysis in result.paths[:3]:
            point = f"; earliest affected point {analysis.earliest_affected_point}" if analysis.earliest_affected_point else ""
            lines.append(f"Path {analysis.source} -> {analysis.destination}: {analysis.status}{point} (forward direction only)")
        radius = result.blast_radius
        lines.append(f"Impact: sites {', '.join(radius.affected_sites) or 'none identified'}; potentially affected "
                     f"{', '.join(radius.potentially_affected_sites) or 'none'}; business impact not assessed")
        strongest = result.changes.correlations[0] if result.changes.correlations else None
        lines.append(f"Change correlation ({strongest.strength.value}, temporal only): {strongest.change.change_type} on "
                     f"{strongest.change.device_id} {strongest.seconds_from_onset:+d}s from onset" if strongest else result.changes.message)
        lines.append(result.history.message)
        lines.append(f"{len(result.anomalies.anomalies)} telemetry anomalies against explicit thresholds or first-sample baselines")
        lines.append("Recommended: run the listed read-only checks; any change or closure requires human verification")
        return lines

    def validate(self, result: AdvancedDiagnosis, catalog: list) -> list[str]:
        known = {item.evidence_id for item in catalog}
        issues = []
        cited = {i for c in result.root_cause_candidates for i in c.supporting_evidence_ids + c.contradicting_evidence_ids + c.dependent_symptom_ids}
        cited |= {i for item in result.blast_radius.items for i in item.evidence_ids}
        cited |= {i for c in result.changes.correlations for i in c.related_evidence_ids}
        cited |= {e.evidence_id for e in result.cross_layer.aligned_evidence}
        issues += [f"Evidence {i} does not resolve to a tool result" for i in sorted(cited - known)]
        issues += [f"Device {d} is not in the topology" for c in result.root_cause_candidates for d in c.device_ids if d not in self.devices]
        issues += [f"Command '{c.command}' is not read-only" for c in result.next_checks
                   if not is_read_only_command(c.command)]
        if result.primary_fault and result.primary_fault.confidence != result.base.confidence.level:
            issues.append("Primary fault confidence differs from the evidence-based diagnosis confidence")
        return issues

    def apply_to_incident(self, result: AdvancedDiagnosis, actor: Actor) -> Incident:
        if self.incidents is None or result.incident_id is None:
            raise ValueError("Applying an advanced diagnosis requires an incident service and incident identifier")
        incident = self.incidents.associate_diagnosis(result.incident_id, actor, result.base)
        updates = [AssetUpdate(asset_type=asset_type, asset_id=asset_id, basis=ImpactBasis.INFERRED)
                   for asset_type, asset_id in incident_asset_updates(result.blast_radius, self.topology)]
        known = {(a.asset_type, a.asset_id) for a in incident.affected_assets}
        updates = [u for u in updates if (u.asset_type, u.asset_id) not in known]
        if updates:
            incident = self.incidents.update_affected_assets(result.incident_id, actor, updates)
        if self.knowledge is not None:
            linked = {(k.record_id, k.version) for k in incident.knowledge_references}
            assessment = self.knowledge.guidance_for_incident(incident)
            ids = ([assessment.selected_playbook_id] if assessment.selected_playbook_id else []) + assessment.runbook_ids
            if any((record_id, self.knowledge.repository.get(record_id).version) not in linked for record_id in ids):
                incident = self.knowledge.link_to_incident(self.incidents, result.incident_id, actor)
        return incident
