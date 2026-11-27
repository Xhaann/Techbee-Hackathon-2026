"""Agent tool over the Phase 3 protocol and security engines.

One read-only tool, one engine per call, scoped to a site or device. It returns a compact summary computed in code
(status, a few findings with their status, confidence and evidence references), so a model or the conversation never
sees raw telemetry and every claim stays traceable. Findings keep their status in the summary: a suspicious indicator is
never reported as a confirmed fault.
"""
from typing import Any

from app.diagnostics.common import Finding, FindingKind, ToolOutput, diagnostic_tool, invalid, load_dataset, require_device, require_site

STATUS_TEXT = {"confirmed_fault": "Confirmed", "suspicious_indicator": "Suspicious (not confirmed)", "possible_explanation": "Possible",
               "insufficient_evidence": "Insufficient evidence"}
MAX_FINDINGS = 6


@diagnostic_tool("analyze_protocol")
def analyze_protocol(scenario_id: str, protocol: Any, site_id: Any = None, device_id: Any = None) -> ToolOutput:
    from app.protocols.registry import BY_NAME, run_engines
    from app.protocols.repository import load_telemetry
    topology, dataset = load_dataset(scenario_id)
    if not isinstance(protocol, str) or (protocol not in BY_NAME and protocol != "all"):
        raise invalid(f"protocol must be one of: {', '.join(BY_NAME)}, all")
    site = require_site(topology, site_id).site_id if site_id is not None else None
    device = require_device(topology, device_id).device_id if device_id is not None else None
    telemetry = load_telemetry(dataset.scenario.scenario_id)
    names = list(BY_NAME) if protocol == "all" else [protocol]
    results, findings = run_engines(topology, dataset, telemetry, names, site, device)
    rank = {"confirmed_fault": 0, "suspicious_indicator": 1, "possible_explanation": 2, "insufficient_evidence": 3}
    severity = {"critical": 0, "major": 1, "minor": 2, "info": 3}
    findings = sorted(findings, key=lambda f: (rank[f.status], severity[f.severity]))
    statuses = [r.status for r in results]
    overall = next((s for s in ("fault", "suspicious", "possible", "error", "insufficient") if s in statuses), "healthy")
    output = ToolOutput(scenario_id=dataset.scenario.scenario_id, data={
        "engine": protocol, "title": results[0].title if len(results) == 1 else "All protocol and security engines", "status": overall,
        "synthetic": True, "checked": results[0].checked if len(results) == 1 else [r.title for r in results],
        "notes": list(dict.fromkeys(n for r in results for n in r.notes))[:4],
        "findings": [{"finding_id": f.finding_id, "code": f.code, "status": f.status, "confidence": f.confidence, "title": f.title,
                      "device_id": f.device_id, "sites": f.affected_sites, "commands": [c.command for c in f.commands[:2]]}
                     for f in findings[:MAX_FINDINGS]],
    }, warnings=["Synthetic protocol telemetry. Statuses distinguish confirmed faults, suspicious indicators, possible explanations and "
                 "insufficient evidence; suspicious indicators are not confirmed and say nothing about who is responsible."])
    for finding in findings[:MAX_FINDINGS]:
        if finding.status == "insufficient_evidence":
            output.missing_data.append(f"{finding.title}: {finding.summary}"[:300])
            continue
        output.findings.append(Finding(
            code=finding.code, kind=FindingKind.OBSERVED if finding.status == "confirmed_fault" else FindingKind.INFERRED,
            summary=f"[{STATUS_TEXT[finding.status]}] {finding.title}: {finding.summary}"[:600], device_id=finding.device_id,
            evidence=finding.evidence[:6]))
    output.missing_data += list(dict.fromkeys(m for r in results for m in r.missing))[:3]
    return output
