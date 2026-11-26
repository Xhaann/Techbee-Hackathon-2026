import type { AdvancedDiagnosis, Incident } from "@/lib/api/types";
import { CONFIDENCE_LABEL, faultHeadline, FAULT_LABEL, METHOD_LABEL, PRIORITY_LABEL, SEVERITY_LABEL, STATUS_LABEL } from "@/lib/labels";
import { stamp } from "@/lib/time";
import { activeRecord, currentResolution } from "./model";

/** A Markdown incident report built from the incident, its active diagnosis and the advanced analysis. */
export function incidentReport(incident: Incident, advanced?: AdvancedDiagnosis): string {
  const site = incident.site_ids[0];
  const record = activeRecord(incident);
  const d = record?.diagnosis;
  const lines: string[] = [
    `# ${incident.incident_id}: ${incident.title}`,
    "",
    `- Status: ${STATUS_LABEL[incident.status]}`,
    `- Priority: ${PRIORITY_LABEL[incident.priority]} · Severity: ${SEVERITY_LABEL[incident.severity]}`,
    `- Sites: ${incident.site_ids.join(", ")}`,
    `- Opened: ${stamp(incident.created_at, site)} · Updated: ${stamp(incident.updated_at, site)}`,
    `- Dataset: ${incident.dataset_scenario_id ?? "none"} (synthetic telemetry)`,
    "",
    "## Report",
    "",
    incident.description,
  ];

  if (d && record) {
    lines.push(
      "",
      "## Likely root cause",
      "",
      `**${faultHeadline(d.fault.fault_domain, d.fault.root_cause)}** (${FAULT_LABEL[d.fault.fault_domain]})`,
      "",
      d.fault.root_cause,
      "",
      `- Confidence: ${CONFIDENCE_LABEL[d.confidence.level]}. ${d.confidence.explanation}`,
      `- Method: ${METHOD_LABEL[record.method]} · Diagnosis ${record.diagnosis_id}`,
      `- Classification: ${incident.classification?.confirmed_fault_domain ? `confirmed as ${FAULT_LABEL[incident.classification.confirmed_fault_domain]} by ${incident.classification.confirmed_by?.actor_id}` : "not confirmed by a person"}`,
      "",
      "## Summary",
      "",
      d.explanation.summary,
    );
    if (d.affected_path) lines.push("", "## Affected path", "", d.affected_path.path.join(" → "), "", `Reachability: ${d.affected_path.reachability}`);
    if (advanced?.anomalies.anomalies.length) {
      lines.push("", "## Measured anomalies", "", "| Asset | Category | Observed | Baseline |", "| --- | --- | --- | --- |");
      for (const a of advanced.anomalies.anomalies) lines.push(`| ${a.asset_id} | ${a.category} | ${a.observed} | ${a.baseline} |`);
    }
    lines.push("", "## Evidence", "");
    for (const e of d.evidence) lines.push(`- **${e.evidence_id}** (${e.evidence_type.replace("_", " ")}, ${e.tool}): ${e.summary}`);
    if (d.next_checks.length) {
      lines.push("", "## Next checks (read-only)", "");
      d.next_checks.forEach((c, i) => lines.push(`${i + 1}. \`${c.device_id}# ${c.command}\`: ${c.purpose}. Expect: ${c.expected_observation}`));
    }
    if (d.alternatives.length) {
      lines.push("", "## Alternatives", "");
      for (const a of d.alternatives) lines.push(`- ${FAULT_LABEL[a.fault_domain]}: ${a.hypothesis}`);
    }
    lines.push("", "## Escalation recommendation", "", `${d.escalation.team} (${PRIORITY_LABEL[d.escalation.priority]}): ${d.escalation.reason}`);
    if (d.escalation.unknowns.length) {
      lines.push("", "Unknowns:");
      for (const u of d.escalation.unknowns) lines.push(`- ${u}`);
    }
  }

  const resolution = currentResolution(incident);
  if (resolution) {
    lines.push("", "## Resolution", "", `${resolution.resolution_id} (${resolution.verification}): ${resolution.summary}`);
  }
  if (incident.escalations?.length) {
    lines.push("", "## Escalations", "");
    for (const e of incident.escalations) lines.push(`- ${e.escalation_id} · ${e.status} · ${e.assigned_team ?? e.recommended_team} · ${e.reason}`);
  }
  lines.push("", "## Timeline", "");
  for (const event of incident.timeline) lines.push(`- ${stamp(event.timestamp, site)} · ${event.actor.actor_id}: ${event.description}`);
  lines.push("", "---", "", "Every hypothesis here needs human verification before any change is made.", "");
  return lines.join("\n");
}

export function downloadText(filename: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/markdown;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
