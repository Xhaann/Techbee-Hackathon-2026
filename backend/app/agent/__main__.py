import argparse
import sys

from app.agent.review import AgentReport, build_report
from app.agent.session import DiagnosisAgent
from app.engine.planner import DiagnosisRequestError
from app.engine.providers import ProviderError
from app.network.repository import list_scenario_ids
from app.security.secrets import redact

CONFIGURATION_HELP = "Configure AI_PROVIDER=openai, AI_MODEL and AI_API_KEY in backend/.env, or pass --rule-based"


def render(report: AgentReport) -> str:
    lines = [
        f"Incident: {report.incident_summary}",
        f"Method: {report.method.value}" + (f" (model {report.model})" if report.model else "") + f" | status: {report.status}",
        f"Affected site: {', '.join(report.affected_site)} | service: {', '.join(report.affected_service)}",
        f"Fault domain: {report.fault_domain.value} | confidence: {report.confidence.level.value}"
        + (f" (capped from {report.confidence.capped_from.value})" if report.confidence.capped_from else ""),
        f"Hypothesis ({report.root_cause_hypothesis.origin}, requires human confirmation): {report.root_cause_hypothesis.statement}",
    ]
    if report.affected_path:
        lines.append(f"Affected path: {' -> '.join(report.affected_path.path)} ({report.affected_path.reachability})")
    sections = [
        ("Discrepancies", report.discrepancies),
        ("Verified facts", [f"{fact.evidence_id} [{fact.tool} {fact.call_id}] {fact.statement}" for fact in report.verified_facts]),
        ("Timeline", [f"{entry.timestamp.isoformat()} {entry.device_id or '-'} {entry.event} ({entry.evidence_id})"
                      for entry in report.correlated_timeline]),
        ("Alternatives", [f"{alt.fault_domain.value}: {alt.hypothesis}" for alt in report.alternatives]),
        ("Recommended read-only checks", [f"{check.device_id}: {check.command} - {check.purpose}"
                                          for check in report.recommended_next_checks]),
        ("Missing evidence", report.missing_evidence),
        ("Knowledge consulted (unverified guidance)", [f"{ref.reference_id}: {ref.title}" for ref in report.knowledge_guidance]),
        ("Escalation (not sent)", [f"{report.escalation.team} {report.escalation.priority}: {report.escalation.reason}"]),
        ("Narrative", report.diagnostic_narrative),
        ("Required human confirmations", report.required_human_confirmations),
        ("Validation issues", report.validation_issues),
        ("Security flags", report.security_flags),
    ]
    for title, items in sections:
        if items:
            lines.append(f"\n{title}:")
            lines += [f"  - {item}" for item in items]
    lines.append("\nHuman review is required before any action.")
    return "\n".join(lines)


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.agent", description="Local Network Incident Diagnosis Assistant agent")
    parser.add_argument("--scenario", required=True, choices=list_scenario_ids(), help="Synthetic dataset scenario")
    parser.add_argument("--json", action="store_true", help="Print the structured report as JSON")
    parser.add_argument("--rule-based", action="store_true", help="Run without a model using the deterministic planner")
    parser.add_argument("report", help="Natural-language incident report")
    options = parser.parse_args(arguments)
    try:
        agent = DiagnosisAgent(rule_based=options.rule_based)
        report = build_report(agent.run(options.scenario, options.report))
    except ProviderError as exc:
        sys.stderr.write(f"Agent configuration error: {redact(exc.message)}. {CONFIGURATION_HELP}\n")
        return 2
    except DiagnosisRequestError as exc:
        sys.stderr.write(f"Invalid request: {redact(str(exc))}\n")
        return 2
    sys.stdout.write((report.model_dump_json(indent=2) if options.json else render(report)) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
