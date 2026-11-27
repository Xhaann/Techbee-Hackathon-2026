"""One command for the Phase A and Phase 2 benchmarks. Prints to the terminal only and writes nothing to the repository.

Covers: root cause, evidence correctness, confidence and tool selection on all 16 scenarios; the Phase 2 reasoning
layer (Bayesian ranking of the engine's evidence, the multi-agent investigation, self-evaluation and calibration); the
17 conversational probes; concurrent sign-in, user isolation and failure recovery (run as their specs). Everything is
rule-based on simulated data; no model is called.

Run from backend/:  .venv/bin/python -m verification.benchmark.run
"""
import sys
import tempfile
from collections import Counter
from pathlib import Path

import pytest

from verification.api.helpers import ApiHarness
from verification.benchmark.cases import CASES, CONFIDENT, CONTROL, evaluate
from verification.conversation.probe_spec import CONVERSATIONS, failures, run

SPEC_GROUPS = {
    "Concurrent sign-in": ["verification/security/sessions_spec.py", "verification/api/live_server_spec.py"],
    "User isolation": ["verification/api/isolation_spec.py"],
    "Timeouts and recovery": ["verification/api/reliability_spec.py"],
}


def diagnosis_scoreboard() -> bool:
    rows = []
    for entry in ("engine", "agent"):
        for scenario_id in sorted(CASES) + [CONTROL]:
            for with_sites in (True, False) if scenario_id != CONTROL else (True,):
                rows.append((evaluate(scenario_id, entry, with_sites), with_sites))
    print(f"{'scenario':32} {'entry':6} {'input':11} {'result':7} {'domain':22} {'confidence':21} calls")
    for outcome, with_sites in rows:
        d = outcome.diagnosis
        print(f"{outcome.scenario_id:32} {outcome.entry:6} {'sites+text' if with_sites else 'text only':11} "
              f"{'ok' if outcome.correct else 'MISS':7} {d.fault.fault_domain.value:22} {d.confidence.level.value:21} {len(outcome.executed)}")
    scored = [o for o, _ in rows if o.scenario_id != CONTROL]
    correct = sum(o.correct for o in scored)
    confident_wrong = sum(1 for o in scored if not o.correct and o.diagnosis.confidence.level in CONFIDENT)
    calls = [len(o.executed) for o in scored]
    controls_ok = all(o.correct for o, _ in rows if o.scenario_id == CONTROL)
    print(f"\nRoot cause and evidence correct: {correct}/{len(scored)} runs over {len(CASES)} failure scenarios")
    print(f"Wrong at medium or high confidence: {confident_wrong}")
    print(f"Tool calls per diagnosis: mean {sum(calls) / len(calls):.1f}, max {max(calls)} (budget 10)")
    print(f"Healthy baseline control: {'no false positive' if controls_ok else 'FALSE POSITIVE'}")
    for o in scored:
        if not o.correct:
            print(f"  {o.scenario_id} ({o.entry}): {'; '.join(o.problems)}")
    return correct == len(scored) and confident_wrong == 0 and controls_ok


def reasoning_scoreboard() -> bool:
    from verification.phase2.reasoning_spec import engine_run, team_run
    print(f"{'scenario':32} {'engine evidence':24} {'multi-agent':24} {'self-check':10} {'calibrated'}")
    ranked = team_ok = sound = 0
    brier = []
    for scenario_id in sorted(CASES):
        _, _, report = engine_run(scenario_id)
        run, team = team_run(scenario_id)
        domains = CASES[scenario_id].domains
        top, lead = report.hypotheses[0], team.leading
        ranked += top.domain in domains
        team_ok += lead in domains
        sound += report.self_evaluation.verdict == "sound"
        brier.append((1 - sum(h.probability for h in report.hypotheses if h.domain in domains)) ** 2)
        print(f"{scenario_id:32} {top.domain.value + f' {top.probability:.0%}':24} "
              f"{(lead.value if lead else 'none') + f' ({len(run.executed)} calls)':24} {report.self_evaluation.verdict:10} "
              f"{report.self_evaluation.calibrated_confidence}")
    _, control = team_run(CONTROL)
    print(f"\nBayesian ranking of the engine's evidence: {ranked}/{len(CASES)}")
    print(f"Multi-agent investigation (5 specialists, shared 10-call budget): {team_ok}/{len(CASES)}")
    print(f"Self-evaluation sound on correct diagnoses: {sound}/{len(CASES)}; Brier score {sum(brier) / len(brier):.4f}")
    print(f"Healthy baseline control: {'no fault supported' if not control.fault_supported else 'FALSE POSITIVE'}")
    return ranked == team_ok == sound == len(CASES) and not control.fault_supported


def protocol_scoreboard() -> bool:
    """Phase 3: the 17 protocol and security engines over 36 synthetic scenarios (20 protocol scenarios and the 16 core ones)."""
    from app.protocols.analysis import analyze
    from verification.phase3.cases import CASES as PROTOCOL_CASES, SECURITY_CODES, correct
    print(f"{'scenario':32} {'kind':12} {'expected':10} {'false pos.':10} {'root / host':14} {'grounded'}")
    detected = expected = false_positives = roots = root_cases = hosts = host_cases = grounded = 0
    clean_controls = controls = 0
    pairs = []
    for scenario_id in sorted(PROTOCOL_CASES):
        case = PROTOCOL_CASES[scenario_id]
        report = analyze(scenario_id)
        found = {f.code: f.status for f in report.findings}
        hit = sum(found.get(code) == status for code, status in case.expect.items())
        wrong = [f.code for f in report.findings if not correct(scenario_id, f.code)]
        detected, expected, false_positives = detected + hit, expected + len(case.expect), false_positives + len(wrong)
        root_text = "-"
        if case.root:
            root_cases += 1
            lead = next((f.code for f in report.findings if report.root_causes and f.finding_id == report.root_causes[0]), None)
            roots += lead == case.root
            root_text = "ok" if lead == case.root else f"got {lead}"
        if case.host:
            host_cases += 1
            cluster = next((f for f in report.findings if f.code == "THREAT_CORRELATED_ACTIVITY"), None)
            hosts += bool(cluster and cluster.facts["main_host"] == case.host)
            root_text = "host ok" if cluster and cluster.facts["main_host"] == case.host else "host wrong"
        if case.kind == "normal" or scenario_id == "P3-ADV-DECOYS":
            controls += 1
            clean_controls += not report.findings
        grounded += report.validation.grounded
        pairs += [(f.confidence, 1.0 if correct(scenario_id, f.code) else 0.0) for f in report.findings if f.confidence is not None]
        security_confirmed = [f.code for f in report.findings if f.code.startswith(SECURITY_CODES) and f.status == "confirmed_fault"]
        false_positives += len(security_confirmed)
        print(f"{scenario_id:32} {case.kind:12} {f'{hit}/{len(case.expect)}':10} {len(wrong):<10} {root_text:14} {'yes' if report.validation.grounded else 'NO'}")
    brier = sum((c - o) ** 2 for c, o in pairs) / len(pairs)
    total = len(PROTOCOL_CASES)
    print(f"\nExpected protocol and security findings detected with the right status: {detected}/{expected}")
    print(f"False positives (unexpected findings, or a security finding stated as confirmed): {false_positives}")
    print(f"Root cause named correctly: {roots}/{root_cases}; threat cluster centred on the actor: {hosts}/{host_cases}")
    print(f"Healthy, busy and decoy controls with no finding at all: {clean_controls}/{controls}")
    print(f"Findings grounded in existing records: {grounded}/{total} reports; finding confidence Brier score {brier:.4f} over {len(pairs)} findings")
    return detected == expected and false_positives == 0 and roots == root_cases and hosts == host_cases \
        and clean_controls == controls and grounded == total and brier < 0.08


def incident_set_scoreboard() -> bool:
    """SCN-01 to SCN-10, scored against cards written before any engine ran on them. Accuracy is reported as measured and
    does not gate the benchmark (gating it would invite fitting the rules to the scenarios); grounding and safety do."""
    from verification.scenarios.evaluate import SCENARIOS, evaluate
    print("Incident set SCN-01..SCN-10 (accuracy measured, not gated)")
    print(f"{'scenario':36} {'Phase A':22} {'team':16} {'protocol':10} {'root':6} {'decoys':7} {'notes'}")
    rows = [evaluate(s) for s in SCENARIOS]
    for o in rows:
        expected = len(o.expected_met) + len(o.expected_missed)
        notes = "; ".join(o.expected_missed + o.forbidden_hit + o.count_violations + o.unexpected + o.decoy_hits)[:110]
        print(f"{o.scenario_id:36} {(o.phase_a_domain or '-') + (' ok' if o.phase_a_ok else ' MISS'):22} "
              f"{(o.team_domain or 'none') + (' ok' if o.team_ok else ' MISS'):16} {f'{len(o.expected_met)}/{expected}':10} "
              f"{'ok' if o.root_ok else 'MISS':6} {len(o.decoy_hits):<7} {notes}")
    met = sum(len(o.expected_met) for o in rows)
    expected = sum(len(o.expected_met) + len(o.expected_missed) for o in rows)
    print(f"\nPhase A rule-based diagnosis right: {sum(o.phase_a_ok for o in rows)}/10; decoys it concluded: "
          f"{sum(1 for o in rows for d in o.decoy_hits if d.startswith('Phase A'))}")
    print(f"Specialist team right: {sum(o.team_ok for o in rows)}/10")
    print(f"Protocol engines: expected findings {met}/{expected}; root cause right {sum(o.root_ok for o in rows)}/10; "
          f"threat clusters right {sum(o.threats_ok for o in rows)}/10; forbidden or unexpected findings "
          f"{sum(len(o.forbidden_hit) + len(o.unexpected) + len(o.count_violations) for o in rows)}")
    grounded = all(o.grounded and not o.phase_a_provenance for o in rows)
    safe = not any(o.security_confirmed for o in rows)
    print(f"Grounded (Phase A provenance and protocol references): {'10/10' if grounded else 'NO'}; security findings stated as confirmed: "
          f"{sum(len(o.security_confirmed) for o in rows)}")
    return grounded and safe


def probe_scoreboard() -> bool:
    passed = total = 0
    with tempfile.TemporaryDirectory() as root:
        api = ApiHarness(Path(root))
        for scenario, steps in CONVERSATIONS.items():
            previous = None
            for step, turn in run(api, scenario, steps):
                problems = failures(step, turn, previous)
                total, passed = total + 1, passed + (not problems)
                if problems:
                    print(f"  probe miss [{scenario}] {step.message!r}: {'; '.join(problems)}")
                previous = turn
    print(f"Conversational probes: {passed}/{total} (target 16/17)")
    return total == 17 and passed >= 16


class Tally:
    def __init__(self) -> None:
        self.outcomes: Counter[str] = Counter()

    def pytest_runtest_logreport(self, report) -> None:
        if report.when == "call" or (report.when == "setup" and report.outcome != "passed"):
            self.outcomes[report.outcome] += 1


def spec_scoreboard() -> bool:
    ok = True
    for name, files in SPEC_GROUPS.items():
        tally = Tally()
        code = pytest.main([*files, "-qq", "-p", "no:cacheprovider", "-p", "no:warnings", "--no-header",
                            "-o", "console_output_style=classic"], plugins=[tally])
        passed, failed = tally.outcomes["passed"], tally.outcomes["failed"]
        print(f"{name}: {passed} passed, {failed} failed")
        ok &= code == 0 and failed == 0 and passed > 0
    return ok


def main() -> int:
    print("Mode: rule-based on simulated data; no model calls.\n")
    results = [diagnosis_scoreboard()]
    print()
    results.append(reasoning_scoreboard())
    print()
    results.append(protocol_scoreboard())
    print()
    results.append(incident_set_scoreboard())
    print()
    results.append(probe_scoreboard())
    print()
    results.append(spec_scoreboard())
    print("\nBenchmark " + ("PASSED" if all(results) else "FAILED"))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
