import asyncio

import pytest

from app.agent import DiagnosisAgent, build_report
from app.agent.review import AgentReport
from app.agent.runtime import agent_model, build_agent
from app.agent.tools import ToolBudget
from app.core.config import Settings
from app.engine.engine import DiagnosisEngine
from app.engine.executor import MAX_TOOL_CALLS, ToolExecutor
from app.engine.providers import MODEL_NAME
from app.engine.retrieval import NoRetrieval
from app.engine.safety import is_read_only_command
from app.engine.schema import Confidence, Diagnosis, DiagnosisMethod, DiagnosisRequest

SCENARIOS = {
    "A": ("WAN-FAILURE", "Users at the Singapore branch cannot access internal applications."),
    "B": ("WAN-FAILURE", "Users at the Bengaluru branch cannot access internal applications because of a suspected WAN failure."),
    "C": ("SHARED-DEVICE-FAILURE", "New York and Singapore offices are both offline."),
}
LOW_OR_BELOW = {Confidence.LOW, Confidence.INSUFFICIENT_EVIDENCE}


@pytest.fixture(scope="module")
def settings() -> Settings:
    return Settings()


@pytest.fixture(scope="module")
def reports(settings: Settings) -> dict[str, AgentReport]:
    agent = DiagnosisAgent(settings=settings)
    return {name: build_report(agent.run(scenario, text)) for name, (scenario, text) in SCENARIOS.items()}


def oracle(name: str) -> Diagnosis:
    scenario, text = SCENARIOS[name]
    return DiagnosisEngine().diagnose(DiagnosisRequest(scenario_id=scenario, description=text))


def common_checks(report: AgentReport) -> None:
    assert report.human_review_required is True and report.escalation.delivery_status == "not_sent"
    assert 1 <= len([c for c in report.tool_calls if c.status in ("executed", "failed")]) <= MAX_TOOL_CALLS
    assert all(is_read_only_command(check.command) for check in report.recommended_next_checks)
    cited = {e.evidence_id for e in report.evidence_references}
    assert {f.evidence_id for f in report.verified_facts} <= cited


def test_live_configuration_is_complete_without_exposing_secrets(settings: Settings) -> None:
    model = agent_model(settings)
    assert model.config.api_key.get_secret_value() and MODEL_NAME.match(model.model)
    assert model.config.endpoint.startswith("https://") and model.config.api_key.get_secret_value() not in repr(model)


def test_live_minimal_model_request(settings: Settings) -> None:
    budget = ToolBudget(ToolExecutor("BASELINE"), NoRetrieval(), limit=0)
    response = asyncio.run(build_agent(agent_model(settings), budget).run("Reply with the single word OK. Do not call any tool."))
    assert response.text.strip() and budget.attempts == 0


def test_live_scenario_a_success(reports: dict[str, AgentReport]) -> None:
    report = reports["A"]
    common_checks(report)
    assert report.method == DiagnosisMethod.MODEL, report.validation_issues
    assert report.affected_site == ["SIN"] and report.fault_domain == oracle("A").fault.fault_domain
    assert report.root_cause_hypothesis.evidence_support == "supported" and report.discrepancies == []
    assert report.evidence_references and not [i for i in report.validation_issues if "provenance" in i]


def test_live_scenario_b_conflict(reports: dict[str, AgentReport]) -> None:
    report = reports["B"]
    common_checks(report)
    assert report.affected_site == ["BLR"] and report.discrepancies
    assert report.confidence.level in LOW_OR_BELOW
    assert report.root_cause_hypothesis.evidence_support != "supported" or "BLR" not in " ".join(report.root_cause_hypothesis.device_ids)
    assert report.recommended_next_checks


def test_live_scenario_c_missing_evidence(reports: dict[str, AgentReport]) -> None:
    report = reports["C"]
    common_checks(report)
    assert report.fault_domain == oracle("C").fault.fault_domain
    assert any(item.startswith("CORE-RTR-01") and "not proof of failure" in item for item in report.missing_evidence)
    assert not any("CORE-RTR-01" in f.statement and "is down" in f.statement for f in report.verified_facts)
