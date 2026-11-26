import json

import pytest

from app.agent import DiagnosisAgent
from app.agent.__main__ import main
from app.agent.runtime import AGENT_INSTRUCTIONS, MAX_RUN_SECONDS, agent_model, build_agent, run_deadline
from app.agent.tools import KNOWLEDGE_SCHEMA, KNOWLEDGE_TOOL, ToolBudget, build_tools
from app.core.config import Settings
from app.engine.engine import MAX_MODEL_TURNS
from app.engine.executor import MAX_TOOL_CALLS, ToolExecutor
from app.engine.instructions import SYSTEM_INSTRUCTIONS
from app.engine.providers import ProviderError, ProviderErrorKind
from app.engine.registry import REGISTRY
from app.engine.retrieval import NoRetrieval
from verification.agent.helpers import FAKE_KEY, answer, scripted_agent
from verification.engine.helpers import ai_settings


def budget() -> ToolBudget:
    return ToolBudget(ToolExecutor("WAN-FAILURE"), NoRetrieval())


def test_agent_initialises_with_configured_model() -> None:
    model = agent_model(ai_settings())
    assert (model.name, model.model, model.config.endpoint) == ("openai", "approved-test-model", "https://api.openai.com/v1")
    assert FAKE_KEY not in repr(model) and FAKE_KEY not in repr(DiagnosisAgent(settings=ai_settings()).__dict__)


@pytest.mark.parametrize("values,message", [
    ({"ai_provider": "disabled"}, "disabled"), ({"ai_model": None}, "AI_MODEL"), ({"ai_model": "bad model name!"}, "AI_MODEL"),
    ({"openai_api_key": None}, "API key"), ({"ai_endpoint": "http://insecure.example/v1"}, "https"),
    ({"ai_provider": "foundry", "foundry_api_key": "k" * 20, "ai_endpoint": "https://x.example"}, "openai only"),
])
def test_invalid_model_configuration_is_rejected(values: dict, message: str) -> None:
    with pytest.raises(ProviderError) as error:
        DiagnosisAgent(settings=ai_settings(**values))
    assert error.value.kind == ProviderErrorKind.CONFIGURATION and message in error.value.message
    assert FAKE_KEY not in error.value.message


def test_ai_api_key_setting_is_supported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AI_API_KEY", "sk-env-configured-test")
    settings = Settings(_env_file=None, ai_provider="openai", ai_model="approved-test-model")
    assert agent_model(settings).config.api_key.get_secret_value() == "sk-env-configured-test"


def test_all_diagnostic_tools_and_knowledge_are_registered() -> None:
    tools = {tool.name: tool for tool in build_tools(budget())}
    assert set(tools) == set(REGISTRY) | {KNOWLEDGE_TOOL} and len(tools) == 13
    for name, spec in REGISTRY.items():
        assert tools[name].parameters() == spec.schema()["function"]["parameters"]
    assert tools[KNOWLEDGE_TOOL].parameters() == KNOWLEDGE_SCHEMA


def test_runtime_applies_execution_limits() -> None:
    model = agent_model(ai_settings())
    agent = build_agent(model, budget())
    configuration = agent.client.function_invocation_configuration
    assert configuration["max_function_calls"] == MAX_TOOL_CALLS == 10
    assert configuration["max_iterations"] == MAX_MODEL_TURNS
    assert configuration["allow_concurrent_invocation"] is False and configuration["include_detailed_errors"] is False
    assert configuration["max_duration_seconds"] == run_deadline(model.config) <= MAX_RUN_SECONDS
    assert agent.client.client.max_retries == 0 and agent.client.client.timeout == 30.0
    assert agent.default_options["allow_multiple_tool_calls"] is False
    assert AGENT_INSTRUCTIONS.startswith(SYSTEM_INSTRUCTIONS)


def test_model_request_uses_configured_model_key_and_limits() -> None:
    agent, model = scripted_agent([answer("not json")])
    agent.run("WAN-FAILURE", "Users at the Singapore branch cannot access internal applications.")
    request = model.requests[0]
    assert request["model"] == "approved-test-model" and request["max_completion_tokens"] == 2000
    assert request["parallel_tool_calls"] is False and len(request["tools"]) == 13
    assert model.headers[0]["authorization"] == f"Bearer {FAKE_KEY}"
    assert request["messages"][0] == {"role": "system", "content": AGENT_INSTRUCTIONS}


def test_cli_rule_based_run_and_json(capsys: pytest.CaptureFixture) -> None:
    assert main(["--rule-based", "--json", "--scenario", "WAN-FAILURE", "Singapore office cannot reach any corporate service"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["human_review_required"] is True and report["fault_domain"] == "wan_isp"
    assert main(["--rule-based", "--scenario", "WAN-FAILURE", "Singapore office cannot reach any corporate service"]) == 0
    text = capsys.readouterr().out
    assert "Fault domain: wan_isp" in text and "Human review is required before any action." in text


def test_cli_rejects_unknown_scenario_and_missing_configuration(capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(SystemExit):
        main(["--scenario", "../../etc/passwd", "report"])
    monkeypatch.setattr("app.agent.session.get_settings", lambda: Settings(_env_file=None, openai_api_key=FAKE_KEY))
    assert main(["--scenario", "WAN-FAILURE", "report"]) == 2
    error = capsys.readouterr().err
    assert "AI_API_KEY" in error and FAKE_KEY not in error
    assert main(["--rule-based", "--scenario", "WAN-FAILURE", " "]) == 2
