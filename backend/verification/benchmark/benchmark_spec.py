"""All-scenario diagnostic benchmark (rule-based, deterministic, offline).

Simulated data and rule-based reasoning only: no model is called. A model-mode run needs approval and is not part of this
suite. Print the scoreboard with: .venv/bin/python -m verification.benchmark.run
"""
import pytest

from app.engine.schema import Confidence
from verification.api.helpers import ApiHarness
from verification.benchmark.cases import CASES, CONFIDENT, CONTROL, all_scenarios, evaluate

ENTRIES = ("engine", "agent")


def test_every_scenario_is_in_the_benchmark() -> None:
    scenarios = all_scenarios()
    assert len(scenarios) == 16 and set(scenarios) == set(CASES) | {CONTROL}


@pytest.mark.parametrize("entry", ENTRIES)
@pytest.mark.parametrize("scenario_id", sorted(CASES) + [CONTROL])
def test_scenario_is_diagnosed_correctly(scenario_id: str, entry: str) -> None:
    outcome = evaluate(scenario_id, entry)
    assert outcome.correct, (scenario_id, entry, outcome.problems, outcome.diagnosis.fault.root_cause)


@pytest.mark.parametrize("scenario_id", sorted(CASES))
def test_scenario_is_diagnosed_from_the_description_alone(scenario_id: str) -> None:
    outcome = evaluate(scenario_id, "engine", with_sites=False)
    assert outcome.correct, (scenario_id, outcome.problems)


def test_scoreboard_meets_targets() -> None:
    outcomes = [evaluate(scenario_id) for scenario_id in sorted(CASES)]
    correct = sum(outcome.correct for outcome in outcomes)
    confident_wrong = [o.scenario_id for o in outcomes if not o.correct and o.diagnosis.confidence.level in CONFIDENT]
    high = [o for o in outcomes if o.diagnosis.confidence.level == Confidence.HIGH]
    assert correct == len(CASES) == 15
    assert confident_wrong == []
    assert all(o.correct for o in high)
    assert max(len(o.executed) for o in outcomes) <= 10


def test_every_scenario_loads_through_the_api(tmp_path) -> None:
    api = ApiHarness(tmp_path)
    for scenario_id in all_scenarios():
        response = api.get("/dashboard/network-health", params={"scenario_id": scenario_id}, as_="viewer")
        assert response.status_code == 200 and response.json()["device_count"] == 17, scenario_id
