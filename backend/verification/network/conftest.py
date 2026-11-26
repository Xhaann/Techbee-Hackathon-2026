import pytest

from app.network.models import NetworkTopology, ScenarioDataset
from app.network.repository import list_scenario_ids, load_scenario, load_topology


@pytest.fixture(scope="session")
def topology() -> NetworkTopology:
    return load_topology()


@pytest.fixture(scope="session")
def scenarios() -> dict[str, ScenarioDataset]:
    return {scenario_id: load_scenario(scenario_id) for scenario_id in list_scenario_ids()}
