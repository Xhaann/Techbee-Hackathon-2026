import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.network.models import NetworkTopology, ScenarioDataset
from app.network.repository import (
    DATA_DIR,
    SCENARIOS_DIR,
    DatasetIntegrityError,
    DatasetNotFoundError,
    find_reference_errors,
    list_scenario_ids,
    load_scenario,
)


def copy_data(tmp_path: Path) -> Path:
    target = tmp_path / "data"
    shutil.copytree(DATA_DIR, target)
    return target


def test_data_directory_is_package_relative() -> None:
    assert DATA_DIR == Path(__file__).resolve().parents[2] / "app" / "network" / "data"
    assert len(list_scenario_ids()) == 16


@pytest.mark.parametrize("scenario_id", ["UNKNOWN", "../topology", "", "baseline"])
def test_unknown_scenarios_are_rejected(scenario_id: str) -> None:
    with pytest.raises(DatasetNotFoundError):
        load_scenario(scenario_id)


def test_reference_errors_are_reported(topology: NetworkTopology, scenarios: dict[str, ScenarioDataset]) -> None:
    dataset = scenarios["WAN-FAILURE"]
    event = dataset.events[0].model_copy(update={"device_id": "GHOST-RTR-01", "interface_id": None})
    broken = dataset.model_copy(update={"events": [event, *dataset.events[1:]]})
    assert find_reference_errors(topology, broken) == ["unknown device reference: GHOST-RTR-01"]
    truth = dataset.ground_truth.model_copy(update={"affected_path_ids": ["PATH-NOWHERE"]})
    assert find_reference_errors(topology, dataset.model_copy(update={"ground_truth": truth})) == [
        "unknown path reference: PATH-NOWHERE"
    ]


def test_integrity_errors_are_raised_when_loading(tmp_path: Path) -> None:
    data_dir = copy_data(tmp_path)
    path = data_dir / SCENARIOS_DIR / "BASELINE.json"
    content = path.read_text(encoding="utf-8")
    original = '"server_device_id": "DC1-SRV-DHCP-01"'
    assert original in content
    path.write_text(content.replace(original, '"server_device_id": "DC9-SRV-DHCP-01"'), encoding="utf-8")
    with pytest.raises(DatasetIntegrityError, match="DC9-SRV-DHCP-01"):
        load_scenario("BASELINE", data_dir)


def test_partially_renamed_device_is_rejected_by_model_validation(tmp_path: Path) -> None:
    data_dir = copy_data(tmp_path)
    path = data_dir / SCENARIOS_DIR / "BASELINE.json"
    content = path.read_text(encoding="utf-8")
    assert '"DC1-SRV-DHCP-01:eth0"' in content
    path.write_text(content.replace('"DC1-SRV-DHCP-01"', '"DC9-SRV-DHCP-01"'), encoding="utf-8")
    with pytest.raises(ValidationError, match="statistics interface must belong to the device"):
        load_scenario("BASELINE", data_dir)


def test_mismatched_scenario_file_is_rejected(tmp_path: Path) -> None:
    data_dir = copy_data(tmp_path)
    shutil.copy(data_dir / SCENARIOS_DIR / "BASELINE.json", data_dir / SCENARIOS_DIR / "COPY.json")
    with pytest.raises(DatasetIntegrityError, match="contains scenario BASELINE"):
        load_scenario("COPY", data_dir)


def test_malformed_dataset_is_rejected(tmp_path: Path) -> None:
    data_dir = copy_data(tmp_path)
    (data_dir / SCENARIOS_DIR / "BASELINE.json").write_text('{"scenario": {}}', encoding="utf-8")
    with pytest.raises(ValidationError):
        load_scenario("BASELINE", data_dir)
