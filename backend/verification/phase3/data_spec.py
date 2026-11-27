"""Synthetic scenario and telemetry integrity: every dataset validates and references only real topology, record ids are
unique, generation is deterministic (the committed files are exactly what the generator writes), the core scenario set and
its enumeration are untouched, and every kind of scenario the brief asks for exists."""
import json
import re
from pathlib import Path

import pytest

from app.network.repository import (
    DatasetIntegrityError,
    all_scenario_ids,
    list_protocol_scenario_ids,
    list_scenario_ids,
    load_scenario,
    load_topology,
    scenario_exists,
)
from app.protocols.models import ProtocolTelemetry
from app.protocols.repository import duplicate_ids, load_telemetry, record_index, reference_errors
from app.protocols.scenarios import PROTOCOL_SCENARIO_DIR, SPECS, build_dataset, build_telemetry_dict, to_json


def test_core_scenario_set_is_unchanged_and_protocol_scenarios_are_separate() -> None:
    assert len(list_scenario_ids()) == 16 and not any(s.startswith("P3-") for s in list_scenario_ids())
    protocol = list_protocol_scenario_ids()
    assert len(protocol) == 30 and sum(s.startswith("P3-") for s in protocol) == 20 and sum(s.startswith("SCN-") for s in protocol) == 10
    assert all(scenario_exists(s) for s in all_scenario_ids()) and not scenario_exists("P3-NOPE")


def test_every_kind_of_scenario_exists() -> None:
    kinds = {spec.kind for spec in SPECS}
    assert kinds == {"normal", "failure", "edge", "adversarial"}
    assert sum(spec.kind == "failure" for spec in SPECS) >= 13 and sum(spec.kind == "adversarial" for spec in SPECS) >= 4


@pytest.mark.parametrize("spec", SPECS, ids=lambda s: s.scenario_id)
def test_committed_dataset_is_exactly_what_the_generator_writes(spec) -> None:
    committed = (PROTOCOL_SCENARIO_DIR / f"{spec.scenario_id}.json").read_text(encoding="utf-8")
    assert committed == to_json(build_dataset(spec))


@pytest.mark.parametrize("scenario", all_scenario_ids())
def test_telemetry_is_synthetic_valid_unique_and_references_the_topology(scenario: str) -> None:
    telemetry = load_telemetry(scenario)
    assert telemetry.synthetic is True and "Synthetic" in telemetry.description
    assert reference_errors(load_topology(), telemetry) == [] and duplicate_ids(telemetry) == []
    assert ProtocolTelemetry.model_validate(build_telemetry_dict(load_scenario(scenario))) == telemetry  # deterministic
    assert sum(len(ids) for ids in record_index(telemetry).values()) > 100


def test_protocol_datasets_keep_the_core_dataset_rules() -> None:
    for scenario in list_protocol_scenario_ids():
        dataset = load_scenario(scenario)
        assert dataset.scenario.scenario_id == scenario
        assert (dataset.incident is None) == (dataset.ground_truth is None)


def test_tampered_telemetry_is_rejected(monkeypatch) -> None:
    from app.protocols import repository
    original = repository.build_telemetry_dict

    def tampered(dataset):
        data = original(dataset)
        data["bgp"]["routes"].append(dict(data["bgp"]["routes"][0]))  # duplicate record id
        return data
    monkeypatch.setattr(repository, "build_telemetry_dict", tampered)
    repository.load_telemetry.cache_clear()
    try:
        with pytest.raises(DatasetIntegrityError):
            repository.load_telemetry("BASELINE")
    finally:
        repository.load_telemetry.cache_clear()


def test_unknown_device_reference_is_rejected() -> None:
    data = build_telemetry_dict(load_scenario("BASELINE"))
    data["events"].append({"event_id": "PE-X", "timestamp": data["bgp"]["collected_at"], "protocol": "bgp", "kind": "TEST",
                           "device_id": "NOT-A-DEVICE-01", "detail": "x"})
    assert any("NOT-A-DEVICE-01" in e for e in reference_errors(load_topology(), ProtocolTelemetry.model_validate(data)))


def test_scenario_files_hold_no_real_addresses_or_secrets() -> None:
    text = "".join(path.read_text() for path in Path(PROTOCOL_SCENARIO_DIR).glob("*.json"))
    assert "BEGIN PRIVATE KEY" not in text and not re.search(r"(?:password|passwd|secret|psk)\s*[:=]\s*\S", text, re.I)
    for scenario in list_protocol_scenario_ids():
        dumped = json.dumps(load_telemetry(scenario).model_dump(mode="json"))
        assert "8.8.8.8" not in dumped and "1.1.1.1" not in dumped
