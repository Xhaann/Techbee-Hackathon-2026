import hashlib
import os
import subprocess
import sys
from pathlib import Path

from app.network.advanced_scenarios import build as build_advanced
from app.network.generator import build_scenarios, build_topology, to_json, write_datasets
from app.network.repository import DATA_DIR, SCENARIOS_DIR, TOPOLOGY_FILE, list_scenario_ids

BACKEND_DIR = Path(__file__).resolve().parents[2]
DIGEST_SCRIPT = (
    "import hashlib, pathlib, sys\n"
    "from app.network.generator import build_scenarios, build_topology, to_json\n"
    "topology = build_topology()\n"
    "digest = hashlib.sha256(to_json(topology).encode())\n"
    "from app.network.advanced_scenarios import build\n"
    "[digest.update(to_json(dataset).encode()) for dataset in build_scenarios(topology) + build()]\n"
    "pathlib.Path(sys.argv[1]).write_text(digest.hexdigest())\n"
)


def full_digest() -> str:
    topology = build_topology()
    digest = hashlib.sha256(to_json(topology).encode())
    for dataset in build_scenarios(topology) + build_advanced():
        digest.update(to_json(dataset).encode())
    return digest.hexdigest()


def test_generation_is_repeatable_in_process() -> None:
    assert full_digest() == full_digest()


def test_generation_is_independent_of_hash_seed(tmp_path: Path) -> None:
    digests = set()
    for seed in ("0", "4242"):
        output = tmp_path / f"digest-{seed}.txt"
        environment = os.environ | {"PYTHONHASHSEED": seed}
        subprocess.run([sys.executable, "-c", DIGEST_SCRIPT, str(output)], cwd=BACKEND_DIR, env=environment, check=True)
        digests.add(output.read_text())
    assert digests == {full_digest()}


def test_committed_datasets_match_generator() -> None:
    topology = build_topology()
    assert (DATA_DIR / TOPOLOGY_FILE).read_bytes() == to_json(topology).encode("utf-8")
    datasets = build_scenarios(topology) + build_advanced()
    assert list_scenario_ids() == sorted(dataset.scenario.scenario_id for dataset in datasets)
    for dataset in datasets:
        path = DATA_DIR / SCENARIOS_DIR / f"{dataset.scenario.scenario_id}.json"
        assert path.read_bytes() == to_json(dataset).encode("utf-8")


def test_write_datasets_produces_identical_files(tmp_path: Path) -> None:
    write_datasets(tmp_path)
    for dataset in build_advanced():
        (tmp_path / SCENARIOS_DIR / f"{dataset.scenario.scenario_id}.json").write_text(to_json(dataset), encoding="utf-8",
                                                                                        newline="\n")
    written = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*.json"))
    committed = sorted(path.relative_to(DATA_DIR) for path in DATA_DIR.rglob("*.json"))
    assert written == committed
    for relative in written:
        assert (tmp_path / relative).read_bytes() == (DATA_DIR / relative).read_bytes()
        assert b"\r\n" not in (tmp_path / relative).read_bytes()
