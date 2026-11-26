import ast
import re
import sys
from importlib.metadata import packages_distributions
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
DEPENDENCY = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==\S+$")


def declared() -> dict[str, str]:
    names = {}
    for manifest in ("requirements.txt", "requirements-dev.txt"):
        for line in (BACKEND / manifest).read_text(encoding="utf-8").splitlines():
            match = DEPENDENCY.match(line.strip())
            if match:
                names[match.group(1).lower().replace("_", "-")] = manifest
            else:
                assert line.strip() in ("", "-r requirements.txt"), line
    return names


def test_runtime_is_python_312_or_newer() -> None:
    assert sys.version_info >= (3, 12)


def test_single_unified_dependency_manifest() -> None:
    assert not (BACKEND / "requirements-agent.txt").exists()
    assert "agent-framework-core" in declared() and declared()["pytest"] == "requirements-dev.txt"


def test_every_directly_imported_package_is_pinned() -> None:
    distributions = packages_distributions()
    names = declared()
    for root in ("app", "verification"):
        for path in (BACKEND / root).rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                modules = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                    [node.module] if isinstance(node, ast.ImportFrom) and node.module and node.level == 0 else []
                for module in modules:
                    top = module.split(".")[0]
                    if top in sys.stdlib_module_names or top in ("app", "verification"):
                        continue
                    packages = {d.lower().replace("_", "-") for d in distributions.get(top, [])}
                    assert packages & set(names), (path.name, module)
