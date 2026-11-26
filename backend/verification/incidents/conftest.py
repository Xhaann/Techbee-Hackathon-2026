from pathlib import Path

import pytest

from app.incidents import IncidentService, JsonIncidentRepository
from verification.incidents.helpers import SteppingClock


@pytest.fixture
def clock() -> SteppingClock:
    return SteppingClock()


@pytest.fixture
def store(tmp_path: Path) -> Path:
    return tmp_path / "incidents"


@pytest.fixture
def service(store: Path, clock: SteppingClock) -> IncidentService:
    return IncidentService(JsonIncidentRepository(store), clock)
