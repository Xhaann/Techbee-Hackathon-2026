from pathlib import Path

import pytest

from verification.api.helpers import ApiHarness


@pytest.fixture
def api(tmp_path: Path) -> ApiHarness:
    return ApiHarness(tmp_path)
