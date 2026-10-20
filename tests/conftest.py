from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def passive_policy_path() -> Path:
    return Path(__file__).parent / "fixtures" / "passive.yaml"


@pytest.fixture
def active_policy_path() -> Path:
    return Path(__file__).parent / "fixtures" / "active.yaml"
