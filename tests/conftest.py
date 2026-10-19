from __future__ import annotations

from functools import lru_cache

import pytest

from incident_agent.simulate.scenarios import build


@lru_cache(maxsize=64)
def _built(sid: str, seed: int):
    return build(sid, seed)


@pytest.fixture
def scenario():
    """scenario("31") -> (snapshot, ground truth); cached across tests (treat as read-only)."""
    def get(sid: str, seed: int = 0):
        return _built(str(sid), seed)
    return get


@pytest.fixture
def fresh():
    """An uncached build, safe to modify."""
    return lambda sid, seed=0: build(str(sid), seed)
