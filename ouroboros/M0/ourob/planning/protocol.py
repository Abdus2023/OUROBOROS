"""Provider-independent planner protocol."""
from __future__ import annotations

from typing import Protocol

from .model import PlanningRequest, PlanningResponse


class Planner(Protocol):
    """A planner proposes data; it has no filesystem or kernel authority."""

    def plan(self, request: PlanningRequest) -> PlanningResponse:
        ...
