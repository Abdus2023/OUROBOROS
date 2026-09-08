"""Kernel-facing planning bridge (M2.3).

This is the only composition point between planner output and the existing
kernel lifecycle. Planner responses are validated first; only the validator's
normalized Actions are handed to the kernel's existing plan/authorization
path. No planner receives a kernel reference.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..kernel import Kernel
from ..model import Action, Plan, Run
from .model import PlanningRequest
from .validator import PlanValidator


@dataclass(frozen=True)
class PlanningBridgeResult:
    run: Run
    accepted: bool
    violations: tuple[Any, ...] = ()


class PlanningBridge:
    def __init__(self, kernel: Kernel, validator: PlanValidator):
        self.kernel = kernel
        self.validator = validator

    def apply(self, request: PlanningRequest, response: Any) -> PlanningBridgeResult:
        result = self.validator.validate(request, response)
        if not result.accepted:
            raise ValueError("planner response rejected by planning boundary: " + "; ".join(v.code for v in result.violations))
        if not result.normalized_actions:
            raise ValueError("planner produced no executable actions")
        if any(not isinstance(action, Action) for action in result.normalized_actions):
            raise TypeError("planning validator returned a non-Action object")

        run = self.kernel.intake(request.run_id, request.objective)
        self.kernel.plan(run, Plan(request.objective, tuple(result.normalized_actions)))
        return PlanningBridgeResult(run=run, accepted=True)
