"""Kernel-facing planning bridge (M2.4).

Planner output remains untrusted until validated. Planning failures are durable
observations, while accepted proposals enter only the kernel's normal planning
state; this bridge never grants authorization, executes actions, verifies, or
promotes.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..kernel import Kernel
from ..model import Action, Event, Plan, Run
from .model import PlanningRequest
from .validator import PlanValidator


PLANNING_FAILED = "PLANNING_FAILED"


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
        """Validate a proposal against the live kernel boundary.

        A rejected proposal is recorded against a freshly-created INTAKE run,
        but does not alter its state, generation, or verification epoch. A
        caller may subsequently issue a new planning request; that request
        must carry the then-current generation/epoch and still pass validation.
        """
        run = self.kernel.intake(request.run_id, request.objective)
        actual_generation = run.generation
        if request.generation != actual_generation:
            violations = ("STALE_GENERATION",)
            self.kernel.journal.append(
                Event(
                    PLANNING_FAILED,
                    run.id,
                    generation=actual_generation,
                    data={"violations": list(violations), "requested_generation": request.generation},
                )
            )
            return PlanningBridgeResult(run=run, accepted=False, violations=violations)
        if request.mutation_epoch != run.verification_epoch:
            violations = ("STALE_EPOCH",)
            self.kernel.journal.append(
                Event(
                    PLANNING_FAILED,
                    run.id,
                    generation=actual_generation,
                    data={"violations": list(violations), "requested_epoch": request.mutation_epoch, "actual_epoch": run.verification_epoch},
                )
            )
            return PlanningBridgeResult(run=run, accepted=False, violations=violations)

        result = self.validator.validate(request, response)
        if not result.accepted:
            codes = tuple(v.code for v in result.violations)
            self.kernel.journal.append(
                Event(
                    PLANNING_FAILED,
                    run.id,
                    generation=actual_generation,
                    data={"violations": list(codes)},
                )
            )
            return PlanningBridgeResult(run=run, accepted=False, violations=result.violations)
        if not result.normalized_actions:
            violation = "EMPTY_PLAN"
            self.kernel.journal.append(
                Event(PLANNING_FAILED, run.id, generation=actual_generation, data={"violations": [violation]})
            )
            return PlanningBridgeResult(run=run, accepted=False, violations=(violation,))
        if any(not isinstance(action, Action) for action in result.normalized_actions):
            raise TypeError("planning validator returned a non-Action object")

        self.kernel.plan(run, Plan(request.objective, tuple(result.normalized_actions)))
        return PlanningBridgeResult(run=run, accepted=True)
