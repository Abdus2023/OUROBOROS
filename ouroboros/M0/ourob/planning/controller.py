"""Bounded planner-to-kernel lifecycle controller (M2.15).

The controller is orchestration only. Planner output is proposal data; the
planning bridge validates it, and the kernel remains the sole authority for
authorization, execution, verification, and promotion. Planning budgets are
derived from canonical durable planning history bound to the live boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..model import Event, Run, RunState
from .bridge import PLANNING_FAILED, PlanningBridge, PlanningBridgeResult, planning_history
from .context import PlanningContext
from .model import PlanningRequest, PlanningResponse
from .validator import request_digest


@dataclass(frozen=True)
class PlanningCycleResult:
    run: Run
    planning: PlanningBridgeResult | None
    planner_error: str = ""


class PlanningController:
    """Drive one bounded planning attempt and, if accepted, the kernel lifecycle."""

    def __init__(self, bridge: PlanningBridge, *, max_attempts: int = 1):
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        self.bridge = bridge
        self.max_attempts = max_attempts

    def run(
        self,
        run: Run,
        request: PlanningRequest,
        planner: Callable[[PlanningRequest, PlanningContext], PlanningResponse],
        context: PlanningContext,
    ) -> PlanningCycleResult:
        if run.state is not RunState.INTAKE:
            raise ValueError(f"planning requires INTAKE run, found {run.state.value}")
        history = planning_history(self.bridge.kernel, run.id)
        history.bound_to(run.generation, run.verification_epoch)
        attempts = history.count
        run.planning_attempts = attempts  # compatibility cache; never authoritative
        if attempts >= self.max_attempts:
            raise ValueError("planning attempt budget exhausted")
        if context.run_id != request.run_id or context.repository_id != request.repository_id:
            raise ValueError("planning context does not match request")
        if context.generation != request.generation or context.mutation_epoch != request.mutation_epoch:
            raise ValueError("planning context is stale")

        try:
            response = planner(request, context)
        except Exception as exc:
            attempt = planning_history(self.bridge.kernel, run.id).count + 1
            self.bridge.kernel.journal.append(Event(
                PLANNING_FAILED,
                run.id,
                generation=run.generation,
                data={
                    "attempt": attempt,
                    "request_digest": request_digest(request),
                    "response_digest": "",
                    "violations": ["PLANNER_ERROR"],
                    "error": f"{type(exc).__name__}: {exc}",
                    "mutation_epoch": run.verification_epoch,
                },
            ))
            run.planning_attempts = attempt
            return PlanningCycleResult(run, None, f"{type(exc).__name__}: {exc}")

        planning = self.bridge.apply_to_run(run, request, response)
        if not planning.accepted:
            return PlanningCycleResult(run, planning)

        self.bridge.kernel.authorize(run)
        self.bridge.kernel.execute_all(run)
        if run.state is RunState.OBSERVED:
            self.bridge.kernel.verify(run)
        if run.state is RunState.VERIFIED:
            self.bridge.kernel.promote(run)
        return PlanningCycleResult(run, planning)


__all__ = ["PlanningController", "PlanningCycleResult"]
