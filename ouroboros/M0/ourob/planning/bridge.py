"""Kernel-facing planning bridge (M2.10).

Planner output remains untrusted until validated. Planning attempts are
identified by canonical request/response digests before proposals enter the
kernel's normal planning lifecycle. Attempt history is derived from the
append-only journal rather than trusted from mutable run state.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..kernel import Kernel
from ..model import Action, Event, Plan, Run, RunState
from .model import PlanningRequest
from .validator import PlanValidator, digest, request_digest


PLANNING_FAILED = "PLANNING_FAILED"
PLANNING_ACCEPTED = "PLANNING_ACCEPTED"
PLANNING_ATTEMPT_EVENTS = frozenset({PLANNING_FAILED, PLANNING_ACCEPTED})


def planning_attempt_count(kernel: Kernel, run_id: str) -> int:
    """Derive the durable planning-attempt count from the journal.

    ``Run.planning_attempts`` is retained as a compatibility cache only and
    is never authoritative for planning budgets or attempt identity.
    """
    return sum(
        1
        for event in kernel.journal.events()
        if event.run_id == run_id and event.name in PLANNING_ATTEMPT_EVENTS
    )


@dataclass(frozen=True)
class PlanningBridgeResult:
    run: Run
    accepted: bool
    violations: tuple[Any, ...] = ()
    attempt: int = 0
    request_digest: str = ""
    response_digest: str = ""


class PlanningBridge:
    def __init__(self, kernel: Kernel, validator: PlanValidator):
        self.kernel = kernel
        self.validator = validator

    def _failure(self, run: Run, request_hash: str, response_hash: str,
                 violations: tuple[Any, ...], **data: Any) -> PlanningBridgeResult:
        attempt = planning_attempt_count(self.kernel, run.id) + 1
        payload = {
            "attempt": attempt,
            "request_digest": request_hash,
            "response_digest": response_hash,
            "violations": [v.code if hasattr(v, "code") else str(v) for v in violations],
            **data,
        }
        self.kernel.journal.append(Event(PLANNING_FAILED, run.id, generation=run.generation, data=payload))
        run.planning_attempts = attempt
        return PlanningBridgeResult(run, False, violations, attempt, request_hash, response_hash)

    def apply(self, request: PlanningRequest, response: Any) -> PlanningBridgeResult:
        """Create an INTAKE run and submit one planning attempt."""
        run = self.kernel.intake(request.run_id, request.objective)
        return self.apply_to_run(run, request, response)

    def apply_to_run(self, run: Run, request: PlanningRequest, response: Any) -> PlanningBridgeResult:
        """Submit a proposal to an existing INTAKE run without granting authority."""
        request_hash = request_digest(request)
        try:
            response_hash = digest(response)
        except (AttributeError, TypeError, ValueError):
            response_hash = ""

        if run.state is not RunState.INTAKE:
            raise ValueError(f"replanning requires INTAKE run, found {run.state.value}")
        if request.run_id != run.id or request.objective != run.task:
            return self._failure(run, request_hash, response_hash, ("RUN_MISMATCH",), requested_run=request.run_id)
        if request.generation != run.generation:
            return self._failure(run, request_hash, response_hash, ("STALE_GENERATION",), requested_generation=request.generation)
        if request.mutation_epoch != run.verification_epoch:
            return self._failure(run, request_hash, response_hash, ("STALE_EPOCH",), requested_epoch=request.mutation_epoch, actual_epoch=run.verification_epoch)

        result = self.validator.validate(request, response)
        if not result.accepted:
            return self._failure(run, request_hash, response_hash, result.violations)
        if not result.normalized_actions:
            return self._failure(run, request_hash, response_hash, ("EMPTY_PLAN",))
        if any(not isinstance(action, Action) for action in result.normalized_actions):
            raise TypeError("planning validator returned a non-Action object")

        attempt = planning_attempt_count(self.kernel, run.id) + 1
        self.kernel.plan(run, Plan(request.objective, tuple(result.normalized_actions)))
        self.kernel.journal.append(Event(
            PLANNING_ACCEPTED,
            run.id,
            generation=run.generation,
            data={"attempt": attempt, "request_digest": request_hash, "response_digest": response_hash},
        ))
        run.planning_attempts = attempt
        return PlanningBridgeResult(run, True, (), attempt, request_hash, response_hash)


__all__ = ["PLANNING_FAILED", "PLANNING_ACCEPTED", "planning_attempt_count", "PlanningBridge", "PlanningBridgeResult"]
