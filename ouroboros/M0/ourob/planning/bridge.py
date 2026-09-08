"""Kernel-facing planning bridge (M2.15).

Planner output remains untrusted until validated. Planning attempts are
identified by canonical request/response digests before proposals enter the
kernel's normal planning lifecycle. Durable planning state is reconstructed
through the canonical history auditor; mutable run counters are compatibility
cache only.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..kernel import Kernel
from ..model import Action, Event, Plan, Run, RunState, plan_digest
from .events import PLANNING_ACCEPTED, PLANNING_ATTEMPT_EVENTS, PLANNING_FAILED
from .model import PlanningRequest
from .validator import PlanValidator, digest, request_digest


def planning_history(kernel: Kernel, run_id: str):
    """Return canonical journal-derived planning state."""
    from .history import reconstruct_planning_history
    return reconstruct_planning_history(kernel, run_id)


def planning_attempt_count(kernel: Kernel, run_id: str) -> int:
    """Derive the durable planning-attempt count from canonical history."""
    return planning_history(kernel, run_id).count


@dataclass(frozen=True)
class PlanningBridgeResult:
    run: Run
    accepted: bool
    violations: tuple[Any, ...] = ()
    attempt: int = 0
    request_digest: str = ""
    response_digest: str = ""
    plan_digest: str = ""


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
            "mutation_epoch": run.verification_epoch,
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
        normalized_actions = tuple(result.normalized_actions)
        canonical_plan_hash = plan_digest(normalized_actions)
        self.kernel.plan(run, Plan(request.objective, normalized_actions))
        self.kernel.journal.append(Event(
            PLANNING_ACCEPTED,
            run.id,
            generation=run.generation,
            data={
                "attempt": attempt,
                "request_digest": request_hash,
                "response_digest": response_hash,
                "plan_digest": canonical_plan_hash,
                "mutation_epoch": run.verification_epoch,
            },
        ))
        run.planning_attempts = attempt
        return PlanningBridgeResult(run, True, (), attempt, request_hash, response_hash, canonical_plan_hash)


__all__ = [
    "PLANNING_FAILED", "PLANNING_ACCEPTED", "PLANNING_ATTEMPT_EVENTS",
    "planning_history", "planning_attempt_count", "PlanningBridge", "PlanningBridgeResult",
]
