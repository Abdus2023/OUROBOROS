"""Kernel-facing planning bridge (M2.6).

Planner output remains untrusted until validated. Planning attempts are
identified by canonical request/response digests before proposals enter the
kernel's normal planning lifecycle.
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
        run.planning_attempts += 1
        codes = tuple(v.code if hasattr(v, "code") else str(v) for v in violations)
        payload = {
            "attempt": run.planning_attempts,
            "request_digest": request_hash,
            "response_digest": response_hash,
            "violations": list(codes),
            **data,
        }
        self.kernel.journal.append(Event(PLANNING_FAILED, run.id, generation=run.generation, data=payload))
        return PlanningBridgeResult(run, False, violations, run.planning_attempts, request_hash, response_hash)

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

        actual_generation = run.generation
        if request.generation != actual_generation:
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

        run.planning_attempts += 1
        self.kernel.plan(run, Plan(request.objective, tuple(result.normalized_actions)))
        self.kernel.journal.append(Event(
            PLANNING_ACCEPTED,
            run.id,
            generation=actual_generation,
            data={
                "attempt": run.planning_attempts,
                "request_digest": request_hash,
                "response_digest": response_hash,
            },
        ))
        return PlanningBridgeResult(run, True, (), run.planning_attempts, request_hash, response_hash)
